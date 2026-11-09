#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <inttypes.h>
#include <linux/kvm.h>
#include <pthread.h>
#include <sched.h>
#include <stdatomic.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <sys/prctl.h>
#include <sys/utsname.h>
#include <time.h>
#include <unistd.h>

/* 整组采样只执行一次 KVM_RUN；共享内存握手给每次客体读时钟建立宿主时间包络。 */
__asm__(
    ".pushsection .rodata\n.balign 16\n.code16\n"
    ".global sshpool_tsc_guest_begin, sshpool_tsc_guest_end\n"
    "sshpool_tsc_guest_begin:\n"
    "cld\n"
    "1: movl 0x2000, %eax\n"
    "testl %eax, %eax\n jz 1b\n"
    "cmpl 0x2004, %eax\n je 1b\n"
    "cmpl $-1, %eax\n je 3f\n"
    "movl %eax, %ebx\n"
    "2: movl 0x3000, %eax\n"
    "testb $1, %al\n jnz 2b\n"
    "movl %eax, %ebp\n"
    "movw $0x3000, %si\n movw $0x2020, %di\n movw $16, %cx\n rep movsw\n"
    "lfence\n rdtsc\n lfence\n"
    "movl %eax, 0x2008\n movl %edx, 0x200c\n"
    "movl 0x3000, %eax\n cmpl %ebp, %eax\n jne 2b\n"
    "movl %ebx, 0x2004\n jmp 1b\n"
    "3: hlt\n"
    "sshpool_tsc_guest_end:\n.code64\n.popsection\n");
extern const uint8_t sshpool_tsc_guest_begin[], sshpool_tsc_guest_end[];

struct pvclock_record {
    uint32_t version, padding;
    uint64_t tsc, system_time;
    uint32_t multiplier;
    int8_t shift;
    uint8_t flags, reserved[2];
};
_Static_assert(sizeof(struct pvclock_record) == 32, "pvclock ABI");

struct execution {
    int fd, affinity, result, error;
};

static void fail(const char *operation)
{
    fprintf(stderr, "TSC_ERROR operation=%s errno=%d message=%s\n", operation, errno, strerror(errno));
    exit(1);
}

static int checked(int fd, unsigned long operation, void *value)
{
    int result = ioctl(fd, operation, value);
    if (result < 0) { fail("ioctl"); }
    return result;
}

static uint64_t now(void)
{
    struct timespec time;
    if (clock_gettime(CLOCK_MONOTONIC_RAW, &time)) { fail("clock"); }
    return (uint64_t)time.tv_sec * UINT64_C(1000000000) + time.tv_nsec;
}

static void pin(int cpu)
{
    cpu_set_t mask;
    CPU_ZERO(&mask);
    CPU_SET(cpu, &mask);
    if (sched_setaffinity(0, sizeof(mask), &mask)) { fail("affinity"); }
}

static void *execute(void *opaque)
{
    struct execution *execution = opaque;
    pin(execution->affinity);
    prctl(PR_SET_NAME, "tsc-vcpu");
    errno = 0;
    execution->result = ioctl(execution->fd, KVM_RUN, 0);
    execution->error = errno;
    return NULL;
}

static void print_sample(unsigned index, uint64_t before, uint64_t after, const uint8_t *memory)
{
    struct pvclock_record record;
    uint64_t tsc;
    memcpy(&record, memory + 0x2020, sizeof(record));
    memcpy(&tsc, memory + 0x2008, sizeof(tsc));
    printf("{\"op\":\"sample\",\"index\":%u,\"host_before_ns\":%" PRIu64
           ",\"host_after_ns\":%" PRIu64 ",\"guest_tsc\":%" PRIu64
           ",\"pvclock\":{\"version\":%u,\"tsc\":%" PRIu64 ",\"system_time\":%" PRIu64
           ",\"multiplier\":%u,\"shift\":%d,\"flags\":%u}}\n",
           index, before, after, tsc, record.version, record.tsc, record.system_time,
           record.multiplier, record.shift, record.flags);
}

int main(int argc, char **argv)
{
    struct utsname host;
    if (argc != 3 || uname(&host) || strcmp(host.machine, "x86_64") || strcmp(host.release, argv[1]) ||
        (strcmp(argv[2], "native") && strcmp(argv[2], "faster") && strcmp(argv[2], "slower"))) {
        fprintf(stderr, "usage: probe-tsc-frequency REQUIRED_KERNEL native|faster|slower\n");
        return 2;
    }
    setvbuf(stdout, NULL, _IONBF, 0);
    prctl(PR_SET_NAME, "probe-tsc");
    /* 看门狗只终止本探针；标准 KVM fd 随进程退出释放，不改变宿主时钟。 */
    alarm(10);
    cpu_set_t available;
    if (sched_getaffinity(0, sizeof(available), &available)) { fail("available_cpus"); }
    int first = -1, second = -1;
    for (int cpu = 0; cpu < CPU_SETSIZE; cpu++) {
        if (!CPU_ISSET(cpu, &available)) { continue; }
        if (first < 0) { first = cpu; } else { second = cpu; break; }
    }
    if (second < 0) { errno = ENOSPC; fail("two_cpus_required"); }
    pin(second);
    int kvm = open("/dev/kvm", O_RDWR | O_CLOEXEC);
    if (kvm < 0) { fail("open_kvm"); }
    if (ioctl(kvm, KVM_GET_API_VERSION, 0) != 12 || ioctl(kvm, KVM_CHECK_EXTENSION, KVM_CAP_GET_TSC_KHZ) != 1) {
        errno = ENOTSUP; fail("kvm_api");
    }
    int control = checked(kvm, KVM_CHECK_EXTENSION, (void *)(uintptr_t)KVM_CAP_TSC_CONTROL);
    int vm = checked(kvm, KVM_CREATE_VM, NULL);
    int cpu = checked(vm, KVM_CREATE_VCPU, NULL);
    uint32_t native = checked(cpu, KVM_GET_TSC_KHZ, NULL);
    uint32_t requested = native;
    if (!strcmp(argv[2], "faster")) { requested = (uint64_t)native * 6 / 5; }
    if (!strcmp(argv[2], "slower")) { requested = (uint64_t)native * 4 / 5; }
    /* 先完成客体状态初始化，再设置频率；不能在设置后写 MSR 掩盖 catch-up 状态。 */
    uint8_t *memory = mmap(NULL, 65536, PROT_READ | PROT_WRITE, MAP_ANONYMOUS | MAP_PRIVATE, -1, 0);
    if (memory == MAP_FAILED) { fail("guest_memory"); }
    size_t code_bytes = (uintptr_t)sshpool_tsc_guest_end - (uintptr_t)sshpool_tsc_guest_begin;
    if (!code_bytes || code_bytes > 4096) { errno = EINVAL; fail("code_size"); }
    memcpy(memory + 0x1000, sshpool_tsc_guest_begin, code_bytes);
    printf("{\"op\":\"guest_code\",\"gpa\":4096,\"bytes\":%zu,\"hex\":\"", code_bytes);
    for (size_t index = 0; index < code_bytes; index++) { printf("%02x", sshpool_tsc_guest_begin[index]); }
    puts("\"}");
    struct kvm_userspace_memory_region region = {.slot = 0, .guest_phys_addr = 0,
        .memory_size = 65536, .userspace_addr = (uintptr_t)memory};
    checked(vm, KVM_SET_USER_MEMORY_REGION, &region);
    struct kvm_sregs sregs;
    checked(cpu, KVM_GET_SREGS, &sregs);
    sregs.cs.base = sregs.ds.base = sregs.es.base = sregs.ss.base = 0;
    sregs.cs.selector = sregs.ds.selector = sregs.es.selector = sregs.ss.selector = 0;
    checked(cpu, KVM_SET_SREGS, &sregs);
    struct kvm_regs regs = {.rip = 0x1000, .rflags = 2};
    checked(cpu, KVM_SET_REGS, &regs);
    struct { struct kvm_msrs header; struct kvm_msr_entry entries[2]; } msrs = {
        .header.nmsrs = 2, .entries = {{.index = 0x10, .data = 0}, {.index = 0x4b564d01, .data = 0x3001}}};
    if (checked(cpu, KVM_SET_MSRS, &msrs) != 2) { errno = ENOTSUP; fail("clock_msrs"); }
    errno = 0;
    int set_result = ioctl(cpu, KVM_SET_TSC_KHZ, (unsigned long)requested);
    int set_error = errno;
    int reported = checked(cpu, KVM_GET_TSC_KHZ, NULL);
    printf("{\"op\":\"configuration\",\"kernel\":\"%s\",\"mode\":\"%s\",\"native_khz\":%u,"
           "\"requested_khz\":%u,\"reported_khz\":%d,\"control\":%d,\"set_result\":%d,\"set_errno\":%d,"
           "\"vcpu_host_cpu\":%d,\"observer_host_cpu\":%d}\n",
           host.release, argv[2], native, requested, reported, control, set_result, set_error, first, second);
    if (set_result < 0) {
        /* 失败也可能已改变临时 vCPU 字段；直接释放，绝不在此实例上继续运行。 */
        if (munmap(memory, 65536) || close(cpu) || close(vm) || close(kvm)) { fail("close_rejected"); }
        puts("{\"op\":\"closed\",\"run_calls\":0,\"fds_closed\":3,\"rejected\":true}");
        return 0;
    }
    int run_bytes = checked(kvm, KVM_GET_VCPU_MMAP_SIZE, NULL);
    struct kvm_run *run = mmap(NULL, run_bytes, PROT_READ | PROT_WRITE, MAP_SHARED, cpu, 0);
    if (run == MAP_FAILED) { fail("run_mapping"); }
    _Atomic uint32_t *request = (_Atomic uint32_t *)(memory + 0x2000);
    _Atomic uint32_t *response = (_Atomic uint32_t *)(memory + 0x2004);
    if (!atomic_is_lock_free(request) || !atomic_is_lock_free(response)) { errno = ENOTSUP; fail("handshake_atomic"); }
    struct execution execution = {.fd = cpu, .affinity = first};
    pthread_t worker;
    int status = pthread_create(&worker, NULL, execute, &execution);
    if (status) { errno = status; fail("thread_create"); }
    for (unsigned index = 0; index < 12; index++) {
        uint64_t before = now();
        atomic_store_explicit(request, index + 1, memory_order_release);
        unsigned polls = 0;
        while (atomic_load_explicit(response, memory_order_acquire) != index + 1) {
            if (++polls % 1024) { continue; }
            if (now() - before > UINT64_C(1000000000)) { errno = ETIMEDOUT; fail("guest_handshake"); }
            sched_yield();
        }
        uint64_t after = now();
        print_sample(index, before, after, memory);
        if (index < 11) {
            struct timespec pause = {.tv_nsec = 100000000};
            while (nanosleep(&pause, &pause)) {
                if (errno != EINTR) { fail("sample_interval"); }
            }
        }
    }
    atomic_store_explicit(request, UINT32_MAX, memory_order_release);
    status = pthread_join(worker, NULL);
    if (status) { errno = status; fail("thread_join"); }
    checked(cpu, KVM_GET_REGS, &regs);
    struct kvm_clock_data clock = {};
    checked(vm, KVM_GET_CLOCK, &clock);
    int reported_after = checked(cpu, KVM_GET_TSC_KHZ, NULL);
    printf("{\"op\":\"run_done\",\"result\":%d,\"errno\":%d,\"exit_reason\":%u,\"rip\":%" PRIu64
           ",\"clock\":%" PRIu64 ",\"clock_flags\":%u,\"reported_khz_after_run\":%d}\n",
           execution.result, execution.error, run->exit_reason,
           (uint64_t)regs.rip, (uint64_t)clock.clock, clock.flags, reported_after);
    if (execution.result != 0 || run->exit_reason != KVM_EXIT_HLT || regs.rip != 0x1000 + code_bytes) {
        errno = EIO; fail("guest_halt");
    }
    if (munmap(run, run_bytes) || close(cpu) || close(vm) || munmap(memory, 65536) || close(kvm)) { fail("close"); }
    alarm(0);
    puts("{\"op\":\"closed\",\"run_calls\":1,\"fds_closed\":3,\"rejected\":false}");
    return 0;
}
