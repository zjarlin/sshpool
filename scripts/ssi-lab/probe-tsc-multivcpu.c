#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <inttypes.h>
#include <limits.h>
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

/* 先由客体写就绪标记，再由独立宿主 CPU 握手计时；IO 退出发生在采样确认之后。 */
__asm__(
    ".pushsection .rodata\n.balign 16\n.code16\n"
    ".global sshpool_tsc_guest_begin, sshpool_tsc_guest_end\n"
    "sshpool_tsc_guest_begin:\n"
    "cld\n"
    "4: movl $1, 0x2048\n"
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
    "rdtscp\n lfence\n"
    "movl %eax, 0x2010\n movl %edx, 0x2014\n movl %ecx, 0x2018\n"
    "movl $0x10, %ecx\n rdmsr\n lfence\n"
    "movl %eax, 0x2040\n movl %edx, 0x2044\n"
    "movl 0x3000, %eax\n cmpl %ebp, %eax\n jne 2b\n"
    "movl %ebx, 0x2004\n movb $0x5a, %al\n outb %al, $0x80\n jmp 4b\n"
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

static void print_sample(unsigned index, unsigned vcpu, int host_cpu, uint64_t before, uint64_t after, const uint8_t *memory)
{
    struct pvclock_record record;
    uint64_t tsc, tscp, msr;
    uint32_t aux;
    memcpy(&record, memory + 0x2020, sizeof(record));
    memcpy(&tsc, memory + 0x2008, sizeof(tsc));
    memcpy(&tscp, memory + 0x2010, sizeof(tscp));
    memcpy(&aux, memory + 0x2018, sizeof(aux));
    memcpy(&msr, memory + 0x2040, sizeof(msr));
    printf("{\"op\":\"sample\",\"index\":%u,\"vcpu\":%u,\"host_cpu\":%d,\"host_before_ns\":%" PRIu64
           ",\"host_after_ns\":%" PRIu64 ",\"guest_tsc\":%" PRIu64
           ",\"guest_tscp\":%" PRIu64 ",\"tsc_aux\":%u,\"guest_msr\":%" PRIu64
           ",\"pvclock\":{\"version\":%u,\"tsc\":%" PRIu64 ",\"system_time\":%" PRIu64
           ",\"multiplier\":%u,\"shift\":%d,\"flags\":%u}}\n",
           index, vcpu, host_cpu, before, after, tsc, tscp, aux, msr, record.version, record.tsc, record.system_time,
           record.multiplier, record.shift, record.flags);
}

/* 两个 vCPU 在同一个 VM 中初始化；所有比例确定后才设置共同偏移。 */
struct cpu_state {
    int fd;
    uint32_t native, requested;
    uint64_t offset;
    struct kvm_run *run;
    uint8_t *memory;
};

static uint64_t tsc_offset(int cpu, int write, uint64_t value)
{
    struct kvm_device_attr attr = {.group = KVM_VCPU_TSC_CTRL,
        .attr = KVM_VCPU_TSC_OFFSET, .addr = (uintptr_t)&value};
    checked(cpu, write ? KVM_SET_DEVICE_ATTR : KVM_GET_DEVICE_ATTR, &attr);
    return value;
}

static void configure(struct cpu_state *cpu, int kvm, int vm, unsigned id,
                      const char *mode, uint32_t target, uint8_t *memory, int run_bytes)
{
    cpu->fd = checked(vm, KVM_CREATE_VCPU, (void *)(uintptr_t)id);
    cpu->native = checked(cpu->fd, KVM_GET_TSC_KHZ, NULL);
    uint64_t enabled = 1;
    struct kvm_device_attr attr = {.group = KVM_VCPU_TSC_CTRL,
        .attr = 0x53534931ULL, .addr = (uintptr_t)&enabled};
    checked(cpu->fd, KVM_HAS_DEVICE_ATTR, &attr);
    checked(cpu->fd, KVM_SET_DEVICE_ATTR, &attr);
    enabled = 0;
    checked(cpu->fd, KVM_GET_DEVICE_ATTR, &attr);
    if (enabled != 1) { errno = EIO; fail("software_selection"); }
    cpu->requested = cpu->native;
    if (!strcmp(mode, "faster")) { cpu->requested = (uint64_t)cpu->native * 6 / 5; }
    if (!strcmp(mode, "slower")) { cpu->requested = (uint64_t)cpu->native * 4 / 5; }
    if (!strcmp(mode, "target")) { cpu->requested = target; }
    checked(cpu->fd, KVM_SET_TSC_KHZ, (void *)(uintptr_t)cpu->requested);
    if (checked(cpu->fd, KVM_GET_TSC_KHZ, NULL) != (int)cpu->requested) { fail("frequency_readback"); }
    struct kvm_cpuid2 *cpuid = calloc(1, sizeof(*cpuid) + 256 * sizeof(struct kvm_cpuid_entry2));
    if (!cpuid) { fail("cpuid_allocation"); }
    cpuid->nent = 256;
    checked(kvm, KVM_GET_SUPPORTED_CPUID, cpuid);
    checked(cpu->fd, KVM_SET_CPUID2, cpuid);
    free(cpuid);
    uint64_t gpa = (uint64_t)id * 65536;
    cpu->memory = memory + gpa;
    memcpy(cpu->memory + 0x1000, sshpool_tsc_guest_begin,
           (uintptr_t)sshpool_tsc_guest_end - (uintptr_t)sshpool_tsc_guest_begin);
    struct kvm_sregs sregs;
    checked(cpu->fd, KVM_GET_SREGS, &sregs);
    sregs.cs.base = sregs.ds.base = sregs.es.base = sregs.ss.base = gpa;
    sregs.cs.selector = sregs.ds.selector = sregs.es.selector = sregs.ss.selector = gpa >> 4;
    checked(cpu->fd, KVM_SET_SREGS, &sregs);
    struct kvm_regs regs = {.rip = 0x1000, .rflags = 2};
    checked(cpu->fd, KVM_SET_REGS, &regs);
    struct { struct kvm_msrs header; struct kvm_msr_entry entries[3]; } msrs = {
        .header.nmsrs = 3, .entries = {{.index = 0x10, .data = 0},
            {.index = 0xc0000103, .data = 0x53534900 + id},
            {.index = 0x4b564d01, .data = gpa + 0x3001}}};
    if (checked(cpu->fd, KVM_SET_MSRS, &msrs) != 3) { fail("clock_msrs"); }
    cpu->run = mmap(NULL, run_bytes, PROT_READ | PROT_WRITE, MAP_SHARED, cpu->fd, 0);
    if (cpu->run == MAP_FAILED) { fail("run_mapping"); }
}

static void wait_word(_Atomic uint32_t *word, uint32_t expected)
{
    uint64_t deadline = now() + UINT64_C(1000000000);
    unsigned polls = 0;
    while (atomic_load_explicit(word, memory_order_acquire) != expected) {
        if (++polls % 1024 == 0 && now() > deadline) { errno = ETIMEDOUT; fail("guest_handshake"); }
    }
}

static void pause_ns(long ns)
{
    struct timespec pause = {.tv_nsec = ns};
    while (nanosleep(&pause, &pause)) {
        if (errno != EINTR) { fail("sample_interval"); }
    }
}

int main(int argc, char **argv)
{
    struct utsname host;
    if (argc != 5 || uname(&host) || strcmp(host.machine, "x86_64") || strcmp(host.release, argv[1]) ||
        (strcmp(argv[2], "native") && strcmp(argv[2], "faster") && strcmp(argv[2], "slower") && strcmp(argv[2], "target")) ||
        (strcmp(argv[4], "aligned") && strcmp(argv[4], "skew"))) {
        fprintf(stderr, "usage: probe-tsc-multivcpu REQUIRED_KERNEL native|faster|slower|target TARGET_KHZ aligned|skew\n");
        return 2;
    }
    char *end;
    errno = 0;
    unsigned long target = strtoul(argv[3], &end, 10);
    if (errno || !*argv[3] || *end || !target || target > INT_MAX) { return 2; }
    setvbuf(stdout, NULL, _IONBF, 0);
    prctl(PR_SET_NAME, "probe-tsc");
    alarm(10);
    cpu_set_t available;
    if (sched_getaffinity(0, sizeof(available), &available)) { fail("available_cpus"); }
    int hosts[2], count = 0;
    for (int cpu = 0; cpu < CPU_SETSIZE && count < 2; cpu++) {
        if (CPU_ISSET(cpu, &available)) { hosts[count++] = cpu; }
    }
    if (count != 2) { errno = ENOSPC; fail("two_cpus_required"); }
    int kvm = open("/dev/kvm", O_RDWR | O_CLOEXEC);
    if (kvm < 0) { fail("open_kvm"); }
    if (ioctl(kvm, KVM_GET_API_VERSION, 0) != 12 ||
        ioctl(kvm, KVM_CHECK_EXTENSION, KVM_CAP_TSC_CONTROL) != 0) { errno = ENOTSUP; fail("kvm_capability"); }
    int vm = checked(kvm, KVM_CREATE_VM, NULL);
    int run_bytes = checked(kvm, KVM_GET_VCPU_MMAP_SIZE, NULL);
    uint8_t *memory = mmap(NULL, 131072, PROT_READ | PROT_WRITE, MAP_ANONYMOUS | MAP_PRIVATE, -1, 0);
    if (memory == MAP_FAILED) { fail("guest_memory"); }
    struct kvm_userspace_memory_region region = {.slot = 0, .guest_phys_addr = 0,
        .memory_size = 131072, .userspace_addr = (uintptr_t)memory};
    checked(vm, KVM_SET_USER_MEMORY_REGION, &region);
    size_t code_bytes = (uintptr_t)sshpool_tsc_guest_end - (uintptr_t)sshpool_tsc_guest_begin;
    if (!code_bytes || code_bytes > 4096) { errno = EINVAL; fail("code_size"); }
    struct cpu_state cpus[2];
    for (unsigned id = 0; id < 2; id++) { configure(&cpus[id], kvm, vm, id, argv[2], target, memory, run_bytes); }
    if (cpus[0].requested != cpus[1].requested || cpus[0].native != cpus[1].native) { fail("vcpu_rates_differ"); }
    uint64_t common_offset = tsc_offset(cpus[0].fd, 0, 0);
    printf("{\"op\":\"configuration\",\"kernel\":\"%s\",\"mode\":\"%s\",\"alignment\":\"%s\","
           "\"native_khz\":%u,\"requested_khz\":%u,\"control\":0,\"vcpus\":2,\"vms\":1,\"host_cpus\":[%d,%d],\"guest_hex\":\"",
           host.release, argv[2], argv[4], cpus[0].native, cpus[0].requested, hosts[0], hosts[1]);
    for (size_t i = 0; i < code_bytes; i++) { printf("%02x", sshpool_tsc_guest_begin[i]); }
    puts("\"}");
    for (unsigned id = 0; id < 2; id++) {
        uint64_t skew = id && !strcmp(argv[4], "skew") ? (uint64_t)cpus[id].requested * 50 : 0;
        cpus[id].offset = common_offset + skew;
        tsc_offset(cpus[id].fd, 1, cpus[id].offset);
        uint64_t reported = tsc_offset(cpus[id].fd, 0, 0);
        if (reported != cpus[id].offset) { fail("offset_readback"); }
        printf("{\"op\":\"offset\",\"vcpu\":%u,\"written\":%" PRIu64 ",\"reported\":%" PRIu64 "}\n",
               id, cpus[id].offset, reported);
    }
    /* 固定轮换 vCPU 顺序与宿主 CPU；观测者使用另一 CPU，排除进入和 IO 退出开销。 */
    for (unsigned round = 0; round < 12; round++) {
        for (unsigned order = 0; order < 2; order++) {
            unsigned id = order ^ (round & 1);
            int host_cpu = hosts[id ^ ((round / 3) & 1)];
            struct cpu_state *cpu = &cpus[id];
            pin(hosts[1 - (id ^ ((round / 3) & 1))]);
            _Atomic uint32_t *request = (_Atomic uint32_t *)(cpu->memory + 0x2000);
            _Atomic uint32_t *response = (_Atomic uint32_t *)(cpu->memory + 0x2004);
            if (!atomic_is_lock_free(request)) { errno = ENOTSUP; fail("handshake_atomic"); }
            _Atomic uint32_t *ready = (_Atomic uint32_t *)(cpu->memory + 0x2048);
            atomic_store_explicit(ready, 0, memory_order_release);
            struct execution execution = {.fd = cpu->fd, .affinity = host_cpu};
            pthread_t worker;
            int status = pthread_create(&worker, NULL, execute, &execution);
            if (status) { errno = status; fail("thread_create"); }
            wait_word(ready, 1);
            uint64_t before = now();
            atomic_store_explicit(request, round + 1, memory_order_release);
            wait_word(response, round + 1);
            uint64_t after = now();
            status = pthread_join(worker, NULL);
            if (status) { errno = status; fail("thread_join"); }
            if (execution.result || execution.error) { errno = execution.error; fail("guest_run"); }
            struct kvm_run *run = cpu->run;
            if (run->exit_reason != KVM_EXIT_IO || run->io.direction != KVM_EXIT_IO_OUT ||
                run->io.port != 0x80 || run->io.size != 1 || run->io.count != 1 ||
                run->io.data_offset >= (uint64_t)run_bytes || *((uint8_t *)run + run->io.data_offset) != 0x5a ||
                atomic_load_explicit(response, memory_order_acquire) != round + 1) { fail("sample_exit"); }
            print_sample(round * 2 + order, id, host_cpu, before, after, cpu->memory);
            if (!order) { pause_ns(1000000); }
        }
        if (round != 11) { pause_ns(500000000); }
    }
    for (unsigned id = 0; id < 2; id++) {
        struct cpu_state *cpu = &cpus[id];
        atomic_store_explicit((_Atomic uint32_t *)(cpu->memory + 0x2000), UINT32_MAX, memory_order_release);
        checked(cpu->fd, KVM_RUN, NULL);
        struct kvm_regs regs;
        checked(cpu->fd, KVM_GET_REGS, &regs);
        if (cpu->run->exit_reason != KVM_EXIT_HLT || regs.rip != 0x1000 + code_bytes) { fail("guest_halt"); }
        errno = 0;
        int late = ioctl(cpu->fd, KVM_SET_TSC_KHZ, (unsigned long)cpu->requested + 1000);
        int late_errno = errno;
        int reported = checked(cpu->fd, KVM_GET_TSC_KHZ, NULL);
        uint64_t offset_after = tsc_offset(cpu->fd, 0, 0);
        printf("{\"op\":\"vcpu_done\",\"vcpu\":%u,\"exit_reason\":%u,\"rip\":%" PRIu64
               ",\"run_calls\":13,\"late_result\":%d,\"late_errno\":%d,\"reported_khz\":%d,\"offset_after\":%" PRIu64 "}\n",
               id, cpu->run->exit_reason, (uint64_t)regs.rip, late, late_errno, reported, offset_after);
        if (late != -1 || late_errno != EINVAL || reported != (int)cpu->requested || offset_after != cpu->offset) {
            fail("configuration_changed");
        }
        if (munmap(cpu->run, run_bytes) || close(cpu->fd)) { fail("close_vcpu"); }
    }
    if (close(vm) || munmap(memory, 131072) || close(kvm)) { fail("close"); }
    alarm(0);
    puts("{\"op\":\"closed\",\"run_calls\":26,\"fds_closed\":4}");
    return 0;
}
