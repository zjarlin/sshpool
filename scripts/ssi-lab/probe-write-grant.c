#define _GNU_SOURCE
#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <inttypes.h>
#include <linux/kvm.h>
#include <pthread.h>
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

/* 每次 KVM_RUN 只执行一条共享页写入及 HLT，宿主标记给调用建立唯一边界。 */
struct dsm_params { uint32_t node, count; uint64_t peers; };
struct dsm_copy { uint8_t write, padding[7]; uint64_t host, user, length; };
struct dsm_close { uint32_t version, flags; uint64_t generation; uint32_t timeout_ms, reserved; };
#define DSM_ENABLE _IOW(KVMIO, 0xf0, struct dsm_params)
#define DSM_MEMCPY _IOW(KVMIO, 0xf1, struct dsm_copy)
#define DSM_CLOSE _IOW(KVMIO, 0xfb, struct dsm_close)
_Static_assert(sizeof(struct dsm_copy) == 32, "copy ABI");
_Static_assert(sizeof(struct dsm_close) == 24, "close ABI");
static int vm, marker = -1;
static uint8_t *memory;
static atomic_bool reading;
static pthread_t reader;
static uint64_t reads, regressions;
static uint32_t last_value;

static void fail(const char *op)
{
    fprintf(stderr, "GRANT_ERROR operation=%s errno=%d message=%s\n", op, errno, strerror(errno));
    exit(1);
}

static int checked(int fd, unsigned long request, void *value)
{
    int result = ioctl(fd, request, value);
    if (result < 0) { fail("ioctl"); }
    return result;
}

static uint64_t now_ns(void)
{
    struct timespec value;
    if (clock_gettime(CLOCK_MONOTONIC_RAW, &value)) { fail("clock"); }
    return (uint64_t)value.tv_sec * 1000000000 + value.tv_nsec;
}

static uint32_t read_value(void)
{
    uint32_t value = 0;
    struct dsm_copy request = {.host = (uintptr_t)(memory + 4096), .user = (uintptr_t)&value, .length = 4};
    checked(vm, DSM_MEMCPY, &request);
    return value;
}

static void *read_loop(void *ignored)
{
    (void)ignored;
    prctl(PR_SET_NAME, "grant-reader");
    while (atomic_load(&reading)) {
        uint32_t value = read_value();
        regressions += value < last_value;
        last_value = value;
        reads++;
    }
    return NULL;
}

static void stop_reader(void)
{
    atomic_store(&reading, 0);
    int status = pthread_join(reader, NULL);
    if (status) { errno = status; fail("join"); }
    printf("{\"op\":\"reader_stopped\",\"reads\":%" PRIu64 ",\"regressions\":%" PRIu64 ",\"last\":%u}\n", reads, regressions, last_value);
}

static void mark(const char *phase, uint32_t value)
{
    if (marker < 0) { return; }
    char text[96];
    int length = snprintf(text, sizeof(text), "grant_%s value=%u", phase, value);
    if (write(marker, text, length) != length) { fail("trace_marker"); }
}

int main(int argc, char **argv)
{
    struct utsname host;
    struct in_addr ip;
    setvbuf(stdout, NULL, _IONBF, 0);
    if (argc != 5 || (strcmp(argv[1], "0") && strcmp(argv[1], "1")) || uname(&host) ||
        strcmp(host.machine, "x86_64") || strcmp(host.release, argv[4])) { return 2; }
    int node = atoi(argv[1]), count = strcmp(argv[3], "-") ? 2 : 1;
    if (node >= count) { return 2; }
    char *peers[] = {argv[2], argv[3]};
    for (int i = 0; i < count; i++) {
        if (inet_pton(AF_INET, peers[i], &ip) != 1) { return 2; }
    }
    prctl(PR_SET_NAME, "probe-grant");
    int kvm = open("/dev/kvm", O_RDWR | O_CLOEXEC);
    if (kvm < 0 || ioctl(kvm, KVM_CHECK_EXTENSION, 249) != 1) { fail("capability"); }
    vm = checked(kvm, KVM_CREATE_VM, NULL);
    struct dsm_params parameters = {.node = node, .count = count, .peers = (uintptr_t)peers};
    checked(vm, DSM_ENABLE, &parameters);
    memory = mmap(NULL, 8192, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (memory == MAP_FAILED) { fail("mmap"); }
    /* 16 位实模式地址、32 位操作数：mov [0x2000],eax；随后只有 HLT。 */
    const uint8_t code[] = {0x66, 0xa3, 0x00, 0x20, 0xf4};
    memcpy(memory, code, sizeof(code));
    struct kvm_userspace_memory_region region = {.slot = 0, .guest_phys_addr = 0x1000,
        .memory_size = 8192, .userspace_addr = (uintptr_t)memory};
    checked(vm, KVM_SET_USER_MEMORY_REGION, &region);
    int cpu = checked(vm, KVM_CREATE_VCPU, (void *)(uintptr_t)node);
    int size = checked(kvm, KVM_GET_VCPU_MMAP_SIZE, NULL);
    struct kvm_run *run = mmap(NULL, size, PROT_READ | PROT_WRITE, MAP_SHARED, cpu, 0);
    if (run == MAP_FAILED) { fail("run_mmap"); }
    struct kvm_sregs sregs;
    checked(cpu, KVM_GET_SREGS, &sregs);
    sregs.cs.base = sregs.ds.base = sregs.es.base = sregs.ss.base = 0;
    sregs.cs.selector = sregs.ds.selector = sregs.es.selector = sregs.ss.selector = 0;
    checked(cpu, KVM_SET_SREGS, &sregs);
    printf("{\"op\":\"ready\",\"node\":%d,\"nodes\":%d,\"pid\":%d,\"rip\":4096,\"address\":8192}\n", node, count, getpid());
    char command[160], extra;
    unsigned amount, base;
    uint64_t generation;
    int sealed = 0;
    while (fgets(command, sizeof(command), stdin)) {
        if (!strcmp(command, "quit\n")) { break; }
        if (sealed) { errno = EINVAL; fail("sealed"); }
        if (!strcmp(command, "trace\n")) {
            char path[160];
            snprintf(path, sizeof(path), "/sys/kernel/tracing/instances/sshpool_grant_%d/trace_marker", getpid());
            if (marker >= 0) { errno = EALREADY; fail("trace_duplicate"); }
            marker = open(path, O_WRONLY | O_CLOEXEC);
            if (marker < 0) { fail("trace_open"); }
            puts("{\"op\":\"trace_ready\"}");
        } else if (!strcmp(command, "untrace\n")) {
            if (marker < 0 || close(marker)) { fail("trace_close"); }
            marker = -1;
            puts("{\"op\":\"trace_closed\"}");
        } else if (!strcmp(command, "reader_start\n")) {
            if (atomic_load(&reading)) { errno = EALREADY; fail("reader_active"); }
            last_value = read_value(); reads = regressions = 0;
            atomic_store(&reading, 1);
            int status = pthread_create(&reader, NULL, read_loop, NULL);
            if (status) { errno = status; fail("reader_create"); }
            puts("{\"op\":\"reader_started\"}");
        } else if (!strcmp(command, "reader_stop\n")) {
            if (!atomic_load(&reading)) { errno = EINVAL; fail("reader_inactive"); }
            stop_reader();
        } else if (!strcmp(command, "read\n")) {
            printf("{\"op\":\"read\",\"value\":%u}\n", read_value());
        } else if (sscanf(command, "write %u %u %c", &amount, &base, &extra) == 2 &&
                   amount > 0 && amount <= 4096 && base <= UINT32_MAX - amount) {
            if (atomic_load(&reading)) { errno = EBUSY; fail("reader_local"); }
            for (unsigned i = 1; i <= amount; i++) {
                uint32_t value = base + i;
                struct kvm_regs regs = {.rip = 0x1000, .rflags = 2, .rax = value};
                struct kvm_mp_state mp = {.mp_state = KVM_MP_STATE_RUNNABLE};
                checked(cpu, KVM_SET_REGS, &regs);
                checked(cpu, KVM_SET_MP_STATE, &mp);
                mark("begin", value);
                uint64_t begin = now_ns();
                checked(cpu, KVM_RUN, NULL);
                uint64_t end = now_ns();
                mark("end", value);
                checked(cpu, KVM_GET_REGS, &regs);
                uint32_t observed;
                memcpy(&observed, memory + 4096, sizeof(observed));
                printf("{\"op\":\"write\",\"value\":%u,\"observed\":%u,\"exit_reason\":%u,\"rip\":%" PRIu64
                       ",\"elapsed_ns\":%" PRIu64 "}\n", value, observed, run->exit_reason, (uint64_t)regs.rip, end - begin);
                if (run->exit_reason != KVM_EXIT_HLT || regs.rip != 0x1005 || observed != value) {
                    errno = EIO; fail("guest_write");
                }
            }
            puts("{\"op\":\"writes_done\"}");
        } else if (sscanf(command, "seal %" SCNu64 " %c", &generation, &extra) == 1 && generation && !atomic_load(&reading)) {
            struct dsm_close request = {.version = 1, .generation = generation, .timeout_ms = 15000};
            checked(vm, DSM_CLOSE, &request);
            sealed = 1;
            printf("{\"op\":\"sealed\",\"generation\":%" PRIu64 "}\n", generation);
        } else { errno = EINVAL; fail("command"); }
    }
    if (atomic_load(&reading)) { stop_reader(); }
    if (!sealed) { errno = EINVAL; fail("close_not_sealed"); }
    if (marker >= 0) { close(marker); }
    munmap(run, size); close(cpu); close(vm); munmap(memory, 8192); close(kvm);
    puts("{\"op\":\"closed\"}");
    return 0;
}
