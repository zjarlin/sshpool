#define _GNU_SOURCE
#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <inttypes.h>
#include <linux/kvm.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <sys/utsname.h>
#include <unistd.h>

/* 真实 KVM 探针：只运行 HLT，分别让两个 vCPU 更新同一页中的时钟记录。 */
#define PAGE_SIZE 4096
#define CODE_GPA UINT64_C(0x1000)
#define CLOCK_GPA UINT64_C(0x2000)
#define RECORD_STRIDE 64
#define MARKER_OFFSET 256
#define KVM_CAP_X86_DSM 249
#define MSR_KVM_SYSTEM_TIME_NEW 0x4b564d01
#define MSR_KVM_STEAL_TIME 0x4b564d03

static int steal_mode;

struct dsm_params {
    uint32_t node;
    uint32_t count;
    uint64_t peers;
};

struct dsm_copy {
    uint8_t write;
    uint8_t padding[7];
    uint64_t host_address;
    uint64_t user_address;
    uint64_t length;
};

#define DSM_ENABLE _IOW(KVMIO, 0xf0, struct dsm_params)
#define DSM_MEMCPY _IOW(KVMIO, 0xf1, struct dsm_copy)

struct clock_record {
    uint32_t version;
    uint32_t pad;
    uint64_t tsc;
    uint64_t time;
    uint32_t multiplier;
    int8_t shift;
    uint8_t flags;
    uint8_t padding[2];
};

struct steal_record {
    uint64_t steal;
    uint32_t version;
    uint32_t flags;
    uint8_t preempted;
    uint8_t padding[47];
};

struct dsm_close_request {
    uint32_t version;
    uint32_t flags;
    uint64_t generation;
    uint32_t timeout_ms;
    uint32_t reserved;
};

#define DSM_CLOSE _IOW(KVMIO, 0xfb, struct dsm_close_request)

_Static_assert(sizeof(struct clock_record) == 32, "pvclock ABI size");
_Static_assert(sizeof(struct dsm_params) == 16, "DSM params ABI size");
_Static_assert(sizeof(struct dsm_copy) == 32, "DSM copy ABI size");
_Static_assert(sizeof(struct steal_record) == 64, "steal-time ABI size");
_Static_assert(sizeof(struct dsm_close_request) == 24, "DSM close ABI size");

static void fail(const char *operation)
{
    fprintf(stderr, "PVCLOCK_ERROR operation=%s errno=%d message=%s\n",
            operation, errno, strerror(errno));
    exit(1);
}

static int checked_ioctl(int fd, unsigned long operation, void *argument)
{
    int result = ioctl(fd, operation, argument);
    if (result < 0) {
        fail("ioctl");
    }
    return result;
}

static void copy_page(int vm, void *page, void *buffer, size_t length, int write)
{
    struct dsm_copy request = {
        .write = write,
        .host_address = (uintptr_t)page,
        .user_address = (uintptr_t)buffer,
        .length = length,
    };
    checked_ioctl(vm, DSM_MEMCPY, &request);
}

static void print_page(const char *operation, const void *data)
{
    struct clock_record record[2];
    struct steal_record stolen[2];
    uint64_t marker;

    memcpy(&record[0], data, sizeof(record[0]));
    memcpy(&record[1], (const char *)data + RECORD_STRIDE, sizeof(record[1]));
    memcpy(&stolen[0], data, sizeof(stolen[0]));
    memcpy(&stolen[1], (const char *)data + RECORD_STRIDE, sizeof(stolen[1]));
    memcpy(&marker, (const char *)data + MARKER_OFFSET, sizeof(marker));
    printf("{\"op\":\"%s\",\"marker\":%" PRIu64 ",\"records\":[", operation, marker);
    for (int cpu = 0; cpu < 2; cpu++) {
        if (steal_mode) {
            printf("%s{\"version\":%u,\"steal\":%" PRIu64 ",\"flags\":%u,\"preempted\":%u,\"padding\":\"",
                   cpu ? "," : "", stolen[cpu].version, stolen[cpu].steal,
                   stolen[cpu].flags, stolen[cpu].preempted);
            for (size_t byte = 0; byte < sizeof(stolen[cpu].padding); byte++) {
                printf("%02x", stolen[cpu].padding[byte]);
            }
            printf("\"}");
            continue;
        }
        printf("%s{\"version\":%u,\"tsc\":%" PRIu64 ",\"time\":%" PRIu64
               ",\"multiplier\":%u,\"shift\":%d,\"flags\":%u}",
               cpu ? "," : "", record[cpu].version, record[cpu].tsc,
               record[cpu].time, record[cpu].multiplier, record[cpu].shift,
               record[cpu].flags);
    }
    puts("]}");
}

static void tick(int vm, int cpu, struct kvm_run *run, int index, void *page)
{
    struct {
        struct kvm_msrs header;
        struct kvm_msr_entry entry;
    } msrs = {
        .header.nmsrs = 1,
        .entry.index = steal_mode ? MSR_KVM_STEAL_TIME : MSR_KVM_SYSTEM_TIME_NEW,
        .entry.data = CLOCK_GPA + index * RECORD_STRIDE + 1,
    };
    struct kvm_regs regs = { .rip = CODE_GPA, .rflags = 2 };
    struct kvm_mp_state state = { .mp_state = KVM_MP_STATE_RUNNABLE };
    struct kvm_clock_data clock = {};

    if (checked_ioctl(cpu, KVM_SET_MSRS, &msrs) != 1) {
        errno = ENOTSUP;
        fail("enable_pvclock");
    }
    if (!steal_mode) {
        checked_ioctl(vm, KVM_GET_CLOCK, &clock);
        checked_ioctl(vm, KVM_SET_CLOCK, &clock);
    }
    checked_ioctl(cpu, KVM_SET_REGS, &regs);
    checked_ioctl(cpu, KVM_SET_MP_STATE, &state);
    checked_ioctl(cpu, KVM_RUN, NULL);
    if (run->exit_reason != KVM_EXIT_HLT) {
        fprintf(stderr, "PVCLOCK_ERROR operation=run exit_reason=%u\n", run->exit_reason);
        exit(1);
    }
    /* 只观察内核刚写的本地记录，不在这里通过 DSM 获取页面而改变归属。 */
    print_page("tick", page);
}

int main(int argc, char **argv)
{
    struct utsname host;
    struct in_addr address;
    char *peers[2];
    int cpus[2];
    struct kvm_run *runs[2];

    setvbuf(stdout, NULL, _IONBF, 0);
    steal_mode = argc == 6 && strcmp(argv[5], "--steal-time") == 0;
    if ((argc != 5 && !steal_mode) || (strcmp(argv[1], "0") && strcmp(argv[1], "1"))) {
        fprintf(stderr, "usage: probe-pvclock NODE PEER0 PEER1_OR_DASH REQUIRED_KERNEL [--steal-time]\n");
        return 2;
    }
    if (uname(&host) || strcmp(host.machine, "x86_64") || strcmp(host.release, argv[4])) {
        fprintf(stderr, "PVCLOCK_ERROR operation=kernel_or_architecture_guard\n");
        return 2;
    }
    int node = atoi(argv[1]);
    int count = strcmp(argv[3], "-") ? 2 : 1;
    if (node >= count) {
        return 2;
    }
    for (int index = 0; index < count; index++) {
        peers[index] = argv[index + 2];
        if (inet_pton(AF_INET, peers[index], &address) != 1) {
            return 2;
        }
    }
    int kvm = open("/dev/kvm", O_RDWR | O_CLOEXEC);
    if (kvm < 0) {
        fail("open_kvm");
    }
    if (ioctl(kvm, KVM_CHECK_EXTENSION, KVM_CAP_X86_DSM) != 1) {
        fprintf(stderr, "PVCLOCK_ERROR operation=dsm_capability\n");
        return 2;
    }
    int vm = checked_ioctl(kvm, KVM_CREATE_VM, NULL);
    struct dsm_params dsm = { .node = node, .count = count, .peers = (uintptr_t)peers };
    checked_ioctl(vm, DSM_ENABLE, &dsm);
    void *memory = mmap(NULL, PAGE_SIZE * 2, PROT_READ | PROT_WRITE,
                        MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (memory == MAP_FAILED) {
        fail("memory");
    }
    /* 注册前初始化代码；时钟页从此只能由明确的探针命令或 KVM 更新。 */
    ((uint8_t *)memory)[0] = 0xf4;
    struct kvm_userspace_memory_region region = {
        .slot = 0,
        .guest_phys_addr = CODE_GPA,
        .memory_size = PAGE_SIZE * 2,
        .userspace_addr = (uintptr_t)memory,
    };
    checked_ioctl(vm, KVM_SET_USER_MEMORY_REGION, &region);
    int run_size = checked_ioctl(kvm, KVM_GET_VCPU_MMAP_SIZE, NULL);
    for (int index = 0; index < 2; index++) {
        struct kvm_sregs sregs;
        cpus[index] = checked_ioctl(vm, KVM_CREATE_VCPU, (void *)(uintptr_t)index);
        runs[index] = mmap(NULL, run_size, PROT_READ | PROT_WRITE, MAP_SHARED, cpus[index], 0);
        if (runs[index] == MAP_FAILED) {
            fail("run_mapping");
        }
        checked_ioctl(cpus[index], KVM_GET_SREGS, &sregs);
        sregs.cs.base = 0;
        sregs.cs.selector = 0;
        checked_ioctl(cpus[index], KVM_SET_SREGS, &sregs);
    }
    void *page = (char *)memory + PAGE_SIZE;
    char command[80];
    int sealed = 0;
    printf("{\"op\":\"ready\",\"node\":%d,\"nodes\":%d}\n", node, count);
    while (fgets(command, sizeof(command), stdin)) {
        if (steal_mode && !strncmp(command, "seal ", 5)) {
            char *end;
            errno = 0;
            uint64_t generation = strtoull(command + 5, &end, 10);
            if (errno || generation == 0 || strcmp(end, "\n") || sealed) {
                fprintf(stderr, "PVCLOCK_ERROR operation=invalid_close_generation\n");
                return 2;
            }
            struct dsm_close_request request = { .version = 1, .generation = generation, .timeout_ms = 15000 };
            checked_ioctl(vm, DSM_CLOSE, &request);
            sealed = 1;
            printf("{\"op\":\"sealed\",\"generation\":%" PRIu64 "}\n", generation);
            continue;
        }
        if (sealed && strcmp(command, "quit\n")) {
            fprintf(stderr, "PVCLOCK_ERROR operation=command_after_close\n");
            return 2;
        }
        if (!strcmp(command, "tick0\n") || !strcmp(command, "tick1\n")) {
            int index = command[4] - '0';
            tick(vm, cpus[index], runs[index], index, page);
        } else if (!strcmp(command, "read\n")) {
            uint8_t buffer[MARKER_OFFSET + sizeof(uint64_t)];
            copy_page(vm, page, buffer, sizeof(buffer), 0);
            print_page("read", buffer);
        } else if (!strcmp(command, "claim\n")) {
            uint64_t marker = node + 1;
            copy_page(vm, (char *)page + MARKER_OFFSET, &marker, sizeof(marker), 1);
            printf("{\"op\":\"claim\",\"node\":%d}\n", node);
        } else if (!strcmp(command, "quit\n")) {
            break;
        } else {
            fprintf(stderr, "PVCLOCK_ERROR operation=unknown_command\n");
            return 2;
        }
    }
    for (int index = 0; index < 2; index++) {
        munmap(runs[index], run_size);
        close(cpus[index]);
    }
    close(vm);
    munmap(memory, PAGE_SIZE * 2);
    close(kvm);
    puts("{\"op\":\"closed\"}");
    return 0;
}
