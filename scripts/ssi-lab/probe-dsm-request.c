#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <linux/kvm.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <sys/utsname.h>
#include <unistd.h>

/* 保持空 VM 打开，按命令延迟注册一页内存；不创建或运行 vCPU。 */
#define KVM_CAP_X86_DSM 249
#define PAGE_BYTES 4096
#define PAGE_GPA UINT64_C(0x2000)
struct dsm_params {
    uint32_t node;
    uint32_t count;
    uint64_t peers;
};
#define DSM_ENABLE _IOW(KVMIO, 0xf0, struct dsm_params)
_Static_assert(sizeof(struct dsm_params) == 16, "DSM params ABI size");

static void fail(const char *operation)
{
    fprintf(stderr, "REQUEST_ERROR operation=%s errno=%d message=%s\n",
            operation, errno, strerror(errno));
    exit(1);
}

int main(int argc, char **argv)
{
    struct utsname host;
    setvbuf(stdout, NULL, _IONBF, 0);
    if (argc != 2 || uname(&host) || strcmp(host.machine, "x86_64") ||
        strcmp(host.release, argv[1])) {
        fputs("usage: probe-dsm-request REQUIRED_KERNEL\n", stderr);
        return 2;
    }
    int kvm = open("/dev/kvm", O_RDWR | O_CLOEXEC);
    if (kvm < 0 || ioctl(kvm, KVM_CHECK_EXTENSION, KVM_CAP_X86_DSM) != 1) {
        fail("dsm_capability");
    }
    int vm = ioctl(kvm, KVM_CREATE_VM, 0);
    if (vm < 0) {
        fail("create_vm");
    }
    char *peers[] = {"127.0.0.1", "127.0.0.2"};
    struct dsm_params params = {.node = 0, .count = 2, .peers = (uintptr_t)peers};
    if (ioctl(vm, DSM_ENABLE, &params)) {
        fail("enable_dsm");
    }
    uint8_t *memory = mmap(NULL, PAGE_BYTES, PROT_READ | PROT_WRITE,
                           MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (memory == MAP_FAILED) {
        fail("allocate_page");
    }
    for (size_t index = 0; index < PAGE_BYTES; index++) {
        memory[index] = (uint8_t)(index * 17 + 3);
    }
    struct kvm_userspace_memory_region region = {
        .slot = 0,
        .guest_phys_addr = PAGE_GPA,
        .memory_size = PAGE_BYTES,
        .userspace_addr = (uintptr_t)memory,
    };
    puts("{\"op\":\"ready\",\"registered_pages\":0}");
    char command[32];
    int registered = 0;
    while (fgets(command, sizeof(command), stdin)) {
        if (!strcmp(command, "register\n") && !registered) {
            if (ioctl(vm, KVM_SET_USER_MEMORY_REGION, &region)) {
                fail("register_page");
            }
            registered = 1;
            puts("{\"op\":\"registered\",\"gfn\":2}");
        } else if (!strcmp(command, "quit\n")) {
            break;
        } else {
            fputs("REQUEST_ERROR operation=unknown_or_repeated_command\n", stderr);
            return 2;
        }
    }
    if (close(vm)) {
        fail("close_vm");
    }
    if (munmap(memory, PAGE_BYTES) || close(kvm)) {
        fail("release_process_resources");
    }
    puts("{\"op\":\"closed\"}");
    return 0;
}
