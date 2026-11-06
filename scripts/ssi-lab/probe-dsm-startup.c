#define _GNU_SOURCE
#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <linux/kvm.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <sys/utsname.h>
#include <unistd.h>

/* 仅创建空 VM 和回环监听器，验证真实启用 ioctl 的错误与重试；不运行 vCPU。 */
#define KVM_CAP_X86_DSM 249
struct dsm_params {
    uint32_t node;
    uint32_t count;
    uint64_t peers;
};
#define DSM_ENABLE _IOW(KVMIO, 0xf0, struct dsm_params)
_Static_assert(sizeof(struct dsm_params) == 16, "DSM params ABI size");

static int kvm;

static void die(const char *operation)
{
    fprintf(stderr, "STARTUP_ERROR operation=%s errno=%d message=%s\n",
            operation, errno, strerror(errno));
    exit(1);
}

static int create_vm(void)
{
    int vm = ioctl(kvm, KVM_CREATE_VM, 0);
    if (vm < 0) {
        die("create_vm");
    }
    return vm;
}

static void close_vm(int vm)
{
    puts("STARTUP_CLOSE_BEGIN");
    if (close(vm)) {
        die("close_vm");
    }
    puts("STARTUP_CLOSE_DONE");
}

static int enable(int vm, const char *label, struct dsm_params *params, int wanted)
{
    errno = 0;
    int result = ioctl(vm, DSM_ENABLE, params);
    int code = errno;
    printf("STARTUP_ENABLE case=%s result=%d errno=%d expected_errno=%d\n",
           label, result, code, wanted);
    return wanted ? result == -1 && code == wanted : result == 0;
}

static int occupy(void)
{
    int listener = socket(AF_INET, SOCK_STREAM | SOCK_CLOEXEC, 0);
    struct sockaddr_in address = {
        .sin_family = AF_INET,
        .sin_port = htons(37710),
        .sin_addr.s_addr = htonl(INADDR_LOOPBACK),
    };
    if (listener < 0 || bind(listener, (struct sockaddr *)&address, sizeof(address)) ||
        listen(listener, 1)) {
        die("occupy_lab_port");
    }
    return listener;
}

int main(int argc, char **argv)
{
    struct utsname host;
    setvbuf(stdout, NULL, _IONBF, 0);
    if (argc != 3 || uname(&host) || strcmp(host.machine, "x86_64") ||
        strcmp(host.release, argv[1])) {
        fputs("usage: probe-dsm-startup REQUIRED_KERNEL occupied|cycles|invalid\n", stderr);
        return 2;
    }
    if (strcmp(argv[2], "occupied") && strcmp(argv[2], "cycles") && strcmp(argv[2], "invalid")) {
        return 2;
    }
    kvm = open("/dev/kvm", O_RDWR | O_CLOEXEC);
    if (kvm < 0 || ioctl(kvm, KVM_CHECK_EXTENSION, KVM_CAP_X86_DSM) != 1) {
        die("dsm_capability");
    }
    char *peers[] = {"127.0.0.1"};
    struct dsm_params valid = {.node = 0, .count = 1, .peers = (uintptr_t)peers};
    int passed = 1;
    printf("STARTUP_BEGIN mode=%s kernel=%s\n", argv[2], host.release);
    if (!strcmp(argv[2], "occupied")) {
        int listener = occupy();
        int vm = create_vm();
        passed = enable(vm, "occupied", &valid, EADDRINUSE);
        close(listener);
        /* 只有失败确实返回给调用者，才验证同一个 VM 能否重新启用。 */
        if (passed) {
            passed = enable(vm, "retry", &valid, 0);
        }
        close_vm(vm);
    } else if (!strcmp(argv[2], "cycles")) {
        for (int cycle = 0; cycle < 64 && passed; cycle++) {
            int vm = create_vm();
            passed = enable(vm, "cycle", &valid, 0);
            close_vm(vm);
            int listener = occupy();
            close(listener);
            printf("STARTUP_CYCLE index=%d released=1\n", cycle);
        }
    } else {
        struct dsm_params cases[] = {
            {.node = 0, .count = 0, .peers = (uintptr_t)peers},
            {.node = 1, .count = 1, .peers = (uintptr_t)peers},
            {.node = 0, .count = 65, .peers = (uintptr_t)peers},
            {.node = 0, .count = 1, .peers = 1},
        };
        const char *labels[] = {"empty", "node_outside_list", "too_many", "bad_pointer"};
        int errors[] = {EINVAL, EINVAL, EINVAL, EFAULT};
        int vm = create_vm();
        for (unsigned int i = 0; i < sizeof(cases) / sizeof(cases[0]); i++) {
            passed &= enable(vm, labels[i], &cases[i], errors[i]);
        }
        if (passed) {
            passed = enable(vm, "retry", &valid, 0);
        }
        close_vm(vm);
    }
    close(kvm);
    printf("STARTUP_RESULT passed=%d\n", passed);
    return !passed;
}
