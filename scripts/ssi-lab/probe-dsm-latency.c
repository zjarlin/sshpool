#define _GNU_SOURCE
#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <inttypes.h>
#include <linux/kvm.h>
#include <pthread.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <sys/utsname.h>
#include <time.h>
#include <unistd.h>

/* 无 vCPU 的真实 KVM 页面交接；只在 ioctl 内计时，排除管理 SSH 的往返时间。 */
#define PAGE_BYTES 4096
#define KVM_CAP_X86_DSM 249
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
_Static_assert(sizeof(struct dsm_params) == 16, "DSM params ABI size");
_Static_assert(sizeof(struct dsm_copy) == 32, "DSM copy ABI size");

static void fail(const char *operation)
{
    fprintf(stderr, "LATENCY_ERROR operation=%s errno=%d message=%s\n", operation, errno, strerror(errno));
    exit(1);
}

static uint64_t now_ns(void)
{
    struct timespec time;
    if (clock_gettime(CLOCK_MONOTONIC_RAW, &time)) {
        fail("clock");
    }
    return (uint64_t)time.tv_sec * UINT64_C(1000000000) + time.tv_nsec;
}

static void fill_page(uint8_t *page, uint64_t seed)
{
    for (size_t i = 0; i < PAGE_BYTES; i++) {
        page[i] = (uint8_t)(i * 17 + seed * 13 + (seed >> ((i % 8) * 8)));
    }
    memcpy(page, &seed, sizeof(seed));
}

static uint64_t checksum(const uint8_t *page)
{
    uint64_t hash = UINT64_C(14695981039346656037);
    for (size_t i = 0; i < PAGE_BYTES; i++) {
        hash = (hash ^ page[i]) * UINT64_C(1099511628211);
    }
    return hash;
}

static void copy_page(int vm, uint8_t *page, int node, const char *operation, uint64_t seed, int thread)
{
    uint8_t buffer[PAGE_BYTES] = {};
    int write = !strcmp(operation, "write");
    if (write) {
        fill_page(buffer, seed);
    }
    struct dsm_copy request = {
        .write = write, .host_address = (uintptr_t)page,
        .user_address = (uintptr_t)buffer, .length = sizeof(buffer),
    };
    uint64_t begin = now_ns();
    int result = ioctl(vm, DSM_MEMCPY, &request);
    uint64_t end = now_ns();
    if (result < 0) {
        fail("copy_page");
    }
    uint64_t observed;
    memcpy(&observed, buffer, sizeof(observed));
    printf("{\"op\":\"%s\",\"node\":%d,\"seed\":%" PRIu64
           ",\"observed_seed\":%" PRIu64 ",\"begin_ns\":%" PRIu64
           ",\"end_ns\":%" PRIu64 ",\"elapsed_ns\":%" PRIu64
           ",\"checksum\":\"%016" PRIx64 "\",\"ioctl_result\":%d,\"thread\":%d,\"tid\":%d}\n",
           operation, node, seed, observed, begin, end, end - begin, checksum(buffer), result, thread, gettid());
}

struct burst_context {
    int vm;
    uint8_t *page;
    int node;
    int thread;
    uint64_t base;
    unsigned count;
    pthread_barrier_t *barrier;
};

static void *burst_writer(void *argument)
{
    struct burst_context *context = argument;
    int status = pthread_barrier_wait(context->barrier);
    if (status != 0 && status != PTHREAD_BARRIER_SERIAL_THREAD) {
        errno = status;
        fail("barrier_wait");
    }
    for (unsigned i = 0; i < context->count; i++) {
        uint64_t seed = context->base + context->thread * context->count + i + 1;
        copy_page(context->vm, context->page, context->node, "write", seed, context->thread);
    }
    return NULL;
}

static void burst(int vm, uint8_t *page, int node, unsigned count, uint64_t base)
{
    pthread_barrier_t barrier;
    pthread_t threads[2];
    struct burst_context contexts[2];
    int status = pthread_barrier_init(&barrier, NULL, 2);
    if (status) {
        errno = status;
        fail("barrier_init");
    }
    for (int i = 0; i < 2; i++) {
        contexts[i] = (struct burst_context){vm, page, node, i, base, count, &barrier};
        status = pthread_create(&threads[i], NULL, burst_writer, &contexts[i]);
        if (status) {
            errno = status;
            fail("thread_create");
        }
    }
    for (int i = 0; i < 2; i++) {
        status = pthread_join(threads[i], NULL);
        if (status) {
            errno = status;
            fail("thread_join");
        }
    }
    status = pthread_barrier_destroy(&barrier);
    if (status) {
        errno = status;
        fail("barrier_destroy");
    }
    printf("{\"op\":\"burst_done\",\"node\":%d,\"count\":%u,\"base\":%" PRIu64 "}\n", node, count, base);
}

int main(int argc, char **argv)
{
    struct utsname host;
    struct in_addr address;
    setvbuf(stdout, NULL, _IONBF, 0);
    if (argc != 5 || (strcmp(argv[1], "0") && strcmp(argv[1], "1")) ||
        uname(&host) || strcmp(host.machine, "x86_64") || strcmp(host.release, argv[4])) {
        fputs("usage: probe-dsm-latency NODE PEER0 PEER1_OR_DASH REQUIRED_KERNEL\n", stderr);
        return 2;
    }
    int node = atoi(argv[1]);
    int count = strcmp(argv[3], "-") ? 2 : 1;
    char *peers[] = {argv[2], argv[3]};
    if (node >= count) {
        return 2;
    }
    for (int i = 0; i < count; i++) {
        if (inet_pton(AF_INET, peers[i], &address) != 1) {
            return 2;
        }
    }
    int kvm = open("/dev/kvm", O_RDWR | O_CLOEXEC);
    if (kvm < 0 || ioctl(kvm, KVM_CHECK_EXTENSION, KVM_CAP_X86_DSM) != 1) {
        fail("dsm_capability");
    }
    int vm = ioctl(kvm, KVM_CREATE_VM, 0);
    if (vm < 0) {
        fail("create_vm");
    }
    uint8_t *page = mmap(NULL, PAGE_BYTES, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (page == MAP_FAILED) {
        fail("allocate_page");
    }
    fill_page(page, 0);
    struct dsm_params params = {.node = node, .count = count, .peers = (uintptr_t)peers};
    if (ioctl(vm, DSM_ENABLE, &params)) {
        fail("enable_dsm");
    }
    struct kvm_userspace_memory_region region = {
        .slot = 0, .guest_phys_addr = 0x2000, .memory_size = PAGE_BYTES, .userspace_addr = (uintptr_t)page,
    };
    if (ioctl(vm, KVM_SET_USER_MEMORY_REGION, &region)) {
        fail("register_page");
    }
    printf("{\"op\":\"ready\",\"node\":%d,\"nodes\":%d,\"pid\":%d}\n", node, count, getpid());
    char command[80];
    while (fgets(command, sizeof(command), stdin)) {
        if (!strcmp(command, "quit\n")) {
            break;
        }
        uint64_t seed, count;
        char operation[8], extra;
        if (sscanf(command, "%7s %" SCNu64 " %" SCNu64 " %c", operation, &count, &seed, &extra) == 3 &&
            !strcmp(operation, "burst") && count >= 1 && count <= 512 && seed < (UINT64_C(1) << 48)) {
            burst(vm, page, node, count, seed);
            continue;
        }
        if (sscanf(command, "%7s %" SCNu64 " %c", operation, &seed, &extra) != 2 ||
            (strcmp(operation, "write") && strcmp(operation, "read"))) {
            fputs("LATENCY_ERROR operation=invalid_command\n", stderr);
            return 2;
        }
        copy_page(vm, page, node, operation, seed, -1);
    }
    if (close(vm) || munmap(page, PAGE_BYTES) || close(kvm)) {
        fail("close");
    }
    printf("{\"op\":\"closed\",\"node\":%d}\n", node);
    return 0;
}
