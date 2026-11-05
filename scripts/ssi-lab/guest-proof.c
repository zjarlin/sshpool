#define _GNU_SOURCE
#include <errno.h>
#include <inttypes.h>
#include <pthread.h>
#include <sched.h>
#include <stdatomic.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mount.h>
#include <sys/reboot.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <unistd.h>

/* 作为独立 initramfs 的 PID 1，验证同一地址空间中的 CPU 亲和性和共享写入。 */
#define MAX_CPUS 4
#define WORDS_PER_CPU (1024 * 1024)
static uint64_t *memory;
static atomic_uint counter;
static pthread_barrier_t start;
static int cpus;
static int failures[MAX_CPUS];
static uint64_t checksums[MAX_CPUS];

static uint64_t next_value(uint64_t value)
{
    value ^= value << 13;
    value ^= value >> 7;
    value ^= value << 17;
    return value;
}

static void *worker(void *argument)
{
    int cpu = (int)(intptr_t)argument;
    cpu_set_t affinity;
    CPU_ZERO(&affinity);
    CPU_SET(cpu, &affinity);
    int error = pthread_setaffinity_np(pthread_self(), sizeof(affinity), &affinity);
    if (error != 0) {
        printf("PROOF_ERROR affinity cpu=%d error=%s\n", cpu, strerror(error));
        failures[cpu] = 1;
    }
    pthread_barrier_wait(&start);
    uint64_t value = (uint64_t)cpu + 1;
    size_t base = (size_t)cpu * WORDS_PER_CPU;
    for (size_t i = 0; i < WORDS_PER_CPU; i++) {
        value = next_value(value);
        memory[base + i] = value;
    }
    /* 计算阶段无远程任务提交，线程仍共享同一个进程和虚拟地址空间。 */
    for (size_t i = 0; i < 20000000; i++) {
        value = next_value(value);
    }
    checksums[cpu] = value;
    for (int i = 0; i < 128; i++) {
        atomic_fetch_add_explicit(&counter, 1, memory_order_seq_cst);
    }
    int observed = sched_getcpu();
    if (observed != cpu) {
        failures[cpu] = 1;
    }
    printf("PROOF_THREAD pid=%ld tid=%ld requested_cpu=%d observed_cpu=%d checksum=%" PRIu64 "\n",
           (long)getpid(), syscall(SYS_gettid), cpu, observed, value);
    return NULL;
}

static int run_proof(void)
{
    long online = sysconf(_SC_NPROCESSORS_ONLN);
    if (online != MAX_CPUS) {
        printf("PROOF_ERROR expected_online_cpus=%d actual=%ld\n", MAX_CPUS, online);
        return 1;
    }
    cpus = (int)online;
    memory = calloc((size_t)cpus * WORDS_PER_CPU, sizeof(uint64_t));
    if (memory == NULL) {
        perror("PROOF_ERROR calloc");
        return 1;
    }
    if (pthread_barrier_init(&start, NULL, (unsigned int)cpus) != 0) {
        puts("PROOF_ERROR barrier_init");
        return 1;
    }
    pthread_t threads[MAX_CPUS];
    printf("PROOF_START pid=%ld online_cpus=%d bytes=%zu\n",
           (long)getpid(), cpus, (size_t)cpus * WORDS_PER_CPU * sizeof(uint64_t));
    for (int cpu = 0; cpu < cpus; cpu++) {
        int error = pthread_create(&threads[cpu], NULL, worker, (void *)(intptr_t)cpu);
        if (error != 0) {
            printf("PROOF_ERROR pthread_create error=%s\n", strerror(error));
            return 1;
        }
    }
    for (int cpu = 0; cpu < cpus; cpu++) {
        if (pthread_join(threads[cpu], NULL) != 0) {
            puts("PROOF_ERROR pthread_join");
            return 1;
        }
    }
    for (int cpu = 0; cpu < cpus; cpu++) {
        if (failures[cpu]) {
            return 1;
        }
        uint64_t value = (uint64_t)cpu + 1;
        size_t base = (size_t)cpu * WORDS_PER_CPU;
        for (size_t i = 0; i < WORDS_PER_CPU; i++) {
            value = next_value(value);
            if (memory[base + i] != value) {
                printf("PROOF_ERROR memory cpu=%d word=%zu\n", cpu, i);
                return 1;
            }
        }
        for (size_t i = 0; i < 20000000; i++) {
            value = next_value(value);
        }
        if (checksums[cpu] != value) {
            printf("PROOF_ERROR checksum cpu=%d\n", cpu);
            return 1;
        }
    }
    unsigned int total = atomic_load(&counter);
    if (total != (unsigned int)cpus * 128) {
        printf("PROOF_ERROR atomic_counter=%u\n", total);
        return 1;
    }
    printf("PROOF_PASS cpus=%d shared_counter=%u memory_verified_bytes=%zu\n",
           cpus, total, (size_t)cpus * WORDS_PER_CPU * sizeof(uint64_t));
    return 0;
}

int main(void)
{
    setvbuf(stdout, NULL, _IONBF, 0);
    if (getpid() == 1) {
        mkdir("/proc", 0755);
        if (mount("proc", "/proc", "proc", 0, NULL) != 0) {
            perror("PROOF_ERROR mount_proc");
        }
    }
    int result = run_proof();
    printf("PROOF_EXIT status=%d\n", result);
    if (getpid() == 1) {
        /* 留出收集节点侧线程统计的时间，然后结束这个无磁盘客体。 */
        sleep(20);
        reboot(RB_POWER_OFF);
        for (;;) {
            pause();
        }
    }
    return result;
}
