#define _GNU_SOURCE
#include <inttypes.h>
#include <pthread.h>
#include <sched.h>
#include <stdatomic.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/mount.h>
#include <sys/reboot.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <unistd.h>

/* 让同一批 4 KiB 页反复换写入方，覆盖 DSM 降权、失效和重新获取。 */
#define CPUS 4
#define PAGES 1024
#define WORDS_PER_PAGE 512
#define ROUNDS 8
#define ATOMICS_PER_ROUND 128
#define ALLOCATIONS 2
static uint64_t *memory;
static pthread_barrier_t barrier;
static atomic_uint counter;
static unsigned int allocation;

static void check_pthread(int result, const char *operation)
{
    if (result != 0) {
        printf("STRESS_ERROR operation=%s error=%s\n", operation, strerror(result));
        exit(1);
    }
}

static void synchronize(void)
{
    int result = pthread_barrier_wait(&barrier);
    if (result != PTHREAD_BARRIER_SERIAL_THREAD) {
        check_pthread(result, "barrier_wait");
    }
}

static uint64_t expected_word(unsigned int round, size_t page, size_t word)
{
    uint64_t value = ((uint64_t)allocation << 56) | ((uint64_t)round << 48)
                   | ((uint64_t)page << 16) | word;
    value ^= value >> 30;
    value *= UINT64_C(0xbf58476d1ce4e5b9);
    value ^= value >> 27;
    value *= UINT64_C(0x94d049bb133111eb);
    return value ^ (value >> 31);
}

static void *worker(void *argument)
{
    int cpu = (int)(intptr_t)argument;
    cpu_set_t affinity;
    CPU_ZERO(&affinity);
    CPU_SET(cpu, &affinity);
    check_pthread(pthread_setaffinity_np(pthread_self(), sizeof(affinity), &affinity),
                  "setaffinity");
    for (unsigned int round = 0; round < ROUNDS; round++) {
        /* 先等所有读者离开上一轮，再把相邻页分给不同 CPU 写入。 */
        synchronize();
        for (size_t page = 0; page < PAGES; page++) {
            if ((page + round) % CPUS != (unsigned int)cpu) {
                continue;
            }
            for (size_t word = 0; word < WORDS_PER_PAGE; word++) {
                memory[page * WORDS_PER_PAGE + word] = expected_word(round, page, word);
            }
        }
        synchronize();
        /* 每个 CPU 都读全部页；置换访问顺序，避免只验本节点刚写入的内容。 */
        for (size_t index = 0; index < PAGES; index++) {
            size_t page = (index * 17 + (size_t)cpu) % PAGES;
            for (size_t word = 0; word < WORDS_PER_PAGE; word++) {
                uint64_t expected = expected_word(round, page, word);
                uint64_t observed = memory[page * WORDS_PER_PAGE + word];
                if (observed != expected) {
                    printf("STRESS_ERROR allocation=%u round=%u cpu=%d page=%zu word=%zu expected=%" PRIu64 " observed=%" PRIu64 "\n",
                           allocation, round, cpu, page, word, expected, observed);
                    exit(1);
                }
            }
        }
        for (unsigned int i = 0; i < ATOMICS_PER_ROUND; i++) {
            atomic_fetch_add_explicit(&counter, 1, memory_order_seq_cst);
        }
        synchronize();
        if (cpu == 0) {
            unsigned int total = atomic_load(&counter);
            unsigned int expected = (round + 1) * CPUS * ATOMICS_PER_ROUND;
            if (total != expected) {
                printf("STRESS_ERROR counter=%u expected=%u\n", total, expected);
                exit(1);
            }
            printf("STRESS_ROUND allocation=%u round=%u counter=%u\n", allocation, round, total);
        }
    }
    int observed = sched_getcpu();
    printf("STRESS_THREAD allocation=%u pid=%ld tid=%ld requested_cpu=%d observed_cpu=%d\n",
           allocation, (long)getpid(), syscall(SYS_gettid), cpu, observed);
    if (observed != cpu) {
        puts("STRESS_ERROR affinity_changed");
        exit(1);
    }
    return NULL;
}

static int run_stress(void)
{
    long online = sysconf(_SC_NPROCESSORS_ONLN);
    long page_size = sysconf(_SC_PAGESIZE);
    size_t bytes = (size_t)PAGES * WORDS_PER_PAGE * sizeof(uint64_t);
    if (online != CPUS || page_size != 4096) {
        printf("STRESS_ERROR online_cpus=%ld page_size=%ld\n", online, page_size);
        return 1;
    }
    printf("STRESS_START pid=%ld online_cpus=%d bytes=%zu rounds=%d allocations=%d\n",
           (long)getpid(), CPUS, bytes, ROUNDS, ALLOCATIONS);
    for (allocation = 0; allocation < ALLOCATIONS; allocation++) {
        memory = mmap(NULL, bytes, PROT_READ | PROT_WRITE,
                      MAP_SHARED | MAP_ANONYMOUS, -1, 0);
        if (memory == MAP_FAILED) {
            perror("STRESS_ERROR mmap");
            return 1;
        }
        atomic_store(&counter, 0);
        check_pthread(pthread_barrier_init(&barrier, NULL, CPUS), "barrier_init");
        pthread_t threads[CPUS];
        for (int cpu = 0; cpu < CPUS; cpu++) {
            check_pthread(pthread_create(&threads[cpu], NULL, worker, (void *)(intptr_t)cpu),
                          "pthread_create");
        }
        for (int cpu = 0; cpu < CPUS; cpu++) {
            check_pthread(pthread_join(threads[cpu], NULL), "pthread_join");
        }
        check_pthread(pthread_barrier_destroy(&barrier), "barrier_destroy");
        if (munmap(memory, bytes) != 0) {
            perror("STRESS_ERROR munmap");
            return 1;
        }
    }
    printf("STRESS_PASS cpus=%d rounds=%d allocations=%d counter_per_allocation=%d bytes=%zu\n",
           CPUS, ROUNDS, ALLOCATIONS, CPUS * ROUNDS * ATOMICS_PER_ROUND, bytes);
    return 0;
}

int main(void)
{
    setvbuf(stdout, NULL, _IONBF, 0);
    if (getpid() == 1) {
        mkdir("/proc", 0755);
        if (mount("proc", "/proc", "proc", 0, NULL) != 0) {
            perror("STRESS_ERROR mount_proc");
            return 1;
        }
    }
    int result = run_stress();
    printf("STRESS_EXIT status=%d\n", result);
    if (getpid() == 1) {
        sleep(20);
        reboot(RB_POWER_OFF);
        for (;;) {
            pause();
        }
    }
    return result;
}
