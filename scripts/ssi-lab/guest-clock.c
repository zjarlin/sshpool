#define _GNU_SOURCE
#include <errno.h>
#include <inttypes.h>
#include <sched.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

/* 跨 vCPU 迁移同一线程，直接检测计数器和应用可见时钟是否倒退。 */
#define CPUS 4
#define ROUNDS 8
#define TIMER_NS UINT64_C(20000000)

static const clockid_t clocks[] = {
    CLOCK_MONOTONIC, CLOCK_MONOTONIC_RAW, CLOCK_BOOTTIME,
};

static int read_clock(clockid_t clock, uint64_t *value)
{
    struct timespec now;
    if (clock_gettime(clock, &now) != 0) {
        printf("CLOCK_ERROR operation=clock_gettime errno=%d\n", errno);
        return -1;
    }
    *value = (uint64_t)now.tv_sec * UINT64_C(1000000000) + (uint64_t)now.tv_nsec;
    return 0;
}

static uint64_t read_tsc(void)
{
    unsigned int low;
    unsigned int high;
    /* 不依赖 RDTSCP 特性；围栏约束读数相对当前线程指令的顺序。 */
    __asm__ volatile("lfence; rdtsc; lfence" : "=a"(low), "=d"(high) : : "memory");
    return ((uint64_t)high << 32) | low;
}

static int select_cpu(int cpu)
{
    cpu_set_t affinity;
    CPU_ZERO(&affinity);
    CPU_SET(cpu, &affinity);
    if (sched_setaffinity(0, sizeof(affinity), &affinity) != 0) {
        printf("CLOCK_ERROR operation=setaffinity cpu=%d errno=%d\n", cpu, errno);
        return -1;
    }
    int observed = sched_getcpu();
    if (observed != cpu) {
        printf("CLOCK_ERROR operation=cpu cpu=%d observed=%d\n", cpu, observed);
        return -1;
    }
    return 0;
}

static int check_timer(int cpu, int timer_intervals)
{
    uint64_t before;
    uint64_t after;
    if (read_clock(CLOCK_MONOTONIC, &before) != 0) {
        return -1;
    }
    struct timespec delay = { .tv_sec = 0, .tv_nsec = TIMER_NS };
    int result;
    do {
        result = clock_nanosleep(CLOCK_MONOTONIC, 0, &delay, &delay);
    } while (result == EINTR);
    if (result != 0) {
        printf("CLOCK_ERROR operation=nanosleep cpu=%d error=%s\n", cpu, strerror(result));
        return -1;
    }
    if (read_clock(CLOCK_MONOTONIC, &after) != 0) {
        return -1;
    }
    if (after < before || after - before < TIMER_NS) {
        printf("CLOCK_ERROR operation=early_timer cpu=%d before=%" PRIu64 " after=%" PRIu64 "\n",
               cpu, before, after);
        return -1;
    }
    printf("CLOCK_TIMER cpu=%d requested_ns=%" PRIu64 " elapsed_ns=%" PRIu64 "\n",
           cpu, TIMER_NS, after - before);
    /* 额外记录在测量结束后输出，供客体定时器跟踪关联同一线程与单调时钟区间。 */
    if (timer_intervals) {
        printf("TIMER_INTERVAL pid=%ld cpu=%d before_ns=%" PRIu64 " after_ns=%" PRIu64 "\n",
               (long)getpid(), cpu, before, after);
    }
    return 0;
}

int main(int argc, char **argv)
{
    int interactive = argc == 2 && strcmp(argv[1], "--pause-rounds") == 0;
    int timer_intervals = argc == 2 && strcmp(argv[1], "--timer-intervals") == 0;
    if (argc != 1 && !interactive && !timer_intervals) {
        fprintf(stderr, "usage: guest-clock [--pause-rounds|--timer-intervals]\n");
        return 2;
    }
    setvbuf(stdout, NULL, _IONBF, 0);
    long online = sysconf(_SC_NPROCESSORS_ONLN);
    printf("CLOCK_START online_cpus=%ld rounds=%d\n", online, ROUNDS);
    if (online != CPUS) {
        printf("CLOCK_ERROR operation=cpu_count expected=%d\n", CPUS);
        return 1;
    }
    uint64_t previous_tsc = 0;
    uint64_t previous[3] = {0};
    /* 先跨执行节点，再访问另一组核心，避免只覆盖同节点内迁移。 */
    const int order[CPUS] = {0, 2, 1, 3};
    for (int round = 0; round < ROUNDS; round++) {
        if (interactive && round > 0) {
            char line[32];
            printf("CLOCK_WAIT round=%d\n", round);
            if (!fgets(line, sizeof(line), stdin) || strcmp(line, "continue\n") != 0) {
                printf("CLOCK_ERROR operation=resume_input round=%d\n", round);
                return 1;
            }
        }
        for (int index = 0; index < CPUS; index++) {
            int cpu = order[index];
            if (select_cpu(cpu) != 0) {
                return 1;
            }
            uint64_t tsc = read_tsc();
            if (tsc < previous_tsc) {
                printf("CLOCK_ERROR operation=tsc_backwards round=%d cpu=%d previous=%" PRIu64 " now=%" PRIu64 "\n",
                       round, cpu, previous_tsc, tsc);
                return 1;
            }
            previous_tsc = tsc;
            for (int clock = 0; clock < 3; clock++) {
                uint64_t now;
                if (read_clock(clocks[clock], &now) != 0) {
                    return 1;
                }
                if (now < previous[clock]) {
                    printf("CLOCK_ERROR operation=clock_backwards round=%d cpu=%d clock=%d previous=%" PRIu64 " now=%" PRIu64 "\n",
                           round, cpu, clock, previous[clock], now);
                    return 1;
                }
                previous[clock] = now;
            }
            printf("CLOCK_SAMPLE round=%d cpu=%d tsc=%" PRIu64 " mono=%" PRIu64 " raw=%" PRIu64 " boot=%" PRIu64 "\n",
                   round, cpu, tsc, previous[0], previous[1], previous[2]);
            if (round == ROUNDS - 1 && check_timer(cpu, timer_intervals) != 0) {
                return 1;
            }
        }
    }
    printf("CLOCK_PASS cpus=%d samples=%d timers=%d\n", CPUS, CPUS * ROUNDS, CPUS);
    return 0;
}
