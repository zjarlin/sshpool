#define _GNU_SOURCE
#include <errno.h>
#include <sched.h>
#include <stdio.h>

/* 在客体四个 vCPU 的真实用户态执行 PAUSE，检查退出后能正确推进指令。 */
int main(void)
{
    for (int cpu = 0; cpu < 4; cpu++) {
        cpu_set_t affinity;
        CPU_ZERO(&affinity);
        CPU_SET(cpu, &affinity);
        if (sched_setaffinity(0, sizeof(affinity), &affinity) != 0 || sched_getcpu() != cpu) {
            printf("PAUSE_ERROR cpu=%d errno=%d\n", cpu, errno);
            return 1;
        }
        unsigned short segment;
        __asm__ volatile("mov %%cs, %0" : "=r"(segment));
        if ((segment & 3) != 3) {
            printf("PAUSE_ERROR cpl=%u\n", segment & 3);
            return 1;
        }
        unsigned int sum = 0;
        for (unsigned int step = 1; step <= 64; step++) {
            __asm__ volatile("pause" : : : "memory");
            sum += step;
        }
        printf("PAUSE_CPU cpu=%d cpl=3 iterations=64 checksum=%u\n", cpu, sum);
        if (sum != 2080) {
            return 1;
        }
    }
    return 0;
}
