#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <linux/rtc.h>
#include <sched.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/mount.h>
#include <sys/reboot.h>
#include <sys/stat.h>
#include <unistd.h>

/* 仅在带显式标记的无磁盘实验客体中运行；不设置时间或写入 RTC 数据。 */
#define CPUS 4
#define ROUNDS 8

static void fatal(const char *operation)
{
    printf("RTCPROBE_ERROR operation=%s errno=%d\n", operation, errno);
    exit(1);
}

static void pin(int cpu)
{
    cpu_set_t mask;
    CPU_ZERO(&mask);
    CPU_SET(cpu, &mask);
    if (sched_setaffinity(0, sizeof(mask), &mask) != 0 || sched_getcpu() != cpu) {
        fatal("affinity");
    }
}

static int run_probe(void)
{
    char command_line[4096];
    FILE *input = fopen("/proc/cmdline", "r");
    if (input == NULL || fgets(command_line, sizeof(command_line), input) == NULL) {
        fatal("cmdline");
    }
    fclose(input);
    if (strstr(command_line, "sshpool_rtc_probe=1") == NULL ||
        sysconf(_SC_NPROCESSORS_ONLN) != CPUS) {
        fatal("guest_guard");
    }
    int fd = open("/dev/rtc0", O_RDONLY | O_CLOEXEC);
    if (fd < 0) {
        fatal("open_rtc");
    }
    printf("RTCPROBE_START cpus=%d rounds=%d\n", CPUS, ROUNDS);
    const int order[CPUS] = {0, 2, 1, 3};
    unsigned int failures = 0;
    for (int round = 0; round < ROUNDS; round++) {
        for (int index = 0; index < CPUS; index++) {
            int cpu = order[index];
            pin(cpu);
            struct rtc_time value = {0};
            errno = 0;
            int status = ioctl(fd, RTC_RD_TIME, &value);
            int saved_errno = errno;
            int observed_cpu = sched_getcpu();
            int valid = status == 0 && observed_cpu == cpu &&
                value.tm_year >= 100 && value.tm_year <= 199 &&
                value.tm_mon >= 0 && value.tm_mon <= 11 &&
                value.tm_mday >= 1 && value.tm_mday <= 31 &&
                value.tm_hour >= 0 && value.tm_hour <= 23 &&
                value.tm_min >= 0 && value.tm_min <= 59 &&
                value.tm_sec >= 0 && value.tm_sec <= 59;
            if (!valid) {
                failures++;
            }
            printf("RTCPROBE_READ round=%d cpu=%d observed_cpu=%d status=%d errno=%d "
                   "year=%d month=%d day=%d hour=%d minute=%d second=%d\n",
                   round, cpu, observed_cpu, status, saved_errno,
                   value.tm_year + 1900, value.tm_mon + 1, value.tm_mday,
                   value.tm_hour, value.tm_min, value.tm_sec);
        }
    }
    if (close(fd) != 0) {
        fatal("close_rtc");
    }
    printf("RTCPROBE_RESULT reads=%d failures=%u\n", CPUS * ROUNDS, failures);
    return failures != 0;
}

int main(void)
{
    setvbuf(stdout, NULL, _IONBF, 0);
    if (getpid() != 1) {
        puts("RTCPROBE_ERROR operation=not_guest_pid1");
        return 2;
    }
    mkdir("/proc", 0755);
    mkdir("/sys", 0755);
    mkdir("/dev", 0755);
    if (mount("proc", "/proc", "proc", 0, NULL) != 0 ||
        mount("sysfs", "/sys", "sysfs", 0, NULL) != 0 ||
        mount("devtmpfs", "/dev", "devtmpfs", 0, NULL) != 0) {
        fatal("mount");
    }
    int status = run_probe();
    printf("RTCPROBE_EXIT status=%d\n", status);
    reboot(RB_POWER_OFF);
    for (;;) {
        pause();
    }
}
