#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <inttypes.h>
#include <pthread.h>
#include <sched.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/mount.h>
#include <sys/reboot.h>
#include <sys/stat.h>
#include <unistd.h>

/* 只在专用无磁盘客体作为 PID 1 运行；EDU 不挂驱动，不接触 RTC 或宿主设备。 */
#define CPUS 4
#define ROUNDS 64
#define DEVICE "/sys/bus/pci/devices/0000:00:02.0/"
static volatile uint32_t *registers;
static pthread_mutex_t lock = PTHREAD_MUTEX_INITIALIZER;
static pthread_barrier_t barrier;
static uint32_t expected;
static unsigned int checks;
static unsigned int failures;

static void fatal(const char *operation, int code)
{
    printf("IORDER_ERROR operation=%s code=%d\n", operation, code);
    exit(1);
}

static void check_thread(int result, const char *operation)
{
    if (result != 0) {
        fatal(operation, result);
    }
}

static void pin(int cpu)
{
    cpu_set_t cpus;
    CPU_ZERO(&cpus);
    CPU_SET(cpu, &cpus);
    check_thread(pthread_setaffinity_np(pthread_self(), sizeof(cpus), &cpus), "affinity");
    if (sched_getcpu() != cpu) {
        fatal("wrong_cpu", cpu);
    }
}

static void synchronize(void)
{
    int code = pthread_barrier_wait(&barrier);
    if (code != PTHREAD_BARRIER_SERIAL_THREAD) {
        check_thread(code, "barrier");
    }
}

static uint32_t read_register(void)
{
    uint32_t value = registers[1];
    __asm__ volatile("mfence" : : : "memory");
    return value;
}

static void write_register(uint32_t value)
{
    registers[1] = value;
    __asm__ volatile("mfence" : : : "memory");
}

static void *worker(void *argument)
{
    int cpu = (int)(intptr_t)argument;
    pin(cpu);
    for (unsigned int round = 0; round < ROUNDS; round++) {
        synchronize();
        check_thread(pthread_mutex_lock(&lock), "lock");
        uint32_t observed = read_register();
        if (observed != expected) {
            failures++;
            printf("IORDER_MISMATCH round=%u cpu=%d check=%u expected=%08" PRIx32
                   " observed=%08" PRIx32 "\n", round, cpu, checks, expected, observed);
        }
        checks++;
        uint32_t value = UINT32_C(0xa5000000) | ((uint32_t)cpu << 16) | checks;
        write_register(value);
        expected = ~value;
        /* 下一位持锁者应看见上一位已经完成的设备写入。 */
        check_thread(pthread_mutex_unlock(&lock), "unlock");
        synchronize();
        if (cpu == 0) {
            printf("IORDER_ROUND round=%u checks=%u failures=%u\n", round, checks, failures);
        }
    }
    printf("IORDER_THREAD requested_cpu=%d observed_cpu=%d\n", cpu, sched_getcpu());
    return NULL;
}

static unsigned int read_id(const char *path)
{
    unsigned int value;
    FILE *input = fopen(path, "r");
    if (input == NULL || fscanf(input, "%x", &value) != 1) {
        fatal("pci_id", errno);
    }
    fclose(input);
    return value;
}

static int run_probe(void)
{
    char command_line[4096];
    FILE *input = fopen("/proc/cmdline", "r");
    if (input == NULL || fgets(command_line, sizeof(command_line), input) == NULL) {
        fatal("cmdline", errno);
    }
    fclose(input);
    if (strstr(command_line, "sshpool_io_order_probe=1") == NULL ||
        sysconf(_SC_NPROCESSORS_ONLN) != CPUS) {
        fatal("guest_guard", 0);
    }
    struct stat driver;
    if (lstat(DEVICE "driver", &driver) == 0 || errno != ENOENT) {
        fatal("device_has_driver", errno);
    }
    if (read_id(DEVICE "vendor") != 0x1234 || read_id(DEVICE "device") != 0x11e8) {
        fatal("not_edu", 0);
    }
    int enable = open(DEVICE "enable", O_WRONLY);
    if (enable < 0 || write(enable, "1", 1) != 1) {
        fatal("enable", errno);
    }
    close(enable);
    int resource = open(DEVICE "resource0", O_RDWR | O_SYNC);
    if (resource < 0) {
        fatal("resource", errno);
    }
    registers = mmap(NULL, 4096, PROT_READ | PROT_WRITE, MAP_SHARED, resource, 0);
    if (registers == MAP_FAILED) {
        fatal("mmap", errno);
    }
    close(resource);
    pin(0);
    printf("IORDER_START cpus=%d rounds=%d device_id=%08" PRIx32 "\n", CPUS, ROUNDS, registers[0]);
    write_register(UINT32_C(0xa5000000));
    expected = ~UINT32_C(0xa5000000);
    if (read_register() != expected) {
        fatal("initial_readback", 0);
    }
    check_thread(pthread_barrier_init(&barrier, NULL, CPUS), "barrier_init");
    pthread_t workers[CPUS];
    for (int cpu = 0; cpu < CPUS; cpu++) {
        check_thread(pthread_create(&workers[cpu], NULL, worker, (void *)(intptr_t)cpu), "create");
    }
    for (int cpu = 0; cpu < CPUS; cpu++) {
        check_thread(pthread_join(workers[cpu], NULL), "join");
    }
    uint32_t observed = read_register();
    if (observed != expected) {
        printf("IORDER_FINAL_MISMATCH expected=%08" PRIx32 " observed=%08" PRIx32 "\n", expected, observed);
        failures++;
    }
    printf("IORDER_RESULT checks=%u failures=%u expected_checks=%d\n", checks, failures, CPUS * ROUNDS);
    return failures != 0 || checks != CPUS * ROUNDS;
}

int main(void)
{
    setvbuf(stdout, NULL, _IONBF, 0);
    if (getpid() != 1) {
        puts("IORDER_ERROR operation=not_guest_pid1");
        return 2;
    }
    mkdir("/proc", 0755);
    mkdir("/sys", 0755);
    if (mount("proc", "/proc", "proc", 0, NULL) != 0 ||
        mount("sysfs", "/sys", "sysfs", 0, NULL) != 0) {
        fatal("mount", errno);
    }
    int code = run_probe();
    printf("IORDER_EXIT status=%d\n", code);
    reboot(RB_POWER_OFF);
    for (;;) {
        pause();
    }
}
