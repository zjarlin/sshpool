#!/bin/sh
# 仅在无磁盘四核实验客体采样，保留计数与原始事件，不改变时钟或调度策略。
set -eu
root=/sys/kernel/tracing
instance=$root/instances/sshpool_guest_timers
output=/tmp/ssi-timer-capture
[ "$(uname -r)" = 6.8.0-147-generic ]
[ "$(hostname)" = sshpool-ssi-guest ]
[ "$(nproc)" = 4 ]
grep -qw 'rdinit=/init' /proc/cmdline
case "${1:-}" in
start)
    if ! grep -q ' /sys/kernel/tracing tracefs ' /proc/mounts; then
        mount -t tracefs tracefs "$root"
    fi
    [ -z "$(ls -A "$root/instances")" ]
    [ -z "$(cat "$root/kprobe_events")" ]
    mkdir "$output"
    mkdir "$instance"
    echo 0 > "$instance/tracing_on"
    echo global > "$instance/trace_clock"
    echo 4096 > "$instance/buffer_size_kb"
    cat /proc/cmdline > "$output/cmdline"
    cat /proc/version > "$output/version"
    cat /proc/sys/kernel/tainted > "$output/tainted"
    cat /proc/cpuinfo > "$output/cpuinfo"
    cat /sys/devices/system/clocksource/clocksource0/current_clocksource > "$output/clocksource"
    cat "$instance/trace_clock" > "$output/trace_clock"
    cat "$instance/buffer_size_kb" > "$output/buffer_size_kb"
    for event in timer/hrtimer_init timer/hrtimer_start timer/hrtimer_cancel timer/hrtimer_expire_entry timer/hrtimer_expire_exit sched/sched_switch sched/sched_waking sched/sched_wakeup workqueue/workqueue_execute_start workqueue/workqueue_execute_end irq_vectors/local_timer_entry irq_vectors/local_timer_exit; do
        name=${event##*/}
        cat "$instance/events/$event/format" > "$output/format-$name"
        case "$event" in
        sched/sched_switch) echo 'prev_comm == "ssi-clock" || next_comm == "ssi-clock"' > "$instance/events/$event/filter";;
        sched/sched_waking|sched/sched_wakeup) echo 'comm == "ssi-clock"' > "$instance/events/$event/filter";;
        esac
        cat "$instance/events/$event/filter" > "$output/filter-$name"
        echo 1 > "$instance/events/$event/enable"
    done
    echo 1 > "$instance/tracing_on"
    echo guest_timer_begin > "$instance/trace_marker"
    echo GUEST_TIMER_TRACE_READY
    ;;
stop)
    [ -d "$output" ]
    [ -d "$instance" ]
    echo guest_timer_end > "$instance/trace_marker"
    echo 0 > "$instance/tracing_on"
    cat "$instance/trace" > "$output/trace"
    for cpu in "$instance"/per_cpu/cpu*; do
        cat "$cpu/stats" > "$output/stats-${cpu##*/}"
    done
    echo 0 > "$instance/events/enable"
    rmdir "$instance"
    [ ! -e "$instance" ]
    echo complete > "$output/cleanup"
    echo GUEST_TIMER_TRACE_STOPPED
    ;;
*) echo 'usage: guest-timer-trace.sh start|stop' >&2; exit 2;;
esac
