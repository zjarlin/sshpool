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
    mode=${2:-timers}
    case "$mode" in timers|irq|ktime) ;; *) echo 'unknown capture mode' >&2; exit 2;; esac
    if [ "$mode" != timers ]; then
        if ! grep -q ' /sys/kernel/debug debugfs ' /proc/mounts; then
            mount -t debugfs debugfs /sys/kernel/debug
        fi
        [ "$(cat /sys/kernel/debug/kprobes/enabled)" = 1 ]
        [ -z "$(cat /sys/kernel/debug/kprobes/list)" ]
    fi
    mkdir "$output"
    echo "$mode" > "$output/mode"
    mkdir "$instance"
    echo 0 > "$instance/tracing_on"
    echo global > "$instance/trace_clock"
    echo 8192 > "$instance/buffer_size_kb"
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
    if [ "$mode" != timers ]; then
        cat /sys/kernel/debug/kprobes/enabled > "$output/kprobes-before"
        cat /proc/kallsyms > "$output/kallsyms"
        for symbol in ktime_get_update_offsets_now tick_sched_do_timer tick_sched_handle; do
            echo "p:ssi_guest_irq/${symbol}_enter $symbol" >> "$root/kprobe_events"
            echo "r128:ssi_guest_irq/${symbol}_exit $symbol" >> "$root/kprobe_events"
        done
        if [ "$mode" = ktime ]; then
            # 偏移只对应本次哈希固定的 6.8 客体，避开高频 PAUSE 循环。
            grep -qx 'ffffffff81213bc0 T ktime_get_update_offsets_now' "$output/kallsyms"
            echo 'p:ssi_guest_irq/ktime_seq_even ktime_get_update_offsets_now+0x38 seq=%r13:u32' >> "$root/kprobe_events"
            echo 'p:ssi_guest_irq/ktime_clock_done ktime_get_update_offsets_now+0x4e' >> "$root/kprobe_events"
            echo 'p:ssi_guest_irq/ktime_seq_check ktime_get_update_offsets_now+0xda before=%r13:u32 after=%dx:u32' >> "$root/kprobe_events"
        fi
        for event in "$instance"/events/ssi_guest_irq/*; do
            [ -d "$event" ] || continue
            name=${event##*/}
            cat "$event/format" > "$output/format-$name"
            cat "$event/filter" > "$output/filter-$name"
        done
        cat "$root/kprobe_events" > "$output/probes"
        cat "$root/kprobe_profile" > "$output/profile-before"
    fi
    echo 1 > "$instance/tracing_on"
    if [ "$mode" != timers ]; then
        echo 1 > "$instance/events/ssi_guest_irq/enable"
    fi
    echo guest_timer_begin > "$instance/trace_marker"
    echo GUEST_TIMER_TRACE_READY
    ;;
stop)
    [ -d "$output" ]
    [ -d "$instance" ]
    mode=$(cat "$output/mode")
    echo guest_timer_end > "$instance/trace_marker"
    if [ "$mode" != timers ]; then
        # 停用入口并等待同步后再冻结，避免清除事件标记期间漏记命中。
        echo 0 > /sys/kernel/debug/kprobes/enabled
        cat /sys/kernel/debug/kprobes/enabled > "$output/kprobes-disabled"
    fi
    echo 0 > "$instance/tracing_on"
    cat "$instance/trace" > "$output/trace"
    for cpu in "$instance"/per_cpu/cpu*; do
        cat "$cpu/stats" > "$output/stats-${cpu##*/}"
    done
    echo 0 > "$instance/events/enable"
    if [ "$mode" != timers ]; then
        cat "$root/kprobe_profile" > "$output/profile-after"
    fi
    rmdir "$instance"
    [ ! -e "$instance" ]
    if [ "$mode" != timers ]; then
        for symbol in ktime_get_update_offsets_now tick_sched_do_timer tick_sched_handle; do
            echo "-:ssi_guest_irq/${symbol}_enter" >> "$root/kprobe_events"
            echo "-:ssi_guest_irq/${symbol}_exit" >> "$root/kprobe_events"
        done
        if [ "$mode" = ktime ]; then
            for name in ktime_seq_even ktime_clock_done ktime_seq_check; do
                echo "-:ssi_guest_irq/$name" >> "$root/kprobe_events"
            done
        fi
        [ -z "$(cat "$root/kprobe_events")" ]
        [ -z "$(cat /sys/kernel/debug/kprobes/list)" ]
        echo 1 > /sys/kernel/debug/kprobes/enabled
        cat /sys/kernel/debug/kprobes/enabled > "$output/kprobes-restored"
    fi
    echo complete > "$output/cleanup"
    echo GUEST_TIMER_TRACE_STOPPED
    ;;
*) echo 'usage: trace-guest-timers.sh start [timers|irq|ktime] | stop' >&2; exit 2;;
esac
