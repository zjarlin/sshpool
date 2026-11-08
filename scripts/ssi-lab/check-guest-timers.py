#!/usr/bin/env python3
"""关联无磁盘实验客体的定时器、唤醒与中断区间；不推断宿主停顿根因。"""
import argparse
from collections import Counter, defaultdict
import importlib.util
import json
from pathlib import Path
import re
import tarfile


def load(name):
    spec = importlib.util.spec_from_file_location(name, Path(__file__).with_name(name + '.py'))
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


native = load('check-native-trace')
clock = load('check-clock')
demand = native.demand
EVENTS = {
    'hrtimer_init', 'hrtimer_start', 'hrtimer_cancel', 'hrtimer_expire_entry',
    'hrtimer_expire_exit', 'sched_switch', 'sched_waking', 'sched_wakeup',
    'workqueue_execute_start', 'workqueue_execute_end', 'local_timer_entry', 'local_timer_exit',
}
INTERVAL = re.compile(r'TIMER_INTERVAL pid=(\d+) cpu=(\d+) before_ns=(\d+) after_ns=(\d+)')


def read_archive(path):
    """只在内存中读取限定大小的普通文件，不向文件系统解包。"""
    files, total = {}, 0
    with tarfile.open(path, 'r:gz') as archive:
        for member in archive:
            if member.isdir() and member.name == '.':
                continue
            name = member.name.removeprefix('./')
            demand(member.isfile() and re.fullmatch(r'[a-zA-Z0-9_-]+', name) is not None,
                   '归档包含非普通文件或路径')
            demand(name not in files, '归档文件重复')
            total += member.size
            demand(0 <= member.size <= 64 * 1024 * 1024 and total <= 96 * 1024 * 1024,
                   '归档超过实验记录大小限制')
            files[name] = archive.extractfile(member).read().decode('utf-8')
    return files


def field(row, key):
    values = re.findall(r'\b' + key + r'=([^ ]+)', row['detail'])
    demand(len(values) == 1, f'事件字段缺失或重复：{key}')
    return values[0]


def parse(files):
    demand(files['cleanup'].strip() == 'complete', '采集没有完成清理')
    demand('[global]' in files['trace_clock'].split(), '需要 global 跟踪时钟')
    demand(files['clocksource'].strip() == 'kvm-clock' and files['tainted'].strip() == '0',
           '时钟源或内核污染状态不符')
    demand(files['version'].startswith('Linux version 6.8.0-147-generic '), '客体内核不符')
    demand('nokaslr' in files['cmdline'].split(), '缺少实验客体启动参数')
    for name in EVENTS:
        demand(files['format-' + name].startswith('name: ' + name + '\n'), '事件格式身份不符')
    for name in ('sched_waking', 'sched_wakeup'):
        demand(files['filter-' + name].strip() == 'comm == "ssi-clock"', '唤醒过滤器不符')
    demand(files['filter-sched_switch'].strip() == 'prev_comm == "ssi-clock" || next_comm == "ssi-clock"',
           '切换过滤器不符')
    for name in EVENTS - {'sched_switch', 'sched_waking', 'sched_wakeup'}:
        demand(files['filter-' + name].strip() == 'none', '不允许隐藏定时器或中断事件')
    rows = []
    for line in files['trace'].splitlines():
        if not line.strip() or line.startswith('#'):
            continue
        match = native.drain.safety.teardown.EVENT.fullmatch(line)
        demand(match is not None, '跟踪行损坏')
        comm, pid, cpu, stamp, name, detail = match.groups()
        seconds, fraction = stamp.split('.')
        demand(name in EVENTS | {'tracing_mark_write'}, '存在未声明的事件')
        rows.append({'comm': comm.strip(), 'pid': int(pid), 'cpu': int(cpu), 'name': name,
                     'ns': int(seconds) * 1_000_000_000 + int(fraction.ljust(9, '0')),
                     'detail': detail, 'index': len(rows)})
    demand(re.findall(r'entries-in-buffer/entries-written: (\d+)/(\d+)', files['trace']) ==
           [(str(len(rows)), str(len(rows)))], '跟踪头部计数不符')
    demand(all(a['ns'] <= b['ns'] for a, b in zip(rows, rows[1:])), '跟踪时间倒退')
    counts = Counter(row['cpu'] for row in rows)
    demand(set(counts) <= set(range(4)) and
           {name for name in files if name.startswith('stats-')} == {f'stats-cpu{cpu}' for cpu in range(4)},
           '需要完整四 CPU 统计')
    for cpu in range(4):
        stats = files[f'stats-cpu{cpu}']
        demand(re.findall(r'^entries: (\d+)$', stats, re.M) == [str(counts[cpu])], '逐 CPU 计数不符')
        for key in ('overrun', 'commit overrun', 'dropped events'):
            demand(re.findall(r'^' + key + r': (\d+)$', stats, re.M) == ['0'], '跟踪丢失')
    marks = [row for row in rows if row['name'] == 'tracing_mark_write']
    demand([row['detail'] for row in marks] == ['guest_timer_begin', 'guest_timer_end'] and
           marks[0]['ns'] < marks[1]['ns'], '测量窗口不完整')
    return rows, marks


def pair_nested(rows, entry, leave, identity):
    """按 CPU 栈配对可嵌套区间，边界缺失单列且不补造耗时。"""
    pending, seen, complete, prefix = defaultdict(list), set(), [], []
    for row in rows:
        cpu = row['cpu']
        if row['name'] == entry:
            pending[cpu].append(row)
            seen.add(cpu)
        elif row['name'] == leave:
            if not pending[cpu]:
                demand(cpu not in seen, '窗口内部返回缺少入口')
                prefix.append(row)
                continue
            start = pending[cpu].pop()
            demand(identity(start) == identity(row) and start['pid'] == row['pid'],
                   '区间嵌套、线程或对象不匹配')
            complete.append({'start': start, 'end': row, 'duration_ns': row['ns'] - start['ns']})
    return complete, {'prefix': prefix, 'suffix': [row for stack in pending.values() for row in stack]}


def application_intervals(log):
    """旧时钟校验仍负责完整顺序；额外区间只补充 PID 和同域单调读数。"""
    trials = re.findall(r'CLOCK_START[^\n]*\n.*?CLOCK_PASS[^\n]*', log, re.S)
    demand(bool(trials), '缺少完整应用探针')
    relevant = [line.strip() for line in log.splitlines()
                if line.strip().startswith(('CLOCK_', 'TIMER_INTERVAL', 'TRACE_CLOCK_PID='))]
    expected, intervals, pids = [], [], set()
    for trial in trials:
        clock.validate(trial)
        lines = trial.splitlines()
        demand(sum(line.startswith('TIMER_INTERVAL') for line in lines) == 4, '应用区间缺失或重复')
        records = []
        for i, line in enumerate(lines):
            match = clock.TIMER.fullmatch(line)
            if match is None:
                continue
            interval = INTERVAL.fullmatch(lines[i + 1]) if i + 1 < len(lines) else None
            demand(interval is not None, '定时器后缺少应用区间')
            cpu, requested, elapsed = map(int, match.groups())
            pid, actual_cpu, before, after = map(int, interval.groups())
            demand(pid > 0 and cpu == actual_cpu and after - before == elapsed and before > 0,
                   '应用区间与定时器读数不匹配')
            sample = clock.SAMPLE.fullmatch(lines[i - 1])
            demand(sample is not None and int(sample[4]) <= before, '区间起点早于前置采样')
            following = [clock.SAMPLE.fullmatch(line) for line in lines[i + 2:]]
            following = [sample for sample in following if sample is not None]
            demand(not following or after <= int(following[0][4]), '区间终点晚于后置采样')
            records.append({'pid': pid, 'cpu': cpu, 'before_ns': before, 'after_ns': after,
                            'requested_ns': requested, 'elapsed_ns': elapsed})
        demand(len(records) == 4 and len({row['pid'] for row in records}) == 1, '应用 PID 不唯一')
        pid = records[0]['pid']
        demand(pid not in pids, '应用 PID 复用未被身份协议覆盖')
        pids.add(pid)
        expected += [f'TRACE_CLOCK_PID={pid}', *lines]
        intervals += records
    demand(relevant == expected, '应用记录缺失、重复或包含额外失败')
    demand(all(a['after_ns'] <= b['before_ns'] for a, b in zip(intervals, intervals[1:])), '应用区间重叠或倒退')
    return intervals


def timer_generations(rows):
    current, selected = {}, []
    for row in rows:
        if not row['name'].startswith('hrtimer_'):
            continue
        pointer = field(row, 'hrtimer')
        if row['name'] == 'hrtimer_init':
            previous = current.get(pointer, {})
            demand(not previous.get('selected') or 'end' in previous, '定时器未完成就重用指针')
            current[pointer] = {'init': row}
            continue
        generation = current.get(pointer)
        if row['name'] == 'hrtimer_start' and row['comm'] == 'ssi-clock' and field(row, 'function') == 'hrtimer_wakeup':
            demand(generation is not None and not generation.get('selected'), '定时器缺少初始化或重复启动')
            init = generation['init']
            demand(init['pid'] == row['pid'] and init['cpu'] == row['cpu'] and init['comm'] == 'ssi-clock'
                   and field(init, 'clockid') == 'CLOCK_MONOTONIC' and field(init, 'mode') == 'REL',
                   '定时器初始化身份或时钟域不符')
            demand(field(row, 'function') == 'hrtimer_wakeup' and field(row, 'mode') == 'REL' and
                   field(row, 'was_armed') == '0', '定时器模式或回调不符')
            generation.update(selected=True, start=row)
            selected.append(generation)
            continue
        if generation is None or not generation.get('selected'):
            continue
        demand(row['cpu'] == generation['start']['cpu'], '目标定时器迁移 CPU')
        if row['name'] == 'hrtimer_expire_entry':
            demand('expire' not in generation and field(row, 'function') == 'hrtimer_wakeup', '重复或错误回调')
            generation['expire'] = row
        elif row['name'] == 'hrtimer_expire_exit':
            demand('expire' in generation and 'end' not in generation, '回调缺少入口或重复返回')
            generation['end'] = row
        else:
            raise ValueError('目标定时器取消或未经重新初始化就重用')
    demand(all('end' in generation for generation in selected), '目标定时器回调不完整')
    return selected


def inspect(files, log):
    rows, marks = parse(files)
    apps = application_intervals(log)
    generations = timer_generations(rows)
    demand(len(generations) == len(apps), '应用区间与目标定时器数量不符')
    irqs, irq_boundary = pair_nested(rows, 'local_timer_entry', 'local_timer_exit', lambda row: field(row, 'vector'))
    callbacks, callback_boundary = pair_nested(rows, 'hrtimer_expire_entry', 'hrtimer_expire_exit',
                                               lambda row: field(row, 'hrtimer'))
    timers = []
    for generation, app in zip(generations, apps):
        init, start, expire, end = (generation[key] for key in ('init', 'start', 'expire', 'end'))
        pid, cpu = app['pid'], app['cpu']
        demand((start['pid'], start['cpu']) == (pid, cpu), '应用顺序、PID 或 CPU 不匹配')
        demand(marks[0]['index'] < init['index'] < start['index'] < expire['index'] < end['index'] < marks[1]['index'],
               '目标定时器跨越测量边界或顺序错误')
        soft, hard, base_now = int(field(start, 'softexpires')), int(field(start, 'expires')), int(field(expire, 'now'))
        demand(app['before_ns'] + app['requested_ns'] <= soft <= hard and soft <= base_now <= app['after_ns'],
               '单调时钟域的到期与应用边界不相容')
        inside = rows[expire['index'] + 1:end['index']]
        wakes = [row for row in inside if row['name'] in ('sched_waking', 'sched_wakeup') and
                 int(field(row, 'pid')) == pid]
        demand([row['name'] for row in wakes] == ['sched_waking', 'sched_wakeup'], '缺少唯一回调内唤醒')
        demand(all(field(row, 'comm') == 'ssi-clock' and int(field(row, 'target_cpu')) == cpu and
                   row['cpu'] == cpu for row in wakes), '唤醒的目标 CPU 或进程不符')
        switches = [row for row in rows[start['index'] + 1:marks[1]['index']] if row['name'] == 'sched_switch']
        asleep = [row for row in switches if row['index'] < expire['index'] and
                  int(field(row, 'prev_pid')) == pid and field(row, 'prev_state') == 'S']
        demand(len(asleep) == 1 and asleep[0]['cpu'] == cpu, '缺少唯一睡眠切换')
        resumes = [row for row in switches if row['index'] > wakes[1]['index'] and int(field(row, 'next_pid')) == pid]
        demand(bool(resumes) and resumes[0]['cpu'] == cpu and field(resumes[0], 'next_comm') == 'ssi-clock',
               '缺少目标 CPU 的重新运行')
        resumed = resumes[0]
        suspended = rows[asleep[0]['index'] + 1:resumed['index']]
        demand(not any(row['name'] == 'sched_switch' and
                       (int(field(row, 'prev_pid')) == pid or int(field(row, 'next_pid')) == pid)
                       for row in suspended), '睡眠至重新运行之间出现额外调度')
        suspended_wakes = [row for row in suspended if row['name'] in ('sched_waking', 'sched_wakeup') and
                           int(field(row, 'pid')) == pid]
        demand(suspended_wakes == wakes, '睡眠区间出现额外唤醒')
        demand(resumed['index'] > end['index'], '回调返回前进程已在同 CPU 运行')
        enclosing = [irq for irq in irqs if irq['start']['cpu'] == cpu and
                     irq['start']['index'] < expire['index'] < end['index'] < irq['end']['index']]
        demand(bool(enclosing), '目标回调没有完整本地定时器中断')
        irq = max(enclosing, key=lambda item: item['start']['index'])
        demand(irq['end']['index'] < resumed['index'], '同 CPU 中断尚未退出就切回进程')
        first = next(row for row in rows[irq['start']['index'] + 1:expire['index'] + 1]
                     if row['cpu'] == cpu and row['name'] == 'hrtimer_expire_entry')
        tick_calls = [call for call in callbacks if call['start']['cpu'] == cpu and
                      wakes[1]['index'] < call['start']['index'] < call['end']['index'] < irq['end']['index'] and
                      field(call['start'], 'function') == 'tick_nohz_highres_handler']
        timers.append({**app, 'pointer': field(start, 'hrtimer'), 'generation_index': init['index'],
                       'base_now_minus_softexpires_ns': base_now - soft,
                       'before_to_arm_reference_ns': soft - app['requested_ns'] - app['before_ns'],
                       'base_now_to_after_ns': app['after_ns'] - base_now,
                       'start_to_callback_ns': expire['ns'] - start['ns'],
                       'wakeup_to_switch_ns': resumed['ns'] - wakes[1]['ns'],
                       'wakeup_to_irq_exit_ns': irq['end']['ns'] - wakes[1]['ns'],
                       'irq_entry_to_first_callback_ns': first['ns'] - irq['start']['ns'],
                       'irq': irq, 'post_wakeup_ticks': tick_calls,
                       'endpoints': {'init': init, 'start': start, 'expire': expire, 'end': end,
                                     'sleep': asleep[0], 'waking': wakes[0], 'wakeup': wakes[1], 'resume': resumed}})
    return {'events': len(rows), 'window_ns': marks[1]['ns'] - marks[0]['ns'], 'timers': timers,
            'boundaries': {'irq': irq_boundary, 'callback': callback_boundary},
            'timer_gate_ns': 250_000_000, 'timer_gate_passed': all(row['elapsed_ns'] <= 250_000_000 for row in apps),
            'stall_cause_established': False, 'full_ssi_accepted': False}


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('archive', type=Path)
    parser.add_argument('clock_log', type=Path)
    args = parser.parse_args()
    print(json.dumps(inspect(read_archive(args.archive), args.clock_log.read_text()), indent=2))
