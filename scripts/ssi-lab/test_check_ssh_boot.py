"""启动就绪标记不能掩盖已经发生的客体错误，也不能拼接多次启动。"""
import importlib.util
from pathlib import Path
import unittest

directory = Path(__file__).resolve().parent
spec = importlib.util.spec_from_file_location('check_ssh_boot', directory / 'check-ssh-boot.py')
checker = importlib.util.module_from_spec(spec)
spec.loader.exec_module(checker)
control = '''[    0.000000] Linux version 6.8.0-147-generic (buildd)
SSH_GUEST_READY kernel=6.8.0-147-generic cpus=4
Server listening on 0.0.0.0 port 22.
Server listening on :: port 22.
'''


class CheckSshBootTest(unittest.TestCase):
    def test_accepts_complete_startup(self):
        checker.validate(control)

    def test_qemu_recommended_cpu_limit_is_not_a_kernel_warning(self):
        advisory = 'qemu: warning: Number of SMP cpus requested (4) exceeds the recommended cpus supported by KVM (2)\n'
        checker.validate(advisory + control)

    def test_ready_does_not_override_kernel_clock_or_network_errors(self):
        errors = (
            'WARNING: CPU: 1 PID: 414 at kernel/time/hrtimer.c:1056 hrtimer_forward',
            'watchdog: BUG: soft lockup - CPU#1 stuck for 23s!',
            'Measured 2941101754 cycles TSC warp between CPUs, turning off TSC clock.',
            'tsc: Marking TSC unstable due to check_tsc_sync_source failed',
            'rtc_cmos 00:04: hctosys: unable to read the hardware clock',
            'net eth0: Failed to set MAC filter table.',
            'e1000: The EEPROM Checksum Is Not Valid',
            'KVM_DSM_MEMCPY failed -14',
            'virtio: cached queue write failed',
            'Kernel panic - not syncing: Attempted to kill init!',
            'rcu: INFO: rcu_preempt detected stalls on CPUs/tasks:',
            'WARNING: arch/x86/kvm/../../../virt/kvm/kvm_main.c:3523 at mark_page_dirty_in_slot',
            'kvm-dsm: node-0 failed to handle page fault on gfn[62896,0], error: -4',
        )
        for error in errors:
            with self.subTest(error=error), self.assertRaises(ValueError):
                checker.validate(error + '\n' + control)

    def test_host_error_scan_does_not_require_guest_ready_marker(self):
        checker.check_errors('kernel: Linux version 7.1.0-rc3\n')
        with self.assertRaises(ValueError):
            checker.check_errors('kernel: WARNING: virt/kvm/kvm_main.c:3523 at mark_page_dirty_in_slot')

    def test_rejects_recorded_failed_network_experiment(self):
        evidence = directory.parents[1] / 'docs/evidence/ssi-ssh-network-20261105.txt'
        with self.assertRaises(ValueError):
            checker.validate(evidence.read_text())

    def test_rejects_incomplete_mismatched_or_combined_boots(self):
        invalid = (
            control + control,
            control.replace('cpus=4', 'cpus=2'),
            control.replace('kernel=6.8.0-147-generic', 'kernel=6.12.115-0-virt'),
            control.split('SSH_GUEST_READY')[0],
            control.replace('Server listening on 0.0.0.0 port 22.', ''),
            'Server listening on 0.0.0.0 port 22.\n' + control.split('Server listening')[0],
        )
        for log in invalid:
            with self.subTest(log=log), self.assertRaises(ValueError):
                checker.validate(log)


if __name__ == '__main__':
    unittest.main()
