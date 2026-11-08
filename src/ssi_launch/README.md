# SSI 双节点启动准入

从 `ssi_launch::launch(plan, ssh_config, output, trace)` 或 CLI 调用：

```sh
sshpool ssi-launch --plan lab-plan.json --ssh-config lab-ssh-config --output new-run
```

`model.rs` 定义计划、实际封存报告与双端一致性校验；`session.rs` 维护 OpenSSH 会话和有界日志；`../ssi_launch.rs` 编排准备、许可、心跳与中止。远端 `../ssi_launch_worker.py` 在专用 PF24 Linux 节点封存三个输入，收到双方许可后从同一组 memfd 执行，并监督本次子进程。

计划使用两个不同的 SSH 别名、machine-id SHA-256、IPv4 地址。每个节点指定 QEMU、guest kernel、initramfs 的绝对路径及 SHA-256，以及可信宿主固件目录。`schema=1`，`require_kernel=7.1.0-rc3-sshpool-gvm-pf24`，`run_seconds=1..900`，可选 `ssh_port>=1024` 只转发节点 0 的回环端口。两端实际输入必须逐字节一致；这比协议版本号相同更严格。

控制 JSONL 每行上限 64 KiB、每端总上限 256 KiB，队列最多 16 条；失败报文先按上限保存再拒绝。镜像以非阻塞方式打开，再拒绝 FIFO 等非常规文件。

控制器每两秒续租；远端十秒无心跳即回收。控制会话关闭、显式中止、运行期限或日志上限触发本次进程组的 TERM/KILL。helper 被杀时 Linux 父进程死亡信号停止 QEMU。无法回收的内核任务保留锁并报告 `cleanup_pending`，需要独立恢复通道；不能声称任意内核故障都能有界清理。

退出零只代表两个已准入的进程均正常退出。客体 SSH、时钟、共享内存、SFTP、设备关闭和持久化仍须分别验证。许可发送不是分布式原子提交：半发送时一侧可能已执行，但会中止并保留失败记录。固件、动态链接器和宿主动态库属于可信宿主依赖，没有封存在三个镜像内。

四种混版本的真实 CLI 跟踪、同版本 proof/SSH 工作区、活跃客体故障回收及 helper 路径替换与半许可结果见 [实机复核](../../docs/ssi-launch.md#双端实机复核)。启动前拒绝已验证；RTC 中断丢失和 DSM 正常关闭失败仍保留，`full_ssi_accepted` 继续为 false。
