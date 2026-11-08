# SSI 双端启动准入 CLI

2026-11-08。新增实验命令 `sshpool ssi-launch`：两个远端 helper 先从实际输入字节计算摘要并封存 QEMU、guest kernel、initramfs；控制器确认两份准备报告一致后，才向双方发送执行许可。它针对旧主节点在新节点拒绝版本前已经执行客体的问题，背景见 [路由版本实验](ssi-router-startup.md)。

当前实现尚未完成真实 PF24 双端混版本和工作区回归，`180-ssi-device-order.feature` 对应场景保持 **partial**。已有 Rust 检查、Linux memfd/父进程死亡信号实测以及原版内核拒绝记录，不能替代双端 QEMU 验收。[初版 e7d29b7 的开发阶段记录](evidence/ssi-launch-development-20261108.json) 保留实际结果和中断原因。

## 使用

```sh
sshpool ssi-launch --plan lab-plan.json --ssh-config lab-ssh-config --output new-run
```

`new-run` 必须不存在，父目录必须已存在。输出包含计划、每个节点的控制 JSONL、SSH stderr 和最终报告。`--trace-syscalls` 用于拒绝路径的原生取证；每个节点的 stderr 超过 32 MiB 会中止本次运行，因此不适合持续采集正常客体的全部 KVM ioctl。

计划结构如下。摘要占位符必须换成已核验的实际值；节点身份取 `/etc/machine-id` 去掉首尾空白后字节的 SHA-256。

```json
{
  "schema": 1,
  "require_kernel": "7.1.0-rc3-sshpool-gvm-pf24",
  "addresses": ["192.0.2.10", "192.0.2.11"],
  "run_seconds": 180,
  "ssh_port": 22230,
  "peers": [
    {
      "ssh": "ssi-lab-1",
      "machine_id_sha256": "<node-0-machine-id-sha256>",
      "qemu": {"path": "/home/ubuntu/ssi/qemu-system-x86_64-router-startup-2", "sha256": "<qemu-sha256>"},
      "guest_kernel": {"path": "/home/ubuntu/ssi/guest-vmlinuz", "sha256": "<kernel-sha256>"},
      "initramfs": {"path": "/home/ubuntu/ssi/guest-initramfs.cpio.gz", "sha256": "<initramfs-sha256>"},
      "firmware": "/home/ubuntu/ssi/pc-bios"
    },
    {
      "ssh": "ssi-lab-2",
      "machine_id_sha256": "<node-1-machine-id-sha256>",
      "qemu": {"path": "/home/ubuntu/ssi/qemu-system-x86_64-router-startup-2", "sha256": "<qemu-sha256>"},
      "guest_kernel": {"path": "/home/ubuntu/ssi/guest-vmlinuz", "sha256": "<kernel-sha256>"},
      "initramfs": {"path": "/home/ubuntu/ssi/guest-initramfs.cpio.gz", "sha256": "<initramfs-sha256>"},
      "firmware": "/home/ubuntu/ssi/pc-bios"
    }
  ]
}
```

当前固定为两个专用 x86_64 PF24 节点、四个客体 CPU、256 MiB 内存、无磁盘。运行期限为 1–900 秒，`ssh_port` 可设为 `null`；启用时仅在节点 0 的回环地址转发客体 SSH，端口必须至少为 1024。它不修改内核、引导、防火墙或普通 Worker 注册表。

## 准入与执行对象

远端校验机器身份、运行内核、APICv、实验端口和已有进程，并持有独占运行锁。每个输入必须是有界常规文件，末级符号链接会被拒绝。helper 将实际字节复制到 memfd，检查复制前后的文件元数据与摘要，再设置禁止写入、伸缩和修改封条的四种 seal。后续执行和加载使用同一组 fd，并检查实际进程 executable inode。

准入要求两端三份镜像的摘要、大小和封条全部一致。这比同协议版本更严格：即使版本号相同，不同 ELF 也拒绝。本地路径在准备后被替换不会改变封存的字节。宿主固件、动态链接器、动态库仍是可信依赖，没有随三个镜像封存。

每次运行使用新 run ID、计划摘要和每端随机 token。远端独立复核双方报告与自身原始报告，拒绝过期或替换的许可。两个节点上的许可发送不是原子操作：半发送时一个节点可能已执行，控制器会中止并记录失败。它不提供网络分区下的共识或故障接管。

## 生命周期与验收边界

控制器每两秒发送心跳，远端十秒无心跳、控制输入关闭、显式中止、运行期限或客体日志上限都会触发本次进程组的回收：先 TERM 等五秒，再 KILL 等五秒。helper 被直接杀死时，exec 前设置的 Linux 父进程死亡信号停止 QEMU，设置窗口中的父进程变化也会拒绝执行。

若内核任务不可回收，helper 保留锁并报告 `cleanup_pending`，控制器报告未确认清理；必须通过独立实验恢复通道处理。不能将此实现解释为任意内核故障都有界停止。客体 stdout/stderr 分别限制 16 MiB，禁止生成 core 文件。

退出零要求双方已准入、许可已发送、真实封存启动事件与结束事件匹配、两条 SSH 会话正常退出，并且没有错误或强制清理。报告固定保留 `full_ssi_accepted=false`。客体 SSH、时钟、跨节点共享内存、SFTP、DSM 关闭和持久化要分别验收。

## 初版检查与中断

- Rust 全套：300 项通过，30 项需要专用外部环境的测试未运行；新增 5 项覆盖计划、报告一致性和缺失/伪造生命周期拒绝。格式化和 Clippy 通过。
- SSI Python：Mac 上 372 项发现，367 项通过、5 项 Linux 专用测试跳过。5 项 Linux 测试在添加 core 限制和最终退出状态轮询前，已在独占实验 VM 的原版内核上真实通过，包括不可写 memfd、原子替换源路径、错误摘要/符号链接、许可重放、helper 被杀后子进程停止并释放继承锁，以及父进程变化竞态。
- 初版 CLI 对两台原版内核的真实 SSH 调用均返回错误 2，明确提示需要专用 PF24；`admission_passed=false`、`commit_sent=[false,false]`，没有 QEMU 启动。
- 切换节点 0 到一次性 PF24 启动项后，节点 1 在本轮未发出重启命令的情况下被 ESXi root 于 11:49:56（Asia/Shanghai）发起 Guest OS Shutdown，11:50:00 关机。本轮双端实验因此未开始。节点 0 随后恢复原版内核，核对原引导文件、防火墙、空 GRUB 待执行项和无残留进程；它又在 11:56:17 被 root 发起 Guest OS Shutdown。两台均保持外部关机状态，等待确认资源仍可用。

后续仍需真实 CLI 的 3/5、5/3、4/5、5/4 混配原生跟踪，证明双方准备完成但都没有 QEMU exec 或 `KVM_RUN`；同版本 proof guest、原 250 ms 时钟门槛、共享内存和 1 MiB SFTP；以及真实 QEMU 的路径替换、半许可、控制器断连、租约与锁冲突。已有 `/bin/true`、`/bin/sleep` Linux 测试不能替代这些实验。

## 输入与控制流边界修正

镜像路径误指向 FIFO 时，初版的阻塞式 `open` 会在文件类型检查之前等待写入者，可能一直占住运行锁。现在以非阻塞方式打开，再用同一 fd 检查常规文件；常规文件的复制与封存流程保持一致。Linux 回归测试创建没有写入者的真实 FIFO，要求 helper 在三秒内明确拒绝。

控制 JSONL 每行最多 64 KiB，每个节点累计最多 256 KiB，控制器事件队列最多 16 条，连续小报文也不能无限积压。接收端先保留有界原始字节再校验；截断、超长、字段缺失和过期身份均会留下可复核的失败输入。新增三项 Rust 测试覆盖拒绝记录、报文顺序和累计上限。

新增 Linux 管道测试覆盖半帧等待期限、半帧 EOF、超长输入和同次读取中的多条报文。这些测试验证文件和控制流边界；两台专用 VM 的混版本、半许可及断连 QEMU 实验仍未完成，场景保持 partial。

代码阅读顺序：[启动计划和校验](../src/ssi_launch/model.rs) → [控制流程](../src/ssi_launch.rs) → [远端执行与监督](../src/ssi_launch_worker.py)。
