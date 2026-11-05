# DSM 设备内存与映射修复实验

2026-11-05。继续验证真实 SSI 的设备路径，使用两个专用 x86 实验 VM；它们仍位于同一个物理 ESXi，不能作为跨物理机性能或容错证据。所有新补丁留在 `scripts/ssi-lab/experiments/`，没有替换默认 PF2 构建流程。

## 已复现的问题

`probe-dsm-device.py` 直接调用真实 `/dev/kvm`，创建没有 vCPU、磁盘或宿主共享挂载的 VM。它只使用回环 DSM 节点。PF2 中，32 字节跨页写入的数据正确，但脏页位图为 `0b0`，应为 `0b11`。关闭 VM 时还出现不可被 SIGKILL 终止的内核循环，NMI 栈落在 `pte_list_remove → kvm_dsm_free_rmap → kvm_dsm_free → kvm_destroy_vm`。

源码显示，DSM 用 `gfn << 1` 编码页号，奇数页会设置 bit 1；新版 KVM 普通反向映射把 bit 1 用作 `KVM_RMAP_LOCKED`。上游只绕过了添加路径的锁，查询仍会清除此位，删除仍等待此位清零。这既会把奇数页查询成相邻偶数页，也会卡住销毁。此前小规模内存测试通过，没有覆盖这组设备接口和退出路径，不能因此认为 PF2 没有缺陷。

旧内核的实验进程阻止正常重启，记录调用栈并同步磁盘后，通过 ESXi 重置了唯一受影响的专用实验 VM。已确认回到原版 Ubuntu，再继续安装研究内核。业务 VM 和公司数据没有参与操作。

## 修复边界

`kernel-dsm-rmap.patch` 复用反向映射列表的读取和删除逻辑，保留普通 KVM 的原有锁；DSM 路径保留完整编码值，并使用自身的 `slot->rmap_lock`。没有删除数据损坏检查，也没有更改客体页号编码或网络协议。

`kernel-dsm-device-writes.patch` 在 DSM 位图模式允许非 vCPU 写入，给 MEMCPY 覆盖的页面记录脏位；复制失败返回 `EFAULT`，零长度直接成功，地址溢出拒绝。DSM 与 dirty ring 互斥，两种启用顺序都检查，并通过同一个 VM 锁串行化。这是受限的设备写入修复：**多个客体地址别名的完整脏页传播、未映射用户地址、并发内存槽变动和部分复制失败仍需继续实现和验证**。

`qemu-dma-unpin.patch` 将解除固定的长度从实际传输 `access_len` 改为最初映射的 `len`，避免短包或取消后留下尾部页面。源码修正和编译完成，单节点网络对照通过；远端页面重新获取、取消和设备复位仍缺专门验收。

## 真实接口测试

两个节点分别运行 PF5 的同一份五组探针，全部退出 0，每组均在 `close(vm)` 成功后输出通过：

| 测试 | 已覆盖 |
| --- | --- |
| `device_write` | 跨页内容与 `0b11`、只读不标脏、单页 `0b100`、EFAULT、零长度、溢出 |
| `slot_remove` | 奇数 GFN 起步的三页内存槽，两次删除重建 |
| `alias_remove` | 同一用户内存的两个客体地址，链表形式的删除、重建与销毁；不验证别名写入的脏位传播 |
| `ring_before_dsm` | 先开启 dirty ring，DSM 返回 EOPNOTSUPP |
| `dsm_before_ring` | 先开启 DSM，dirty ring 返回 EOPNOTSUPP |

探针结束后检查两个节点没有 Python/QEMU/DSM 线程残留，也没有本轮新增的宿主 WARNING、BUG、Oops 或引用计数错误。研究宿主采用精简 defconfig，这不是完整内核内存安全审计。脱敏输出、版本哈希与基线失败栈见 [设备内存证据](evidence/ssi-device-memory-20261105.txt)。

使用同一新内核与 QEMU 的单节点对照，SSH、四线程内存压力测试、1 MiB SFTP 校验、客体正常关机及 QEMU 退出 0 均通过。双节点也通过了 SSH 四线程内存测试和 SFTP 往返，但仍有 TSC 偏移，且被运行时限终止；完整工作区仍未通过。细节见 [PF5 SSH 证据](evidence/ssi-ssh-pf5-20261105.txt)，不能将接口测试通过视为持久磁盘、Docker 或数据库验收。

## 重现

先应用 README 中固定上游版本的 PF2 补丁，再应用 `experiments/kernel-dsm-device-writes.patch` 与 `experiments/kernel-dsm-rmap.patch`，构建单独的 `-sshpool-gvm-pf5` 内核；QEMU 在单节点路由补丁之后应用 virtio 缓存候选和 DMA unpin 补丁，另存运行时。实际构建文件已与从固定上游 tar 重新应用内核补丁的结果逐字节比较。

只在可重置的独立实验 VM，保留原版内核为默认启动项，用 `grub-reboot` 一次性启动研究内核：

```sh
timeout --kill-after=5 45 python3 scripts/ssi-lab/probe-dsm-device.py \
  --require-kernel 7.1.0-rc3-sshpool-gvm-pf5
```

探针故意覆盖内核清理路径；PF2 已实测发生 timeout 无法杀掉的内核循环，因此外层超时不能代替实验机恢复措施。不能对业务宿主运行。结尾必须有 `DEVICE_PROBE_EXIT failures=0`，仅中间某项通过不够。
