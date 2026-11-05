# 未通过完整验收的设备一致性候选补丁

本目录不是默认安装路径。`qemu-virtio-dsm-cache.patch` 只用于已有隔离实验环境，不能纳入此前已通过的 PF2 内存测试基线，也不能部署到业务宿主。补丁修改 QEMU GPL 源码，许可证为 GPL-2.0-or-later，正文见上级目录的 `COPYING.GPL-2.0`。

固定上游提交仍是 `da3f3b05d23ba714a3e961f80c059c376007d7d7`。在已应用 `qemu-single-node-routing.patch` 的独立源码目录使用 `patch -p1 < qemu-virtio-dsm-cache.patch`，重新构建并另存二进制，保留原始运行时。

## 改动与已观察结果

`address_space_cache_init()` 原先为 DSM RAM 保留本地直接指针，virtio 队列读取与完成索引写回可能绕过 DSM 页面获取。候选补丁在 TCP DSM 模式取消该直接指针，并让 virtio 的标量队列访问走已有的字节读写接口；这些接口的慢路径调用 `KVM_DSM_MEMCPY`。单节点和共享内存模式不取消直接指针。

本次只研究 virtio 队列缓存。其他设备的标量访问、DMA pin/unpin、错误传播、脏页跟踪和设备复位尚未系统验证，不能把这一修改称为完整设备一致性实现。

- 单节点对照：SSH、同进程内存测试、1 MiB SFTP 往返及正常关机通过。
- 双节点：成功认证一次并返回客体主机名；随后客体 RCU 停顿，后续 SSH 与 SFTP 握手超时。
- 宿主在设备访问时出现 `mark_page_dirty_in_slot` 告警，调用链含 `__kvm_write_guest_page`、`ivy_kvm_dsm_page_fault` 和 `kvm_vm_ioctl_dsm`。
- 两边到运行时限后终止，没有完成正常客体关机。**完整验收失败。**

运行二进制 SHA-256 为 `a2d0a9c4eaf74e72e044ff229b6cbbc9d1a7aeeb36ac8d8799f30e91ade8e7fc`。脱敏记录和测试边界见 [SSH 设备实验](../../../docs/evidence/ssi-ssh-network-20261105.txt)。这些结果既不能确定 RCU 停顿的根因，也不能证明补丁已经修复整个网络路径。

## 客体对照构建

诊断使用原版 Ubuntu `6.8.0-147-generic` 客体内核（哈希见证据），保留由上级 `build-ssh-guest.py` 生成的 Alpine 用户态、OpenSSH、主机密钥和测试程序。这个 Ubuntu 内核内建 `VIRTIO/ VIRTIO_PCI/ VIRTIO_NET/ FAILOVER/ NET_FAILOVER`。

在新建私有构建目录复制生成器的 `root/`，将其中 `/init` 的三行 `insmod` 替换为 `test -d /sys/module/virtio_net`，其后输出 `SSH_INIT_NETWORK_BUILTIN`；其他初始化步骤不变。用文档中的 `cpio --owner=0:0 --format=newc` 和 `gzip -1` 重新打包，给两节点分发完全相同的镜像与内核。原 Alpine 模块未加载，未修改发行版内核。镜像中含 SSH 私钥，不能发布。

下一步要先定位时钟、RCU 停顿和非 vCPU 设备写入的脏页记账，再重跑单节点、双节点与重复冷启动。不能以关闭 watchdog 或删除 WARN 来验收。
