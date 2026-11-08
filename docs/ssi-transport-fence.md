# DSM 本地传输封闭实验

2026-11-08。PF25 增加本地传输准入封闭，为整机关闭提供一个必要条件。**尚未实现全部节点的 CLOSE/ACK，也没有改变 EOF 的故障语义。** 现有整机关闭场景保持 `@research`，正常关闭场景保持 `@partial`。

先阅读 [ioctl 准入](ssi-ioctl-admission.md) 与 [事务计数](ssi-exchange-accounting.md)，再看 `probe-transport-fence.py`、`check-transport-fence.py` 和 [本轮原始证据](evidence/ssi-transport-fence-20261108.json)。两台独占 VM 位于同一 ESXi；回环探针使用真实 KVM 与受控协议对端，不执行客体，也不证明跨物理机性能或故障接管。

## 问题与实现

PF24 的 transport status 是一次快照。读到出站、缓存和入站均为零后，另一个服务线程仍可准入新请求。因此不能用“零计数”作为释放连接的许可。

`kernel-dsm-transport-fence.patch` 基于 PF24。`KVM_DSM_TRANSPORT_FENCE` 在 `dsm_admission_lock` 内同时核对普通 ioctl、固定操作、读写固定引用、出站事务、缓存响应和入站请求均为零，再设置不可逆的 transport generation。页面请求与出站事务也在同一个锁内检查该状态。调用者必须先用相同 generation 完成 ioctl seal；固定引用必须在 seal 之前解除。

ABI 使用 `0x4018AEFA` 与 24 字节 `kvm_dsm_ioctl_drain` 参数：version 为 1、flags/reserved 为零、非零 generation、1–30000 ms 期限。未启用返回 `EINVAL`，未 seal 返回 `EPERM`，世代不符返回 `ESTALE`。超时返回 `ETIMEDOUT`，不提交 transport fence；先前已经准入的请求仍能反向取页。首次故障也在相同准入锁下锁存，等待者不能把故障后的计数归零当作成功。

`KVM_DSM_TRANSPORT_STATUS` 仍为 32 字节和 `0x8020AEF8`，版本升为 2。原末尾保留字段改为 `state:u32` 与 `generation:u64`；state 为 1 只表示本地页面与出站准入已封闭。现有 CLI 的 PF24 限定没有放宽，PF25 实验直接使用独立探针和 QEMU 回归工具。

## 两节点实测

每台 VM 各执行以下七种场景，全部保存 ioctl 原始输入输出、原始请求响应、按线程配对的内核入口返回、逐 CPU 计数、探针漏采统计、内核日志和防火墙前后快照。

| 场景 | 验证内容 |
| --- | --- |
| validation | 未启用、未 seal、非法参数、错误世代拒绝；同世代重复封闭成功；新复制调用拒绝 |
| reverse | seal 后两个入站服务仍发起真实反向取页，封闭等待所有响应完成 |
| cached | 半帧读者缓存另一事务响应，观察到 `(2,1,2)` 时仍不得封闭 |
| timeout | 100 ms 期限返回超时，状态仍开放；随后完成响应并成功封闭 |
| late | 封闭后完整页面请求原生返回 `ESHUTDOWN`，VM 失败，线程在探针清理前退出 |
| fault | 等待期间注入非法请求，封闭返回 `EPROTO`，故障优先于零计数 |
| race | 真实竞争观察到请求先准入和封闭先完成两种排序，均核对计数释放与返回顺序 |

检查器重新解析原始字节和事件，不依赖探针的通过标记。跟踪时钟与用户态单调时钟各自在自己的时间域内校验，不能直接相减；ioctl 通过线程身份、顺序、命令和返回值对应。时间断言同时检查等待区间覆盖真实在途和缓存状态。

本轮没有测试信号打断、三十二位兼容 ABI、长期竞态压力、恶意持续请求或设备后台生产者的整机协调。已有测试不被这些局部通过结果替代。

## 完整客体回归

同一 PF25 内核搭配现有路由协议 5 QEMU，分别运行普通单节点与双节点无磁盘工作区。两轮都完成 SSH、三次四 CPU 时钟采样、两次分配各八轮的 4 MiB 共享内存校验、用户态 PAUSE 探针和 1 MiB SFTP 往返。

| 本轮观察 | 单节点 | 双节点 |
| --- | ---: | ---: |
| 全流程 | 21.04 s | 71.37 s |
| 20 ms 定时器最大实测耗时 | 20.21 ms | 26.35 ms |
| QEMU 退出码 | 0 | 0 / 0 |
| 路由双向排空确认 | 不适用 | 完整 |
| 内核 DSM 正常关闭 | 不适用 | 未通过，保留 `-104` |

这只是各一次回归，不是吞吐或长期尾延迟结论。本次记录未发现 RTC 中断丢失或 watchdog 跳过检查，也不能据此关闭历史时钟问题。双节点已有路由确认不覆盖内核 DSM：两端仍出现接收连接重置，节点零锁存 `-104`。QEMU 尚未调用 PF25 fence，更没有全局最终确认，完整 SSI 验收继续不通过。

## 仍需完成的关闭协议

当前 fence 在单个节点上永久拒绝新请求。若另一节点仍持有一条尚未结束的请求链，提前 fence 会把它变成故障；因此不能直接接到 QEMU 退出路径就宣称正常关闭。

后续必须在关闭任何必要连接前，协调全部节点的外部入口、设备清理、反向请求链和所有连接。半帧占满接收线程、建连等待、确认发送均需要取消与期限验证；最终双方确认及故障优先级通过后，才有依据区分正常 EOF 与连接故障。持久 I/O、容器和数据库验收继续独立保留。

## 复现与回收

在已核对的 PF24 源码上应用补丁，另行构建 `7.1.0-rc3-sshpool-gvm-pf25`。本轮补丁零 fuzz 重放结果与实际编译源一致，内核 SHA-256 为 `ba645c3545acf528c13a2f7bbf002bcceb6432e66e2ae19f04614919197e617e`。

只在独占实验节点一次性启动该内核，保留 stock 默认项。部署探针及其同目录依赖，核对精确内核与脚本哈希；仅临时放行回环地址的实验端口，不能开放生产接口。每轮使用新输出文件，等待所有 TCP 状态消失后再开始下一轮。

```sh
sudo python3 scripts/ssi-lab/probe-transport-fence.py \
  --require-kernel 7.1.0-rc3-sshpool-gvm-pf25 \
  --mode cached --output new-cached.json
python3 scripts/ssi-lab/check-transport-fence.py new-cached.json
python3 -m unittest discover -s scripts/ssi-lab -p 'test_transport_fence.py'
```

探针拒绝其他内核、已有实验进程、端口或跟踪。检查器的变异测试覆盖伪造提前完成、缓存消费、超时封闭、故障成功、错误世代、页面损坏、事务重号、丢失跟踪和清理残留。

实验结束，两台节点均恢复 `6.8.0-147-generic`，原有 `/boot` 文件哈希与防火墙快照一致，`/lib -> usr/lib` 和 stock 默认启动项保留，GRUB 无待执行项，实验进程、跟踪与 TCP 状态均已清理。独立 PF25 产物保留供后续研究，不作为默认启动项。
