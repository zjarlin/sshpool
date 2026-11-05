Feature: 隔离的同 ISA 双节点 GiantVM 实验
  实验 VM 不等于独立物理机，实验进展不计作生产 SSI 完成。

  # evidence: docs/ssi-lab.md
  @verified @p0
  Scenario: 两个实验节点提供真正的 KVM DSM 接口
    Given 两个新建的独立 x86_64 Linux 实验 VM
    When 安装固定版本的配对内核并启动
    Then 两节点 KVM API 为 12 且可以创建 VM
    And DSM capability 249 从 0 变为 1
    And 保留原内核作为默认回退启动项

  # evidence: docs/ssi-lab.md
  @verified @p0
  Scenario: 单节点对照排除测试程序自身错误
    Given 修正单节点路由空指针后的 GVM QEMU
    When 在一个节点运行原版 Ubuntu 客体内核和内存测试
    Then 同一 PID 的四个线程各运行于一个指定 vCPU
    And 32 MiB 内存逐字校验与原子计数 512 通过
    And 不把这项单机结果当成跨节点通过

  # evidence: docs/ssi-lab.md
  @verified @p0
  Scenario: 同一客体的四个 vCPU 分属两个实验节点
    Given 两节点使用相同源码修正和运行时文件
    When 以传统 APIC 模式启动一个总共四 vCPU 的客体
    Then 客体四个 CPU 全部在线
    And 节点零只执行 vCPU 零和一
    And 节点一只执行 vCPU 二和三
    And 记录节点侧线程时间与客体输出

  # evidence: docs/evidence/ssi-20261105.txt
  @verified @p0
  Scenario: 双节点同一进程通过确定性计算与内存校验
    Given 测试程序必须看到四个在线 CPU
    When 在跨节点客体运行该程序
    Then 同一 PID 的四个线程算术结果与参考结果一致
    And 32 MiB 共享内存逐字校验与原子计数 512 通过
    And 只有两个 CPU 在线时明确失败
    And 同时核查宿主页引用错误和进程崩溃日志

  @research @p0
  Scenario: 冷启动重复性和宿主内存安全
    Given 已记录上游与本地补丁的精确版本
    When 重复冷启动并交错执行缺页失效和关闭流程
    Then 排除页引用重复释放以及未经 DSM 授权的预取映射
    And 通过内存压力并发原子操作与长时间运行验证
    And 未完成该门槛前不迁移生产数据库
