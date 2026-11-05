Feature: 同一个 Linux 客体真实使用多机硬件
  这是严格 SSI 目标，不能用 SSH 调度或构建缓存替代。

  @research @p0
  Scenario: 现有设备能够承载同一个客体
    Given 集群包含 x86 Linux 和 Apple Silicon 上的 Linux 虚拟机
    When 选择和部署分布式虚拟化实现
    Then 每种宿主 ISA 与虚拟化接口都有可复现支持证据
    And 不以跨架构软件仿真冒充接近原生性能

  @research @p0
  Scenario: 同一进程使用多机 CPU
    Given 一个未按任务拆分的多线程程序运行于客体
    When 程序使用多个 vCPU 进行计算
    Then 至少两台物理机执行属于同一程序的线程
    And 结果与单机参考结果一致
    And 不以两个独立作业替代同一进程

  @research @p0
  Scenario: 单实例工作集超过任一节点内存
    Given 各节点有明确且不可超配的集群内存配额
    When 一个未修改的程序分配并随机读写超过最大单节点配额的内存
    Then 多台节点实际承载其驻留内存页
    And 页内容和原子操作语义保持一致
    And 不依赖 swap 或磁盘 mmap 伪造 DRAM 容量

  @research @p0
  Scenario: 未修改 Docker 镜像兼容
    Given 固定 digest 的 sub2api PostgreSQL 和 Redis 镜像
    When 镜像运行在同一个 SSI 客体
    Then 无需改写应用为分布式任务
    And 多进程共享内存锁信号和持久化语义有集成测试

  @research @p0
  Scenario: 分布式磁盘的持久化语义
    Given 任务文件和数据库卷位于隔离实验存储
    When 执行随机 I/O fsync 和节点掉电实验
    Then 持久化确认与重启后数据校验一致
    And 不把网络目录挂载视作已经通过容错测试

  @research @p0
  Scenario: 性能接近各节点之和需要同工作负载测量
    Given 已记录各单节点基线和入口后台开销
    When 测量相同编译计算和数据库工作负载
    Then 报告吞吐尾延迟网络传输与一致性开销
    And 不按异构 CPU 逻辑核数简单相加推断性能
    And 明确给出尚未达到的目标

  @research @p0
  Scenario: 入口平时低负载且后备容量可信
    Given 正常工作由其他节点承担且入口有保留配额
    When 主节点失效
    Then 恢复任务受剩余节点可用资源限制
    And 报告常驻复制与恢复过程在入口的开销
    And 不声称失去节点后仍拥有故障前总资源
