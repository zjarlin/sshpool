Feature: 物理主机准入与独立磁盘冗余
  KVM 预检不等于加入 SSI，存储冗余不等于客体内存恢复。

  # evidence: docs/evidence/ssi-physical-preflight-20261107.json
  @verified @p0
  Scenario: 在安装前发现真实物理节点的原生 TSC 频率不匹配
    Given 两个专用 ESXi 实验 VM 和一个独立 x86 物理候选主机
    When Rust CLI 通过已有 SSH 创建并关闭临时空 KVM VM 和两个 vCPU
    Then 同 ESXi 的相同原生频率通过这项前提检查
    And 跨物理候选的不同原生频率返回退出码二并保留双方读数
    And 即使存在缩放能力位也不能绕过尚未实现的频率转换
    And 不执行客体不安装软件不读写块设备且没有集群资源汇总
    And 空 VM 的零时钟标志不能冒充运行中可靠时钟验证
    And 保留首轮将空 VM 快照误作运行时快照的检查错误

  # evidence: tests/ssi_preflight.rs::duplicate_alias_and_failed_peer_stay_in_the_decision
  @verified @p0
  Scenario: 重复 SSH 别名和探测失败不能增加可用节点数
    Given 两个 SSH 别名可能指向同一机器或其中一端不可达
    When 运行 SSI 前提检查
    Then 对重复 machine-id 的摘要明确拒绝
    And 单端 SSH 失败仍保留在报告中且返回非零
    And 缺少原始读数接口或对象回收确认时不能判定通过
    And 不以不同 machine-id 推断独立物理故障域

  # evidence: docs/evidence/ssi-physical-host-20261107.json
  @verified @manual @p0
  Scenario: 新物理主机以隔离实验环境加入
    Given SSH 和真实 KVM 创建能力已在候选物理主机核验
    When 准备跨物理机实验
    Then 只创建有资源限额且不挂载业务目录的独立实验 VM
    And 八条 KVM vCPU 线程在物理宿主 CPU 上产生执行时间
    And 独立构建任务在物理宿主的 Docker 中完成编译和清理
    And 保存物理宿主身份与实验 VM 的对应关系和回退记录
    And 不覆盖物理宿主内核或已有磁盘内容

  # evidence: docs/ssi-physical-storage.md
  @partial @p0
  Scenario: 不同物理机时钟频率有可验证的共同语义
    Given 某执行节点不提供 KVM TSC 频率缩放能力
    When 将其与另一台物理机组成同一客体
    Then 先验证 CPU 能力交集和实际 TSC 频率是否兼容
    And 频率不同时拒绝启动或使用经过验证的时间转换
    And 不通过删除频率检查掩盖长期漂移
    And 同一进程的跨宿主执行归属和时钟测试都有原始证据

  @planned @p0
  Scenario: 新存储设备不能以未识别文件系统推断为空盘
    Given 设备可能有未挂载分区或公司内部数据
    When 请求加入分布式存储
    Then 按稳定硬件身份核对设备归属和明确用途
    And 检查分区签名文件系统卷管理软件阵列及现有使用者
    And 归属未确认时拒绝格式化覆盖或建立 OSD
    And 初期试验只使用单独创建且限制大小的实验文件

  @planned @p0
  Scenario: 无 RAID 的冗余按真实物理主机放置
    Given 各独立磁盘直接交由分布式存储管理
    When 设置副本数写入门槛和仲裁拓扑
    Then 不把同一物理机的多个 VM 计为独立主机故障域
    And 报告副本恢复预留之后的可用容量
    And 节点数量不足时拒绝对应的容错承诺

  @research @p0
  Scenario: 存储故障恢复与 SSI 状态恢复分别验收
    Given 只含演示数据的持久卷与同一 SSI 客体
    When 分别注入掉盘整机故障和网络分区
    Then 校验已确认写入的重启持久性和唯一有效写入方
    And 单独验证失效主机上内存状态的恢复协议
    And PostgreSQL Redis 的数据丢失上限和恢复时间可测量
    And 不以 Ceph 健康或挂载成功替代数据库与 SSI 验收
