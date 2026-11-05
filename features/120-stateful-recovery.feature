Feature: sub2api PostgreSQL Redis 一致性恢复
  数据库恢复和计算任务重试不是同一种操作。

  @planned @p0
  Scenario: 精确识别应用的状态与持久化约定
    Given 指定的应用版本配置和镜像
    When 审核迁移方案
    Then 核对 PostgreSQL Redis 本地文件会话计费与后台任务
    And 明确客户端重连请求去重和 RPO RTO 目标
    And 不假设 Redis 只存可丢弃缓存

  @planned @p0
  Scenario: 在演示数据上验收迁移和切回
    Given 独立创建的演示数据库和已验证备份
    When 停写并执行一致性恢复和切回
    Then 业务记录计费序列和持久化状态校验一致
    And 保留原数据与可恢复的操作记录

  @research @p0
  Scenario: SSI 节点故障后恢复同一个服务状态
    Given 数据库位于已通过兼容测试的 SSI 客体
    When 承载唯一内存页或磁盘状态的节点失效
    Then 按明确复制或检查点协议恢复客体与数据库
    And 已确认事务满足约定的数据丢失上限
    And 未通过该测试不能宣称数据库高可用

  @research @p0
  Scenario: 网络分区只有一个有效写入方
    Given 节点间无法确认彼此状态
    When 恢复流程尝试启用后备数据库
    Then 先通过仲裁和写入隔离确保旧实例不能继续提交
    And 不以 SSH 超时等同于旧实例已停止

  @research @p0
  Scenario: 承诺容量符合最坏存活集合
    Given 需要容忍任意一个节点失效
    When 接纳数据库工作集与常驻副本
    Then 按最坏存活集合减去系统复制与恢复开销计算容量
    And 超过可恢复容量时拒绝做高可用承诺
