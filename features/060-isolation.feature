Feature: 运行时与资源隔离
  保护宿主公司数据和业务资源。

  # evidence: docs/validation.md#isolation
  @partial @manual @p0
  Scenario: 容器无宿主文件权限
    Given 使用预批准且不声明 VOLUME 的镜像
    When 创建构建容器
    Then 使用非 root 只读根文件系统和空 capability
    And 没有宿主 bind mount 或 Docker socket
    And 默认网络关闭

  @partial @manual @p0
  Scenario: 工作空间和执行资源受限
    Given 任务配置 CPU 内存进程日志工作空间与时间限额
    When 超过限额
    Then 对应资源控制拒绝分配或终止任务
    And 工作区 tmpfs 被计入任务内存

  @planned @p1
  Scenario: 业务 SLO 实测
    Given 业务持续承受基线和峰值流量
    When Worker 并行执行构建
    Then 测量业务延迟错误率 swap 和磁盘水位
    And 超出预算时暂停接单

  @research @p2
  Scenario: 比较 Landlock 与 microVM
    Given 使用专门的测试环境
    When 比较 rootless 容器 Landlock seccomp 和 microVM
    Then 使用同一硬件工具链与攻击样本测量
    And 不把 Landlock 的 TCP 端口规则等同于完整网络隔离
    And 不直接采用来源不明的启动耗时
