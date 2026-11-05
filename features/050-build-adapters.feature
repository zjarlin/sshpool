Feature: 常用构建命令接入统一工作台
  项目必须显式加入，普通 shell 命令仍在工作台运行。

  # evidence: docs/validation.md#rust
  @verified @manual @p0
  Scenario: 原命令触发隔离 Rust 构建
    Given 项目配置与 Cargo shim 已安装
    When 从统一 SSH 会话执行 cargo build
    Then 编译发生在非 root 任务容器
    And 产物可被回取并执行

  @partial @p1
  Scenario: Gradle Make Node 和 Python
    Given 项目配置批准的运行镜像
    When 使用对应 shim 或 run 显式提交构建
    Then 复用相同调度和隔离链路
    And 每类工具都有实际兼容性验收

  @planned @p1
  Scenario: sccache 分布式编译与缓存
    Given 构建器工具链和身份经过验证
    When 项目启用 sccache profile
    Then 可分发的编译步骤在多个兼容节点运行
    And 缓存按工具链目标和项目策略隔离

  @planned @p2
  Scenario: Icecream 和测试分片
    Given C 或 C++ 工具链与可分片测试已配置
    When 用户启用对应 adapter
    Then 独立编译单元或测试分片并行执行
    And 汇总退出码而不重试有副作用的分片
