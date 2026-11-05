Feature: 单一系统映像研究边界
  研究路线不作为当前可部署产品的验收承诺。

  @research
  Scenario: 普通进程跨节点共享内存
    Given 一个未修改的程序需要超过单机内存
    When 它运行在当前 SSHPool
    Then 不声称能自动合并所有节点内存
    And 应按单节点资源检查或改用分布式算法

  @research
  Scenario: Popcorn 专用实验
    Given 使用独立测试虚拟机和经过核查的论文实现
    When 安装定制内核编译器与运行时
    Then 单独验证线程迁移一致性性能和应用限制
    And 不把实验内核部署到公司业务宿主

  @research
  Scenario: tidsOS 观察
    Given 公开项目仍声明 Pre-alpha
    When 评估其节点注册与存储实现
    Then 不推断它已经具备生产调度网络和安全能力
    And 新能力必须先完成可重复实验
