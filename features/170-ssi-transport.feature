Feature: SSI 传输等待与启动资源生命周期
  先在真实 KVM 监听器和独占实验 VM 中验证，不将同一 ESXi 的结果当作跨物理机性能。

  # evidence: docs/evidence/ssi-shutdown-flush-20261106.json
  @verified @p0
  Scenario: 最终块层刷盘失败不能被 QEMU 关闭吞掉
    Given 新建的独立测试盘已完成真实非 FUA 写入且 blkdebug 只令最终刷盘失败
    When 原版和候选分别以单节点及暂停双节点实例关闭
    Then 保留原版在 EIO 与 ENOSPC 时仍退出零的真实对照
    And 候选故障节点保留原始刷盘错误并退出一
    And 双节点另一端也退出一且没有正常排空完成标记
    And 无故障对照仍退出零并核对原生块层跟踪与实际进程状态
    And 不把 HMP 写入或缓存读回当作客体 DMA 或掉电持久化证明

  # evidence: docs/evidence/ssi-host-timers-20261106.json
  @verified @p0
  Scenario: 宿主定时器中断退出与延期重装使用同一时钟核查
    Given 两节点完整记录定时器中断重装与 LAPIC 编程入口
    When 分析同 CPU 的中断退出至首次重装间隔
    Then 拒绝丢失记录并区分中断内重装和采样边界
    And 以期限与设备指针匹配后续编程调用且不混用期限时钟与跟踪时钟
    And LAPIC 函数入口仅证明编程尝试不能冒充中断已经送达
    And 导出空间不足必须在启用跟踪前拒绝且损坏文件不得作为通过证据

  # evidence: docs/evidence/ssi-host-timers-20261106.json
  @partial @p0
  Scenario: KVM 返回路径兑现宿主定时器延期重装
    Given PF15 研究内核在重新开启中断前调用已有重装函数
    When 两个独占节点运行相同客体与定时器负载
    Then 完整跟踪核查延期缩短并独立执行三轮无跟踪测试
    And 普通单节点虚拟机仍须单独通过回归
    And RTC 与 watchdog 告警和 DSM 关闭错误仍阻止完整工作区验收
    And 本项不代表持久 I/O 容器数据库或跨物理机故障接管已经完成

  # evidence: docs/evidence/ssi-vcpu-residency-20261106.json
  @verified @p0
  Scenario: KVM 进入退出区间与宿主中断使用完整记录核查
    Given 两个独占实验节点记录目标 vCPU 以及宿主调度和中断事件
    When 分析 KVM 进入退出与本地定时器间隔
    Then 检查线程身份全局时钟事件总数和每 CPU 丢失计数
    And 区间包含 KVM 准备和返回代码且不能直接当作有效客体计算时间
    And 开关产生更多事件导致缓冲溢出时必须拒绝该次时间分析
    And 缩短诊断窗口不改变三轮无跟踪运行的原时钟验收门槛

  # evidence: docs/evidence/ssi-timer-progress-20261106.json
  @verified @p0
  Scenario: 定时器空档内的频繁退出不能冒充宿主调度进度
    Given 同一 PF14 开关对照的四份完整跟踪已核对原始哈希
    When 逐宿主 CPU 分析相邻真实定时器入口之间的事件
    Then 分别报告 PAUSE 退出调度切换和相邻事件最大间隔
    And 其他 CPU 的活动不能填补本 CPU 的空档且采样边界不得外推
    And 跟踪点中断标志不能证明整个窗口持续关闭中断
    And 诊断结果不替代客体时钟内存与关闭验收

  # evidence: docs/evidence/ssi-vcpu-residency-20261106.json
  @partial @p0
  Scenario: 无 PLE 实验宿主可显式强制 DSM 客体从 PAUSE 返回
    Given 默认关闭的实验开关和缺少 PLE 的两个独占 x86 VMX 节点
    When 对同一候选内核分别开启和关闭该开关
    Then 仅开启时捕获真实 PAUSE 退出且四个客体 vCPU 的用户态探针能继续执行
    And 记录开关对 KVM 区间和调度等待的影响及额外退出开销
    And 仍需解决剩余时钟关闭与性能问题后才能通过完整 SSI 验收

  # evidence: docs/evidence/ssi-latency-20261106.json
  @verified @p0
  Scenario: 页面交接计时排除管理 SSH 且可以独立复核
    Given 单节点对照与两个实验 VM 都创建没有 vCPU 的真实 KVM 页面
    When 执行一百六十次顺序操作和每节点两个线程各二百五十六次写入
    Then 每次 ioctl 使用工作进程内的单调时钟计时并按线程对应内核入口和返回
    And 各次顺序读取内容正确且并发结束后各节点得到相同的完整最终页面
    And 验收重新计算页面校验和与所有耗时而不采信通过标记
    And 所有调用配对且跟踪没有丢失并确认工作进程完成关闭
    And 空闲监听等待单独报告且不能当作响应延迟

  @partial @p0
  Scenario: 完整客体的慢取页可以定位但尚未消除
    Given 两个实验 VM 上运行同一未经修改的 Linux 客体
    When 在应用时钟采样期间同时记录页面获取网络与锁调用
    Then 报告热点页面与函数等待并区分测量窗口边缘的不完整调用
    And 两侧窗口在导出任一大文件之前同时停止避免导出污染对端
    And 仍须在无跟踪运行中消除秒级停顿与 watchdog 告警后才通过完整工作区验收

  # evidence: docs/evidence/ssi-scheduling-20261106.json
  @verified @p0
  Scenario: 调度等待分解必须保留未知边界并拒绝丢失采样
    Given 独占实验 VM 中记录目标 QEMU 与 DSM 线程的身份及切换事件
    When 分解函数调用期间的等待
    Then 区分可运行等待睡眠已调度和窗口外未知时间
    And 已调度时间不冒充有效 CPU 计算且空闲接收不冒充响应延迟
    And 跟踪溢出探针遗漏时间倒退和线程身份变化均不能通过验收
    And 未覆盖的窗口边界不能用最后一次线程状态外推

  # evidence: docs/evidence/ssi-receive-probes-20261106.json
  @verified @p0
  Scenario: 空闲连接和未完整接收的帧都能让出 CPU
    Given 只有停止的 vCPU 和一个已建立的 DSM 回环连接
    When 不发送请求以及只发送八字节不完整帧
    Then 接收线程等待网络而不反复调用非阻塞接收
    And 两个独立测量窗口中的接收线程总 CPU 用量都低于零点一个核心
    And 关闭连接和 VM 后没有残留的接收线程
    And 保持半帧连接开放时销毁 VM 也能中断等待并回收线程
    And EOF 错误继续被记录而不被伪装成正常协议关闭

  @partial @p0
  Scenario: 等待改动保留事务分流和页面交接正确性
    Given 多个 vCPU 共用同一 DSM 连接并有不同事务编号
    When 指定事务尚未收到数据或者已收到半帧
    Then 空缓冲区时让出接收锁给其他事务
    And 半帧由同一读者接收完整后再解析
    And 跨节点 pvclock 探针与完整客体内存和 SFTP 校验分别通过

  # evidence: docs/evidence/ssi-router-drain-20261106.json
  @partial @p0
  Scenario: 显式关闭协议区分任务结束与节点故障
    Given 请求仍在传输或者对端已退出
    When 客体正常关机或某个节点失联
    Then 正常关闭须完成双方确认和在途请求排空
    And 故障退出必须传递给客体管理层且不能伪装成干净关机
    And 正在处理的页面请求与缺失内存槽重试都应响应停止信号

  # evidence: docs/evidence/ssi-router-drain-20261106.json
  @verified @p0
  Scenario: QEMU 关闭路由前核对本地停止和双向排空确认
    Given 两个 PF17 实验 VM 使用相同的路由协议三候选
    When 客体关机并停止 vCPU 后交换本次排空标记
    Then 两端发送和收到的确认具有匹配节点与序号且先于关闭完成
    And 非法版本帧失败退出且本地尚未停止时不能提前确认
    And 原来没有屏障但退出码为零的日志不能通过验收
    And 内核 DSM 连接重置继续阻止完整关闭验收且持久化仍未验证

  # evidence: docs/evidence/ssi-kernel-drain-20261106.json
  @verified @p0
  Scenario: 内核入站流确认等待早先请求响应和锁释放
    Given PF18 和 PF19 独占实验 VM 的一条连接有七个缺页请求或一个等待页锁的请求
    When 同一流随后收到带版本和关联序号的排空标记
    Then 等待条件解除前不能确认且确认发送晚于全部页面响应页锁和 SRCU 释放
    And 空闲流也能确认而非法版本零序号重复标记与屏障后新请求均报错
    And PF19 在同流坏帧后先锁存故障再释放接收锁且不能确认紧接的标记
    And 等待超时与另一连接故障不得产生确认且错误在清理前传播至管理接口
    And 半帧仍可取消且原始跟踪缺失或测试线程尚未就绪不能通过验收
    And 此项仅证明一条入站流不代表整个 VM 正常关闭或持久化成功

  # evidence: docs/evidence/ssi-ioctl-admission-20261106.json
  @verified @p0
  Scenario: 原生 VM 与 vCPU ioctl 封闭入口并等待已准入操作
    Given PF20 两个专用实验 VM 的真实写入正在等待远端页面或 vCPU 正在 HLT 等待
    When 控制端原子封闭普通 VM 与 vCPU ioctl 入口
    Then 新管理运行和内存复制调用均返回 ESHUTDOWN 而旧操作保持计数
    And 旧写入完成并释放 SRCU 后等待者才能成功且封闭期间页面服务仍返回正确内容
    And KVM_RUN 真实退出后才释放计数且控制等待者不计入自己等待的操作
    And 参数错误不封闭入口超时不重开入口相同序号可复核不同序号被拒绝
    And 故障唤醒全部等待者并保留错误而不能以计数归零冒充成功
    And 此项不证明后台设备 DMA 固定页面出站缓存响应或整个 VM 已经排空

  # evidence: docs/evidence/ssi-kernel-close-20261108.json
  @verified @p0
  Scenario: 原生 DSM 关闭使用同一代际确认所有连接并等待根线程回收
    Given 两个独占 PF28 实验 VM 创建没有 vCPU 和磁盘的真实 KVM
    When 双向页面传输后使用同一代际发起关闭
    Then 普通调用先结束监听集合真正冻结且每条数据连接完成 CLOSE 与确认
    And 全节点 READY 与 FINISH 之后才接受帧边界 EOF
    And 根线程释放所有入站连接后关闭调用才能返回成功
    And 半帧未知连接建连阻塞发送阻塞及缺失确认均受同一总期限约束
    And 保留错误代际晚到请求与 PF27 成功返回却残留根线程的失败记录
    And 完整原生跟踪实际页面与受控对端字节均独立检查且不冒充 QEMU 整机关闭

  # evidence: docs/evidence/ssi-qemu-close-20261108.json
  @verified @p0
  Scenario: 限定 QEMU 设备清理后完成双节点 DSM 正常关闭
    Given 两个独占 PF28 VM 使用协议六候选和保存的四 vCPU virtio-net 或 virtio-blk 配置
    When 实际 Ubuntu 客体关机或正常块写入后由主节点发起 QMP quit
    Then 双端 QUIESCE 确认所有 vCPU 停止之后才销毁设备
    And 设备解除和退出通知完成后双端 DRAIN 再查询真实零页引用
    And 使用同一代际关闭原生 DSM 且根线程回收先于成功返回
    And 两端退出零且完整跟踪中最终关闭以后不再发起 VM ioctl
    And 保留客体 watchdog 与 workqueue 告警而不声明完整 SSI 或持久化通过

  # evidence: docs/evidence/ssi-qemu-close-20261108.json
  @verified @p0
  Scenario: 正常关闭接线不能覆盖真实块设备错误
    Given 实际双节点 virtio-blk 客体注入 EIO 或交换实验 VM 角色后注入 ENOSPC
    When 最终刷盘返回零但失败请求仍在队列且后端错误未恢复
    Then 两端退出一并保留原始块请求错误与副节点屏障失败
    And 不调用正常内核关闭协议也不输出设备正常关闭完成
    And 故障销毁回收 DSM 根线程但不冒充数据恢复或存储副本

  @research @p0
  Scenario: 封闭入口之前验证其余跨调用资源和后台生产者已经停止
    Given 设备持有 DMA 固定页面或存在 device fd irqfd 定时器及后台任务
    When 管理器准备封闭 VM 与 vCPU ioctl 入口
    Then 所有需要后续 ioctl 的设备清理和 unpin 须先完成并有真实证据
    And 补齐其余入口和三十二位兼容路径的动态故障及并发验证
    And ioctl 计数为零不能冒充固定页面归零或所有异步任务已结束

  # evidence: docs/evidence/ssi-exchange-accounting-20261106.json
  @verified @p0
  Scenario: 出站事务持续计数直到响应消费或故障回收
    Given PF21 与 PF22 在两个专用实验 VM 上分别连接受控回环页面对端
    When 普通写入或已封闭 ioctl 入口下的服务线程发起真实反向取页
    Then 建连之前即登记出站工作且完整响应元数据处理和事务退休后才减少计数
    And 同连接两个活跃事务使用不同且非保留的编号
    And 半帧阻塞读者可将另一事务的响应缓存并观察两个出站一个缓存两个入站
    And 正常消费返回正确页面而重复或未知响应锁存 EPROTO 并回收全部线程
    And 建连失败与半帧中止分别有完整生命周期证据且缓存丢弃不冒充消费成功
    And 本地瞬时零计数不能证明跨节点请求链终止或整个 VM 已安全关闭

  # evidence: docs/evidence/ssi-exchange-accounting-20261106.json
  @verified @p0
  Scenario: 真实 Linux IDR 的编号耗尽不会反复分配保留编号
    Given 单线程用户态测试连接真实 Linux IDR 并使用从内核源提取的分配函数
    When 填满全部六万五千五百三十五个可用编号后继续分配
    Then 保留 PF21 无限重试导致五秒超时的失败记录
    And PF22 返回 ENOSPC 且解除一个编号后能重新分配并完全回收
    And 地址与未定义行为检查没有报错但不冒充六万多个并发 KVM 请求验证

  # evidence: docs/evidence/ssi-transport-fence-20261108.json
  @research @p0
  Scenario: 整机关闭协调外部入口反向请求和所有连接
    Given 入站流屏障已完成而其他连接仍可能产生反向取页
    When 管理端开始关闭整个分布式 VM
    Then 原子停止新外部操作并等待此前操作真正返回及全部响应被消费
    And 各节点的瞬时零计数仍需与新入站请求的准入和协议世代原子协调
    And PF25 本地封闭须保留反向请求及缓存消费并优先返回故障且不能代替全局确认
    And 保留反向请求所需连接直到所有节点确认没有未完成的请求链
    And 对尚未读到标记的八线程占满半帧建连和确认发送分别验证取消及期限
    And 最终双方确认和故障优先级通过后才能将连接 EOF 视为正常结束
    And 设备清理产生的内存访问须在内核最终关闭之前完成

  # evidence: docs/evidence/ssi-request-cancel-20261106.json
  @verified @p0
  Scenario: 完整读页请求等待缺失内存槽时可取消
    Given 独占实验 VM 已接收完整 DSM 读页请求但尚未注册目标页
    When 根线程向处理线程定向发送取消或调用者直接关闭 VM
    Then 九个 DSM 线程在目标页仍未注册时完成退出
    And 故障取消保留 EINTR 且不依赖稍后补注册才能回收
    And 未取消的对照在延迟注册后返回相同事务号和完整正确页面
    And 两台节点上的事件计数完整且没有跟踪丢失

  # evidence: docs/evidence/ssi-request-safety-20261106.json
  @verified @p0
  Scenario: 请求接收在复制前检查容量并拒绝无效字段
    Given PF11 历史内核的独占实验 VM 接收十五种长度类型与节点字段异常的完整帧
    When 超过二十四字节容量或请求字段非法
    Then 返回 EMSGSIZE 或 EPROTO 且不获取 KVM SRCU 与页面锁
    And 每个处理器的临时页面分配和释放均有配对的真实跟踪事件
    And 同一 VM 仍能注册内存并返回正确页面和已清零的失效确认帧
    And 两台节点的全部线程退出且临时跟踪和防火墙规则恢复

  # evidence: docs/evidence/ssi-request-safety-20261106.json
  @verified @p0
  Scenario: 同页锁等待者可在持锁者等待远端响应时单独取消
    Given PF11 历史内核中的真实处理器持有页面锁并等待受控对端的响应
    And 第二个处理器进入同一页面锁但尚未获得锁
    When 仅向第二个处理器定向发送取消信号
    Then 等待者在五百毫秒内返回 EINTR 并释放 SRCU 和临时页面
    And 等待者没有解锁自己未持有的锁且先于持锁者释放完成退出
    And 随后释放对端响应时持锁者仍返回完整正确页面

  # evidence: docs/evidence/ssi-failure-propagation-20261106.json
  @verified @p0
  Scenario: 请求故障终止本地 VM 并唤醒已建立连接中的等待者
    Given PF16 与 PF17 在两台独占 VM 各运行同一真实 KVM 探针和合成协议对端
    And 本地写入正在等远端页面且另一连接的请求正在等缺失内存槽
    When 注入非法请求类型超长请求或对端断开
    Then PF16 基线仍等待而 PF17 在五百毫秒内向本地写入返回首次错误
    And PF17 的十七个 DSM 线程在探针清理前全部退出
    And KVM_RUN 与 VM 及 vCPU 管理接口均拒绝继续运行故障实例
    And 正常页面响应的写入内容通过校验且管理接口仍可用
    And 清理后才返回的错误不能作为故障传播证据
    And 不把故障停止当作正常关闭握手自动恢复或节点接管

  # evidence: docs/evidence/ssi-failure-propagation-20261106.json
  @verified @p0
  Scenario: 双节点执行错误能传播至 QEMU 并避免递归转储崩溃
    Given 同一 PF17 内核分别搭配旧 QEMU 和故障退出候选运行真实双节点客体
    When 完成 SSH 时钟内存与 SFTP 后向真实 KVM 监听器注入非法请求
    Then 两端保留协议错误与对端断连并向 KVM 执行接口返回错误
    And 旧版递归同步 CPU 状态并段错误的完整记录必须保留
    And 新候选两端返回退出码一且没有同步递归段错误或强制终止
    And 普通单节点回归返回零但双节点正常关闭仍因连接重置而未验收
    And 失败退出不代表客体刷盘数据库恢复自动接管或跨物理机容量相加

  @research @p0
  Scenario: 更多异常事务与内部不变量分支也能安全回收
    Given 事务缓存中的超长响应或超长失效确认或内部页面状态不一致
    When 请求被取消或协议校验失败
    Then 独立故障注入应证明所有 SRCU 和页面锁均被释放
    And 响应复制不能越过实际目标缓冲区且临时页面必须被回收
    And 错误保留给调用者而不伪装为成功

  # evidence: docs/evidence/ssi-teardown-20261106.json
  @verified @p0
  Scenario: 本地 VM 销毁前先停止访问其资源的 DSM 线程
    Given 真实 KVM VM 包含两个 vCPU 内存槽和一个 DSM 半帧连接
    When 对端先关闭连接或本地先关闭 VM
    Then 内核跟踪确认八个接收线程和根线程先全部退出
    And 停止函数返回后才进入 vCPU 和 MMU 销毁
    And 最终释放仍可再次调用停止函数且没有重复的线程退出
    And 跟踪缓冲区与 kprobe 计数都没有丢失事件
    And 临时跟踪事件和防火墙规则均完成清理

  # evidence: docs/evidence/ssi-startup-20261106.json
  @verified @p0
  Scenario: 本地监听失败同步返回并允许在同一空 VM 重试
    Given 独占实验节点上有一个占用 DSM 端口的真实监听器
    When 通过 KVM ioctl 启用 DSM
    Then 返回 EADDRINUSE 而不是异步报告成功
    And 释放端口后在同一个 VM 启用成功并可关闭
    And 真实 QEMU 遇到相同冲突会报告错误并在客体启动前退出

  # evidence: docs/evidence/ssi-startup-20261106.json
  @verified @p0
  Scenario: 无连接的重复启停和参数失败不会遗留监听器
    Given 两台独占实验节点各运行创建空 VM 的真实 KVM 探针
    When 每台节点执行六十四次启用与关闭
    Then 每次关闭后原端口都能由新的监听器绑定
    And 空列表越界节点和过多节点返回 EINVAL
    And 无效用户地址返回 EFAULT
    And 参数失败后同一 VM 可使用有效参数启用并关闭
    And 所有探针退出后没有 DSM 线程残留

  @partial @p0
  Scenario: 重启实验时处理端口占用与监听失败
    Given 上一实例已经退出但 TCP 连接尚未完全回收
    When 尝试再次创建分布式客体
    Then 前置检查拒绝仍占用实验端口的所有 TCP 状态
    And 内核监听失败应向整个实例传播而不留下半启动节点
    And 退出失败的实例无需重置宿主即可完整回收

  @research @p0
  Scenario: 多物理机性能有可重复的负载对照
    Given 实际部署在不同物理机且网络和资源配额明确
    When 运行相同输入的编译内存和磁盘负载
    Then 分别报告单节点与分布式吞吐和尾延迟
    And 区分有用计算传输等待与采样工具开销
    And 不把客体显示更多 CPU 当作性能相加的证据
