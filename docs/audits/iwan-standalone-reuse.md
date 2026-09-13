# iWAN standalone 对照与集成边界

本分支以私有 standalone iWAN 的 Linux 数据面作为性能参考，但不复制其协议实现、认证代码或独立 daemon。线协议仍由 `protocol/iwan` 唯一实现，standalone 只用于验证收发、队列和所有权设计。

## 已复用的设计

- **批量 I/O**：集成版保留 `recvmmsg`/`sendmmsg`，并复用有界 workspace，避免每包建立 `ipv4.Message` 和临时切片。
- **SID 快路径**：服务端按 standalone 的 authenticated SID table 建立不可变快照；正常 DATA 只做无锁 SID + token + remote tuple 校验，SID 冲突回退到受锁 remote map，兼容性优先。
- **队列隔离**：服务端可按 endpoint 配置 `server_socket_readers`，Linux 使用 `SO_REUSEPORT` 为每个 socket 建立一个 ingress reader；控制包不会被单个 reader 的数据处理锁住。默认值为 1，旧内核或不支持 reuse-port 时自动回退。
- **TUN 多队列**：现有 `SINGBOX_IWAN_TUN_QUEUES` 继续按五元组分片，保证同流有序、不同流并行。
- **内存边界**：reader、TUN 和回收路径使用已有的批量缓冲与池，不引入无界 channel 或 per-packet goroutine。

## 明确不直接移植的部分

Rust standalone 的 arena/SPSC 类型不能直接塞进 sing-box：它们依赖独立 daemon 的单所有者状态机，而 sing-box 还要兼容 gVisor、Router、on-demand 生命周期。直接复制会造成第二套 session/关闭语义和不可验证的 ABI 漂移。后续若引入更深的 arena，只能在 `transport/iwan` 的所有权边界内逐步替换，并保留现有回收契约。

## 验收边界

`server_socket_readers=0` 保持单 reader；启用多 reader 后必须通过 `go test -race -tags with_iwan`、Linux 多客户端 OPEN/ECHO/关闭回归和 UDP/TCP 吞吐对照。任何 Linux 不支持 `SO_REUSEPORT`、socket 建立失败或 TUN 队列不足，都只能降级到单 reader/单队列，不能阻止 endpoint 启动或改变 wire bytes。
