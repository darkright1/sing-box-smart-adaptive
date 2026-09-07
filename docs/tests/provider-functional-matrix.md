# Provider 组合实验测试矩阵

这组测试用于验证多订阅组合、重名节点和动态刷新；只验证功能闭环，不把结果表述为性能基准。测试环境使用隔离 VM117，生产 VM107/115 不改配置。

## 固定输入

从 NAS SubStore 临时读取两个独立源 `xsus1`、`xsus2`，只在测试进程内存中使用响应，不把 URL、查询参数、凭据或订阅内容写入仓库。两源都应能解析为节点列表，并保留原始显示名。

## 用例与验收

| 编号 | 组合 | 验收条件 |
|---|---|---|
| P1 | 单 provider + `include` | 仅匹配节点进入组；启动无 `missing tags`/`tag not found`。 |
| P2 | 两 provider + 同名节点 | 所有成员保留；显示名稳定为原名、`#2`、`#3`；重排源顺序不会更换 endpoint identity。 |
| P3 | `use_all_providers` | 新增/删除 provider 通过回调反映；删除成员不出现在 `All()`，也不能再被拨号。 |
| P4 | provider-only selector/urltest/loadbalance | `outbounds` 为空但 provider 有效时可启动、可列出成员并可选择/测速。 |
| P5 | 删除当前选中成员 | selector 自动回退 default/首个可用成员；旧对象不再被调用。 |
| P6 | 同步回调与关闭竞态 | provider 在注册回调时立即通知不会死锁；关闭后迟到回调无效且所有句柄注销。 |
| P7 | tag miss | 不存在的显式 provider 返回带索引和 tag 的错误；不会留下半发布 membership。 |
| P8 | 过滤与重复刷新 | `include/exclude` 在缓存和刷新路径一致；未变化 provider 不重复调用 `Outbounds()`。 |

## 执行门

先运行：

```sh
go test ./protocol/group ./adapter/provider
go test -race ./protocol/group ./adapter/provider
```

再在 VM117 用当前 Linux 构建加载临时配置，确认 provider 组实际 `All()`、选择和删除回调；只允许使用临时端口和临时运行目录。GitHub Actions 使用 `release-linux.yml` 手动运行并将 `publish_release=false`，仅上传 Actions Artifact，不创建公开 Release。全部用例通过后才可提出生产部署申请。
