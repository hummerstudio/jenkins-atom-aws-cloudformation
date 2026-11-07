# jenkins-atom-aws-cloudformation

创建或更新 CloudFormation 堆栈，并等它稳定下来。

CloudFormation 用的是老的 Query 协议（表单编码 + `Action` 参数 + XML 回包），不是 JSON。看起来不时髦，
但很稳，而且只需要一个签名器。

两个行为比调用本身重要：

- **无变更的更新是成功**：AWS 会回 `No updates are to be performed`，这里报 `action=noop` 而不是失败
- **回滚要红**：堆栈最终落在 `ROLLBACK_COMPLETE` / `*_FAILED` 时步骤失败，并带上 `StackStatusReason`——
  回滚了还报绿，是坏包上线最常见的方式

```bash
mvn verify
```

假端点自己复算 SigV4，并且维护一个小状态机：第一次调用走创建，第二次走更新，无变更时回 AWS 的原话。
