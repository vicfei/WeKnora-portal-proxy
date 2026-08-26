# WeKnora-portal-proxy（B1 路线 POC）

独立门户代理服务：持有「用户↔知识库」权限表，经 tenant-key API 通道调用 WeKnora，
逐请求按用户过滤后呈现。WeKnora fork（vicfei/WeKnora）**零代码改动**，所有对接均为运行时配置。

## 架构位置

```
浏览器 ──> 公司门户/本代理(:8081) ──> WeKnora app(:8080, tenant key + signed_token)
                │
                └── 权限表（独立数据库 portal_proxy，不进 WeKnora 库）
```

## 纪律（POC 期间必须遵守）

1. WeKnora 仓库零接触：若发现必须改 WeKnora 代码才能继续，立即停下重新评估路线；
2. 权限表建在独立数据库（建议 `portal_proxy`），POC 结束一条 `DROP DATABASE` 清场；
3. tenant key 能力最小化（仅 retrieve/ingest/chat，不发放 full access）；
4. 测试数据使用 `REVIEW-` 前缀工号，不触碰演示数据（租户 10003 / DEMO9001）。

## POC 验收剧本（与 v2 路线共用同一考题）

登录（桩）→ 分组 KB 列表 → KB 检索 → SSE 聊天（带引用）→ 上传文档 → 越权验证（A 访问 B 的 KB 必须被拒）

## 状态

骨架初始化，无业务逻辑。模块规划见 .context 讨论（cmd/proxy 入口、internal/ 分层）。
