# 更新记录

## 0.5.1+donson.20

- 同步评估 Ryan-Orion/UESTC-MoonCheck 的 `main` 至 `6f14a3a`，移植适用于部署版的 CAS 错误诊断。
- CAS 429／5xx 保持为临时服务故障，不再误报为密码错误并暂停账号；保留脱敏后的校方业务码和可见错误提示。
- 核验既有手动／自动重试隔离与分阶段成功提示，保留同日防重复提交规则。
- README 明确当前授权方案的 Ryan-Orion 上游来源及部署分支用途。

## 0.5.1+donson.19

- 撤销微信授权时同时取消未完成扫码；旧扫码不能覆盖后来更新或撤销的授权。
- 管理员撤销额外学号访问授权时同步暂停托管，排队任务不会继续联系学校；保留计划和历史。
- 初次扫码必须取得可续期凭据，避免短期授权被误报为可供每日执行。
- 发布隐私检查覆盖微信令牌和身份标识；GitHub 检查增加完整应用回归测试。
- 验证一次扫码后的跨天续期、令牌轮换持久化、服务重建、退出网站和学校二次验证暂停路径。

## 0.5.1+donson.18

- 接入 UESTC-MoonCheck 的应用宝授权和 Python 小程序登录码协议，在现有账号下提供本人微信扫码授权。
- 每次提交申请新学校操作票据，核对微信与学校登录身份；保留每日计划、历史和防重复提交保护。
- 无需完整微信客户端或 Windows 执行端；仅加密保存明确同意托管的应用授权，失效时提示重新验证。

## 0.5.1+donson.17

- Identify school mini-program operation authorization errors (46001/46002/46003) separately from password verification and uncertain delivery.
- Suspend unsupported submissions across accounts, restarts and days; retain existing plans and no-repeat claims. Official completion can be synchronized using read-only school records.
- Explain existing rejected submissions without rewriting historical jobs. Both dashboards show the official entry requirement, and expired read sessions prompt owner verification without unattended credential retries.

## 0.5.1+donson.16

- 重整首次使用、等待计划、今日完成和异常恢复的首页流程。
- 偏好时间前后五分钟每日随机，再加入秒级错峰；位置浮动半径改为 10 米。
- 桌面、平板、手机与宽屏采用流式布局，托管说明统一到同一数据源。
- 删除旧控制台、独立注册、旧安装发布流程及过期生成快照，重写项目文档。

## 0.5.1+donson.15

- 默认跟随系统的浅深色外观。
- 近期记录与按需加载全部历史。

## 0.5.1+donson.14

- 本人参与的学校认证恢复，停止后台验证码循环。

更早的演进和上游代码保留于 Git 历史，许可见 LICENSE 与 THIRD_PARTY_NOTICES.md。
