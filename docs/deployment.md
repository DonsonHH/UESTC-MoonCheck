# 部署与维护

## 准备

使用 Docker 和 Compose v2。先复制 `.env.example` 为 `.env`，设置学生端 HTTPS 地址，以及宿主机写入数据目录的用户与组 ID。Linux 可用 `id -u`、`id -g` 查询，填入 `PUID`、`PGID`；让 `data/` 属于对应用户。

`MOON_BROWSER_ASSIST_KEY` 使用至少 32 字节随机数据生成的密钥，保存在私有 `.env`。主应用和 helper 共用它，仅在 Docker 内网传递。学校账号由用户通过网页绑定，不写进配置文件。

## 构建与启动

```sh
mkdir -p data
docker build -t moonuestc-local:student-portal .
docker build -t moonuestc-browser:local browser_assist

docker compose -f compose.yaml -f compose.browser.yaml -f compose.admin.yaml run --rm moonuestc init-admin
docker compose -f compose.yaml -f compose.browser.yaml -f compose.admin.yaml up -d
```

helper 默认基于上一步主镜像；改用其他标签时传入 `--build-arg MOON_APP_IMAGE=实际主镜像标签`。首次初始化通过交互输入管理员密码。

学生端回环端口由 `MOON_PORT` 设置，默认 8088；HTTPS 代理只转发这个端口。`MOON_PUBLIC_URL` 必须与浏览器实际地址一致。只将已知反向代理网段填入 `MOON_TRUSTED_PROXY_CIDRS`。

`MOON_PUBLIC_URL` 使用 HTTPS 时，HTTP 页面、API 和回调请求会先以 308 跳转到该 HTTPS 来源，保留路径与参数。应用只信任 `MOON_TRUSTED_PROXY_CIDRS` 中实际连接方的协议标记；Cloudflare Tunnel 使用 `X-Forwarded-Proto` 或 `CF-Visitor` 的原始访客协议。Waitress 默认清理标准代理头时，后者仍可供可信连接核验。不要将所有来源都加入可信代理，否则可能允许伪造协议。

容器内回环 `/healthz` 继续提供健康检查；SSH/Tailscale 私有管理端按独立的回环来源运行。公开端口仍只绑定主机回环，不需要新开公网端口或修改其他域名。

管理端默认绑定 `127.0.0.1:4497`，通过 [私有管理转发](private-admin.md) 访问；不创建公开管理路由。helper 无宿主机公开端口。

## 微信操作票据

需要新版自动提交时，在私有 `.env` 设置 `MOON_ENABLE_WECHAT_AUTH=1`，重新构建并更新主应用和管理应用。每位学生仍需在 `/app/authorization` 确认说明并完成本人的扫码授权；不能用一个人的授权代替其他学校身份。

该模块通过微信和应用宝服务获取真实登录码，再向学校申请短期操作票据，无需部署完整微信客户端或额外 Go 服务。出网需能访问微信开放平台、应用宝授权服务及微信协议服务。授权标识、访问令牌和刷新令牌保存在原账户的 AES-GCM 密文中，继续使用原 `data/dashboard.key`，更新时保留完整 `data/` 与配套密钥。

授权失效时等待本人重新扫码。学校登录认证、现场围栏、执行时段和防重复提交保护保持独立；新增授权不清除已有的提交记录或学校认证保护。

## 用户范围与区域

`MOON_STUDENT_ID_PREFIX` 非空时，允许该前缀加两位数字的学号。管理员可在用户管理中单独增加授权；增加授权仍需本人学校验证。

`MOON_ALLOWED_PRESETS` 选择开放的组团，示例配置开放二、五、八组团。最终仍使用每个账号自己的校方围栏。`MOON_RUN_WINDOW` 默认为 `21:06,23:24`，与学校实时开放窗口共同生效。

## 更新与恢复

1. 确认没有排队或运行中的任务，停止两个应用服务。
2. 成对备份 `data/` 全目录与 `.env`、Compose 配置，包含数据库及 `dashboard.key`。密钥和密文必须来自同一快照。
3. 在新源码目录构建镜像，用备份副本在无网络容器中验证恢复与预期迁移。
4. 切换镜像并确认健康检查、学生登录页、私有管理端和数据摘要，保留旧镜像及成对备份。
5. 如需回滚，停服务后保留失败数据副本，再恢复配套数据、密钥和配置。

容器使用非 root 用户、只读根文件系统、临时目录和资源限制。公开端运行一个调度器，管理端不启动调度器。例行认证、密码、Cookie 与个人资料不进入公开日志。

后台密码重试保护按最近一次成功校验后的连续未确认尝试计算，三次后暂停；成功登录不再累计耗尽重试预算。原始每日计数和签到防重复记录保留。学校验证码、二次验证或密码拒绝仍需本人更新学校验证。管理端读取名单只复用现有会话，不提交学校密码。
