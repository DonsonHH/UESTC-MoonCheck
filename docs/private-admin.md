# 私有管理入口

学生端与管理端使用不同监听器。`MOON_SURFACE=public` 的学生服务拒绝 `/admin*`、管理员登录、用户管理及学号授权接口，也不接受管理员会话访问通用账号接口。`MOON_SURFACE=admin` 的私有服务保留原管理员登录和权限检查，禁用学生接入及后台调度线程；两者共享加密数据目录，仅学生服务运行一个后台队列。

部署时将 `compose.admin.yaml` 与其他 compose 文件一同载入。私有服务仅发布主机回环 `127.0.0.1:4497`；不要为它创建 Cloudflare 路由、LAN 绑定或 Tailscale Funnel。管理员通过 Tailscale 上的 SSH 本地转发访问 `http://127.0.0.1:4497/admin`。HTTP 只在回环两端使用，跨机器链路由 SSH/Tailscale 加密。

Windows 可复制 `deploy/admin-ssh.config.example` 为不入库的 `deploy/admin-ssh.config`，填入 Tailscale 地址、SSH 用户、专用私钥和固定主机密钥。服务器 authorized_keys 中对应公钥使用 `restrict,port-forwarding,permitopen="127.0.0.1:4497",command="/bin/false"` 限制，仅允许转发该管理端口，无 shell/终端/agent/X11。固定并验证服务器主机密钥，不跳过校验。

运行 `node deploy/launch-admin.mjs --check` 检查配置。运行 `node deploy/launch-admin.mjs` 可建立受限转发并打开本机管理页面；`--connect-only` 仅建立连接并验证私有接口。桌面快捷方式指向该脚本，保持私钥与实际 SSH 配置在用户目录，不能提交到公开仓库。

每日调度和一次重试的分配规则见 [系统设计](architecture.md)。学校验证与自动任务共享资料，只有公开服务启动调度器，管理端负责账号授权和维护。
