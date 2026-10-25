# 发布前隐私检查

发布检查覆盖源码工作区、拟推送提交的完整 Git 历史、所有 Release 资产、镜像配置和每个历史文件层。命中敏感内容、检查器不可用、生产隐私清单读取失败、格式不受支持或摘要不一致时，检查返回失败，后续上传停止。

## 本地推送和 Release 上传

维护者首次在自己的源码检出中执行：

    python scripts/release_guard.py install --host YOUR_SSH_HOST --container YOUR_CONTAINER

SSH 使用维护者自己的既有认证，命令不接收学校密码或 Cookie。配置仅写入本机仓库的 Git 配置，新的检出需要重新安装。安装后常规 git push 在传送对象前执行 pre-push 检查。

每次检查通过只读 SSH 和容器 exec 读取当前维护实例的数据库及加密密钥，在内存中解密学校账号和 Cookie 以生成本次匹配值；不调用应用存储初始化、不写数据库、不创建任务、不重启容器。网页模式的可选 CLI 配置文件存在时一并检查，未创建时无需生成。敏感值只经 SSH 加密会话进入本地检查进程内存，不写清单文件、报告或 GitHub Secrets。检查结束进程退出，下一次重新读取。

GitHub Release 创建、资产上传和发布应通过同一个受保护入口：

    python scripts/guarded-publish.py --ref vX.Y.Z --artifact-list /private/release/asset-list.json -- gh release upload vX.Y.Z FILES

asset-list.json 放在仓库外，是本次所有公开文件绝对路径的 JSON 数组，包含源码、部署包、镜像、校验文件、说明及验收报告。也可用多个 --artifact 参数。受保护入口检查通过后才运行实际上传命令；命中内容或无法检查时不会执行该命令。维护者既有发行 API 助手也使用此检查器，覆盖所有写请求及请求内容。

查看不含敏感值的检查结果：

    python scripts/release_guard.py check --ref HEAD --artifact-list /private/release/asset-list.json

生产实例不可访问、账号 Cookie 损坏或必需的数据库、密钥不可用时，发布停止；应先恢复检查条件，不要跳过检查继续上传。

## GitHub Actions

公开 CI 只做合成泄漏测试和全部源码历史检查，不向 GitHub 提供生产数据库、密钥或私有清单。实际推送还在维护者本地读取当前实例的匹配值，检查通过后才传输 Git 对象。仓库不携带旧版自动 GHCR 发布流程。
