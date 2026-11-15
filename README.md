# BiliTV Relay

面向电视/盒子客户端的 B 站接口中转服务，提供设备授权、账号池、画质选择、分地区代理出口、管理面板和公开状态页。

> 本仓库只包含可公开的程序代码。生产数据、会员 Cookie、设备信息、管理密码、日志和 TLS 私钥不会提交。

## 功能

- 多端口上游分流：`api / app / passport / account / bangumi / member`
- 设备授权：手动放行、自助授权码、自动放行和黑名单
- 会员账号池：扫码、短信和 Cookie 导入
- 游客、隐藏身份、完整身份三种共享模式
- 4K、1080P和客户端跟随画质模式
- CN/HK/TW/TH/默认五组 HTTP、HTTPS、SOCKS 代理出口
- 请求、设备、账号和缓存限流
- 管理面板、设备授权页和公开只读状态页
- 日志轮转与敏感查询参数脱敏

## 运行要求

- Node.js 20或更高版本
- Nginx（生产环境推荐）
- Linux/systemd（可选）

## 快速开始

```bash
git clone https://github.com/maoaceo/bilitv.git
cd bilitv
npm ci
BIND=127.0.0.1 PORT=8601 npm start
```

首次启动会在项目目录生成：

- `data.json`：设备、账号和配置状态，包含敏感信息
- `admin-password.txt`：初始后台密码
- `logs/`：运行日志

这些文件已在 `.gitignore` 中排除。请将目录权限设为仅服务用户可读。

本机测试：

```bash
npm test
```

## 端口

默认端口映射：

```text
8601 -> api
8602 -> app
8603 -> passport
8604 -> account
8605 -> bangumi
8606 -> member
```

可通过环境变量覆盖：

```bash
PORT=8601
BIND=127.0.0.1
PORT_MAP=8601:api,8602:app,8603:passport,8604:account,8605:bangumi,8606:member
```

完整示例见 `.env.example`。

## 页面

服务启动后：

- 管理面板：`/panel`
- 设备授权页：`/auth`
- 公开状态页：`/status`
- 状态JSON：`/status-api`

公开状态接口只返回请求数、授权设备数、上游延迟和运行时间等汇总指标，不返回设备标识、IP、账号或 Cookie。

## 生产部署

1. 创建专用服务用户：

```bash
sudo useradd --system --home /opt/bili-relay --shell /usr/sbin/nologin bili-relay
sudo mkdir -p /opt/bili-relay
sudo chown -R bili-relay:bili-relay /opt/bili-relay
```

2. 将代码部署到 `/opt/bili-relay` 并执行：

```bash
sudo -u bili-relay npm ci --omit=dev
```

3. 安装 `deploy/bili-relay.service`，按需调整路径后启用：

```bash
sudo cp deploy/bili-relay.service /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable --now bili-relay
```

4. 参考 `deploy/nginx.example.conf` 配置域名和TLS证书。

生产环境请保持Node只监听 `127.0.0.1`，不要直接把8601～8606暴露到公网。

## 数据备份

需要备份的生产文件：

```text
data.json
admin-password.txt
```

备份中含会员Cookie和设备信息，必须加密保存，禁止上传到Git仓库或公开网盘。

## 安全说明

- 不要提交 `data.json`、数据库、日志、密码文件和TLS私钥。
- 仅通过Nginx向公网提供80/443端口。
- 管理面板建议使用独立域名并限制访问来源。
- 代理配置可包含账号密码，分享配置前务必清理。
- 修改代码后运行 `npm test` 和 `node --check server.js`。

## 项目结构

```text
server.js                  主服务
proxy-routing.js           分地区代理选择与凭据脱敏
device-identity.js         设备身份合并辅助逻辑
status-metrics.js          公开状态指标净化
public/index.html          管理面板
public/auth.html           设备授权页
public/status.html         公开状态页
deploy/                    systemd和Nginx示例
test/                      Node内置测试
```

## License

[ISC](LICENSE)
