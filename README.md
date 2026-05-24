# dnsproxy-unlock

基于 AdGuard dnsproxy 的在线规则 DNS 分流解锁脚本。

脚本会自动安装和配置 `dnsproxy`，并从在线 Clash 规则源拉取域名规则，将 `DOMAIN` / `DOMAIN-SUFFIX` 规则转换为 AdGuard dnsproxy 支持的上游分流格式：

```txt
[/example.com/]https://your-unlock-dns/doh
```

适合用于按域名将 YouTube、Netflix、ChatGPT、Claude、Gemini 等服务的 DNS 查询转发到指定解锁 DNS / DoH，上游规则可在线更新，不需要在本地手动维护大量域名列表。

---

## 功能特点

- 自动安装 / 更新 AdGuard dnsproxy
- 支持在线规则源
- 支持 Clash `.list` 规则转换
- 支持 `DOMAIN` / `DOMAIN-SUFFIX`
- 自动忽略 `IP-CIDR`、`IP-CIDR6`、`DOMAIN-KEYWORD` 等不适合 dnsproxy 的规则
- 支持自定义规则链接
- 支持自定义解锁 DNS / DoH 上游
- 支持普通 IPv4 DNS，例如 `1.1.1.1`
- 支持 DoH / DoT / DoQ / TCP DNS / UDP DNS
- 支持 systemd 开机自启
- 支持 systemd timer 自动更新规则
- 支持测试 DNS 解析
- 支持卸载和恢复系统 DNS

---

## 推荐获取解锁 DNS

本脚本不内置任何默认解锁 DNS / DoH。

请自行从 DNS 解锁服务商获取解锁上游地址。

推荐平台：

```txt
https://dns.akile.ai/
https://gaidns.com/
```

支持输入的上游格式示例：

```txt
https://example.com/doh
1.2.3.4
1.2.3.4:53
tls://example.com
quic://example.com
tcp://1.2.3.4
udp://1.2.3.4
```

注意：

```txt
1.1.1.1、8.8.8.8 这类普通公共 DNS 可以作为 dnsproxy 上游，
但它们不是解锁 DNS，不能用于流媒体解锁。
```

---

## 一键下载并运行

推荐使用下面命令下载脚本并运行：

```bash
curl -fsSL -o dnsproxy-unlock.sh https://raw.githubusercontent.com/pjy02/dnsproxy-unlock./refs/heads/main/dnsproxy-unlock.sh && chmod +x dnsproxy-unlock.sh && sudo ./dnsproxy-unlock.sh
```

或者使用 `wget`：

```bash
wget -O dnsproxy-unlock.sh https://raw.githubusercontent.com/pjy02/dnsproxy-unlock./refs/heads/main/dnsproxy-unlock.sh && chmod +x dnsproxy-unlock.sh && sudo ./dnsproxy-unlock.sh
```

---

## 使用流程

首次使用建议按这个顺序操作：

```txt
1. 安装 / 更新 dnsproxy
3. 在线规则分组管理
   -> 添加内置在线规则链接
   -> 选择 YouTube
   -> 输入你的解锁 DNS / DoH
4. 更新并转换在线规则
5. 启动 / 重启 dnsproxy
9. 测试域名解析
7. 应用系统 DNS 到 127.0.0.1
```

---

## 快速说明

运行脚本后会看到菜单：

```txt
AdGuard dnsproxy 在线规则 DNS 分流解锁脚本

1. 安装 / 更新 dnsproxy
2. 配置普通默认 DNS
3. 在线规则分组管理
4. 更新并转换在线规则
5. 启动 / 重启 dnsproxy
6. 停止 dnsproxy
7. 应用系统 DNS 到 127.0.0.1
8. 恢复系统 DNS 备份
9. 测试域名解析
10. 查看状态
11. 查看日志
12. 预览生成的 upstream 规则
13. 查看被忽略的规则
14. 启用规则自动更新
15. 禁用规则自动更新
16. 卸载 dnsproxy
0. 退出
```

---

## 添加在线规则分组

进入菜单：

```txt
3. 在线规则分组管理
```

可以选择：

```txt
1. 添加内置在线规则链接
2. 添加自定义在线规则链接
3. 删除规则分组
4. 更新并转换在线规则
```

内置示例规则：

```txt
YouTube
```

规则来源：

```txt
https://raw.githubusercontent.com/blackmatrix7/ios_rule_script/refs/heads/master/rule/Clash/YouTube/YouTube.list
```

---

## 自定义规则源格式

规则源配置文件路径：

```txt
/opt/dnsproxy/rule-sources.conf
```

格式：

```txt
分组名|规则URL|解锁DNS或DoH上游
```

示例：

```txt
YouTube|https://raw.githubusercontent.com/blackmatrix7/ios_rule_script/refs/heads/master/rule/Clash/YouTube/YouTube.list|https://your-unlock-dns/doh
```

也可以使用普通 DNS IP：

```txt
YouTube|https://raw.githubusercontent.com/blackmatrix7/ios_rule_script/refs/heads/master/rule/Clash/YouTube/YouTube.list|1.2.3.4:53
```

---

## 规则转换说明

脚本会保留以下规则：

```txt
DOMAIN,example.com
DOMAIN-SUFFIX,example.com
```

转换为：

```txt
[/example.com/]https://your-unlock-dns/doh
```

脚本会忽略以下规则：

```txt
DOMAIN-KEYWORD
DOMAIN-WILDCARD
IP-CIDR
IP-CIDR6
IP-ASN
GEOIP
PROCESS-NAME
USER-AGENT
URL-REGEX
DST-PORT
```

原因是这些规则不适合直接转换为 dnsproxy 的域名上游分流规则。

---

## 生成的 dnsproxy 规则文件

生成后的规则文件路径：

```txt
/opt/dnsproxy/upstream.txt
```

示例内容：

```txt
[/youtube.com/]https://your-unlock-dns/doh
[/googlevideo.com/]https://your-unlock-dns/doh
[/ytimg.com/]https://your-unlock-dns/doh
```

---

## dnsproxy 服务

systemd 服务文件：

```txt
/etc/systemd/system/dnsproxy.service
```

常用命令：

```bash
sudo systemctl status dnsproxy
sudo systemctl restart dnsproxy
sudo systemctl stop dnsproxy
sudo journalctl -u dnsproxy -f
```

---

## 自动更新规则

脚本支持创建 systemd timer 自动更新在线规则。

在菜单中选择：

```txt
14. 启用规则自动更新
```

查看定时器：

```bash
systemctl list-timers | grep dnsproxy
```

手动更新规则：

```bash
sudo /opt/dnsproxy/update-rules.sh
```

---

## 测试解析

脚本内置测试功能：

```txt
9. 测试域名解析
```

也可以手动测试：

```bash
dig youtube.com @127.0.0.1
```

查看完整结果：

```bash
dig youtube.com @127.0.0.1
dig googlevideo.com @127.0.0.1
dig baidu.com @127.0.0.1
```

---

## 系统 DNS 设置

如果希望当前服务器使用 dnsproxy 作为系统 DNS，可以在菜单中选择：

```txt
7. 应用系统 DNS 到 127.0.0.1
```

脚本会修改：

```txt
/etc/resolv.conf
```

并备份原文件到：

```txt
/etc/resolv.conf.bak.dnsproxy
```

恢复 DNS：

```txt
8. 恢复系统 DNS 备份
```

---

## 注意事项

### 1. 不要把普通 DNS 当成解锁 DNS

例如：

```txt
1.1.1.1
8.8.8.8
9.9.9.9
```

这些可以作为普通上游 DNS，但不是解锁 DNS。

要实现解锁，需要填写 DNS 解锁服务商提供的上游地址。

---

### 2. 如果 53 端口被占用

可以查看：

```bash
ss -lntup | grep ':53'
```

如果被 `systemd-resolved`、`dnsmasq`、`named` 等占用，dnsproxy 可能无法启动。

脚本会在启动时检测并提示处理。

---

### 3. Docker 容器不一定自动生效

如果服务运行在 Docker 容器里，容器内的 `127.0.0.1` 不是宿主机。

这种情况下需要额外配置 Docker DNS，或者让 dnsproxy 监听宿主机网桥地址。

---

### 4. 不建议直接对公网开放 53 端口

默认监听地址是：

```txt
127.0.0.1
```

也就是只允许本机使用。

如果你改成：

```txt
0.0.0.0
```

一定要配合防火墙限制来源 IP，避免变成公开 DNS 服务器。

---

## 卸载

运行脚本后选择：

```txt
16. 卸载 dnsproxy
```

卸载内容包括：

```txt
/opt/dnsproxy
/etc/systemd/system/dnsproxy.service
/etc/systemd/system/dnsproxy-rule-update.service
/etc/systemd/system/dnsproxy-rule-update.timer
```

卸载时可以选择是否恢复 `/etc/resolv.conf` 备份。

---

## 免责声明

本项目仅用于 DNS 分流和自用网络解析配置。

请确保你使用的 DNS / DoH 上游来源可信。

DNS 解锁效果取决于你使用的解锁服务商，本脚本不提供任何解锁 DNS 服务。
