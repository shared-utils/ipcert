# ipcert

ZeroSSL IP 证书申请工具。

## 安装

```bash
# 下载最新版本
curl -L -o /usr/local/bin/ipcert \
  https://github.com/shared-utils/ipcert/releases/latest/download/ipcert-linux-amd64

# 添加执行权限
chmod +x /usr/local/bin/ipcert
```

## 使用

```bash
# 确保证书可用（有效期 > 2 天则跳过）
ipcert ensure --zerossl.api-key=YOUR_KEY --public-ips=1.2.3.4

# 强制重新申请证书
ipcert renew --zerossl.api-key=YOUR_KEY --public-ips=1.2.3.4
```

## 参数

| 参数 | 环境变量 | 说明 | 默认值 |
|------|----------|------|--------|
| `--zerossl.api-key` | `ZEROSSL_API_KEY` | ZeroSSL API Key | (必填) |
| `--zerossl.base-url` | `ZEROSSL_BASE_URL` | ZeroSSL API 地址 | `https://api.zerossl.com` |
| `--output-dir` | - | 证书输出目录 | `/etc/ipcert` |
| `--public-ips` | `PUBLIC_IPS` | 公网 IP（逗号分隔） | (必填) |
| `--timeout` | - | 操作超时时间 | `5m` |

## 输出文件

证书文件保存在 `--output-dir` 目录：

- `cert.pem` - 证书
- `chain.pem` - CA 证书链
- `fullchain.pem` - 完整证书链（推荐）
- `privkey.pem` - 私钥

## 注意

ZeroSSL HTTP 验证需要监听 `:80` 端口，确保防火墙允许入站流量。
