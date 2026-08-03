# system_check.sh — Linux 自动化运维巡检脚本

一个面向 Linux 服务器的自动化巡检脚本，覆盖系统基础信息、性能、磁盘、网络、应用服务（主机 + Docker）、SSL 证书、日志、安全账号、时间同步等 10 大项检查。任何单项检查失败都不会中断整个巡检（失败则记录并继续下一项）。

> 本仓库为**通用公开版**（`linux_system_check.sh`），已移除内部业务专属的检测项，可直接用于任意 Linux 服务器的通用巡检。

## 功能总览

| 编号 | 巡检项 | 说明 |
|------|--------|------|
| [1] | 基础信息 | 主机名、IP、OS、CPU、内存、磁盘、网卡、登录记录 |
| [2] | 系统性能 | CPU 使用率、内存、Swap、IOWait、网络流量、进程 |
| [3] | 磁盘文件系统 | 分区使用率、inode、只读挂载、内核错误、挂载点、smartctl |
| [4] | 网络 | 网卡、连通性、端口、防火墙、连接统计、主机名解析 |
| [5] | 应用服务（主机） | MySQL/Redis/Nginx/ActiveMQ/ES 等常见服务进程与端口 |
| [6] | 应用服务（Docker） | docker ps 概览 + 按镜像名/容器名/端口识别容器内服务 |
| [7] | SSL 证书 | 从 nginx/httpd 配置提取证书路径，计算过期倒计时 |
| [8] | 日志巡检 | 自定义路径 + 自动发现 + journalctl（默认关闭，见配置） |
| [9] | 安全与账号 | root 登录限制、空/弱口令、sudo 权限、登录 IP、SELinux、入侵迹象 |
| [10] | 时间同步 | 系统时间、NTP 服务（chronyd/ntpd/timesyncd 自适应）、时间偏差 |

## 使用方法

```bash
# 添加执行权限
chmod +x linux_system_check.sh

# 直接运行（普通用户即可，部分检查自动尝试 sudo）
./linux_system_check.sh

# 建议以 root 运行，可获取最完整的巡检结果
sudo ./linux_system_check.sh
```

运行完成后，巡检日志输出到 `LOG_DIR`（默认 `/var/log/system_check/`，不可写时自动回退到当前目录 `./logs/`）。

## 配置开关（脚本头部配置区）

脚本顶部有集中配置区，可按需调整：

| 配置项 | 默认值 | 说明 |
|--------|--------|------|
| `LOG_DIR` | `/var/log/system_check` | 日志输出目录 |
| `CUSTOM_LOG_PATHS` | （空数组） | 自定义业务日志路径，[8] 优先巡检 |
| `ENABLE_LOG_INSPECTION` | `0` | 日志巡检开关，1=开启（输出较冗余） |
| `SHOW_DMESG_ERRORS` | `0` | 是否显示 dmesg 文件系统错误提示（默认关） |
| `SHOW_MOUNT_INFO` | `0` | 是否显示当前挂载点信息（默认关） |
| `SSL_WARNING_DAYS` | `30` | SSL 证书剩余天数低于此值时告警 |
| `LOG_SEARCH_MAX_AGE_DAYS` | `7` | 自动发现日志的最近修改天数 |

## 设计要点

- **不卡住**：刻意不使用 `set -e`/`set -u`，所有可能失败的命令都用 `|| true` / if 条件兜底，任何单项检查失败都记录后继续；
- **权限自适应**：root → sudo -n → 普通命令三档权限自动探测；
- **兼容性**：CentOS 6/7/8、Ubuntu、Debian 等主流发行版；sed 使用 `-r`（兼容 CentOS 7 的 GNU sed 4.2）。

## 目录结构

```
.
├── linux_system_check.sh   # 主巡检脚本（通用公开版）
├── README.md
└── .gitignore
```

> 历史版本备份位于 `bak/`，未纳入本仓库管理。
