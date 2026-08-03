#!/bin/bash
# =====================================================
# 说明（重要）：
#   本脚本刻意不使用 set -e（errexit）与 set -u（nounset）。
#   原因：这是巡检脚本，最高优先级是"任何单项检查失败都不中断整个巡检"，
#   失败项应记录到日志后继续检查下一项。
#   - 若开启 errexit：命令替换/管道/嵌套函数里某处返回非零就会导致脚本"卡住/中途退出"，
#     这正是早期版本在 SSL/SSH 等处莫名中断的根源（如 pgrep 无匹配、grep 无命中）。
#   - 若开启 nounset：遇到只在特定分支赋值的变量时，未定义即直接退出，同样有中断风险。
#   因此仅保留 pipefail（管道中任一命令失败即视为整条管道失败），
#   同时所有"可能失败"的命令都显式用 || true / if 条件判断兜底。
# =====================================================
set -o pipefail

# =====================================================
# 文件名: system_check_public.sh
# 描述: Linux 系统自动化运维巡检脚本（通用公开版）
#       覆盖：基础信息 / 系统性能 / 磁盘文件系统 / 网络 /
#             应用服务（主机 + Docker 容器） / SSL 证书 / 日志巡检
# 用法: ./system_check_public.sh
# 兼容: CentOS 6/7/8、Ubuntu、Debian 等 Linux 发行版
# 说明: 任何单项检查失败都不会中断整个巡检（失败则记录并继续下一项）
# 说明: 本文件为公开通用版本，已移除内部业务相关的专属检测项
# =====================================================

# =====================================================
# 函数总览（按调用顺序）：
#   init                         初始化日志目录/文件、探测权限模式
#   check_basic_info             [1] 基础信息（主机名/IP/OS/CPU/内存/磁盘/网卡/登录记录）
#   check_system_performance     [2] 系统负载与性能（CPU/内存/Swap/IOWait/网络流量/进程）
#   check_disk_filesystem        [3] 磁盘与文件系统（分区/inode/只读/错误/挂载/smartctl）
#   check_network                [4] 网络（网卡/连通性/端口/防火墙/连接统计/主机名解析）
#   check_app_services_host      [5] 应用服务巡检 - 主机（MySQL/Redis/Nginx/ActiveMQ/ES）
#   check_app_services_docker    [6] 应用服务巡检 - Docker 容器（按镜像名/容器名/端口识别）
#   check_ssl_certificate_expiry [7] SSL 证书过期检查（nginx/httpd 配置 + 常见证书目录）
#   check_log_inspection         [8] 日志巡检（自定义路径 + 自动发现 + journalctl）
#   check_security_accounts      [9] 安全与账号巡检（root登录/空弱口令/sudo/登录/SELinux/入侵迹象）
#   check_time_sync              [10] 时间同步巡检（系统时间/NTP服务/时间偏差）
# =====================================================

# --- 1. 配置区 ---
# LOG_DIR: 日志目录，默认写入 /var/log/system_check，可通过环境变量覆盖
# TIMESTAMP: 用于生成唯一日志文件名
# LOG_FILE: 最终日志文件路径
LOG_DIR="${LOG_DIR:-/var/log/system_check}"
TIMESTAMP=$(date +%Y%m%d_%H%M%S)
LOG_FILE="${LOG_DIR}/check_${TIMESTAMP}.log"

# 阈值配置（后续可以根据需要扩展为报警阈值）
CPU_THRESHOLD=80
MEMORY_THRESHOLD=80
DISK_THRESHOLD=80
LOAD_THRESHOLD=10
SSL_WARNING_DAYS=30

# 是否显示文件系统错误提示 (dmesg)：又臭又长，默认不显示。
# 1=显示 dmesg 错误段；0=不显示（默认）。需要排查存储/磁盘问题时临时开启。
SHOW_DMESG_ERRORS=0

# 是否显示当前挂载点信息 (findmnt/mount)：日常巡检大部分时间不用管，默认不显示。
# 1=显示挂载点列表；0=不显示（默认）。需要排查磁盘/挂载问题时临时开启。
SHOW_MOUNT_INFO=0

# 需要检查的服务、Ping 目标、外网目标、重点分区
SERVICES=("sshd" "nginx" "mysqld")
PING_TARGETS=("8.8.8.8" "114.114.114.114")
EXTERNAL_HOST="www.baidu.com"
MOUNT_POINTS=("/" "/var" "/home" "/boot")

# 日志巡检开关：1=开启，0=关闭（默认关闭）。日志巡检输出冗余，建议仅在排查问题时临时开启
ENABLE_LOG_INSPECTION=0

# 公司/业务自定义日志路径（可在此追加具体路径，脚本会优先巡检这些文件）
CUSTOM_LOG_PATHS=(
    # /home/app/logs/app.log
    # /opt/myapp/logs/gateway.log
)

# 自动发现日志时搜索的根目录（会在这些目录下递归找近期被修改的 *.log 文件）
LOG_SEARCH_ROOTS=("/var/log" "/opt" "/home" "/usr/local" "/app" "/data" "/data/logs" "/data/app" "/opt/logs" "/opt/app")
# 自动发现时每个根目录最多采样的日志文件数（避免日志过多导致脚本卡顿）
LOG_SEARCH_MAX_PER_ROOT=5
# 自动发现时只看最近 N 天内修改过的日志文件
LOG_SEARCH_MAX_AGE_DAYS=3

# 默认 Docker 命令，如果普通用户无法直接访问 Docker daemon，
# check_app_services_docker() 会尝试切换到 sudo docker
DOCKER_CMD=(docker)

# 权限提升配置：脚本优先使用 root；若当前为普通用户，则尝试 sudo -n 进行提权
PRIVILEGE_MODE="none"
SUDO_CMD=()

cmd_exists() {
    # 检查指定命令是否可用
    command -v "$1" >/dev/null 2>&1
}

is_root() {
    [ "$(id -u 2>/dev/null)" = "0" ]
}

setup_privilege_mode() {
    # 若当前是 root，直接使用 root 权限；否则尽量通过 sudo -n 提权
    if is_root; then
        PRIVILEGE_MODE="root"
        SUDO_CMD=()
        return 0
    fi

    if cmd_exists sudo && sudo -n true >/dev/null 2>&1; then
        PRIVILEGE_MODE="sudo"
        SUDO_CMD=(sudo -n)
        return 0
    fi

    PRIVILEGE_MODE="limited"
    SUDO_CMD=()
    return 1
}

setup_docker_command() {
    # 优先使用当前用户直接访问 Docker daemon，如果失败则尝试 sudo（非交互模式）
    if ! cmd_exists docker; then
        return 1
    fi

    if docker info >/dev/null 2>&1; then
        DOCKER_CMD=(docker)
        return 0
    fi

    if [ "${#SUDO_CMD[@]}" -gt 0 ]; then
        if "${SUDO_CMD[@]}" docker info >/dev/null 2>&1; then
            DOCKER_CMD=("${SUDO_CMD[@]}" docker)
            return 0
        fi
    fi

    DOCKER_CMD=(docker)
    return 1
}

run_and_log() {
    # 执行命令并将其标准输出追加到日志文件。
    # 即使命令返回非零，也继续执行后续检查，避免某个单项探测失败中断整个巡检。
    # 说明：本脚本默认不开启 errexit（见文件头注释）。
    #       此处仍保留 errexit 状态保存/恢复逻辑作为防御性代码，
    #       即使将来有人重新加上 set -e，也不会因本函数而意外中断巡检。
    local _saved_errexit
    if [ -o errexit ]; then _saved_errexit=1; else _saved_errexit=0; fi
    set +e
    local rc=0
    if [ "$#" -gt 0 ]; then
        "$@" 2>/dev/null | while IFS= read -r line; do
            echo "$line" | tee -a "$LOG_FILE"
        done
        rc=${PIPESTATUS[0]:-0}
    fi
    if [ "$_saved_errexit" -eq 1 ]; then
        set -e
    fi
    if [ "$rc" -ne 0 ]; then
        echo "[WARN] 命令执行返回非零状态: $*" >> "$LOG_FILE"
    fi
    return 0
}

run_and_log_privileged() {
    # 在具备权限时优先调用 sudo -n 提权；否则按普通命令执行
    if is_root; then
        run_and_log "$@"
    elif [ "${#SUDO_CMD[@]}" -gt 0 ]; then
        run_and_log "${SUDO_CMD[@]}" "$@"
    else
        run_and_log "$@"
    fi
}

log() {
    # 统一输出到 stdout 和日志文件
    echo "$*" | tee -a "$LOG_FILE"
}

log_section() {
    # 输出章节分隔符，增强日志可读性
    log ""
    log "$1"
}

init() {
    # 初始化日志目录和日志文件。如果默认目录不可写，自动回退到当前目录下的 ./logs
    # 默认目录 /var/log/system_check 通常需要 root 权限；普通用户会自动回退，保证巡检能跑起来
    if ! mkdir -p "$LOG_DIR" 2>/dev/null; then
        local fallback_dir="./logs"
        echo "无法创建日志目录: $LOG_DIR，尝试回退到 ${fallback_dir}" >&2
        LOG_DIR="$fallback_dir"
        LOG_FILE="${LOG_DIR}/check_${TIMESTAMP}.log"
    fi

    if ! mkdir -p "$LOG_DIR" 2>/dev/null; then
        echo "无法创建回退日志目录: $LOG_DIR" >&2
        exit 1
    fi

    if ! touch "$LOG_FILE" 2>/dev/null; then
        local fallback_dir="./logs"
        echo "无法写入日志文件: $LOG_FILE，尝试回退到 ${fallback_dir}" >&2
        LOG_DIR="$fallback_dir"
        LOG_FILE="${LOG_DIR}/check_${TIMESTAMP}.log"
        mkdir -p "$LOG_DIR" 2>/dev/null || { echo "无法创建回退日志目录: $LOG_DIR" >&2; exit 1; }
        touch "$LOG_FILE" 2>/dev/null || { echo "无法写入回退日志文件: $LOG_FILE" >&2; exit 1; }
    fi

    # 探测权限：root / sudo（免密）/ limited 三档，供后续各小节决定是否用 sudo 提权
    if setup_privilege_mode; then
        log "权限模式: $PRIVILEGE_MODE"
    else
        log "权限模式: limited（当前用户非 root 且 sudo 无法无密码提权）"
        log "提示: 部分命令（lastb/journalctl/docker 等）可能因权限受限而无法输出"
    fi

    log "========== Linux 系统巡检报告 =========="
    log "巡检时间: $(date '+%Y-%m-%d %H:%M:%S')"
    log "主机名: $(hostname -f 2>/dev/null || hostname)"
    log "日志目录: $LOG_DIR"
    log "日志文件: $LOG_FILE"
    log "========================================"
}

get_ip_addresses() {
    # 获取本机所有全局 IPv4 地址（优先 ip 命令，回退 hostname -I）
    if cmd_exists ip; then
        ip -4 -o addr show scope global 2>/dev/null | awk '{print $2 ": " $4}' | paste -sd '; ' - || echo "未知"
    elif cmd_exists hostname; then
        hostname -I 2>/dev/null | xargs || echo "未知"
    else
        echo "未知"
    fi
}

get_default_gateway() {
    # 获取默认网关地址（优先 ip route，回退 route -n）
    if cmd_exists ip; then
        ip route 2>/dev/null | awk '/^default/ {print $3; exit}' || echo "未知"
    elif cmd_exists route; then
        route -n 2>/dev/null | awk '/^0.0.0.0/ {print $2; exit}' || echo "未知"
    else
        echo "未知"
    fi
}

get_dns_servers() {
    # 从 /etc/resolv.conf 读取 DNS 服务器列表
    awk '/^nameserver/ {print $2}' /etc/resolv.conf 2>/dev/null | paste -sd '; ' - || echo "未知"
}

get_uptime() {
    # 获取系统已运行时长
    if cmd_exists uptime; then
        uptime -p 2>/dev/null || echo "未知"
    else
        echo "未知"
    fi
}

get_load_average() {
    # 获取系统负载平均值（1/5/15 分钟），优先 uptime，回退 /proc/loadavg
    if cmd_exists uptime; then
        uptime | awk -F 'load average:' '{print $2}' | xargs
    elif [ -r /proc/loadavg ]; then
        awk '{print $1", " $2", " $3}' /proc/loadavg
    else
        echo "未知"
    fi
}

is_linux() {
    # 判断当前系统是否为 Linux（部分命令如 ss 仅存在于 Linux）
    [ "$(uname -s 2>/dev/null)" = "Linux" ]
}

check_basic_info() {
    # [1] 基础信息巡检：主机名 / IP / 操作系统 / 内核 / CPU / 内存 / 磁盘 / 网卡 / 登录记录 / 硬件信息
    # 说明：所有取值的命令都带 || true 兜底，任何一项拿不到就显示"未知"，不中断巡检
    log_section "[1] 基础信息巡检"

    local os_name cpu_model cpu_cores mem_total disk_list nic_list
    os_name=$(grep '^PRETTY_NAME=' /etc/os-release 2>/dev/null | cut -d= -f2 | tr -d '"' || true)
    os_name=${os_name:-未知}

    cpu_model=$(awk -F: '/model name/ {print $2; exit}' /proc/cpuinfo 2>/dev/null | xargs || echo "未知")
    cpu_cores=$(nproc 2>/dev/null || echo "未知")

    mem_total=$(awk '/^MemTotal:/ {printf "%.0fMB", $2/1024}' /proc/meminfo 2>/dev/null || echo "未知")

    if cmd_exists lsblk; then
        disk_list=$(lsblk -dn -o NAME,SIZE,TYPE,MODEL 2>/dev/null | awk '$3 == "disk" {print "/dev/" $1 " " $2 " " $4}' | paste -sd '; ' -)
    fi
    disk_list=${disk_list:-未知}

    if cmd_exists ethtool; then
        nic_list=$(for iface in $(ls /sys/class/net 2>/dev/null | grep -v lo); do
            ethtool -i "$iface" 2>/dev/null | awk -F: '/driver|bus-info|firmware-version/ {gsub(/^ +| +$/, "", $2); printf "%s=%s;", $1, $2}'
        done | paste -sd ' ' -)
    elif cmd_exists ip; then
        nic_list=$(ip -o link show 2>/dev/null | awk -F': ' '/^[0-9]+: / {print $2}' | paste -sd '; ' -)
    elif cmd_exists ifconfig; then
        nic_list=$(ifconfig -a 2>/dev/null | awk '/^[a-zA-Z0-9]/ {print $1}' | paste -sd '; ' -)
    else
        nic_list="未知"
    fi
    nic_list=${nic_list:-未知}

    log "主机名: $(hostname -f 2>/dev/null || hostname)"
    log "IP 地址: $(get_ip_addresses)"
    log "操作系统: $os_name"
    log "内核版本: $(uname -r)"
    log "运行时长: $(get_uptime)"

    log "当前登录用户:"
    if cmd_exists who; then
        run_and_log who
    else
        log "  who 命令不可用"
    fi

    if cmd_exists last; then
        log "最近登录记录:"
        run_and_log_privileged last -n 15
    else
        log "最近登录记录: 命令 last 不可用"
    fi

    if cmd_exists lastb; then
        log "异常登录记录:"
        run_and_log_privileged lastb -n 10
    else
        log "异常登录记录: lastb 命令不可用，无法获取"
    fi

    log "硬件信息:"
    log "  CPU型号: ${cpu_model:-未知}"
    log "  CPU核数: ${cpu_cores:-未知}"
    log "  内存总量: ${mem_total:-未知}"
    log "  磁盘摘要: ${disk_list}"
    log "  网卡信息: ${nic_list}"
}

get_cpu_usage() {
    # 计算 CPU 使用率：读取两次 /proc/stat（间隔 1 秒），用 (总时间 - 空闲时间)/总时间 求差值占比
    # 输出：0-100 的整数（无 /proc/stat 时回退 top 命令解析，仍失败则返回 0）
    local cpu_line total_before idle_before total_after idle_after total_delta idle_delta usage

    if [ -f /proc/stat ]; then
        cpu_line=$(grep '^cpu ' /proc/stat | head -n 1)
        read -r _ user nice system idle iowait irq softirq steal guest guest_nice <<< "$cpu_line"
        total_before=$((user + nice + system + idle + iowait + irq + softirq + steal))
        idle_before=$((idle + iowait))

        sleep 1

        # 注意：这里必须用完整的 cpu_line（含 "cpu " 前缀），让 read 的第一个变量 _ 吃掉 "cpu" 标签，
        # 后续 user/nice/... 才能对齐 /proc/stat 的真实字段。若写成 ${cpu_line#cpu }，第一个数值会被 _ 吃掉，
        # 所有字段整体错位一位，导致 CPU 使用率被算成 ~100%。第 300 行与 307 行必须保持一致。
        cpu_line=$(grep '^cpu ' /proc/stat | head -n 1)
        read -r _ user nice system idle iowait irq softirq steal guest guest_nice <<< "$cpu_line"
        total_after=$((user + nice + system + idle + iowait + irq + softirq + steal))
        idle_after=$((idle + iowait))

        total_delta=$((total_after - total_before))
        idle_delta=$((idle_after - idle_before))

        if [ "$total_delta" -le 0 ]; then
            echo 0
            return
        fi

        usage=$(((1000 * (total_delta - idle_delta) / total_delta + 5) / 10))
        echo "$usage"
        return
    fi

    if cmd_exists top; then
        local top_cpu
        top_cpu=$(top -bn1 2>/dev/null | awk '/^%Cpu/ {print $2}' | tail -n 1)
        echo "${top_cpu%.*}"
        return
    fi

    echo 0
}

get_iowait() {
    # 计算 IOWait 百分比：同样读取两次 /proc/stat（间隔 1 秒），用 iowait 时间差 / 总时间差 求占比
    # 输出：0-100 的整数（无 /proc/stat 时返回 0）
    if [ -f /proc/stat ]; then
        local cpu_line user nice system idle iowait irq softirq steal total_before idle_before iowait_before
        local total_after idle_after iowait_after total_delta iowait_delta iowait_pct

        cpu_line=$(grep '^cpu ' /proc/stat | head -n 1)
        read -r _ user nice system idle iowait irq softirq steal guest guest_nice <<< "$cpu_line"
        total_before=$((user + nice + system + idle + iowait + irq + softirq + steal))
        iowait_before=$iowait

        sleep 1

        cpu_line=$(grep '^cpu ' /proc/stat | head -n 1)
        read -r _ user nice system idle iowait irq softirq steal guest guest_nice <<< "$cpu_line"
        total_after=$((user + nice + system + idle + iowait + irq + softirq + steal))
        iowait_after=$iowait

        total_delta=$((total_after - total_before))
        iowait_delta=$((iowait_after - iowait_before))

        if [ "$total_delta" -le 0 ]; then
            echo 0
            return
        fi

        iowait_pct=$(((1000 * iowait_delta / total_delta + 5) / 10))
        echo "$iowait_pct"
        return
    fi

    echo 0
}

check_system_performance() {
    # [2] 系统负载与性能巡检：CPU 使用率 / 负载 / 内存 / Swap / IOWait / 磁盘 IO / 网络流量 / 进程统计
    # 说明：CPU 使用率和 IOWait 通过读取两次 /proc/stat 求差值计算，避免瞬时误差
    log_section "[2] 系统负载与性能"

    local load_avg cpu_usage mem_total mem_available mem_used mem_usage swap_total swap_free swap_used iowait

    load_avg=$(get_load_average)
    cpu_usage=$(get_cpu_usage)

    mem_total=$(awk '/^MemTotal:/ {print $2}' /proc/meminfo)
    mem_available=$(awk '/^MemAvailable:/ {print $2}' /proc/meminfo)
    swap_total=$(awk '/^SwapTotal:/ {print $2}' /proc/meminfo)
    swap_free=$(awk '/^SwapFree:/ {print $2}' /proc/meminfo)

    mem_used=$((mem_total - mem_available))
    mem_usage=$(awk -v used="$mem_used" -v total="$mem_total" 'BEGIN { if (total > 0) printf "%.0f", used*100/total; else print 0 }')
    swap_used=$((swap_total - swap_free))

    iowait=$(get_iowait)

    log "CPU 使用率: ${cpu_usage}%"
    log "系统负载平均值 (1/5/15 分钟): $load_avg"
    log "内存使用率: ${mem_usage}%"
    log "Swap 总量: $((swap_total/1024))MB, 已用: $((swap_used/1024))MB"
    log "IOWait: ${iowait}%"

    if cmd_exists iostat; then
        log "磁盘 I/O 性能 (iostat):"
        run_and_log iostat -dx 1 2 | tail -n 20
    elif [ -r /proc/diskstats ]; then
        log "磁盘 I/O 性能: iostat 未安装，使用 /proc/diskstats 替代"
        awk 'NR>2 {gsub(":", "", $1); printf "%s rx=%s tx=%s ri=%s wi=%s\n", $1, $4, $8, $6, $10}' /proc/diskstats 2>/dev/null | while IFS= read -r line; do echo "$line" | tee -a "$LOG_FILE"; done
    else
        log "磁盘 I/O 性能: iostat 未安装，/proc/diskstats 不可用，跳过"
    fi

    log "网络流量与错误:"
    if [ -r /proc/net/dev ]; then
        awk 'NR>2 {gsub(/:/, "", $1); printf "%s RX_BYTES=%s TX_BYTES=%s RX_PKTS=%s TX_PKTS=%s RX_ERRS=%s TX_ERRS=%s RX_DROP=%s TX_DROP=%s\n", $1, $2, $10, $3, $11, $4, $12, $5, $13}' /proc/net/dev 2>/dev/null | while IFS= read -r line; do echo "$line" | tee -a "$LOG_FILE"; done
    else
        log "  /proc/net/dev 不可用，无法获取网络流量统计"
    fi

    log "进程统计:"
    log "  进程总数: $(ps -e --no-headers 2>/dev/null | wc -l)"
    log "  僵尸进程: $(ps -e -o stat= 2>/dev/null | grep -c '^Z' || true)"

    log "系统中断与上下文切换:"
    log "  中断次数: $(awk '/^intr/ {print $2}' /proc/stat 2>/dev/null || echo 0)"
    log "  上下文切换: $(awk '/^ctxt/ {print $2}' /proc/stat 2>/dev/null || echo 0)"
}

check_disk_filesystem() {
    # [3] 磁盘与文件系统巡检：分区使用率 / inode / 只读挂载 / 内核错误 / 挂载点 / smartctl 磁盘健康
    # 说明：所有可能失败的探测（如某分区未挂载、smartctl 无权访问）都用 if/|| true 兜底，不中断巡检
    log_section "[3] 磁盘与文件系统"

    for mount in "${MOUNT_POINTS[@]}"; do
        log "分区使用率 (${mount}):"
        if df -h "$mount" 2>/dev/null | tail -n +2 | while IFS= read -r line; do echo "$line" | tee -a "$LOG_FILE"; done; then
            true
        else
            log "  ${mount} 未挂载或不可访问"
        fi
    done

    log "inode 使用率:"
    if df -hi 2>/dev/null | while IFS= read -r line; do echo "$line" | tee -a "$LOG_FILE"; done; then
        true
    else
        log "  无法获取 inode 使用率"
    fi

    log "只读文件系统检查:"
    if mount | grep -E ' ro(,|$)' >/dev/null 2>&1; then
        mount | grep -E ' ro(,|$)' | while IFS= read -r line; do echo "$line" | tee -a "$LOG_FILE"; done
    else
        log "  无只读挂载点"
    fi

    # 文件系统错误提示 (dmesg) —— 由 SHOW_DMESG_ERRORS 开关控制，默认关闭
    # 说明：dmesg 输出又臭又长，日常巡检不用看，仅在排查存储/磁盘问题时开启
    if [ "$SHOW_DMESG_ERRORS" -eq 1 ]; then
        log "文件系统错误提示 (dmesg):"
        if run_and_log_privileged dmesg 2>/dev/null | tail -n 50 | egrep -i 'error|fail|corrupt|read-only|invalid' 2>/dev/null | while IFS= read -r line; do echo "$line" | tee -a "$LOG_FILE"; done; then
            true
        else
            log "  未检测到明显错误"
        fi
    else
        log "文件系统错误提示 (dmesg): 已关闭（SHOW_DMESG_ERRORS=0，可设 1 开启）"
    fi

    # 当前挂载点信息 —— 由 SHOW_MOUNT_INFO 开关控制，默认关闭
    # 说明：日常巡检大部分时间不用管挂载点列表，仅在排查磁盘/挂载问题时开启
    if [ "$SHOW_MOUNT_INFO" -eq 1 ]; then
        log "当前挂载点信息:"
        if cmd_exists findmnt; then
            run_and_log_privileged findmnt -rn
        else
            run_and_log_privileged mount
        fi
    else
        log "当前挂载点信息: 已关闭（SHOW_MOUNT_INFO=0，可设 1 开启）"
    fi

    if cmd_exists smartctl; then
        log "磁盘健康状态 (smartctl):"
        for disk in /dev/sd? /dev/nvme?n?; do
            [ -b "$disk" ] || continue
            log "  检查 $disk"
            run_and_log_privileged smartctl -H "$disk"
        done
    else
        log "smartctl 未安装，无法检测磁盘健康状态"
    fi
}

check_network() {
    # [4] 网络巡检：网卡状态 / IP 配置 / 网关 / 连通性 / 监听端口 / 防火墙 / 连接统计 / 主机名解析
    # 说明：连通性检测用 ping -c 2 -W 2（只 ping 2 次、每次 2 秒超时），避免网络不通时长时间卡住
    log_section "[4] 网络巡检"

    log "网卡状态与链路:"
    if cmd_exists ip; then
        run_and_log ip -br link
    elif cmd_exists ifconfig; then
        run_and_log ifconfig -a
    else
        log "  ip/ifconfig 均不可用，无法获取网卡状态"
    fi

    log "网络配置:"
    if cmd_exists ip; then
        run_and_log ip -4 addr show
        run_and_log ip route show
    elif cmd_exists ifconfig; then
        run_and_log ifconfig
        if cmd_exists route; then
            run_and_log route -n
        fi
    else
        log "  ip/ifconfig 均不可用，无法获取网络配置"
    fi
    log "DNS: $(get_dns_servers)"
    log "默认网关: $(get_default_gateway)"

    local gateway
    gateway=$(get_default_gateway)
    if [ -n "$gateway" ] && [ "$gateway" != "未知" ]; then
        log "连通性检测 (网关 $gateway):"
        if ping -c 2 -W 2 "$gateway" >/dev/null 2>&1; then
            log "  网关可达"
        else
            log "  无法到达网关"
        fi
    else
        log "  未检测到默认网关，跳过网关连通性检测"
    fi

    log "连通性检测 (外网):"
    for target in "${PING_TARGETS[@]}" "$EXTERNAL_HOST"; do
        if ping -c 2 -W 2 "$target" >/dev/null 2>&1; then
            log "  $target 可达"
        else
            log "  无法访问 $target"
        fi
    done

    log "端口监听情况:"
    if is_linux && cmd_exists ss; then
        run_and_log_privileged ss -ltnp | head -n 40
    elif is_linux && cmd_exists netstat; then
        run_and_log_privileged netstat -tulnp | head -n 40
    else
        log "  非 Linux 平台或 ss/netstat 不可用，跳过端口监听检测"
    fi

    log "防火墙规则:"
    if is_linux && cmd_exists firewall-cmd; then
        run_and_log_privileged firewall-cmd --state
        run_and_log_privileged firewall-cmd --list-all
    elif is_linux && cmd_exists iptables; then
        run_and_log_privileged iptables -L -n -v
    elif is_linux && cmd_exists nft; then
        run_and_log_privileged nft list ruleset
    else
        log "  非 Linux 平台或防火墙命令不可用 (firewall-cmd/iptables/nft)"
    fi

    log "连接统计:"
    if is_linux && cmd_exists ss; then
        run_and_log_privileged ss -s
        run_and_log_privileged ss -tan state established 2>/dev/null | wc -l | awk '{print "  ESTABLISHED=" $1}' | tee -a "$LOG_FILE"
        run_and_log_privileged ss -tan state time-wait 2>/dev/null | wc -l | awk '{print "  TIME_WAIT=" $1}' | tee -a "$LOG_FILE"
    elif is_linux && cmd_exists netstat; then
        run_and_log_privileged netstat -an 2>/dev/null | grep ESTABLISHED | wc -l | awk '{print "  ESTABLISHED=" $1}' | tee -a "$LOG_FILE"
        run_and_log_privileged netstat -an 2>/dev/null | grep TIME_WAIT | wc -l | awk '{print "  TIME_WAIT=" $1}' | tee -a "$LOG_FILE"
    else
        log "  非 Linux 平台或 ss/netstat 不可用，跳过连接统计"
    fi

    log "主机名解析检测:"
    if is_linux && cmd_exists getent; then
        run_and_log getent hosts "$(hostname)"
        run_and_log getent hosts localhost
    else
        log "  非 Linux 平台或 getent 不可用，无法检测主机名解析"
    fi
}

service_is_running() {
    # 检查指定服务名是否处于 active 状态（优先 systemctl，回退 service status 或 ps 探测进程）
    # 返回值：0 表示服务在运行，1 表示未检测到
    local service_name="$1"
    if cmd_exists systemctl; then
        systemctl is-active "$service_name" 2>/dev/null | grep -q 'active' && return 0
    fi
    if cmd_exists pgrep; then
        pgrep -f "$service_name" 2>/dev/null | grep -q . && return 0
    fi
    return 1
}

# 统计匹配指定正则表达式的进程数量。
# 注意：pgrep 无匹配时返回非零退出码，若不加兜底，会触发脚本顶部的 set -e 导致整个巡检中断。
# 这里统一用 || true 兜底，确保"某个单项检测失败"不会中断后续巡检。
count_matching_procs() {
    local pattern="$1"
    if cmd_exists pgrep; then
        pgrep -af "$pattern" 2>/dev/null | grep -v grep | wc -l || true
    else
        ps -ef 2>/dev/null | grep -E "$pattern" | grep -v grep | wc -l || true
    fi
}

# 列出匹配指定正则表达式的进程（最多 N 行），输出到日志。任何失败都不中断脚本。
log_matching_procs() {
    local pattern="$1" max_lines="${2:-10}"
    if cmd_exists pgrep; then
        pgrep -af "$pattern" 2>/dev/null | grep -v grep | head -n "$max_lines" | while IFS= read -r line; do echo "    $line" | tee -a "$LOG_FILE"; done || true
    else
        ps -ef 2>/dev/null | grep -E "$pattern" | grep -v grep | head -n "$max_lines" | while IFS= read -r line; do echo "    $line" | tee -a "$LOG_FILE"; done || true
    fi
}

check_ssl_certificate_expiry() {
    # [7] SSL 证书过期检查：从 nginx/httpd 配置文件提取证书路径 + 扫描常见证书目录，
    #     用 openssl 读取每张证书的到期时间并计算剩余天数（按 SSL_WARNING_DAYS 阈值提示）
    # 说明：
    #   1. 只扫描已知配置文件（不递归 grep -R），避免在 NFS/stale mount 上卡死；
    #   2. CentOS 7 的 sed 4.2 不支持 -E，统一用 -r；
    #   3. 整段在 set +e 保护下运行，任何证书解析失败都不中断巡检；
    #   4. openssl x509 用 timeout 10 限时，防止异常证书阻塞脚本。
    log_section "[7] SSL 证书过期检查"

    if ! cmd_exists openssl; then
        log "OpenSSL 不可用，跳过证书过期检查"
        return 0
    fi

    # 本函数整体在 set +e 下运行（防御性：即使将来重新开启全局 errexit 也不受影响）。
    # 函数结束时按进入时的 errexit 状态恢复。
    local _saved_errexit=0
    if [ -o errexit ]; then _saved_errexit=1; fi
    set +e

    local cert_candidates=()
    local cert_path
    local cert_found=0

    # 仅扫描已知的 nginx/httpd 配置文件（不递归目录树），避免 grep -R 在 NFS/stale mount 上卡死
    # 注意：CentOS 7 的 sed 4.2 不支持 -E，改用 -r（都是 extended regex 的意思）
    local nginx_certs
    nginx_certs=$(grep -hE 'ssl_certificate[[:space:]]+' \
        /etc/nginx/nginx.conf \
        /etc/nginx/conf.d/*.conf \
        /etc/nginx/sites-enabled/* \
        /etc/httpd/conf/httpd.conf \
        /etc/httpd/conf.d/*.conf \
        /etc/apache2/sites-enabled/*.conf \
        2>/dev/null | \
        sed -r 's/.*ssl_certificate[[:space:]]+//; s/;.*$//' | \
        tr -d '"' | tr -d "'" | sort -u || true)
    # 仅在 grep 有实际输出时才进入 while 读取，避免 <<< "" 喂入空行使 set -e 触发退出
    if [ -n "$nginx_certs" ]; then
        while IFS= read -r cert_path; do
            [ -z "$cert_path" ] && continue
            cert_candidates+=("$cert_path")
        done <<< "$nginx_certs"
    fi

    for cert_path in /etc/ssl/certs/*.pem /etc/ssl/certs/*.crt /etc/pki/tls/certs/*.pem /etc/pki/tls/certs/*.crt /etc/nginx/conf.d/*.pem /etc/nginx/conf.d/*.crt /etc/nginx/certs/*.pem /etc/nginx/certs/*.crt; do
        [ -e "$cert_path" ] || continue
        cert_candidates+=("$cert_path")
    done

    local deduped=()
    for cert_path in "${cert_candidates[@]}"; do
        local already_added=0
        for existing in "${deduped[@]}"; do
            if [ "$existing" = "$cert_path" ]; then
                already_added=1
                break
            fi
        done
        if [ "$already_added" -eq 0 ]; then
            deduped+=("$cert_path")
        fi
    done

    if [ "${#deduped[@]}" -eq 0 ]; then
        log "  未找到常见证书文件，跳过证书过期检查"
        if [ "$_saved_errexit" -eq 1 ]; then set -e; fi
        return 0
    fi

    for cert_path in "${deduped[@]}"; do
        [ -r "$cert_path" ] || continue
        cert_found=1
        local enddate
        # timeout 不存在时降级为直接运行 openssl；|| true 兜底防止任何异常退出
        if cmd_exists timeout; then
            enddate=$(timeout 10 openssl x509 -in "$cert_path" -noout -enddate 2>/dev/null | cut -d= -f2 || true)
        else
            enddate=$(openssl x509 -in "$cert_path" -noout -enddate 2>/dev/null | cut -d= -f2 || true)
        fi
        if [ -z "$enddate" ]; then
            log "  $cert_path: 无法解析证书有效期"
            continue
        fi

        local expiry_epoch
        expiry_epoch=$(date -d "$enddate" +%s 2>/dev/null || true)
        local now_epoch
        now_epoch=$(date +%s 2>/dev/null || true)
        if [ -z "$expiry_epoch" ] || [ -z "$now_epoch" ]; then
            log "  $cert_path: 证书到期时间格式无法解析 ($enddate)"
            continue
        fi

        local days_left=$(( (expiry_epoch - now_epoch) / 86400 ))
        if [ "$days_left" -lt 0 ]; then
            log "  $cert_path: 已过期，剩余天数 $days_left"
        elif [ "$days_left" -lt "$SSL_WARNING_DAYS" ]; then
            log "  $cert_path: 即将过期，剩余 $days_left 天"
        else
            log "  $cert_path: 证书剩余 $days_left 天"
        fi
    done

    if [ "$cert_found" -eq 0 ]; then
        log "  未找到可读取的证书文件"
    fi

    if [ "$_saved_errexit" -eq 1 ]; then set -e; fi
}

# 读取单个日志文件末尾 N 行（优先直接用，权限不足时尝试 sudo -n）
sample_log_tail() {
    local log_file="$1" lines="${2:-20}"
    if [ -r "$log_file" ]; then
        tail -n "$lines" "$log_file" 2>/dev/null | while IFS= read -r line; do echo "    $line" | tee -a "$LOG_FILE"; done || true
    elif [ "${#SUDO_CMD[@]}" -gt 0 ]; then
        log "    当前用户无权读取该日志文件，尝试使用 sudo -n 读取"
        "${SUDO_CMD[@]}" tail -n "$lines" "$log_file" 2>/dev/null | while IFS= read -r line; do echo "    $line" | tee -a "$LOG_FILE"; done || true
    else
        log "    当前用户无权读取该日志文件"
    fi
}

# 自动发现近期活跃的日志文件：
# 在 LOG_SEARCH_ROOTS 下递归查找最近 LOG_SEARCH_MAX_AGE_DAYS 天内修改过的 *.log / *.out 文件
# 每个根目录最多取 LOG_SEARCH_MAX_PER_ROOT 个（按修改时间倒序），返回去重后的路径列表
auto_discover_logs() {
    local root
    local -A seen=()
    local found=()

    for root in "${LOG_SEARCH_ROOTS[@]}"; do
        [ -d "$root" ] || continue
        # find 可能因权限返回非零，加 || true 避免中断
        # 使用变量捕获代替 done < <(...) 进程替换，避免与 set -e pipefail 冲突
        local found_files
        # timeout 不存在时降级为直接运行 find；|| true 兜底防止中断
        if cmd_exists timeout; then
            found_files=$(timeout 60 find "$root" -type f \( -name '*.log' -o -name '*.out' \) \
                -mtime -"$LOG_SEARCH_MAX_AGE_DAYS" \
                2>/dev/null | sort -u | head -n "$LOG_SEARCH_MAX_PER_ROOT" || true)
        else
            found_files=$(find "$root" -type f \( -name '*.log' -o -name '*.out' \) \
                -mtime -"$LOG_SEARCH_MAX_AGE_DAYS" \
                2>/dev/null | sort -u | head -n "$LOG_SEARCH_MAX_PER_ROOT" || true)
        fi
        if [ -n "$found_files" ]; then
            while IFS= read -r f; do
                [ -z "$f" ] && continue
                # 跳过日志巡检自身输出的日志，避免自引用
                case "$f" in
                    *system_check*) continue ;;
                esac
                if [ -z "${seen[$f]:-}" ]; then
                    seen[$f]=1
                    # 跳过 Docker JSON 日志（dockerd 以 json-file 方式输出的乱码日志对凡人不可读）
                    # 跳过系统 core dump / boot 类日志
                    case "$f" in
                        */docker/containers/*)            continue ;;
                        */docker/overlay2/*)              continue ;;
                        *core.*|*core\.[0-9]*)            continue ;;
                        */boot.log*)                      continue ;;
                    esac
                    found+=("$f")
                fi
            done <<< "$found_files"
        fi
    done

    printf '%s\n' "${found[@]}"
}

check_log_inspection() {
    # [8] 日志巡检：依次巡检 ①自定义日志路径 ②自动发现近期活跃日志 ③systemd journal
    # 说明：
    #   1. 自定义路径在 CUSTOM_LOG_PATHS 里配置（公司业务日志，优先巡检）；
    #   2. 自动发现在 LOG_SEARCH_ROOTS 下找最近修改的 *.log/*.out，且用变量捕获代替进程替换，
    #      避免与 set -e pipefail 冲突导致中断；
    #   3. 所有 tail/读取都带 || true 兜底，日志不存在或权限不足时记录提示后继续。
    log_section "[8] 日志巡检"

    # 日志巡检开关（默认关闭，输出冗余较大，建议排查问题时临时开启）
    if [ "$ENABLE_LOG_INSPECTION" -ne 1 ]; then
        log "  日志巡检已设为关闭（ENABLE_LOG_INSPECTION=0），跳过。"
        log "  如需开启，请将脚本配置区中 ENABLE_LOG_INSPECTION 改为 1。"
        return 0
    fi

    local found_any=0
    local log_file

    # 1. 自定义日志路径（公司业务日志，优先巡检）
    if [ "${#CUSTOM_LOG_PATHS[@]}" -gt 0 ]; then
        log "  [日志] 自定义日志路径:"
        for log_file in "${CUSTOM_LOG_PATHS[@]}"; do
            [ -z "$log_file" ] && continue
            if [ -f "$log_file" ]; then
                found_any=1
                log "    [日志] $log_file"
                sample_log_tail "$log_file"
            else
                log "    [日志] $log_file （不存在，跳过）"
            fi
        done
    fi

    # 2. 自动发现近期活跃日志（覆盖未配置的路径）
    log "  [日志] 自动发现近期活跃日志（最近 ${LOG_SEARCH_MAX_AGE_DAYS} 天内修改）:"
    local discovered=0
    local discovered_logs
    # 变量捕获代替 done < <(...) 进程替换，避免与 set -e pipefail 冲突
    discovered_logs=$(auto_discover_logs || true)
    if [ -n "$discovered_logs" ]; then
        while IFS= read -r log_file; do
            [ -z "$log_file" ] && continue
            # 若该文件已在自定义列表里输出过，则跳过，避免重复
            local skip=0
            for custom in "${CUSTOM_LOG_PATHS[@]}"; do
                if [ "$custom" = "$log_file" ]; then
                    skip=1
                    break
                fi
            done
            [ "$skip" -eq 1 ] && continue

            discovered=1
            found_any=1
            log "    [日志] $log_file"
            sample_log_tail "$log_file"
        done <<< "$discovered_logs"
    fi

    if [ "$discovered" -eq 0 ]; then
        log "    未在 ${LOG_SEARCH_ROOTS[*]} 下发现近期活跃的日志文件"
    fi

    if [ "$found_any" -eq 0 ]; then
        log "  未发现任何可巡检的日志文件"
    fi

    # 3. systemd journal（如果存在）
    if cmd_exists journalctl; then
        log "  [日志] 最近系统日志 (journalctl -n 20)"
        run_and_log_privileged journalctl -n 20 --no-pager || true
    fi
}

check_security_accounts() {
    # [9] 安全与账号巡检
    # 检查项：
    #   1. root SSH 登录是否禁用
    #   2. 空口令与无密码账号（扫 /etc/shadow）
    #   3. 异常 sudo 权限（/etc/sudoers + sudoers.d）
    #   4. 历史登录记录与异常 IP（last / lastb / .bash_history）
    #   5. SELinux 状态
    #   6. 入侵迹象（可疑文件 / 异常外连 / crontab / 隐藏文件）
    # 所有读取都带 || true 兜底，文件不存在或无权访问时记提示后继续。
    log_section "[9] 安全与账号巡检"

    # --- 9.1 root SSH 登录限制 ---
    log "[安全] root SSH 登录限制:"
    local sshd_config_found=0
    for cfg in /etc/ssh/sshd_config /etc/openssh/sshd_config; do
        [ -f "$cfg" ] || continue
        sshd_config_found=1
        local permit_root
        permit_root=$(grep -i '^PermitRootLogin' "$cfg" 2>/dev/null | tail -n 1 | awk '{print $2}' || true)
        if [ -n "$permit_root" ]; then
            case "$permit_root" in
                no|prohibit-password) log "  PermitRootLogin=$permit_root ✅ 已限制" ;;
                yes|without-password) log "  PermitRootLogin=$permit_root ⚠️ 建议改为 prohibit-password 或 no" ;;
                *)                     log "  PermitRootLogin=$permit_root (非标准值)" ;;
            esac
        else
            log "  $cfg 中未显式配置 PermitRootLogin（默认允许密码登录）⚠️"
        fi
    done
    if [ "$sshd_config_found" -eq 0 ]; then
        log "  未找到 sshd 配置文件"
    fi

    # --- 9.2 空口令账号 ---
    log "[安全] 空口令 / 无密码账号:"
    if [ -r /etc/shadow ]; then
        # 第二列为空：无密码；第二列为 !! / ! / *：密码已锁定（安全）
        # 我们关注的是第二列为空（可直接无密码登录）和 !!（root 首次锁定属正常）
        local empty_pw
        empty_pw=$(awk -F: '($2 == "" || ($2 ~ /^!!$/ && $1 != "root")) && $7 !~ /nologin|false/ {print $1, $2, $7}' /etc/shadow 2>/dev/null || true)
        if [ -n "$empty_pw" ]; then
            log "  ⚠️ 以下账号无密码或锁定但 shell 可用:"
            echo "$empty_pw" | while IFS= read -r line; do echo "    $line" | tee -a "$LOG_FILE"; done || true
        else
            log "  ✅ 未发现空口令风险账号"
        fi
    else
        log "  /etc/shadow 不可读（需要 root 权限）"
    fi

    # --- 9.3 异常 sudo 权限 ---
    log "[安全] 异常 sudo 权限:"
    if [ -r /etc/sudoers ] || [ -d /etc/sudoers.d ]; then
        local sudo_issues
        # 查找 NOPASSWD 条目和非 wheel/sudo 组的 ALL 权限（排除注释行）
        sudo_issues=$( (cat /etc/sudoers 2>/dev/null; cat /etc/sudoers.d/* 2>/dev/null) \
            | grep -vE '^\s*#|^\s*$|^Defaults|^@includedir' \
            | grep -E 'NOPASSWD|ALL\s*=\s*\(\s*ALL\s*\)\s*ALL' || true)
        if [ -n "$sudo_issues" ]; then
            log "  ⚠️ 以下 sudo 规则值得关注:"
            echo "$sudo_issues" | while IFS= read -r line; do echo "    $line" | tee -a "$LOG_FILE"; done || true
        else
            log "  ✅ sudo 配置无异常"
        fi
    else
        log "  sudo 配置文件不可读，跳过"
    fi

    # 额外检查：wheel 组和 sudo 组里有哪些用户
    if [ -r /etc/group ]; then
        log "  wheel/sudo 组成员:"
        grep -E '^(wheel|sudo):' /etc/group 2>/dev/null | sed 's/^/    /' | tee -a "$LOG_FILE" || true
    fi

    # --- 9.4 历史登录与异常 IP ---
    log "[安全] 历史登录记录 (last -n 20):"
    if cmd_exists last; then
        last -n 20 2>/dev/null | head -n 20 | while IFS= read -r line; do echo "    $line" | tee -a "$LOG_FILE"; done || true
    else
        log "  last 命令不可用"
    fi

    log "[安全] 失败登录记录 (lastb -n 10):"
    if cmd_exists lastb; then
        # lastb 通常需要 root；权限不足时不中断
        lastb -n 10 2>/dev/null | head -n 10 | while IFS= read -r line; do echo "    $line" | tee -a "$LOG_FILE"; done || true
    else
        log "  lastb 命令不可用"
    fi

    # 历史命令大小（可能泄露敏感操作）
    log "[安全] 各用户 .bash_history 文件大小及最近记录:"
    for h in /root /home/*; do
        [ -d "$h" ] || continue
        local hist="$h/.bash_history"
        local hist_size=""
        if [ -f "$hist" ]; then
            hist_size=$(stat -c%s "$hist" 2>/dev/null || true)
            log "  $hist: ${hist_size} 字节"
            # 最近 5 条命令
            tail -n 5 "$hist" 2>/dev/null | while IFS= read -r line; do echo "    $line" | tee -a "$LOG_FILE"; done || true
        fi
    done

    # --- 9.5 SELinux 状态 ---
    log "[安全] SELinux 状态:"
    if cmd_exists getenforce; then
        local selinux_mode
        selinux_mode=$(getenforce 2>/dev/null || true)
        case "$selinux_mode" in
            Enforcing) log "  SELinux: Enforcing ✅" ;;
            Permissive) log "  SELinux: Permissive ⚠️（最好别是Enforcing）" ;;
            Disabled)   log "  SELinux: Disabled ⚠️（开启则为 Enforcing）" ;;
            *)          log "  SELinux 状态未知: $selinux_mode" ;;
        esac
    elif [ -f /etc/selinux/config ]; then
        log "  getenforce 不可用，查看配置文件:"
        grep -E '^SELINUX=' /etc/selinux/config 2>/dev/null | sed 's/^/    /' | tee -a "$LOG_FILE" || true
    else
        log "  未检测到 SELinux 配置"
    fi

    # --- 9.6 入侵迹象扫描 ---
    log "[安全] 入侵迹象扫描:"

    # 9.6a 可疑的监听端口（非标准端口）
    log "  [入侵] 当前监听端口（ss -tlnp）:"
    if cmd_exists ss; then
        run_and_log_privileged ss -tlnp 2>/dev/null | grep -v '127.0.0.1\|::1\|\*:' | while IFS= read -r line; do echo "    $line" | tee -a "$LOG_FILE"; done || true
    elif cmd_exists netstat; then
        run_and_log_privileged netstat -tlnp 2>/dev/null | grep -v '127.0.0.1\|::1' | while IFS= read -r line; do echo "    $line" | tee -a "$LOG_FILE"; done || true
    else
        log "    无 ss/netstat 命令"
    fi

    # 9.6b /tmp 下可疑可执行文件
    log "  [入侵] /tmp 下可执行文件（可能被植入后门）:"
    local tmp_exec
    tmp_exec=$(find /tmp -type f -perm -100 2>/dev/null | head -n 10 || true)
    if [ -n "$tmp_exec" ]; then
        echo "$tmp_exec" | while IFS= read -r line; do echo "    $line" | tee -a "$LOG_FILE"; done || true
    else
        log "    ✅ /tmp 下无可执行文件"
    fi

    # 9.6c /var/tmp 异常文件
    log "  [入侵] /var/tmp 下隐藏文件或可疑脚本:"
    local vartmp_bad
    vartmp_bad=$(find /var/tmp -maxdepth 1 \( -name '.*' -o -name '*.sh' -o -name '*.pl' -o -name '*.py' \) 2>/dev/null | head -n 10 || true)
    if [ -n "$vartmp_bad" ]; then
        echo "$vartmp_bad" | while IFS= read -r line; do echo "    $line" | tee -a "$LOG_FILE"; done || true
    else
        log "    ✅ /var/tmp 下未发现可疑文件"
    fi

    # 9.6d root crontab + /etc/crontab + /etc/cron.* 中可疑条目
    log "  [入侵] crontab 可疑条目（过滤注释和空行）:"
    local cron_entries
    cron_entries=$( (crontab -l 2>/dev/null; cat /etc/crontab 2>/dev/null; cat /etc/cron.d/* 2>/dev/null) \
        | grep -vE '^\s*#|^\s*$' | head -n 20 || true)
    if [ -n "$cron_entries" ]; then
        echo "$cron_entries" | while IFS= read -r line; do echo "    $line" | tee -a "$LOG_FILE"; done || true
    else
        log "    未发现 crontab 条目"
    fi

    # 9.6e /root 下异常隐藏文件
    log "  [入侵] /root 下隐藏文件:"
    local root_hidden
    root_hidden=$(find /root -maxdepth 2 -name '.*' -type f ! -name '.bash*' ! -name '.viminfo' ! -name '.lesshst' ! -name '.mysql_history' 2>/dev/null | head -n 10 || true)
    if [ -n "$root_hidden" ]; then
        echo "$root_hidden" | while IFS= read -r line; do echo "    $line" | tee -a "$LOG_FILE"; done || true
    else
        log "    ✅ /root 下未发现异常隐藏文件"
    fi

    # 9.6f 异常外连尝试（查 conntrack / /proc/net/ip_conntrack）
    log "  [入侵] 活跃外连（ESTABLISHED，过滤本地回环）:"
    if cmd_exists ss; then
        ss -tan state established 2>/dev/null | grep -v '127.0.0.1\|::1' | head -n 20 | while IFS= read -r line; do echo "    $line" | tee -a "$LOG_FILE"; done || true
    elif cmd_exists netstat; then
        netstat -tan 2>/dev/null | grep ESTABLISHED | grep -v '127.0.0.1\|::1' | head -n 20 | while IFS= read -r line; do echo "    $line" | tee -a "$LOG_FILE"; done || true
    else
        log "    无 ss/netstat 命令"
    fi

    log "[安全] 安全与账号巡检完成"
}

check_time_sync() {
    # [10] 时间同步巡检
    # 检查项：
    #   1. 系统时间是否正确（与本地时区和预期时间对比）
    #   2. NTP/Chrony 服务是否正常运行
    #   3. 时间偏差（通过 ntpstat / chronyc / timedatectl 获取）
    log_section "[10] 时间同步巡检"

    # --- 10.1 系统当前时间 ---
    log "[时间] 系统当前时间: $(date '+%Y-%m-%d %H:%M:%S %Z' 2>/dev/null || true)"
    log "[时间] 硬件时钟  : $(hwclock --show 2>/dev/null || hwclock -r 2>/dev/null || echo '不可读（需要 root 权限）')"

    # --- 10.2 系统时钟源与时区 ---
    log "[时间] 时钟源配置:"
    if [ -r /sys/devices/system/clocksource/clocksource0/current_clocksource ]; then
        cat /sys/devices/system/clocksource/clocksource0/current_clocksource 2>/dev/null | sed 's/^/    /' | tee -a "$LOG_FILE" || true
    else
        log "    无法读取 /sys/devices/system/clocksource"
    fi

    if cmd_exists timedatectl; then
        log "  timedatectl 信息:"
        timedatectl 2>/dev/null | while IFS= read -r line; do echo "    $line" | tee -a "$LOG_FILE"; done || true
    fi

    # --- 10.3 NTP/Chrony 服务状态 ---
    log "[时间] NTP 服务状态:"

    # chronyd（CentOS 7+/RHEL 7+ 默认）
    if service_is_running chronyd || cmd_exists chronyc; then
        log "  chronyd:"
        if service_is_running chronyd; then
            log "    chronyd 服务运行中 ✅"
            if cmd_exists chronyc; then
                log "    chronyc tracking:"
                chronyc tracking 2>/dev/null | head -n 10 | while IFS= read -r line; do echo "      $line" | tee -a "$LOG_FILE"; done || true
                log "    chronyc sources -v:"
                chronyc sources -v 2>/dev/null | head -n 15 | while IFS= read -r line; do echo "      $line" | tee -a "$LOG_FILE"; done || true
            else
                log "    chronyc 命令不可用，无法获取详细信息"
            fi
        else
            log "    chronyd 服务未运行 ⚠️"
        fi
    fi

    # ntpd（传统 NTP 服务）
    if service_is_running ntpd || cmd_exists ntpq; then
        log "  ntpd:"
        if service_is_running ntpd; then
            log "    ntpd 服务运行中 ✅"
            if cmd_exists ntpq; then
                log "    ntpq -pn:"
                ntpq -pn 2>/dev/null | head -n 15 | while IFS= read -r line; do echo "      $line" | tee -a "$LOG_FILE"; done || true
            else
                log "    ntpq 命令不可用，无法获取详细信息"
            fi
        else
            log "    ntpd 服务未运行 ⚠️"
        fi
    fi

    # systemd-timesyncd（轻量 systemd 时间同步，常见于 Ubuntu 等）
    if service_is_running systemd-timesyncd; then
        log "  systemd-timesyncd 服务运行中 ✅"
        if cmd_exists timedatectl; then
            log "    timedatectl timesync-status:"
            timedatectl timesync-status 2>/dev/null | while IFS= read -r line; do echo "      $line" | tee -a "$LOG_FILE"; done || true
        fi
    fi

    # time-wait-sync.service（systemd 时间同步等待服务）
    if service_is_running time-wait-sync; then
        log "  time-wait-sync 服务运行中 ✅"
    fi

    # ntpd 传统守护进程别名
    if service_is_running ntp && ! service_is_running ntpd 2>/dev/null; then
        log "  ntp (别名) 服务运行中 ✅"
        if cmd_exists ntpq; then
            ntpq -pn 2>/dev/null | head -n 15 | while IFS= read -r line; do echo "      $line" | tee -a "$LOG_FILE"; done || true
        fi
    fi

    # 如果都没检测到，做兜底探测
    if ! service_is_running chronyd && ! service_is_running ntpd && ! service_is_running systemd-timesyncd; then
        log "  ⚠️ 未检测到任何运行中的 NTP 时间同步服务"
        log "  常见排查: systemctl start chronyd && systemctl enable chronyd"
        log "  或手动同步: ntpdate -u pool.ntp.org (需要 ntpdate 包)"
    fi

    # --- 10.4 时间偏差检查 ---
    log "[时间] 时间偏差:"

    # 优先用 ntpstat（输出直观）
    if cmd_exists ntpstat; then
        ntpstat 2>/dev/null | sed 's/^/    /' | tee -a "$LOG_FILE" || true
    fi

    # chronyc 偏差
    if cmd_exists chronyc; then
        local chrony_offset
        chrony_offset=$(chronyc tracking 2>/dev/null | awk '/System time/ {print $4}' || true)
        if [ -n "$chrony_offset" ]; then
            log "    chronyd 系统时间偏差: ${chrony_offset} 秒"
        fi
    fi

    # ntpq 偏差（offset 一列）
    if cmd_exists ntpq; then
        log "    ntpq peer offset:"
        ntpq -pn 2>/dev/null | awk 'NR>2 && NF>8 {print "      ", $1, $9}' | tee -a "$LOG_FILE" || true
    fi

    # timedatectl 偏差
    if cmd_exists timedatectl; then
        local ntp_sync
        ntp_sync=$(timedatectl show -p NTPSynchronized 2>/dev/null | cut -d= -f2 || true)
        if [ -n "$ntp_sync" ]; then
            case "$ntp_sync" in
                yes) log "    NTP 同步: 已同步 ✅" ;;
                no)  log "    NTP 同步: 未同步 ⚠️" ;;
                *)   log "    NTP 同步: $ntp_sync" ;;
            esac
        fi
    fi

    # NTP 配置文件检查（优先级最高的是哪个，就检查哪个）
    local ntp_conf=""
    if [ -f /etc/chrony.conf ]; then
        ntp_conf="/etc/chrony.conf"
        log "  NTP 配置来源: $ntp_conf"
    elif [ -f /etc/ntp.conf ]; then
        ntp_conf="/etc/ntp.conf"
        log "  NTP 配置来源: $ntp_conf"
    elif [ -f /etc/systemd/timesyncd.conf ]; then
        ntp_conf="/etc/systemd/timesyncd.conf"
        log "  NTP 配置来源: $ntp_conf"
    fi
    if [ -n "$ntp_conf" ] && [ -r "$ntp_conf" ]; then
        log "  NTP 上游服务器:"
        grep -E '^(server|pool)' "$ntp_conf" 2>/dev/null | grep -v '^\s*#' | sed 's/^/    /' | tee -a "$LOG_FILE" || true
    fi

    log "[时间] 时间同步巡检完成"
}

main() {
    # 主巡检入口：按顺序执行各检查小节
    # 每个检查都加 || true 兜底：即使某个小节内部出现意外失败（返回非零），
    # 也能继续执行后面的巡检，不会因 set -e 中断整个脚本。
    # 巡检顺序：基础信息 → 性能 → 磁盘 → 网络 → 应用服务(主机) → 应用服务(Docker) → SSL → 日志
    init || true
    check_basic_info || true
    check_system_performance || true
    check_disk_filesystem || true
    check_network || true

    # --- 应用层/服务巡检（主机和 Docker） ---
    check_app_services_host || true
    check_app_services_docker || true

    # --- 安全与日志巡检 ---
    check_ssl_certificate_expiry || true
    check_log_inspection || true
    check_security_accounts || true
    check_time_sync || true

    log ""
    log "========================================"
    log "巡检完成，报告已保存至: $LOG_FILE"
}

# --- 应用服务层巡检（主机） ---
# 检查宿主机上直接运行的服务，而不是 Docker 容器中的服务
# 说明：服务进程匹配使用 count_matching_procs / log_matching_procs
#       这两个辅助函数内置了 pgrep 无匹配时返回非零的兜底，避免 set -e 中断巡检
check_app_services_host() {
    log_section "[5] 应用服务巡检 - 主机（非容器）"

    # MySQL
    log "MySQL (host):"
    if cmd_exists mysql || cmd_exists mysqladmin; then
        if cmd_exists mysql; then
            run_and_log mysql --version || true
        fi
        if cmd_exists mysqladmin; then
            run_and_log mysqladmin version || true
            run_and_log mysqladmin ping || true
        fi
    elif service_is_running mysql || service_is_running mysqld; then
        log "  MySQL 服务正在运行，但客户端命令不可用，无法获取版本信息"
    else
        log "  MySQL 未检测到运行"
    fi

    # Redis
    log "Redis (host):"
    if cmd_exists redis-cli; then
        run_and_log redis-cli INFO | head -n 5 || true
    elif service_is_running redis || service_is_running redis-server; then
        log "  Redis 服务正在运行，但 redis-cli 不可用，无法获取详细信息"
    else
        log "  Redis 未检测到运行"
    fi

    # Nginx
    log "Nginx (host):"
    if cmd_exists nginx; then
        run_and_log nginx -v || true
    elif service_is_running nginx; then
        log "  Nginx 服务正在运行，但 nginx 命令不可用，无法获取版本信息"
    else
        log "  Nginx 未检测到运行"
    fi

    # ActiveMQ
    log "ActiveMQ (host):"
    # ActiveMQ service name varies; check ports and service
    if service_is_running activemq; then
        log "  ActiveMQ 服务检测到运行 (service)"
    elif is_linux && cmd_exists ss && ss -ltnp 2>/dev/null | grep -E ':61616|:8161' >/dev/null 2>&1; then
        log "  ActiveMQ 可能在监听 61616/8161 端口"
    else
        log "  ActiveMQ 未检测到运行"
    fi

    # Elasticsearch
    log "Elasticsearch (host):"
    if cmd_exists curl; then
        if curl -s --connect-timeout 5 --max-time 10 http://127.0.0.1:9200/ 2>/dev/null | grep -q '"version"'; then
            run_and_log curl -s --connect-timeout 5 --max-time 10 http://127.0.0.1:9200/ | head -n 5
        else
            log "  未在 localhost:9200 发现 Elasticsearch 响应"
        fi
    elif service_is_running elasticsearch; then
        log "  Elasticsearch 服务检测到运行，但 curl 不可用，无法远程查询版本"
    else
        log "  Elasticsearch 未检测到运行"
    fi
}

# --- 应用服务层巡检（Docker 容器） ---
# 说明：为了便于维护和扩展，将镜像/容器名识别、inspect 元信息读取、以及基于服务类型的检查拆成小函数，
#       主循环负责遍历容器并按识别结果调用对应的检查函数。

# detect_service_from_image_or_name: 根据镜像名或容器名识别服务类型，返回小写标识符
# 支持带任意前缀的镜像名（如 registry.example.com/mysql:8.0、myapp_redis 等），
# 只要名称中包含对应的服务关键字即可识别
# 返回值：mysql|redis|nginx|activemq|elasticsearch 或空字符串（未识别则走通用检查）
detect_service_from_image_or_name() {
    local image="$1" name="$2"
    local combo
    combo="${image} ${name}"
    combo=$(echo "$combo" | tr '[:upper:]' '[:lower:]')

    if echo "$combo" | grep -E -q '(^|[^a-z])(mysql|mariadb)([^a-z]|$)'; then
        echo "mysql"; return
    fi
    if echo "$combo" | grep -E -q '(^|[^a-z])(redis)([^a-z]|$)'; then
        echo "redis"; return
    fi
    if echo "$combo" | grep -E -q '(^|[^a-z])(nginx)([^a-z]|$)'; then
        echo "nginx"; return
    fi
    if echo "$combo" | grep -E -q '(^|[^a-z])(activemq)([^a-z]|$)'; then
        echo "activemq"; return
    fi
    if echo "$combo" | grep -E -q '(^|[^a-z])(elastic|elasticsearch|\bes\b)([^a-z]|$)'; then
        echo "elasticsearch"; return
    fi
    echo ""
}

# 读取容器的网络与 health 信息：返回格式 IPS|PORTS_JSON|HEALTH
# 方便在日志中记录容器网络状态、端口映射和健康检查信息
inspect_container_meta() {
    local cid="$1"
    # IPs (all networks) | Ports JSON | health status (or none)
    "${DOCKER_CMD[@]}" inspect --format '{{range $k,$v := .NetworkSettings.Networks}}{{printf "%s " $v.IPAddress}}{{end}}|{{json .NetworkSettings.Ports}}|{{if .State.Health}}{{.State.Health.Status}}{{else}}none{{end}}' "$cid" 2>/dev/null || echo "|{}|none"
}

# 对指定服务类型在容器内进行尽量友好的检查（不会失败脚本，仅记录）
# 如果容器内没有 pgrep，则改用 ps 进行更强兼容识别
# 根据识别出的类型选择最常用的版本或健康检查命令
check_service_in_container() {
    local cid="$1" svc="$2" img="$3" name="$4"

    log "  容器 $name ($cid) -> 服务类型: $svc, 镜像: $img"

    local meta
    meta=$(inspect_container_meta "$cid")
    log "    Inspect: $meta"

    case "$svc" in
        mysql)
            if "${DOCKER_CMD[@]}" exec "$cid" mysql --version >/dev/null 2>&1; then
                run_and_log "${DOCKER_CMD[@]}" exec "$cid" mysql --version
            elif "${DOCKER_CMD[@]}" exec "$cid" mysqladmin version >/dev/null 2>&1; then
                run_and_log "${DOCKER_CMD[@]}" exec "$cid" mysqladmin version
            else
                log "  容器内无法执行 mysql/mysqladmin（可能未安装客户端），尝试检查 3306 端口映射"
                # 尝试查看端口映射信息（非阻塞）
                "${DOCKER_CMD[@]}" port "$cid" 3306 2>/dev/null | sed -n '1,5p' | while IFS= read -r ln; do echo "    $ln" | tee -a "$LOG_FILE"; done || true
            fi
            ;;
        redis)
            if "${DOCKER_CMD[@]}" exec "$cid" redis-cli --version >/dev/null 2>&1; then
                run_and_log "${DOCKER_CMD[@]}" exec "$cid" redis-cli --version
                run_and_log "${DOCKER_CMD[@]}" exec "$cid" redis-cli INFO | head -n 10 || true
            else
                log "  容器内未安装 redis-cli，尝试检查 6379 端口映射"
                "${DOCKER_CMD[@]}" port "$cid" 6379 2>/dev/null | sed -n '1,5p' | while IFS= read -r ln; do echo "    $ln" | tee -a "$LOG_FILE"; done || true
            fi
            ;;
        nginx)
            if "${DOCKER_CMD[@]}" exec "$cid" nginx -v >/dev/null 2>&1; then
                run_and_log "${DOCKER_CMD[@]}" exec "$cid" nginx -v
            else
                # 尝试从容器内访问本地 80/443
                if "${DOCKER_CMD[@]}" exec "$cid" sh -c "curl -sS --max-time 3 http://127.0.0.1:80/ || true" | grep -q .; then
                    log "  容器内 nginx 可能运行并响应 80"
                else
                    log "  容器内无法获取 nginx 版本或响应"
                fi
            fi
            ;;
        activemq)
            # ActiveMQ 通常在 8161 (web) 或 61616 (broker)
            if "${DOCKER_CMD[@]}" exec "$cid" sh -c "curl -sS --max-time 5 http://127.0.0.1:8161/ || true" | grep -q .; then
                run_and_log "${DOCKER_CMD[@]}" exec "$cid" sh -c "curl -sS --max-time 5 http://127.0.0.1:8161/ | head -n 20"
            else
                log "  容器内 ActiveMQ 控制台不可达（可能未启用或需认证）"
            fi
            ;;
        elasticsearch)
            if "${DOCKER_CMD[@]}" exec "$cid" curl -s --connect-timeout 3 --max-time 10 http://127.0.0.1:9200/ >/dev/null 2>&1; then
                run_and_log "${DOCKER_CMD[@]}" exec "$cid" curl -s --connect-timeout 3 --max-time 10 http://127.0.0.1:9200/ | head -n 10
            else
                log "  容器内无法访问 Elasticsearch (9200)"
            fi
            ;;
        *)
        log "  未知服务类型：$svc（跳过深度检查）"
        ;;
    esac
}

check_app_services_docker() {
    # [6] 应用服务巡检 - Docker 容器
    # 说明：
    #   1. 先诊断 docker 命令与 daemon 可用性，daemon 不可用或权限不足时记录诊断信息后跳过（不中断）；
    #   2. 容器识别分两步：先按镜像名/容器名关键词识别，再按端口映射启发式识别；
    #   3. 支持带任意前缀的镜像名（如 registry.example.com/mysql:8.0、myapp_redis 等）；
    #   4. 容器内检查命令都带 || true 兜底，容器内工具缺失（如无 pgrep）不会中断巡检。
    log_section "[6] 应用服务巡检 - Docker 容器"

    # 诊断 docker 可用性：记录 docker 命令、info 输出，若 daemon 不可用或权限不足则记录并跳过
    if ! cmd_exists docker; then
        log "Docker 命令不可用（PATH 中找不到 docker），跳过容器检测"
        return
    fi

    log "Docker 诊断: 尝试设置 Docker CLI 访问方式"
    if setup_docker_command; then
        log "  使用 Docker 命令: ${DOCKER_CMD[*]}"
    else
        log "  尝试访问 Docker daemon 失败，仍将使用 ${DOCKER_CMD[*]} 记录诊断信息"
    fi
 
    log "Docker 诊断: ${DOCKER_CMD[*]} --version"
    run_and_log "${DOCKER_CMD[@]}" --version || log "  ${DOCKER_CMD[*]} --version 失败或无法执行"
 
    # 检查 docker info 是否可运行（daemon 是否可访问）
    if "${DOCKER_CMD[@]}" info >/dev/null 2>&1; then
        log "Docker daemon 可访问，记录部分 docker info 输出："
        run_and_log "${DOCKER_CMD[@]}" info | sed -n '1,40p'
    else
        log "${DOCKER_CMD[*]} info 失败（daemon 可能未运行或当前用户无权访问）"
        # 记录 socket 权限和 systemd 状态，帮助排查权限或守护进程问题
        if [ -S "/var/run/docker.sock" ]; then
            log "/var/run/docker.sock 权限:"
            ls -l /var/run/docker.sock | tee -a "$LOG_FILE"
        else
            log "/var/run/docker.sock 不存在或不是 socket"
        fi
        if cmd_exists systemctl; then
            log "systemctl docker status:"
            run_and_log_privileged systemctl status docker || true
        fi

        # 尝试运行 docker ps 并记录错误输出（不中断脚本）
        log "尝试运行 ${DOCKER_CMD[*]} ps 以获取当前容器列表（此调用可能因权限问题失败）："
        "${DOCKER_CMD[@]}" ps --no-trunc --format '{{.ID}} {{.Image}} {{.Names}} {{.Status}}' 2>&1 | sed -n '1,40p' | while IFS= read -r l; do echo "  $l" | tee -a "$LOG_FILE"; done || true
 
        # 若 docker ps 仍然不可用，则跳过容器检测
        if ! "${DOCKER_CMD[@]}" ps >/dev/null 2>&1; then
            log "${DOCKER_CMD[*]} daemon 不可用或当前用户无权访问 Docker，跳过容器内服务检测（请使用 root 或将用户加入 docker 组）"
            return
        fi
    fi

    # list running containers (ID, IMAGE, NAMES)

    # --- Docker 容器概览 (docker ps) ---
    # 直观展示当前运行的所有容器：ID / 镜像 / 名称 / 状态 / 端口映射
    # 让巡检报告开头就能一眼看出"容器里都跑了什么"，再进入下面的逐容器深度检测
    log "Docker 容器概览 (docker ps):"
    if "${DOCKER_CMD[@]}" ps >/dev/null 2>&1; then
        "${DOCKER_CMD[@]}" ps --format 'table {{.ID}}\t{{.Image}}\t{{.Names}}\t{{.Status}}\t{{.Ports}}' 2>/dev/null \
            | while IFS= read -r l; do echo "  $l" | tee -a "$LOG_FILE"; done || true
    else
        log "  docker ps 不可用（daemon 未运行或权限不足），跳过概览"
    fi
    log ""

    local containers
    containers=$("${DOCKER_CMD[@]}" ps --format '{{.ID}} {{.Image}} {{.Names}}' 2>/dev/null || true)
    if [ -z "$containers" ]; then
        log "未发现运行中的容器"
        return
    fi

    # 逐行解析容器并做识别 + 检查
    while IFS= read -r line; do
        [ -z "$line" ] && continue
        cid=$(echo "$line" | awk '{print $1}')
        img=$(echo "$line" | awk '{print $2}')
        name=$(echo "$line" | awk '{print $3}')

        # 先基于镜像名/容器名关键词识别服务类型
        svc=$(detect_service_from_image_or_name "$img" "$name")
        if [ -n "$svc" ]; then
            check_service_in_container "$cid" "$svc" "$img" "$name"
            continue
        fi

        # 进一步根据端口映射做启发式识别，如果镜像/容器名无法匹配，则根据常见端口识别
        ports_json=$("${DOCKER_CMD[@]}" inspect --format '{{json .NetworkSettings.Ports}}' "$cid" 2>/dev/null || echo "{}")
        if echo "$ports_json" | grep -q '9200'; then
            check_service_in_container "$cid" "elasticsearch" "$img" "$name"
            continue
        elif echo "$ports_json" | grep -q '6379'; then
            check_service_in_container "$cid" "redis" "$img" "$name"
            continue
        elif echo "$ports_json" | grep -q '3306'; then
            check_service_in_container "$cid" "mysql" "$img" "$name"
            continue
        elif echo "$ports_json" | grep -q '8161\|61616'; then
            check_service_in_container "$cid" "activemq" "$img" "$name"
            continue
        fi

        log "容器 $name ($cid) 未匹配到目标镜像关键词，跳过专有检查（可通过配置添加关键词或使用容器 label 标识）"
    done <<< "$containers"
}

main "$@"
