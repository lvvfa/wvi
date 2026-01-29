#!/bin/bash

red='\033[0;31m'
green='\033[0;32m'
blue='\033[0;34m'
yellow='\033[0;33m'
plain='\033[0m'

cur_dir=$(pwd)

xui_folder="${XUI_MAIN_FOLDER:=/usr/local/x-ui}"
xui_service="${XUI_SERVICE:=/etc/systemd/system}"

# 检查 root 权限
[[ $EUID -ne 0 ]] && echo -e "${red}致命错误：${plain} 请使用 root 权限运行此脚本 \n " && exit 1

# 检查操作系统并设置 release 变量
if [[ -f /etc/os-release ]]; then
    source /etc/os-release
    release=$ID
    elif [[ -f /usr/lib/os-release ]]; then
    source /usr/lib/os-release
    release=$ID
else
    echo "无法检测系统 OS，请联系作者！" >&2
    exit 1
fi
echo "当前操作系统发行版为：$release"

arch() {
    case "$(uname -m)" in
        x86_64 | x64 | amd64) echo 'amd64' ;;
        i*86 | x86) echo '386' ;;
        armv8* | armv8 | arm64 | aarch64) echo 'arm64' ;;
        armv7* | armv7 | arm) echo 'armv7' ;;
        armv6* | armv6) echo 'armv6' ;;
        armv5* | armv5) echo 'armv5' ;;
        s390x) echo 's390x' ;;
        *) echo -e "${green}不支持的 CPU 架构！ ${plain}" && rm -f install.sh && exit 1 ;;
    esac
}

echo "架构：$(arch)"

# 简单辅助函数
is_ipv4() {
    [[ "$1" =~ ^([0-9]{1,3}\.){3}[0-9]{1,3}$ ]] && return 0 || return 1
}
is_ipv6() {
    [[ "$1" =~ : ]] && return 0 || return 1
}
is_ip() {
    is_ipv4 "$1" || is_ipv6 "$1"
}
is_domain() {
    [[ "$1" =~ ^([A-Za-z0-9](-*[A-Za-z0-9])*\.)+(xn--[a-z0-9]{2,}|[A-Za-z]{2,})$ ]] && return 0 || return 1
}

# 端口辅助函数
is_port_in_use() {
    local port="$1"
    if command -v ss >/dev/null 2>&1; then
        ss -ltn 2>/dev/null | awk -v p=":${port}$" '$4 ~ p {exit 0} END {exit 1}'
        return
    fi
    if command -v netstat >/dev/null 2>&1; then
        netstat -lnt 2>/dev/null | awk -v p=":${port} " '$4 ~ p {exit 0} END {exit 1}'
        return
    fi
    if command -v lsof >/dev/null 2>&1; then
        lsof -nP -iTCP:${port} -sTCP:LISTEN >/dev/null 2>&1 && return 0
    fi
    return 1
}

install_base() {
    case "${release}" in
        ubuntu | debian | armbian)
            apt-get update && apt-get install -y -q curl tar tzdata socat ca-certificates
        ;;
        fedora | amzn | virtuozzo | rhel | almalinux | rocky | ol)
            dnf -y update && dnf install -y -q curl tar tzdata socat ca-certificates
        ;;
        centos)
            if [[ "${VERSION_ID}" =~ ^7 ]]; then
                yum -y update && yum install -y curl tar tzdata socat ca-certificates
            else
                dnf -y update && dnf install -y -q curl tar tzdata socat ca-certificates
            fi
        ;;
        arch | manjaro | parch)
            pacman -Syu && pacman -Syu --noconfirm curl tar tzdata socat ca-certificates
        ;;
        opensuse-tumbleweed | opensuse-leap)
            zypper refresh && zypper -q install -y curl tar timezone socat ca-certificates
        ;;
        alpine)
            apk update && apk add curl tar tzdata socat ca-certificates
        ;;
        *)
            apt-get update && apt-get install -y -q curl tar tzdata socat ca-certificates
        ;;
    esac
}

gen_random_string() {
    local length="$1"
    local random_string=$(LC_ALL=C tr -dc 'a-zA-Z0-9' </dev/urandom | fold -w "$length" | head -n 1)
    echo "$random_string"
}

install_acme() {
    echo -e "${green}正在安装 acme.sh 用于管理 SSL 证书...${plain}"
    cd ~ || return 1
    curl -s https://get.acme.sh | sh >/dev/null 2>&1
    if [ $? -ne 0 ]; then
        echo -e "${red}acme.sh 安装失败${plain}"
        return 1
    else
        echo -e "${green}acme.sh 安装成功${plain}"
    fi
    return 0
}

setup_ssl_certificate() {
    local domain="$1"
    local server_ip="$2"
    local existing_port="$3"
    local existing_webBasePath="$4"
    
    echo -e "${green}正在设置 SSL 证书...${plain}"
    
    # 检查是否已安装 acme.sh
    if ! command -v ~/.acme.sh/acme.sh &>/dev/null; then
        install_acme
        if [ $? -ne 0 ]; then
            echo -e "${yellow}acme.sh 安装失败，跳过 SSL 设置${plain}"
            return 1
        fi
    fi
    
    # 创建证书目录
    local certPath="/root/cert/${domain}"
    mkdir -p "$certPath"
    
    # 签发证书
    echo -e "${green}正在为 ${domain} 签发 SSL 证书...${plain}"
    echo -e "${yellow}注意：必须确保 80 端口已开放且可从互联网访问${plain}"
    
    ~/.acme.sh/acme.sh --set-default-ca --server letsencrypt >/dev/null 2>&1
    ~/.acme.sh/acme.sh --issue -d ${domain} --listen-v6 --standalone --httpport 80 --force
    
    if [ $? -ne 0 ]; then
        echo -e "${yellow}为 ${domain} 签发证书失败${plain}"
        echo -e "${yellow}请确保 80 端口已开放，稍后可使用命令重试：x-ui${plain}"
        rm -rf ~/.acme.sh/${domain} 2>/dev/null
        rm -rf "$certPath" 2>/dev/null
        return 1
    fi
    
    # 安装证书
    ~/.acme.sh/acme.sh --installcert -d ${domain} \
        --key-file /root/cert/${domain}/privkey.pem \
        --fullchain-file /root/cert/${domain}/fullchain.pem \
        --reloadcmd "systemctl restart x-ui" >/dev/null 2>&1
    
    if [ $? -ne 0 ]; then
        echo -e "${yellow}证书安装失败${plain}"
        return 1
    fi
    
    # 启用自动续期
    ~/.acme.sh/acme.sh --upgrade --auto-upgrade >/dev/null 2>&1
    # 安全权限：私钥仅拥有者可读
    chmod 600 $certPath/privkey.pem 2>/dev/null
    chmod 644 $certPath/fullchain.pem 2>/dev/null
    
    # 为面板设置证书
    local webCertFile="/root/cert/${domain}/fullchain.pem"
    local webKeyFile="/root/cert/${domain}/privkey.pem"
    
    if [[ -f "$webCertFile" && -f "$webKeyFile" ]]; then
        ${xui_folder}/x-ui cert -webCert "$webCertFile" -webCertKey "$webKeyFile" >/dev/null 2>&1
        echo -e "${green}SSL 证书安装并配置成功！${plain}"
        return 0
    else
        echo -e "${yellow}未找到证书文件${plain}"
        return 1
    fi
}

# 签发 Let's Encrypt IP 证书（短效模式，有效期约6天）
# 需要 acme.sh 和 80 端口开放以进行 HTTP-01 验证
setup_ip_certificate() {
    local ipv4="$1"
    local ipv6="$2"  # 可选

    echo -e "${green}正在设置 Let's Encrypt IP 证书（短效模式）...${plain}"
    echo -e "${yellow}注意：IP 证书有效期约为 6 天，将自动续期。${plain}"
    echo -e "${yellow}默认监听端口为 80。如果您选择其他端口，请确保外部 80 端口转发到该端口。${plain}"

    # 检查 acme.sh
    if ! command -v ~/.acme.sh/acme.sh &>/dev/null; then
        install_acme
        if [ $? -ne 0 ]; then
            echo -e "${red}acme.sh 安装失败${plain}"
            return 1
        fi
    fi

    # 验证 IP 地址
    if [[ -z "$ipv4" ]]; then
        echo -e "${red}必须提供 IPv4 地址${plain}"
        return 1
    fi

    if ! is_ipv4 "$ipv4"; then
        echo -e "${red}无效的 IPv4 地址：$ipv4${plain}"
        return 1
    fi

    # 创建证书目录
    local certDir="/root/cert/ip"
    mkdir -p "$certDir"

    # 构建域名参数
    local domain_args="-d ${ipv4}"
    if [[ -n "$ipv6" ]] && is_ipv6 "$ipv6"; then
        domain_args="${domain_args} -d ${ipv6}"
        echo -e "${green}包含 IPv6 地址：${ipv6}${plain}"
    fi

    # 设置自动续期的重载命令（添加 || true 以避免首次安装失败）
    local reloadCmd="systemctl restart x-ui 2>/dev/null || rc-service x-ui restart 2>/dev/null || true"

    # 选择 HTTP-01 监听端口（默认 80，提示覆盖）
    local WebPort=""
    read -rp "请输入用于 ACME HTTP-01 监听的端口（默认 80）：" WebPort
    WebPort="${WebPort:-80}"
    if ! [[ "${WebPort}" =~ ^[0-9]+$ ]] || ((WebPort < 1 || WebPort > 65535)); then
        echo -e "${red}提供的端口无效。回退到 80。${plain}"
        WebPort=80
    fi
    echo -e "${green}使用端口 ${WebPort} 进行独立验证。${plain}"
    if [[ "${WebPort}" -ne 80 ]]; then
        echo -e "${yellow}提醒：Let's Encrypt 仍然连接端口 80；请将外部端口 80 转发到 ${WebPort}。${plain}"
    fi

    # 确保所选端口可用
    while true; do
        if is_port_in_use "${WebPort}"; then
            echo -e "${yellow}端口 ${WebPort} 已被占用。${plain}"

            local alt_port=""
            read -rp "请输入另一个端口用于 acme.sh 独立监听（留空中止）：" alt_port
            alt_port="${alt_port// /}"
            if [[ -z "${alt_port}" ]]; then
                echo -e "${red}端口 ${WebPort} 忙碌；无法继续。${plain}"
                return 1
            fi
            if ! [[ "${alt_port}" =~ ^[0-9]+$ ]] || ((alt_port < 1 || alt_port > 65535)); then
                echo -e "${red}无效的端口。${plain}"
                return 1
            fi
            WebPort="${alt_port}"
            continue
        else
            echo -e "${green}端口 ${WebPort} 空闲，准备进行独立验证。${plain}"
            break
        fi
    done

    # 签发短效证书
    echo -e "${green}正在为 ${ipv4} 签发 IP 证书...${plain}"
    ~/.acme.sh/acme.sh --set-default-ca --server letsencrypt >/dev/null 2>&1
    
    ~/.acme.sh/acme.sh --issue \
        ${domain_args} \
        --standalone \
        --server letsencrypt \
        --certificate-profile shortlived \
        --days 6 \
        --httpport ${WebPort} \
        --force

    if [ $? -ne 0 ]; then
        echo -e "${red}签发 IP 证书失败${plain}"
        echo -e "${yellow}请确保端口 ${WebPort} 可访问（或从外部端口 80 转发）${plain}"
        # 清理 IPv4 和 IPv6 的 acme.sh 数据
        rm -rf ~/.acme.sh/${ipv4} 2>/dev/null
        [[ -n "$ipv6" ]] && rm -rf ~/.acme.sh/${ipv6} 2>/dev/null
        rm -rf ${certDir} 2>/dev/null
        return 1
    fi

    echo -e "${green}证书签发成功，正在安装...${plain}"

    # 安装证书
    # 注意：如果 reloadcmd 失败，acme.sh 可能会报告“Reload error”并非零退出，
    # 但证书文件仍已安装。我们检查文件是否存在而不是依赖退出代码。
    ~/.acme.sh/acme.sh --installcert -d ${ipv4} \
        --key-file "${certDir}/privkey.pem" \
        --fullchain-file "${certDir}/fullchain.pem" \
        --reloadcmd "${reloadCmd}" 2>&1 || true

    # 验证证书文件是否存在
    if [[ ! -f "${certDir}/fullchain.pem" || ! -f "${certDir}/privkey.pem" ]]; then
        echo -e "${red}安装后未找到证书文件${plain}"
        # 清理 IPv4 和 IPv6 的 acme.sh 数据
        rm -rf ~/.acme.sh/${ipv4} 2>/dev/null
        [[ -n "$ipv6" ]] && rm -rf ~/.acme.sh/${ipv6} 2>/dev/null
        rm -rf ${certDir} 2>/dev/null
        return 1
    fi
    
    echo -e "${green}证书文件安装成功${plain}"

    # 启用 acme.sh 自动升级（确保 cron 任务运行）
    ~/.acme.sh/acme.sh --upgrade --auto-upgrade >/dev/null 2>&1

    # 安全权限：私钥仅拥有者可读
    chmod 600 ${certDir}/privkey.pem 2>/dev/null
    chmod 644 ${certDir}/fullchain.pem 2>/dev/null

    # 配置面板使用该证书
    echo -e "${green}正在为面板设置证书路径...${plain}"
    ${xui_folder}/x-ui cert -webCert "${certDir}/fullchain.pem" -webCertKey "${certDir}/privkey.pem"
    
    if [ $? -ne 0 ]; then
        echo -e "${yellow}警告：无法自动设置证书路径${plain}"
        echo -e "${yellow}证书文件位于：${plain}"
        echo -e "  证书: ${certDir}/fullchain.pem"
        echo -e "  私钥: ${certDir}/privkey.pem"
    else
        echo -e "${green}证书路径配置成功${plain}"
    fi

    echo -e "${green}IP 证书安装并配置成功！${plain}"
    echo -e "${green}证书有效期约为 6 天，将通过 acme.sh 定时任务自动续期。${plain}"
    echo -e "${yellow}acme.sh 将在过期前自动续期并重载 x-ui。${plain}"
    return 0
}

# 通过 acme.sh 手动签发 SSL 证书
ssl_cert_issue() {
    local existing_webBasePath=$(${xui_folder}/x-ui setting -show true | grep 'webBasePath:' | awk -F': ' '{print $2}' | tr -d '[:space:]' | sed 's#^/##')
    local existing_port=$(${xui_folder}/x-ui setting -show true | grep 'port:' | awk -F': ' '{print $2}' | tr -d '[:space:]')
    
    # 检查 acme.sh
    if ! command -v ~/.acme.sh/acme.sh &>/dev/null; then
        echo "未找到 acme.sh。正在安装..."
        cd ~ || return 1
        curl -s https://get.acme.sh | sh
        if [ $? -ne 0 ]; then
            echo -e "${red}acme.sh 安装失败${plain}"
            return 1
        else
            echo -e "${green}acme.sh 安装成功${plain}"
        fi
    fi

    # 获取域名并验证
    local domain=""
    while true; do
        read -rp "请输入您的域名：" domain
        domain="${domain// /}"  # 去除空格
        
        if [[ -z "$domain" ]]; then
            echo -e "${red}域名不能为空。请重试。${plain}"
            continue
        fi
        
        if ! is_domain "$domain"; then
            echo -e "${red}域名格式无效：${domain}。请输入有效的域名。${plain}"
            continue
        fi
        
        break
    done
    echo -e "${green}您的域名是：${domain}，正在检查...${plain}"

    # 检查是否已存在证书
    local currentCert=$(~/.acme.sh/acme.sh --list | tail -1 | awk '{print $1}')
    if [ "${currentCert}" == "${domain}" ]; then
        local certInfo=$(~/.acme.sh/acme.sh --list)
        echo -e "${red}系统已存在该域名的证书。无法重复签发。${plain}"
        echo -e "${yellow}当前证书详情：${plain}"
        echo "$certInfo"
        return 1
    else
        echo -e "${green}您的域名现在已准备好签发证书...${plain}"
    fi

    # 创建证书目录
    certPath="/root/cert/${domain}"
    if [ ! -d "$certPath" ]; then
        mkdir -p "$certPath"
    else
        rm -rf "$certPath"
        mkdir -p "$certPath"
    fi

    # 获取独立服务器端口号
    local WebPort=80
    read -rp "请选择使用哪个端口（默认为 80）：" WebPort
    if [[ ${WebPort} -gt 65535 || ${WebPort} -lt 1 ]]; then
        echo -e "${yellow}您的输入 ${WebPort} 无效，将使用默认端口 80。${plain}"
        WebPort=80
    fi
    echo -e "${green}将使用端口：${WebPort} 签发证书。请确保此端口已开放。${plain}"

    # 暂时停止面板
    echo -e "${yellow}暂时停止面板服务...${plain}"
    systemctl stop x-ui 2>/dev/null || rc-service x-ui stop 2>/dev/null

    # 签发证书
    ~/.acme.sh/acme.sh --set-default-ca --server letsencrypt
    ~/.acme.sh/acme.sh --issue -d ${domain} --listen-v6 --standalone --httpport ${WebPort} --force
    if [ $? -ne 0 ]; then
        echo -e "${red}证书签发失败，请检查日志。${plain}"
        rm -rf ~/.acme.sh/${domain}
        systemctl start x-ui 2>/dev/null || rc-service x-ui start 2>/dev/null
        return 1
    else
        echo -e "${green}证书签发成功，正在安装证书...${plain}"
    fi

    # 设置重载命令
    reloadCmd="systemctl restart x-ui || rc-service x-ui restart"
    echo -e "${green}ACME 的默认重载命令 (--reloadcmd) 为：${yellow}systemctl restart x-ui || rc-service x-ui restart${plain}"
    echo -e "${green}此命令将在每次证书签发和续期时运行。${plain}"
    read -rp "您想修改 ACME 的 --reloadcmd 吗？(y/n): " setReloadcmd
    if [[ "$setReloadcmd" == "y" || "$setReloadcmd" == "Y" ]]; then
        echo -e "\n${green}\t1.${plain} 预设：systemctl reload nginx ; systemctl restart x-ui"
        echo -e "${green}\t2.${plain} 输入您自定义的命令"
        echo -e "${green}\t0.${plain} 保持默认重载命令"
        read -rp "请选择一个选项：" choice
        case "$choice" in
        1)
            echo -e "${green}重载命令为：systemctl reload nginx ; systemctl restart x-ui${plain}"
            reloadCmd="systemctl reload nginx ; systemctl restart x-ui"
            ;;
        2)
            echo -e "${yellow}建议在末尾加上 x-ui restart${plain}"
            read -rp "请输入您的自定义重载命令：" reloadCmd
            echo -e "${green}重载命令为：${reloadCmd}${plain}"
            ;;
        *)
            echo -e "${green}保持默认重载命令${plain}"
            ;;
        esac
    fi

    # 安装证书
    ~/.acme.sh/acme.sh --installcert -d ${domain} \
        --key-file /root/cert/${domain}/privkey.pem \
        --fullchain-file /root/cert/${domain}/fullchain.pem --reloadcmd "${reloadCmd}"

    if [ $? -ne 0 ]; then
        echo -e "${red}证书安装失败，退出。${plain}"
        rm -rf ~/.acme.sh/${domain}
        systemctl start x-ui 2>/dev/null || rc-service x-ui start 2>/dev/null
        return 1
    else
        echo -e "${green}证书安装成功，正在启用自动续期...${plain}"
    fi

    # 启用自动续期
    ~/.acme.sh/acme.sh --upgrade --auto-upgrade
    if [ $? -ne 0 ]; then
        echo -e "${yellow}自动续期设置出现问题，证书详情：${plain}"
        ls -lah /root/cert/${domain}/
        # 安全权限
        chmod 600 $certPath/privkey.pem 2>/dev/null
        chmod 644 $certPath/fullchain.pem 2>/dev/null
    else
        echo -e "${green}自动续期成功，证书详情：${plain}"
        ls -lah /root/cert/${domain}/
        # 安全权限
        chmod 600 $certPath/privkey.pem 2>/dev/null
        chmod 644 $certPath/fullchain.pem 2>/dev/null
    fi

    # 启动面板
    systemctl start x-ui 2>/dev/null || rc-service x-ui start 2>/dev/null

    # 证书安装成功后提示用户设置面板路径
    read -rp "您想将此证书应用于面板设置吗？(y/n): " setPanel
    if [[ "$setPanel" == "y" || "$setPanel" == "Y" ]]; then
        local webCertFile="/root/cert/${domain}/fullchain.pem"
        local webKeyFile="/root/cert/${domain}/privkey.pem"

        if [[ -f "$webCertFile" && -f "$webKeyFile" ]]; then
            ${xui_folder}/x-ui cert -webCert "$webCertFile" -webCertKey "$webKeyFile"
            echo -e "${green}面板证书路径已设置${plain}"
            echo -e "${green}证书文件：$webCertFile${plain}"
            echo -e "${green}私钥文件：$webKeyFile${plain}"
            echo ""
            echo -e "${green}访问 URL：https://${domain}:${existing_port}/${existing_webBasePath}${plain}"
            echo -e "${yellow}面板将重启以应用 SSL 证书...${plain}"
            systemctl restart x-ui 2>/dev/null || rc-service x-ui restart 2>/dev/null
        else
            echo -e "${red}错误：未找到域名 $domain 的证书或私钥文件。${plain}"
        fi
    else
        echo -e "${yellow}跳过面板路径设置。${plain}"
    fi
    
    return 0
}

# 可复用的交互式 SSL 设置（域名或 IP）
# 设置全局 `SSL_HOST` 以用于访问 URL 显示
prompt_and_setup_ssl() {
    local panel_port="$1"
    local web_base_path="$2"   # 预期无前导斜杠
    local server_ip="$3"

    local ssl_choice=""

    echo -e "${yellow}选择 SSL 证书设置方式：${plain}"
    echo -e "${green}1.${plain} 为域名申请 Let's Encrypt 证书（90天有效期，自动续期）"
    echo -e "${green}2.${plain} 为 IP 地址申请 Let's Encrypt 证书（6天有效期，自动续期）"
    echo -e "${blue}注意：${plain} 两种选项都需要 80 端口开放。IP 证书使用短效配置文件。"
    read -rp "请选择一个选项（默认 2，使用 IP）：" ssl_choice
    ssl_choice="${ssl_choice// /}"  # 去除空格
    
    # 如果不是 1，默认为 2 (IP 证书)
    if [[ "$ssl_choice" != "1" ]]; then
        ssl_choice="2"
    fi

    case "$ssl_choice" in
    1)
        # 用户选择域名 Let's Encrypt 选项
        echo -e "${green}使用 Let's Encrypt 进行域名证书申请...${plain}"
        ssl_cert_issue
        # 从证书中提取使用的域名
        local cert_domain=$(~/.acme.sh/acme.sh --list 2>/dev/null | tail -1 | awk '{print $1}')
        if [[ -n "${cert_domain}" ]]; then
            SSL_HOST="${cert_domain}"
            echo -e "${green}✓ SSL 证书配置成功，域名：${cert_domain}${plain}"
        else
            echo -e "${yellow}SSL 设置可能已完成，但域名提取失败${plain}"
            SSL_HOST="${server_ip}"
        fi
        ;;
    2)
        # 用户选择 IP Let's Encrypt 选项
        echo -e "${green}使用 Let's Encrypt 进行 IP 证书申请（短效模式）...${plain}"
        
        # 询问可选的 IPv6
        local ipv6_addr=""
        read -rp "您是否有 IPv6 地址需要包含？（留空跳过）：" ipv6_addr
        ipv6_addr="${ipv6_addr// /}"  # 去除空格
        
        # 如果面板正在运行，停止它（需要 80 端口）
        if [[ $release == "alpine" ]]; then
            rc-service x-ui stop >/dev/null 2>&1
        else
            systemctl stop x-ui >/dev/null 2>&1
        fi
        
        setup_ip_certificate "${server_ip}" "${ipv6_addr}"
        if [ $? -eq 0 ]; then
            SSL_HOST="${server_ip}"
            echo -e "${green}✓ Let's Encrypt IP 证书配置成功${plain}"
        else
            echo -e "${red}✗ IP 证书设置失败。请检查 80 端口是否开放。${plain}"
            SSL_HOST="${server_ip}"
        fi
        
        ;;
    *)
        echo -e "${red}无效选项。跳过 SSL 设置。${plain}"
        SSL_HOST="${server_ip}"
        ;;
    esac
}

config_after_install() {
    local existing_hasDefaultCredential=$(${xui_folder}/x-ui setting -show true | grep -Eo 'hasDefaultCredential: .+' | awk '{print $2}')
    local existing_webBasePath=$(${xui_folder}/x-ui setting -show true | grep -Eo 'webBasePath: .+' | awk '{print $2}' | sed 's#^/##')
    local existing_port=$(${xui_folder}/x-ui setting -show true | grep -Eo 'port: .+' | awk '{print $2}')
    # 通过检查 cert: 行是否存在且后面有内容来正确检测空证书
    local existing_cert=$(${xui_folder}/x-ui setting -getCert true | grep 'cert:' | awk -F': ' '{print $2}' | tr -d '[:space:]')
    local URL_lists=(
        "https://api4.ipify.org"
        "https://ipv4.icanhazip.com"
        "https://v4.api.ipinfo.io/ip"
        "https://ipv4.myexternalip.com/raw"
        "https://4.ident.me"
        "https://check-host.net/ip"
    )
    local server_ip=""
    for ip_address in "${URL_lists[@]}"; do
        server_ip=$(curl -s --max-time 3 "${ip_address}" 2>/dev/null | tr -d '[:space:]')
        if [[ -n "${server_ip}" ]]; then
            break
        fi
    done
    
    if [[ ${#existing_webBasePath} -lt 4 ]]; then
        if [[ "$existing_hasDefaultCredential" == "true" ]]; then
            local config_webBasePath=$(gen_random_string 18)
            local config_username=$(gen_random_string 10)
            local config_password=$(gen_random_string 10)
            
            read -rp "您是否想自定义面板端口设置？（如果不设置，将使用随机端口）[y/n]: " config_confirm
            if [[ "${config_confirm}" == "y" || "${config_confirm}" == "Y" ]]; then
                read -rp "请设置面板端口：" config_port
                echo -e "${yellow}您的面板端口是：${config_port}${plain}"
            else
                local config_port=$(shuf -i 1024-62000 -n 1)
                echo -e "${yellow}生成的随机端口：${config_port}${plain}"
            fi
            
            ${xui_folder}/x-ui setting -username "${config_username}" -password "${config_password}" -port "${config_port}" -webBasePath "${config_webBasePath}"
            
            echo ""
            echo -e "${green}═══════════════════════════════════════════${plain}"
            echo -e "${green}     SSL 证书设置（强制）                   ${plain}"
            echo -e "${green}═══════════════════════════════════════════${plain}"
            echo -e "${yellow}为了安全起见，所有面板都需要 SSL 证书。${plain}"
            echo -e "${yellow}Let's Encrypt 现在同时支持域名和 IP 地址！${plain}"
            echo ""

            prompt_and_setup_ssl "${config_port}" "${config_webBasePath}" "${server_ip}"
            
            # 显示最终凭据和访问信息
            echo ""
            echo -e "${green}═══════════════════════════════════════════${plain}"
            echo -e "${green}     面板安装完成！                        ${plain}"
            echo -e "${green}═══════════════════════════════════════════${plain}"
            echo -e "${green}用户名：     ${config_username}${plain}"
            echo -e "${green}密码：       ${config_password}${plain}"
            echo -e "${green}端口：       ${config_port}${plain}"
            echo -e "${green}WebBasePath：${config_webBasePath}${plain}"
            echo -e "${green}访问链接：   https://${SSL_HOST}:${config_port}/${config_webBasePath}${plain}"
            echo -e "${green}═══════════════════════════════════════════${plain}"
            echo -e "${yellow}⚠ 重要：请妥善保存这些凭据！${plain}"
            echo -e "${yellow}⚠ SSL 证书：已启用并配置${plain}"
        else
            local config_webBasePath=$(gen_random_string 18)
            echo -e "${yellow}WebBasePath 缺失或太短。正在生成一个新的...${plain}"
            ${xui_folder}/x-ui setting -webBasePath "${config_webBasePath}"
            echo -e "${green}新 WebBasePath: ${config_webBasePath}${plain}"

            # 如果面板已安装但未配置证书，现在提示 SSL
            if [[ -z "${existing_cert}" ]]; then
                echo ""
                echo -e "${green}═══════════════════════════════════════════${plain}"
                echo -e "${green}     SSL 证书设置（推荐）                   ${plain}"
                echo -e "${green}═══════════════════════════════════════════${plain}"
                echo -e "${yellow}Let's Encrypt 现在同时支持域名和 IP 地址！${plain}"
                echo ""
                prompt_and_setup_ssl "${existing_port}" "${config_webBasePath}" "${server_ip}"
                echo -e "${green}访问链接：  https://${SSL_HOST}:${existing_port}/${config_webBasePath}${plain}"
            else
                # 如果已存在证书，仅显示访问 URL
                echo -e "${green}访问链接：https://${server_ip}:${existing_port}/${config_webBasePath}${plain}"
            fi
        fi
    else
        if [[ "$existing_hasDefaultCredential" == "true" ]]; then
            local config_username=$(gen_random_string 10)
            local config_password=$(gen_random_string 10)
            
            echo -e "${yellow}检测到默认凭据。需要进行安全更新...${plain}"
            ${xui_folder}/x-ui setting -username "${config_username}" -password "${config_password}"
            echo -e "已生成新的随机登录凭据："
            echo -e "###############################################"
            echo -e "${green}用户名： ${config_username}${plain}"
            echo -e "${green}密码：   ${config_password}${plain}"
            echo -e "###############################################"
        else
            echo -e "${green}用户名、密码和 WebBasePath 已正确设置。${plain}"
        fi

        # 现有安装：如果未配置证书，提示用户进行 SSL 设置
        existing_cert=$(${xui_folder}/x-ui setting -getCert true | grep 'cert:' | awk -F': ' '{print $2}' | tr -d '[:space:]')
        if [[ -z "$existing_cert" ]]; then
            echo ""
            echo -e "${green}═══════════════════════════════════════════${plain}"
            echo -e "${green}     SSL 证书设置（推荐）                   ${plain}"
            echo -e "${green}═══════════════════════════════════════════${plain}"
            echo -e "${yellow}Let's Encrypt 现在同时支持域名和 IP 地址！${plain}"
            echo ""
            prompt_and_setup_ssl "${existing_port}" "${existing_webBasePath}" "${server_ip}"
            echo -e "${green}访问链接：  https://${SSL_HOST}:${existing_port}/${existing_webBasePath}${plain}"
        else
            echo -e "${green}SSL 证书已配置。无需操作。${plain}"
        fi
    fi
    
    ${xui_folder}/x-ui migrate
}

install_x-ui() {
    cd ${xui_folder%/x-ui}/
    
    # 下载资源
    if [ $# == 0 ]; then
        tag_version=$(curl -Ls "https://api.github.com/repos/lvvfa/wvi/releases/latest" | grep '"tag_name":' | sed -E 's/.*"([^"]+)".*/\1/')
        if [[ ! -n "$tag_version" ]]; then
            echo -e "${yellow}尝试使用 IPv4 获取版本...${plain}"
            tag_version=$(curl -4 -Ls "https://api.github.com/repos/lvvfa/wvi/releases/latest" | grep '"tag_name":' | sed -E 's/.*"([^"]+)".*/\1/')
            if [[ ! -n "$tag_version" ]]; then
                echo -e "${red}无法获取 x-ui 版本，可能是由于 GitHub API 限制，请稍后重试${plain}"
                exit 1
            fi
        fi
        echo -e "获取到 x-ui 最新版本：${tag_version}，开始安装..."
        curl -4fLRo ${xui_folder}-linux-$(arch).tar.gz https://github.com/lvvfa/wvi/releases/download/${tag_version}/x-ui-linux-$(arch).tar.gz
        if [[ $? -ne 0 ]]; then
            echo -e "${red}下载 x-ui 失败，请确保服务器可以访问 GitHub ${plain}"
            exit 1
        fi
    else
        tag_version=$1
        tag_version_numeric=${tag_version#v}
        min_version="2.3.5"
        
        if [[ "$(printf '%s\n' "$min_version" "$tag_version_numeric" | sort -V | head -n1)" != "$min_version" ]]; then
            echo -e "${red}请使用更新的版本（至少 v2.3.5）。退出安装。${plain}"
            exit 1
        fi
        
        url="https://github.com/lvvfa/wvi/releases/download/${tag_version}/x-ui-linux-$(arch).tar.gz"
        echo -e "开始安装 x-ui $1"
        curl -4fLRo ${xui_folder}-linux-$(arch).tar.gz ${url}
        if [[ $? -ne 0 ]]; then
            echo -e "${red}下载 x-ui $1 失败，请检查版本是否存在 ${plain}"
            exit 1
        fi
    fi
    curl -4fLRo /usr/bin/x-ui-temp https://raw.githubusercontent.com/lvvfa/wvi/main/x-ui.sh
    if [[ $? -ne 0 ]]; then
        echo -e "${red}下载 x-ui.sh 失败${plain}"
        exit 1
    fi
    
    # 停止 x-ui 服务并移除旧资源
    if [[ -e ${xui_folder}/ ]]; then
        if [[ $release == "alpine" ]]; then
            rc-service x-ui stop
        else
            systemctl stop x-ui
        fi
        rm ${xui_folder}/ -rf
    fi
    
    # 解压资源并设置权限
    tar zxvf x-ui-linux-$(arch).tar.gz
    rm x-ui-linux-$(arch).tar.gz -f
    
    cd x-ui
    chmod +x x-ui
    chmod +x x-ui.sh
    
    # 检查系统架构并重命名文件
    if [[ $(arch) == "armv5" || $(arch) == "armv6" || $(arch) == "armv7" ]]; then
        mv bin/xray-linux-$(arch) bin/xray-linux-arm
        chmod +x bin/xray-linux-arm
    fi
    chmod +x x-ui bin/xray-linux-$(arch)
    
    # 更新 x-ui cli 并设置权限
    mv -f /usr/bin/x-ui-temp /usr/bin/x-ui
    chmod +x /usr/bin/x-ui
    mkdir -p /var/log/x-ui
    config_after_install

    # Etckeeper 兼容性
    if [ -d "/etc/.git" ]; then
        if [ -f "/etc/.gitignore" ]; then
            if ! grep -q "x-ui/x-ui.db" "/etc/.gitignore"; then
                echo "" >> "/etc/.gitignore"
                echo "x-ui/x-ui.db" >> "/etc/.gitignore"
                echo -e "${green}已将 x-ui.db 添加到 /etc/.gitignore 以适配 etckeeper${plain}"
            fi
        else
            echo "x-ui/x-ui.db" > "/etc/.gitignore"
            echo -e "${green}创建了 /etc/.gitignore 并添加了 x-ui.db 以适配 etckeeper${plain}"
        fi
    fi
    
    if [[ $release == "alpine" ]]; then
        curl -4fLRo /etc/init.d/x-ui https://raw.githubusercontent.com/lvvfa/wvi/main/x-ui.rc
        if [[ $? -ne 0 ]]; then
            echo -e "${red}下载 x-ui.rc 失败${plain}"
            exit 1
        fi
        chmod +x /etc/init.d/x-ui
        rc-update add x-ui
        rc-service x-ui start
    else
        # 安装 systemd 服务文件
        service_installed=false
        
        if [ -f "x-ui.service" ]; then
            echo -e "${green}在解压文件中发现 x-ui.service，正在安装...${plain}"
            cp -f x-ui.service ${xui_service}/ >/dev/null 2>&1
            if [[ $? -eq 0 ]]; then
                service_installed=true
            fi
        fi
        
        if [ "$service_installed" = false ]; then
            case "${release}" in
                ubuntu | debian | armbian)
                    if [ -f "x-ui.service.debian" ]; then
                        echo -e "${green}在解压文件中发现 x-ui.service.debian，正在安装...${plain}"
                        cp -f x-ui.service.debian ${xui_service}/x-ui.service >/dev/null 2>&1
                        if [[ $? -eq 0 ]]; then
                            service_installed=true
                        fi
                    fi
                ;;
                arch | manjaro | parch)
                    if [ -f "x-ui.service.arch" ]; then
                        echo -e "${green}在解压文件中发现 x-ui.service.arch，正在安装...${plain}"
                        cp -f x-ui.service.arch ${xui_service}/x-ui.service >/dev/null 2>&1
                        if [[ $? -eq 0 ]]; then
                            service_installed=true
                        fi
                    fi
                ;;
                *)
                    if [ -f "x-ui.service.rhel" ]; then
                        echo -e "${green}在解压文件中发现 x-ui.service.rhel，正在安装...${plain}"
                        cp -f x-ui.service.rhel ${xui_service}/x-ui.service >/dev/null 2>&1
                        if [[ $? -eq 0 ]]; then
                            service_installed=true
                        fi
                    fi
                ;;
            esac
        fi
        
        # 如果 tar.gz 中未找到服务文件，从 GitHub 下载
        if [ "$service_installed" = false ]; then
            echo -e "${yellow}在 tar.gz 中未找到服务文件，正在从 GitHub 下载...${plain}"
            case "${release}" in
                ubuntu | debian | armbian)
                    curl -4fLRo ${xui_service}/x-ui.service https://raw.githubusercontent.com/lvvfa/wvi/main/x-ui.service.debian >/dev/null 2>&1
                ;;
                arch | manjaro | parch)
                    curl -4fLRo ${xui_service}/x-ui.service https://raw.githubusercontent.com/lvvfa/wvi/main/x-ui.service.arch >/dev/null 2>&1
                ;;
                *)
                    curl -4fLRo ${xui_service}/x-ui.service https://raw.githubusercontent.com/lvvfa/wvi/main/x-ui.service.rhel >/dev/null 2>&1
                ;;
            esac
            
            if [[ $? -ne 0 ]]; then
                echo -e "${red}从 GitHub 安装 x-ui.service 失败${plain}"
                exit 1
            fi
            service_installed=true
        fi
        
        if [ "$service_installed" = true ]; then
            echo -e "${green}正在设置 systemd 单元...${plain}"
            chown root:root ${xui_service}/x-ui.service >/dev/null 2>&1
            chmod 644 ${xui_service}/x-ui.service >/dev/null 2>&1
            systemctl daemon-reload
            systemctl enable x-ui
            systemctl start x-ui
        else
            echo -e "${red}安装 x-ui.service 文件失败${plain}"
            exit 1
        fi
    fi
    
    echo -e "${green}x-ui ${tag_version}${plain} 安装完成，正在运行..."
    echo -e ""
    echo -e "┌───────────────────────────────────────────────────────┐
│  ${blue}x-ui 控制菜单用法 (子命令):${plain}                        │
│                                                       │
│  ${blue}x-ui${plain}              - 管理脚本                       │
│  ${blue}x-ui start${plain}        - 启动                           │
│  ${blue}x-ui stop${plain}         - 停止                           │
│  ${blue}x-ui restart${plain}      - 重启                           │
│  ${blue}x-ui status${plain}       - 当前状态                       │
│  ${blue}x-ui settings${plain}     - 当前设置                       │
│  ${blue}x-ui enable${plain}       - 开机自启                       │
│  ${blue}x-ui disable${plain}      - 取消开机自启                   │
│  ${blue}x-ui log${plain}          - 查看日志                       │
│  ${blue}x-ui banlog${plain}       - 查看 Fail2ban 封禁日志         │
│  ${blue}x-ui update${plain}       - 更新                           │
│  ${blue}x-ui legacy${plain}       - 旧版本                         │
│  ${blue}x-ui install${plain}      - 安装                           │
│  ${blue}x-ui uninstall${plain}    - 卸载                           │
└───────────────────────────────────────────────────────┘"
}

echo -e "${green}正在运行...${plain}"
install_base
install_x-ui $1
