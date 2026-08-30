// Generates the hardened systemd (DynamicUser) installation command for the
// cf-probe agent, offered as an alternative to the upstream install.sh
// bootstrap (`curl .../install.sh | sh -s -- install ...`).
//
// Behavior of the generated command (multi-line script):
//   - downloads the release binary into /usr/local/bin/cf-probe
//   - writes the config directly to /etc/cf-probe/config.conf (0644, world
//     readable, so any service user can read it without per-user handling)
//   - writes /etc/systemd/system/cf-probe.service running `cf-probe run
//     -config=/etc/cf-probe/config.conf` with DynamicUser=yes and a moderate
//     hardening set; all paths in the unit are static literals
//   - default resource limits: CPUQuota 5% (single-core) / 10% (multi-core,
//     auto-detected at install and hardcoded), MemoryMax=30M, CPUWeight=10
//   - AUTO_UPDATE is fixed to 0: a dynamic user cannot self-update (upstream
//     update path shells out to `install` as root); rerun the command to upgrade
//
// Note: under DynamicUser the /etc/cf-probe directory is not writable by the
// service, so server-pushed config updates and traffic.dat persistence are
// unavailable with this simple layout (config values are baked in at install).
//
// buildSingleLineInstallCommand() then encodes the script as Base64 so the
// whole installation can be pasted as ONE line into an SSH session:
//   echo '<b64>' | base64 -d | sh

export const INSTALL_METHOD_STANDARD = 'standard'
export const INSTALL_METHOD_SYSTEMD = 'systemd'

export const COMMAND_FORMAT_MULTI = 'multi'
export const COMMAND_FORMAT_SINGLE = 'single'

export const CFSM_REPO_SLUG = 'huilang-me/cfsm-agent'
export const CFSM_RELEASE_BASE = `https://github.com/${CFSM_REPO_SLUG}/releases/latest/download`

export const CFSM_BIN_PATH = '/usr/local/bin/cf-probe'
export const CFSM_CONFIG_PATH = '/etc/cf-probe/config.conf'
export const CFSM_SERVICE_PATH = '/etc/systemd/system/cf-probe.service'

const configValue = (value) => String(value ?? '').replace(/"/g, '\\"')

const numericValue = (value, fallback) => {
  if (value === '' || value === null || value === undefined) return fallback
  const n = Number(value)
  return Number.isFinite(n) ? n : fallback
}

export const buildSystemdConfigBlock = (options = {}) => {
  const connectionMode = options.connectionMode === 'http' ? 'http' : 'auto'
  const pingMode = options.pingMode === 'icmp' ? 'icmp' : 'tcp'
  const collectInterval = numericValue(options.collectInterval, 0)
  const reportInterval = numericValue(options.reportInterval, 60)
  const resetDay = options.resetDay === null || options.resetDay === undefined
    ? 1
    : numericValue(options.resetDay, 1)

  const lines = [
    `SERVER_ID="${configValue(options.serverId)}"`,
    `SECRET="${configValue(options.secret)}"`,
    `WORKER_URL="${configValue(options.workerUrl)}"`,
    `COLLECT_INTERVAL="${collectInterval}"`,
    `REPORT_INTERVAL="${reportInterval}"`,
    `RESET_DAY="${resetDay}"`,
    `CONNECTION_MODE="${connectionMode}"`,
    `PING_MODE="${pingMode}"`,
    // dynamicUser 下探针无法自我更新，固定关闭；升级时重新执行安装命令
    `AUTO_UPDATE="0"`
  ]
  if (options.customCt) lines.push(`CT_NODE="${configValue(options.customCt)}"`)
  if (options.customCu) lines.push(`CU_NODE="${configValue(options.customCu)}"`)
  if (options.customCm) lines.push(`CM_NODE="${configValue(options.customCm)}"`)
  if (options.customBd) lines.push(`BD_NODE="${configValue(options.customBd)}"`)
  if (options.networkInterface) lines.push(`INTERFACE="${configValue(options.networkInterface)}"`)
  if (options.ghProxy) lines.push(`UPDATE_PROXY="${configValue(options.ghProxy)}"`)
  return lines
}

export const buildSystemdInstallCommand = (options = {}) => {
  const host = String(options.host || '').replace(/\/+$/, '')
  const proxy = String(options.ghProxy || '').trim().replace(/\/+$/, '')
  const workerUrl = `${host}/update`
  const pingMode = options.pingMode === 'icmp' ? 'icmp' : 'tcp'
  const downloadBase = proxy ? `${proxy}/${CFSM_RELEASE_BASE}` : CFSM_RELEASE_BASE

  // 配置块不加缩进（保持 config.conf 内容干净）
  const configBlock = buildSystemdConfigBlock({ ...options, workerUrl }).join('\n')

  const capabilityBlock = pingMode === 'icmp'
    ? '# ICMP ping 需要 CAP_NET_RAW（仅开放这一项）\nCapabilityBoundingSet=CAP_NET_RAW\nAmbientCapabilities=CAP_NET_RAW'
    : '# 不保留任何 capabilities\nCapabilityBoundingSet=\nAmbientCapabilities='

  const serverLabel = options.serverName ? `服务器: ${options.serverName}  ` : ''

  return `# ============================================================
# CF-Server-Monitor 探针安装 — systemd + DynamicUser 加固模式
# ${serverLabel}服务器ID: ${options.serverId || ''}
# 说明:
#   - 二进制: ${CFSM_BIN_PATH}（0755，全局可执行）
#   - 配置: 直接使用 ${CFSM_CONFIG_PATH}（0644 全局可读，无拷贝/归属处理）
#   - 服务 ${CFSM_SERVICE_PATH} 以 DynamicUser=yes 运行并启用适度安全约束
#   - 资源限额: CPUQuota 5%（单核）/ 10%（多核，安装时自动检测核心数并硬编码进服务）、
#     MemoryMax=30M、CPUWeight=10（较低调度权重）
#   - dynamicUser 下探针无法自我更新，AUTO_UPDATE 固定为 0；
#     升级时重新复制本命令执行即可
# ============================================================
set -e

case "$(uname -m)" in
  x86_64|amd64) ARCH=amd64 ;;
  aarch64|arm64) ARCH=arm64 ;;
  i386|i686) ARCH=386 ;;
  armv5*) ARCH=armv5 ;;
  armv6*) ARCH=armv6 ;;
  armv7*|armv8l) ARCH=armv7 ;;
  loongarch64|loong64) ARCH=loong64 ;;
  *) echo "不支持的架构: $(uname -m)" >&2; exit 1 ;;
esac

echo "[1/4] 下载 cf-probe-linux-$ARCH 到 ${CFSM_BIN_PATH} ..."
curl -fsSL "${downloadBase}/cf-probe-linux-\${ARCH}" -o ${CFSM_BIN_PATH}
chmod 0755 ${CFSM_BIN_PATH}

echo "[2/4] 写入配置 ${CFSM_CONFIG_PATH} ..."
mkdir -p /etc/cf-probe
cat > ${CFSM_CONFIG_PATH} <<'CFG'
${configBlock}
CFG
chmod 0644 ${CFSM_CONFIG_PATH}

echo "[3/4] 写入 systemd 服务 ${CFSM_SERVICE_PATH} ..."
# 检测 CPU 核心数：单核限 5%，多核限 10%（结果直接硬编码进服务配置）
if [ "$(getconf _NPROCESSORS_ONLN 2>/dev/null || nproc 2>/dev/null || echo 1)" -gt 1 ]; then
  CPU_QUOTA=10
else
  CPU_QUOTA=5
fi
cat > ${CFSM_SERVICE_PATH} <<UNIT
[Unit]
Description=CF Server Monitor Probe Agent (hardened)
Documentation=https://github.com/${CFSM_REPO_SLUG}
After=network.target network-online.target
Wants=network-online.target

[Service]
Type=simple
DynamicUser=yes
# 配置直接使用全局可读的 /etc/cf-probe/config.conf（0644），无需专属用户归属处理
ExecStart=${CFSM_BIN_PATH} run -config=${CFSM_CONFIG_PATH}
Restart=on-failure
RestartSec=5
Nice=15
# --- 资源限额（CPU 配额由安装脚本按核心数硬编码；较低调度权重；内存上限 30M）---
CPUQuota=\${CPU_QUOTA}%
MemoryMax=30M
CPUWeight=10
IOSchedulingClass=idle
IOSchedulingPriority=7
UMask=0077
# --- 适度安全约束（DynamicUser 已隐含 NoNewPrivileges/RestrictSUIDSGID/ProtectSystem=strict/ProtectHome=read-only/RemoveIPC）---
NoNewPrivileges=yes
PrivateTmp=yes
ProtectSystem=strict
ProtectHome=read-only
ProtectKernelTunables=yes
ProtectControlGroups=yes
RestrictRealtime=yes
RestrictSUIDSGID=yes
RestrictAddressFamilies=AF_UNIX AF_INET AF_INET6 AF_NETLINK
${capabilityBlock}
StandardOutput=journal
StandardError=journal
SyslogIdentifier=cf-probe

[Install]
WantedBy=multi-user.target
UNIT

echo "[4/4] 启用并启动服务 ..."
systemctl daemon-reload
systemctl enable cf-probe.service >/dev/null 2>&1 || true
systemctl restart cf-probe.service

echo "完成，当前服务状态："
systemctl --no-pager --lines=0 status cf-probe.service || true
echo "日志查看: journalctl -u cf-probe -f"
`
}

const utf8ToBase64 = (text) => {
  const bytes = new TextEncoder().encode(text)
  let binary = ''
  const chunkSize = 0x8000
  for (let i = 0; i < bytes.length; i += chunkSize) {
    binary += String.fromCharCode(...bytes.subarray(i, i + chunkSize))
  }
  return btoa(binary)
}

// 将多行脚本压缩为单行命令：Base64 编码后管道解码并交给 sh 执行，
// 便于快速复制到服务器 SSH 会话中粘贴安装。
export const buildSingleLineInstallCommand = (scriptText) => {
  const encoded = utf8ToBase64(String(scriptText || ''))
  return `echo '${encoded}' | base64 -d | sh`
}
