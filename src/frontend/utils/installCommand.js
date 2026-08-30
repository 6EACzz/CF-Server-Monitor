// Generates the hardened systemd (DynamicUser) installation command for the
// cf-probe agent, offered as an alternative to the upstream install.sh
// bootstrap (`curl .../install.sh | sh -s -- install ...`).
//
// Behavior of the generated command:
//   - downloads the release binary into /usr/local/bin/cf-probe
//   - writes /etc/cf-probe/config.conf (root-only readable)
//   - writes /etc/systemd/system/cf-probe.service running `cf-probe run`
//     with DynamicUser=yes plus strong hardening (ProtectSystem=strict,
//     no capabilities, seccomp, restricted address families, ...)
//   - config used by the agent is a copy inside systemd's StateDirectory
//     (owned by the dynamic user) so remote config updates and traffic.dat
//     state remain writable; `/etc/cf-probe/config.conf` is the seed source
//     re-copied by ExecStartPre when missing
//   - AUTO_UPDATE is fixed to 0: a dynamic user cannot self-update (upstream
//     update path shells out to `install` as root); rerun the command to upgrade

export const INSTALL_METHOD_STANDARD = 'standard'
export const INSTALL_METHOD_SYSTEMD = 'systemd'

export const CFSM_REPO_SLUG = 'huilang-me/cfsm-agent'
export const CFSM_RELEASE_BASE = `https://github.com/${CFSM_REPO_SLUG}/releases/latest/download`

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

  const configBlock = buildSystemdConfigBlock({ ...options, workerUrl }).map(line => `  ${line}`).join('\n')

  const capabilityBlock = pingMode === 'icmp'
    ? '# ICMP ping 需要 CAP_NET_RAW（仅开放这一项）\nCapabilityBoundingSet=CAP_NET_RAW\nAmbientCapabilities=CAP_NET_RAW'
    : '# 不保留任何 capabilities\nCapabilityBoundingSet=\nAmbientCapabilities='

  const serverLabel = options.serverName ? `服务器: ${options.serverName}  ` : ''

  return `# ============================================================
# CF-Server-Monitor 探针安装 — systemd + DynamicUser 加固模式
# ${serverLabel}服务器ID: ${options.serverId || ''}
# 说明:
#   - 二进制安装到 /usr/local/bin/cf-probe
#   - 配置写入 /etc/cf-probe/config.conf（仅 root 可读，作为种子配置）
#   - 服务 cf-probe.service 以 DynamicUser=yes 运行并启用强安全约束
#     （ProtectSystem=strict、seccomp、无 capabilities、受限地址族等）
#   - dynamicUser 下探针无法自我更新，AUTO_UPDATE 固定为 0；
#     升级时重新复制本文命令执行即可（流量计数会保留）
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

echo "[1/5] 下载 cf-probe-linux-$ARCH ..."
curl -fsSL "${downloadBase}/cf-probe-linux-\${ARCH}" -o /usr/local/bin/cf-probe
chmod 0755 /usr/local/bin/cf-probe

echo "[2/5] 写入配置 /etc/cf-probe/config.conf ..."
install -d -m 0755 /etc/cf-probe
cat > /etc/cf-probe/config.conf <<'CFG'
${configBlock}
CFG
chmod 0600 /etc/cf-probe/config.conf

echo "[3/5] 写入 systemd 服务 /etc/systemd/system/cf-probe.service ..."
cat > /etc/systemd/system/cf-probe.service <<'UNIT'
[Unit]
Description=CF Server Monitor Probe Agent (hardened)
Documentation=https://github.com/${CFSM_REPO_SLUG}
After=network.target network-online.target
Wants=network-online.target

[Service]
Type=simple
DynamicUser=yes
StateDirectory=cf-probe
# 首次启动（或配置缺失/重装）时，以 root 将种子配置复制到 StateDirectory 并归属动态用户；
# 运行期配置更新与 traffic.dat 由探针自身写入该目录（动态用户可写）
ExecStartPre=+/bin/sh -c 'test -f "\${STATE_DIRECTORY}/config.conf" || { /bin/install -m 0600 /etc/cf-probe/config.conf "\${STATE_DIRECTORY}/config.conf" && /bin/chown cf-probe:cf-probe "\${STATE_DIRECTORY}/config.conf" || /bin/chmod 0644 "\${STATE_DIRECTORY}/config.conf"; }'
ExecStart=/usr/local/bin/cf-probe run -config="\${STATE_DIRECTORY}/config.conf"
Restart=on-failure
RestartSec=5
Nice=15
IOSchedulingClass=idle
IOSchedulingPriority=7
UMask=0077
# --- 安全加固（DynamicUser 已隐含 NoNewPrivileges/RestrictSUIDSGID/ProtectSystem=strict/ProtectHome=read-only/RemoveIPC）---
NoNewPrivileges=yes
PrivateTmp=yes
PrivateDevices=yes
ProtectSystem=strict
ProtectHome=yes
ProtectKernelTunables=yes
ProtectKernelModules=yes
ProtectControlGroups=yes
ProtectClock=yes
ProtectHostname=yes
ProtectKernelLogs=yes
ProtectProc=invisible
RestrictAddressFamilies=AF_UNIX AF_INET AF_INET6 AF_NETLINK
RestrictNamespaces=yes
RestrictRealtime=yes
RestrictSUIDSGID=yes
LockPersonality=yes
MemoryDenyWriteExecute=yes
SystemCallArchitectures=native
SystemCallErrorNumber=EPERM
SystemCallFilter=@system-service
${capabilityBlock}
KeyringMode=private
StandardOutput=journal
StandardError=journal
SyslogIdentifier=cf-probe

[Install]
WantedBy=multi-user.target
UNIT

echo "[4/5] 启用并启动服务 ..."
systemctl daemon-reload
systemctl enable cf-probe.service >/dev/null 2>&1 || true
# 删除运行期配置副本，让 ExecStartPre 用 /etc 最新种子配置重建（保留 traffic.dat 流量计数）
rm -f /var/lib/private/cf-probe/config.conf /var/lib/cf-probe/config.conf 2>/dev/null || true
systemctl restart cf-probe.service

echo "[5/5] 完成，当前服务状态："
systemctl --no-pager --lines=0 status cf-probe.service || true
echo "日志查看: journalctl -u cf-probe -f"
`
}
