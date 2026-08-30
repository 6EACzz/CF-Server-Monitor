// Generates the hardened systemd (DynamicUser) installation command for the
// cf-probe agent, offered as an alternative to the upstream install.sh
// bootstrap (`curl .../install.sh | sh -s -- install ...`).
//
// Behavior of the generated command (multi-line script):
//   - resolves the install directory to a static absolute path first:
//       <home>/.local/opt/CfServerMonitor/
//     (home is derived from SUDO_USER / $HOME, then mkdir -p creates it)
//   - downloads the release binary into <home>/.local/opt/CfServerMonitor/cf-probe
//   - writes the seed config <home>/.local/opt/CfServerMonitor/config.conf
//   - writes /etc/systemd/system/cf-probe.service running `cf-probe run`
//     with DynamicUser=yes plus strong hardening (ProtectSystem=strict,
//     no capabilities, seccomp, restricted address families, ...); the
//     resolved absolute binary/config paths are baked into the unit
//   - config used by the agent is a copy inside systemd's StateDirectory
//     (owned by the dynamic user) so remote config updates and traffic.dat
//     state remain writable; the seed config is re-copied by ExecStartPre
//     when missing
//   - AUTO_UPDATE is fixed to 0: a dynamic user cannot self-update (upstream
//     update path shells out to `install` as root); rerun the command to upgrade
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
export const CFSM_INSTALL_SUBDIR = '.local/opt/CfServerMonitor'

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
#   - 安装目录: ~/.local/opt/CfServerMonitor/（脚本先解析成静态绝对路径，再 mkdir -p 创建）
#   - 二进制: ~/${CFSM_INSTALL_SUBDIR}/cf-probe（解析后的绝对路径会写入 systemd 单元）
#   - 种子配置: ~/${CFSM_INSTALL_SUBDIR}/config.conf（0600，仅属主可读）
#   - 服务 cf-probe.service 以 DynamicUser=yes 运行并启用强安全约束
#     （ProtectSystem=strict、seccomp、无 capabilities、受限地址族等）
#   - dynamicUser 下探针无法自我更新，AUTO_UPDATE 固定为 0；
#     升级时重新执行本命令即可（流量计数会保留）
# 注意: 动态用户需要能遍历/读取安装目录（home 需为 755 或对路径加 o+x），
#       否则服务无法读取二进制和种子配置。
# ============================================================
set -e

# 0) 解析安装目录为静态绝对路径（systemd 单元不支持 ~ 展开，先解析再写入单元）
if [ -n "\${SUDO_USER:-}" ] && [ "\$SUDO_USER" != "root" ] && getent passwd "\$SUDO_USER" >/dev/null 2>&1; then
  USER_HOME="\$(getent passwd "\$SUDO_USER" | cut -d: -f6)"
else
  USER_HOME="\${HOME:-/root}"
fi
CFSM_DIR="\${USER_HOME}/${CFSM_INSTALL_SUBDIR}"
mkdir -p "\$CFSM_DIR"
CFSM_BIN="\${CFSM_DIR}/cf-probe"

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

echo "[1/5] 下载 cf-probe-linux-\$ARCH 到 \$CFSM_BIN ..."
curl -fsSL "${downloadBase}/cf-probe-linux-\${ARCH}" -o "\$CFSM_BIN"
chmod 0755 "\$CFSM_BIN"

echo "[2/5] 写入种子配置 \$CFSM_DIR/config.conf ..."
cat > "\$CFSM_DIR/config.conf" <<'CFG'
${configBlock}
CFG
chmod 0600 "\$CFSM_DIR/config.conf"

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
ExecStartPre=+/bin/sh -c 'test -f "\${STATE_DIRECTORY}/config.conf" || { /bin/install -m 0600 @CFSM_DIR@/config.conf "\${STATE_DIRECTORY}/config.conf" && /bin/chown cf-probe:cf-probe "\${STATE_DIRECTORY}/config.conf" || /bin/chmod 0644 "\${STATE_DIRECTORY}/config.conf"; }'
ExecStart=@CFSM_BIN@ run -config="\${STATE_DIRECTORY}/config.conf"
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
# 二进制位于用户主目录下，动态用户需能读取（read-only 而非 yes）
ProtectHome=read-only
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
# 将解析后的静态绝对路径写入单元（systemd 不支持 ~/$HOME）
sed -i -e "s|@CFSM_BIN@|\${CFSM_BIN}|g" -e "s|@CFSM_DIR@|\${CFSM_DIR}|g" /etc/systemd/system/cf-probe.service

echo "[4/5] 启用并启动服务 ..."
systemctl daemon-reload
systemctl enable cf-probe.service >/dev/null 2>&1 || true
# 删除运行期配置副本，让 ExecStartPre 用最新种子配置重建（保留 traffic.dat 流量计数）
rm -f /var/lib/private/cf-probe/config.conf /var/lib/cf-probe/config.conf 2>/dev/null || true
systemctl restart cf-probe.service

echo "[5/5] 完成，当前服务状态："
systemctl --no-pager --lines=0 status cf-probe.service || true
echo "日志查看: journalctl -u cf-probe -f"
echo "安装目录: \${CFSM_DIR}"
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
