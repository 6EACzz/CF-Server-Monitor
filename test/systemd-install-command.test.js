import assert from 'node:assert/strict'
import { spawnSync } from 'node:child_process'
import test from 'node:test'

import { buildSingleLineInstallCommand, buildSystemdInstallCommand } from '../src/frontend/utils/installCommand.js'

const baseOptions = {
  host: 'https://status.6eac.top',
  serverId: 'd508c1e2-99e5-4423-8b27-52c27bf7acd9',
  secret: 's3cr3t-value',
  serverName: 'Tokyo VPS',
  collectInterval: 0,
  reportInterval: 60,
  connectionMode: 'auto',
  pingMode: 'tcp',
  resetDay: 1,
  customCt: 'gd-ct-dualstack.ip.zstaticcdn.com',
  customCu: 'gd-cu-dualstack.ip.zstaticcdn.com',
  customCm: 'gd-cm-dualstack.ip.zstaticcdn.com',
  customBd: '',
  networkInterface: 'eth0,ens3',
  ghProxy: ''
}

test('systemd hardened command: global install paths (binary + direct config)', () => {
  const cmd = buildSystemdInstallCommand(baseOptions)

  // Binary -> /usr/local/bin, executable
  assert.match(cmd, /curl -fsSL "https:\/\/github\.com\/huilang-me\/cfsm-agent\/releases\/latest\/download\/cf-probe-linux-\$\{ARCH\}" -o \/usr\/local\/bin\/cf-probe/)
  assert.match(cmd, /chmod 0755 \/usr\/local\/bin\/cf-probe/)

  // Config written straight to /etc/cf-probe/config.conf, world readable
  assert.match(cmd, /mkdir -p \/etc\/cf-probe/)
  assert.match(cmd, /cat > \/etc\/cf-probe\/config\.conf <<'CFG'/)
  assert.match(cmd, /chmod 0644 \/etc\/cf-probe\/config\.conf/)

  // No per-user ownership/permission handling, no state-dir copy machinery
  assert.doesNotMatch(cmd, /chown/)
  assert.doesNotMatch(cmd, /cf-probe:cf-probe/)
  assert.doesNotMatch(cmd, /StateDirectory/)
  assert.doesNotMatch(cmd, /ExecStartPre/)
  assert.doesNotMatch(cmd, /\/var\/lib\/(private\/)?cf-probe/)

  // Service steps
  assert.match(cmd, /\/etc\/systemd\/system\/cf-probe\.service/)
  assert.match(cmd, /systemctl daemon-reload/)
  assert.match(cmd, /systemctl enable cf-probe\.service/)
  assert.match(cmd, /systemctl restart cf-probe\.service/)
})

test('systemd hardened command: unit uses the config file directly with static literal paths', () => {
  const cmd = buildSystemdInstallCommand(baseOptions)

  assert.match(cmd, /ExecStart=\/usr\/local\/bin\/cf-probe run -config=\/etc\/cf-probe\/config\.conf/)
  assert.match(cmd, /DynamicUser=yes/)

  // no leftover copy/seeding machinery or systemd-expanded variables
  assert.doesNotMatch(cmd, /\$\{STATE_DIRECTORY\}/)
  assert.doesNotMatch(cmd, /@CFSM_BIN@/)
  assert.doesNotMatch(cmd, /@CFSM_DIR@/)
  assert.doesNotMatch(cmd, /sed -i/)
  assert.doesNotMatch(cmd, /ExecStartPre/)
})

test('systemd hardened command: config block carries the install parameters without indentation', () => {
  const cmd = buildSystemdInstallCommand(baseOptions)
  assert.match(cmd, /SERVER_ID="d508c1e2-99e5-4423-8b27-52c27bf7acd9"/)
  assert.match(cmd, /SECRET="s3cr3t-value"/)
  assert.match(cmd, /WORKER_URL="https:\/\/status\.6eac\.top\/update"/)
  assert.match(cmd, /COLLECT_INTERVAL="0"/)
  assert.match(cmd, /REPORT_INTERVAL="60"/)
  assert.match(cmd, /RESET_DAY="1"/)
  assert.match(cmd, /CONNECTION_MODE="auto"/)
  assert.match(cmd, /PING_MODE="tcp"/)
  assert.match(cmd, /AUTO_UPDATE="0"/)
  assert.match(cmd, /CT_NODE="gd-ct-dualstack\.ip\.zstaticcdn\.com"/)
  assert.match(cmd, /CU_NODE="gd-cu-dualstack\.ip\.zstaticcdn\.com"/)
  assert.match(cmd, /CM_NODE="gd-cm-dualstack\.ip\.zstaticcdn\.com"/)
  assert.match(cmd, /INTERFACE="eth0,ens3"/)
  assert.doesNotMatch(cmd, /BD_NODE=/)

  // 配置行不允许带缩进（每行直接 KEY="value"）
  const configLines = cmd.split('\n').filter(line => /^(SERVER_ID|SECRET|WORKER_URL|COLLECT_INTERVAL|REPORT_INTERVAL|RESET_DAY|CONNECTION_MODE|PING_MODE|AUTO_UPDATE)=/.test(line))
  assert.ok(configLines.length >= 9)
  for (const line of configLines) {
    assert.equal(line.match(/^(\s*)/)[1], '', `config line has leading whitespace: ${line}`)
  }
})

test('systemd hardened command: default CPU/memory limits with core detection', () => {
  const cmd = buildSystemdInstallCommand(baseOptions)

  // 核心数检测 → 硬编码配额：单核 5%，多核 10%
  assert.match(cmd, /getconf _NPROCESSORS_ONLN 2>\/dev\/null \|\| nproc 2>\/dev\/null \|\| echo 1/)
  assert.match(cmd, /CPU_QUOTA=10/)
  assert.match(cmd, /CPU_QUOTA=5/)

  // 写入服务的资源限额（CPUQuota 由脚本运行时替换为具体数值，最终文件中为纯数字）
  assert.match(cmd, /CPUQuota="?\$\{CPU_QUOTA\}%"?/)
  assert.match(cmd, /MemoryMax=30M/)
  assert.match(cmd, /CPUWeight=10/)
})

test('systemd hardened command: unit uses DynamicUser with a moderate hardening set', () => {
  const cmd = buildSystemdInstallCommand(baseOptions)
  assert.match(cmd, /ProtectSystem=strict/)
  assert.match(cmd, /ProtectHome=read-only/)
  assert.match(cmd, /NoNewPrivileges=yes/)
  assert.match(cmd, /PrivateTmp=yes/)
  assert.match(cmd, /RestrictAddressFamilies=AF_UNIX AF_INET AF_INET6 AF_NETLINK/)
  assert.match(cmd, /^CapabilityBoundingSet=$/m)
  assert.match(cmd, /^AmbientCapabilities=$/m)
  assert.match(cmd, /Restart=on-failure/)
  assert.match(cmd, /WantedBy=multi-user\.target/)

  // 移除过于激进的选项（保留适度约束）
  assert.doesNotMatch(cmd, /SystemCallFilter/)
  assert.doesNotMatch(cmd, /MemoryDenyWriteExecute/)
  assert.doesNotMatch(cmd, /LockPersonality/)
  assert.doesNotMatch(cmd, /RestrictNamespaces/)
  assert.doesNotMatch(cmd, /ProtectKernelModules/)
  assert.doesNotMatch(cmd, /ProtectClock/)
  assert.doesNotMatch(cmd, /ProtectHostname/)
  assert.doesNotMatch(cmd, /ProtectProc=/) // no ProtectProc line at all
  assert.doesNotMatch(cmd, /PrivateDevices=/)
})

test('systemd hardened command: ICMP mode grants only CAP_NET_RAW', () => {
  const cmd = buildSystemdInstallCommand({ ...baseOptions, pingMode: 'icmp' })
  assert.match(cmd, /PING_MODE="icmp"/)
  assert.match(cmd, /CapabilityBoundingSet=CAP_NET_RAW/)
  assert.match(cmd, /AmbientCapabilities=CAP_NET_RAW/)
  assert.doesNotMatch(cmd, /^CapabilityBoundingSet=$/m)
})

test('systemd hardened command: gh proxy prefixes the download URL and sets UPDATE_PROXY', () => {
  const cmd = buildSystemdInstallCommand({ ...baseOptions, ghProxy: 'https://ghfast.top/' })
  assert.match(cmd, /https:\/\/ghfast\.top\/https:\/\/github\.com\/huilang-me\/cfsm-agent\/releases\/latest\/download\/cf-probe-linux-\$\{ARCH\}/)
  assert.match(cmd, /UPDATE_PROXY="https:\/\/ghfast\.top\/"/)
})

test('systemd hardened command: heredocs are closed and the script is shell-syntactically valid', () => {
  const cmd = buildSystemdInstallCommand(baseOptions)
  assert.match(cmd, /<<'CFG'/)
  assert.match(cmd, /^CFG$/m)
  assert.match(cmd, /<<UNIT/)
  assert.match(cmd, /^UNIT$/m)

  const bash = spawnSync('bash', ['-n', '-s'], { input: cmd })
  if (bash.error) {
    // bash unavailable in this environment; skip syntax validation
    return
  }
  assert.equal(bash.status, 0, `bash -n failed:\n${bash.stderr}`)
})

test('systemd hardened command: values are quoted/escaped in the KV config', () => {
  const cmd = buildSystemdInstallCommand({
    ...baseOptions,
    secret: 'ab"cd',
    customCt: 'node.example'
  })
  assert.match(cmd, /SECRET="ab\\"cd"/)
})

test('single-line command: base64 round-trips the script and pipes to sh', () => {
  const script = buildSystemdInstallCommand(baseOptions)
  const line = buildSingleLineInstallCommand(script)

  // One single line: echo '<b64>' | base64 -d | sh
  assert.equal(line.split('\n').length, 1)
  const match = line.match(/^echo '([A-Za-z0-9+/=]+)' \| base64 -d \| sh$/)
  assert.ok(match, `unexpected single-line format: ${line.slice(0, 80)}...`)

  // Decoded content must be exactly the original script
  const decoded = Buffer.from(match[1], 'base64').toString('utf8')
  assert.equal(decoded, script)
  assert.match(decoded, /\/usr\/local\/bin\/cf-probe run -config=\/etc\/cf-probe\/config\.conf/)
  assert.match(decoded, /DynamicUser=yes/)

  // Decoded script must remain shell-syntactically valid
  const bash = spawnSync('bash', ['-n', '-s'], { input: decoded })
  if (!bash.error) {
    assert.equal(bash.status, 0, `bash -n failed on decoded script:\n${bash.stderr}`)
  }
})
