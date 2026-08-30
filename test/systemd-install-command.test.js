import assert from 'node:assert/strict'
import { spawnSync } from 'node:child_process'
import test from 'node:test'

import { buildSystemdInstallCommand, CFSM_REPO_SLUG } from '../src/frontend/utils/installCommand.js'

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

test('systemd hardened command: binary download, config and service paths', () => {
  const cmd = buildSystemdInstallCommand(baseOptions)

  // Binary download -> /usr/local/bin
  assert.match(cmd, /curl -fsSL "https:\/\/github\.com\/huilang-me\/cfsm-agent\/releases\/latest\/download\/cf-probe-linux-\$\{ARCH\}" -o \/usr\/local\/bin\/cf-probe/)
  assert.match(cmd, /chmod 0755 \/usr\/local\/bin\/cf-probe/)

  // Config file location
  assert.match(cmd, /\/etc\/cf-probe\/config\.conf/)
  assert.match(cmd, /install -d -m 0755 \/etc\/cf-probe/)

  // Service unit location
  assert.match(cmd, /\/etc\/systemd\/system\/cf-probe\.service/)

  // systemd-service enable/start steps
  assert.match(cmd, /systemctl daemon-reload/)
  assert.match(cmd, /systemctl enable cf-probe\.service/)
  assert.match(cmd, /systemctl restart cf-probe\.service/)
})

test('systemd hardened command: config block carries the install parameters', () => {
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
})

test('systemd hardened command: unit uses DynamicUser with strong hardening', () => {
  const cmd = buildSystemdInstallCommand(baseOptions)
  assert.match(cmd, /DynamicUser=yes/)
  assert.match(cmd, /StateDirectory=cf-probe/)
  assert.match(cmd, /ExecStart=\/usr\/local\/bin\/cf-probe run -config="\$\{STATE_DIRECTORY\}\/config\.conf"/)
  assert.match(cmd, /ExecStartPre=\+\/bin\/sh -c 'test -f "\$\{STATE_DIRECTORY\}\/config\.conf"/)
  assert.match(cmd, /ProtectSystem=strict/)
  assert.match(cmd, /ProtectHome=yes/)
  assert.match(cmd, /NoNewPrivileges=yes/)
  assert.match(cmd, /PrivateTmp=yes/)
  assert.match(cmd, /PrivateDevices=yes/)
  assert.match(cmd, /MemoryDenyWriteExecute=yes/)
  assert.match(cmd, /SystemCallFilter=@system-service/)
  assert.match(cmd, /RestrictAddressFamilies=AF_UNIX AF_INET AF_INET6 AF_NETLINK/)
  assert.match(cmd, /^CapabilityBoundingSet=$/m)
  assert.match(cmd, /^AmbientCapabilities=$/m)
  assert.match(cmd, /Restart=on-failure/)
  assert.match(cmd, /WantedBy=multi-user\.target/)
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
  assert.match(cmd, /<<'UNIT'/)
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
