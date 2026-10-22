<#
  Agent Detector — 卸载脚本

  作用：
    1. 移除本工具写入的 Agent Hook 条目（会先备份被修改的配置文件）
    2. 打印审计规则卸载命令（auditd 在 Linux 侧，Windows 上忽略）
    3. 提示手动删除数据库、虚拟环境与数据目录

  不会自动删除数据目录与虚拟环境：那属于破坏性操作，需要你自己确认后再执行。
#>
[CmdletBinding()]
param(
  [string]$VenvPath = ".venv",
  [switch]$KeepHookConfig,
  [switch]$PurgeData
)

$ErrorActionPreference = "Stop"
$repoRoot = Split-Path -Parent $PSScriptRoot
$venvPython = Join-Path $repoRoot "$VenvPath\Scripts\python.exe"
if (-not (Test-Path $venvPython)) { $venvPython = "python" }

function Write-Step($text) { Write-Host "==> $text" -ForegroundColor Cyan }

if (-not $KeepHookConfig) {
  Write-Step "卸载 Hook 条目（先备份，再移除本工具写入的条目）"
  & $venvPython -m agent_detector.cli.main hooks uninstall --apply
  Write-Host "    已保留你原有的 Hook 配置项；备份文件与被修改的配置在同一目录。" -ForegroundColor Green
}

Write-Step "当前 Hook 状态"
& $venvPython -m agent_detector.cli.main hooks status

Write-Step "保留策略清理（按配置的天数删除历史行为事件）"
& $venvPython -m agent_detector.cli.main purge

if ($PurgeData) {
  $dataDir = Join-Path $repoRoot "data"
  Write-Step "删除数据目录 $dataDir"
  if (Test-Path $dataDir) {
    Remove-Item -Recurse -Force $dataDir
    Write-Host "    已删除" -ForegroundColor Green
  } else {
    Write-Host "    不存在，跳过"
  }
}

Write-Host ""
Write-Host "卸载完成。仍需要手动处理的项目：" -ForegroundColor Yellow
Write-Host "  - 虚拟环境：Remove-Item -Recurse -Force $VenvPath"
Write-Host "  - 数据库与 Token：$repoRoot\data（加 -PurgeData 可自动删除）"
Write-Host "  - Sysmon 配置：如需还原，运行 sysmon64.exe -c <你原来的配置>"
Write-Host "  - Linux 审计规则：sudo auditctl -W <规则文件> 或删除 /etc/audit/rules.d/agent-detector.rules"
Write-Host "  - pip 安装：$venvPython -m pip uninstall agent-detector"