<#
  Agent Detector — Windows 本地安装脚本（设计文档 §10）

  作用：
    1. 创建虚拟环境并安装本项目（可编辑安装，供 hook_bridge 与 CLI 使用）
    2. 打印本机采集通道可用状态（Sysmon / auditd / 采样）
    3. 生成 Hook 决策服务所需的环境信息（Token 文件、决策接口地址）

  明确不做的事：
    - 不安装 Sysmon，不修改 Sysmon 配置（请按 configs\sysmon.xml 手动合并）
    - 不写入任何 Agent 的 Hook 配置（用 `agent-detector hooks install --apply` 显式安装）
    - 不提权、不改注册表、不开机自启

  用法（普通用户 PowerShell 即可）：
    powershell -ExecutionPolicy Bypass -File scripts\install.ps1
    powershell -ExecutionPolicy Bypass -File scripts\install.ps1 -Python "C:\Python313\python.exe"
#>
[CmdletBinding()]
param(
  [string]$Python = "python",
  [string]$VenvPath = ".venv",
  [switch]$SkipTests
)

$ErrorActionPreference = "Stop"
$repoRoot = Split-Path -Parent $PSScriptRoot
Write-Host "Agent Detector 安装" -ForegroundColor Cyan
Write-Host "仓库目录: $repoRoot"

function Write-Step($text) { Write-Host "==> $text" -ForegroundColor Cyan }
function Write-Ok($text) { Write-Host "    $text" -ForegroundColor Green }
function Write-Warn($text) { Write-Host "    $text" -ForegroundColor Yellow }

Write-Step "检查 Python"
$version = & $Python --version 2>&1
if ($LASTEXITCODE -ne 0) { throw "未找到 Python，可传入 -Python 指定解释器路径" }
Write-Ok $version

Write-Step "创建虚拟环境 $VenvPath"
$venvPython = Join-Path $repoRoot "$VenvPath\Scripts\python.exe"
if (-not (Test-Path $venvPython)) {
  & $Python -m venv (Join-Path $repoRoot $VenvPath)
  Write-Ok "已创建"
} else {
  Write-Ok "已存在，复用"
}

Write-Step "安装依赖与本体（可编辑安装）"
& $venvPython -m pip install --upgrade pip | Out-Null
& $venvPython -m pip install -e (Join-Path $repoRoot ".[test]")
if ($LASTEXITCODE -ne 0) { throw "pip 安装失败" }
Write-Ok "agent-detector 已安装到 $venvPython"

if (-not $SkipTests) {
  Write-Step "运行测试"
  Push-Location $repoRoot
  & $venvPython -m pytest -q
  if ($LASTEXITCODE -ne 0) { Write-Warn "测试未全部通过，请查看上面的输出" } else { Write-Ok "测试通过" }
  Pop-Location
}

Write-Step "采集通道检查"
& $venvPython -m agent_detector.cli.main channels

Write-Step "准备 Hook 决策 Token"
$env:AGENT_DETECTOR_HOOK_TOKEN_FILE = Join-Path $repoRoot "data\hook.token"
& $venvPython -c "from agent_detector.common.config import hook_token; print('Token 文件:', __import__('agent_detector.common.config', fromlist=['HOOK_TOKEN_PATH']).HOOK_TOKEN_PATH); print('Token 前缀:', hook_token()[:8] + '...')"

Write-Host ""
Write-Host "安装完成。下一步：" -ForegroundColor Green
Write-Host "  1. 启动控制台：  $venvPython -m agent_detector.cli.main serve"
Write-Host "  2. 首次扫描：    $venvPython -m agent_detector.cli.main scan"
Write-Host "  3. 查看 Agent：  $venvPython -m agent_detector.cli.main agents list"
Write-Host "  4. 安装 Hook（先 dry-run，确认后再 --apply）："
Write-Host "     $venvPython -m agent_detector.cli.main hooks status"
Write-Host "     $venvPython -m agent_detector.cli.main hooks plan claude_code"
Write-Host "     $venvPython -m agent_detector.cli.main hooks install claude_code --apply"
Write-Host ""
Write-Host "Sysmon（可选，用于系统行为采集）：按 configs\sysmon.xml 的头部说明合并配置。" -ForegroundColor Yellow
Write-Host "注意：Hook 安装在当前用户配置目录，同权限用户可修改；企业级需要托管配置与防篡改。" -ForegroundColor Yellow