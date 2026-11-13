# Build the React console into the Python package's static directory.
# Requires Node 18+ and npm. Run from the repository root.
$ErrorActionPreference = "Stop"
$root = Split-Path -Parent $PSScriptRoot
Push-Location (Join-Path $root "frontend")
try {
    if (-not (Test-Path "node_modules")) {
        npm install
    }
    npm run build
} finally {
    Pop-Location
}
Write-Host "Built: src/agent_detector/console/web/next"