<#
  Chrome + persist-folder state snapshot/restore for the RDP handoff.

  -Mode Snapshot : close Chrome cleanly, save the open-tab list (fallback),
                   zip the Chrome profile (minus regenerable caches) and the
                   C:\rdp-persist folder into C:\rdp-state\chrome-state.zip.
  -Mode Restore  : unpack C:\rdp-state\chrome-state.zip (from the Actions
                   cache) into C:\rdp-state\ChromeProfile and C:\rdp-persist.
                   First run has no zip -> starts fresh, which is fine.

  Everything Chrome needs to restore cookies, logins, history, extensions
  and open tabs lives in the profile; the zip excludes only regenerable
  bulk (shader caches, crash reports, service-worker caches).
#>

param(
  [ValidateSet("Snapshot", "Restore")]
  [string]$Mode
)

$stateDir  = "C:\rdp-state"
$profile   = "$stateDir\ChromeProfile"
$persist   = "C:\rdp-persist"
$zipPath   = "$stateDir\chrome-state.zip"
$stageDir  = "$stateDir\stage"
$tabsPath  = "$stateDir\tabs.json"

# Directories inside the Chrome profile that are safe (and useful) to skip:
# they are large, regenerable, and carry no logins/cookies/history/tabs.
$excludeDirs = @("ShaderCache", "GrShaderCache", "Crashpad", "Crash Reports",
                 "Service Worker", "DawnCache", "GraphiteDawnCache")

function Write-SizeInfo($path, $label) {
  if (Test-Path $path) {
    $mb = [math]::Round((Get-ChildItem $path -Recurse -ErrorAction SilentlyContinue |
      Measure-Object Length -Sum).Sum / 1MB, 1)
    Write-Host "$label : ${mb} MB"
  }
}

if ($Mode -eq "Restore") {
  if (-not (Test-Path $zipPath)) { Write-Host "no state zip found — starting fresh"; exit 0 }
  if (Test-Path $stageDir) { Remove-Item $stageDir -Recurse -Force }
  Expand-Archive -Path $zipPath -DestinationPath $stageDir -Force
  if (Test-Path "$stageDir\ChromeProfile") {
    robocopy "$stageDir\ChromeProfile" $profile /E /R:1 /W:1 /NFL /NDL | Out-Null
  }
  if (Test-Path "$stageDir\persist") {
    robocopy "$stageDir\persist" $persist /E /R:1 /W:1 /NFL /NDL | Out-Null
  }
  Remove-Item $stageDir -Recurse -Force
  Write-SizeInfo $profile "restored Chrome profile"
  Write-Host "state restored"
  exit 0
}

# ---------- Snapshot ----------
New-Item -ItemType Directory -Force -Path $stateDir | Out-Null

# 1. Tab list fallback via CDP (cheap, always useful even if the zip is lost).
try {
  $tabs = Invoke-RestMethod -Uri "http://127.0.0.1:9222/json/list" -TimeoutSec 10
  $tabs | Select-Object url, title, type |
    ConvertTo-Json -Depth 3 | Out-File -Encoding utf8 $tabsPath
  Write-Host "saved tab list ($($tabs.Count) targets)"
} catch {
  Write-Host "CDP tab list unavailable: $($_.Exception.Message)"
}

# 2. Close Chrome so the profile on disk is in a clean, copyable state.
#    taskkill without /F asks nicely first (lets Chrome flush session files).
& taskkill /IM chrome.exe 2>$null | Out-Null
$deadline = (Get-Date).AddSeconds(25)
while ((Get-Process chrome -ErrorAction SilentlyContinue) -and ((Get-Date) -lt $deadline)) {
  Start-Sleep 1
}
& taskkill /F /IM chrome.exe 2>$null | Out-Null
Start-Sleep 2
Write-Host "Chrome closed"

# 3. Stage the profile (minus regenerable bulk) + persist folder.
if (Test-Path $stageDir) { Remove-Item $stageDir -Recurse -Force }
New-Item -ItemType Directory -Force -Path "$stageDir\ChromeProfile" | Out-Null
if (Test-Path $profile) {
  $xd = @("/XD") + $excludeDirs
  robocopy $profile "$stageDir\ChromeProfile" /E /R:1 /W:1 /NFL /NDL @xd | Out-Null
  $rc = $LASTEXITCODE
  if ($rc -ge 8) { throw "robocopy profile failed (exit $rc)" }
}
if (Test-Path $persist) {
  robocopy $persist "$stageDir\persist" /E /R:1 /W:1 /NFL /NDL | Out-Null
  if ($LASTEXITCODE -ge 8) { throw "robocopy persist failed (exit $LASTEXITCODE)" }
}

# 4. Zip it.
if (Test-Path $zipPath) { Remove-Item $zipPath -Force }
Compress-Archive -Path "$stageDir\*" -DestinationPath $zipPath -Force
Remove-Item $stageDir -Recurse -Force
Write-SizeInfo $zipPath "state zip"
Write-Host "snapshot complete: $zipPath"
