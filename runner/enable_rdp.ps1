<#
  Enables RDP on the GitHub-hosted Windows runner for the runneradmin user.

  Env required: RDP_PASSWORD (strong password, from the repo secret).
  Keeps NLA enabled. Waits until 3389 is listening, then exits.
#>

$password = $env:RDP_PASSWORD
if (-not $password) { throw "RDP_PASSWORD env var is required (set the repo secret)" }
if ($password.Length -lt 12) { throw "RDP_PASSWORD must be at least 12 characters" }

# Set the password for the runner's admin user.
net user runneradmin "$password" | Out-Null
if ($LASTEXITCODE -ne 0) { throw "failed to set runneradmin password (exit $LASTEXITCODE)" }
Write-Host "runneradmin password set"

# Enable Remote Desktop (Terminal Services).
Set-ItemProperty -Path "HKLM:\System\CurrentControlSet\Control\Terminal Server" `
  -Name "fDenyTSConnections" -Value 0
Write-Host "Remote Desktop enabled"

# Allow RDP through the Windows firewall.
Enable-NetFirewallRule -DisplayGroup "Remote Desktop"
Write-Host "Firewall rule enabled"

# NLA stays enabled (default) — mstsc and all modern RDP clients support it.

# Wait until 3389 is actually listening.
for ($i = 0; $i -lt 30; $i++) {
  $t = Test-NetConnection -ComputerName 127.0.0.1 -Port 3389 -WarningAction SilentlyContinue
  if ($t.TcpTestSucceeded) { Write-Host "RDP is listening on 3389"; exit 0 }
  Start-Sleep 2
}
throw "RDP did not start listening on 3389"
