# End-to-end test of Windows system mode: the TUN interface with FakeIP DNS,
# and the WFP kill switch (on, and persistent across a daemon stop). Runs
# a separate daemon (own pipe, data dir and ports), so an installed Moley
# is untouched. Needs an elevated PowerShell:
#
#   test\windows\system.ps1 -Bin bin -Log system.log
#
# The kill switch is always lifted at the end, whatever happens.
param([string]$Bin = "$PSScriptRoot\..\..\bin", [string]$Log = "$env:TEMP\moley-system-test.log")
$ErrorActionPreference = 'Stop'
$Bin = (Resolve-Path $Bin).Path
$work = Join-Path $env:TEMP "moley-system-test"
Remove-Item -Recurse -Force $work -ErrorAction SilentlyContinue
New-Item -ItemType Directory -Force "$work\stack", "$work\home" | Out-Null
Start-Transcript -Path $Log -Force | Out-Null

$script:pass = 0
function Ok($what) { "  ok   $what"; $script:pass++ }
function Fail($what) { throw "FAIL $what" }
function Check($what, [scriptblock]$cond) { if (& $cond) { Ok $what } else { Fail $what } }
function Reachable($url, $iface) {
  $a = @('-s', '-o', 'NUL', '-w', '%{http_code}', '--max-time', '4', $url)
  if ($iface) { $a = @('--interface', $iface) + $a }
  $code = & curl.exe @a 2>$null
  return $LASTEXITCODE -eq 0 -and $code -ne '000'
}

$env:MOLEY_HOME = "$work\home"
$env:MOLEY_PIPE = '\\.\pipe\moley-systemtest'
$m = "$Bin\moley.exe"
$daemon = $null
function Start-Daemon {
  $script:daemon = Start-Process -PassThru -WindowStyle Hidden $m -ArgumentList 'service', '--system' -RedirectStandardError "$work\daemon.log"
  for ($i = 0; $i -lt 50; $i++) { & $m status *> $null; if ($LASTEXITCODE -eq 0) { return }; Start-Sleep -Milliseconds 200 }
  throw "daemon did not start: $(Get-Content "$work\daemon.log" -Tail 5)"
}

$stack = Start-Process -PassThru -WindowStyle Hidden "$Bin\teststack.exe" -ArgumentList "$work\stack"
try {
  for ($i = 0; $i -lt 50 -and -not (Test-Path "$work\stack\urls.txt"); $i++) { Start-Sleep -Milliseconds 200 }
  $port = ((Get-Content "$work\stack\urls.txt" | Select-String '^public').ToString() -replace '.*:(\d+)/.*', '$1')
  @{ default_exit = 'direct'; settings = @{ proxy_port = 7995 } } | ConvertTo-Json | Set-Content -Encoding utf8 "$work\home\moley.json"
  $phys = (Get-NetIPConfiguration | Where-Object { $_.IPv4DefaultGateway -and $_.NetAdapter.Status -eq 'Up' } | Select-Object -First 1).IPv4Address.IPAddress
  "physical address: $phys"

  "== service mode"
  Start-Daemon
  & $m import "$work\stack\ss.txt" --id ss | Out-Null
  & $m rules add echo --exit ss --domain echo.test | Out-Null
  Check "runs as the service would (system data dir rules, machine sealing)" { (& $m status --json | ConvertFrom-Json).mode.service }

  "== system mode"
  & $m mode --tun on | Out-Null
  Check "tun adapter up" { Get-NetAdapter -Name moley -ErrorAction SilentlyContinue }
  Check "the internet still works through it" { Reachable 'http://www.msftconnecttest.com/connecttest.txt' }
  Check "  and Moley carried it (inbound tun)" { (& $m conns --closed --json | ConvertFrom-Json).conns | Where-Object { $_.inbound -eq 'tun' } }
  $out = & curl.exe -s --max-time 5 "http://echo.test:$port/trace"
  Check "a rule sends echo.test via Shadowsocks, named through FakeIP ($($out -join ' '))" { "$out" -match 'ip=127\.0\.0\.4' }
  Check "apps got a FakeIP address" { (Resolve-DnsName echo.test -Type A -DnsOnly -ErrorAction SilentlyContinue).IPAddress -match '^198\.1[89]\.' }

  "== kill switch"
  Check "without it, a socket bound to the Wi-Fi/Ethernet address leaks past the tunnel" { Reachable 'http://1.1.1.1/' $phys }
  & $m mode --kill-switch on | Out-Null
  Check "with it, that socket is blocked" { -not (Reachable 'http://1.1.1.1/' $phys) }
  Check "traffic through Moley still flows" { Reachable 'http://1.1.1.1/' }
  & $m rules add other --exit direct --domain other.test | Out-Null
  Check "still blocked after a rebuild (new adapter)" { -not (Reachable 'http://1.1.1.1/' $phys) }
  Check "  and Moley still flows after it" { Reachable 'http://1.1.1.1/' }
  & $m stop | Out-Null; $daemon.WaitForExit(10000) | Out-Null
  Check "on: lifted when Moley stops" { Reachable 'http://1.1.1.1/' $phys }

  "== persistent kill switch"
  Start-Daemon
  & $m mode --kill-switch persistent --yes | Out-Null
  & $m stop | Out-Null; $daemon.WaitForExit(10000) | Out-Null
  Check "persistent: nothing gets out with Moley stopped" { -not (Reachable 'http://1.1.1.1/') }
  $gw = (Get-NetIPConfiguration | Where-Object { $_.IPv4DefaultGateway } | Select-Object -First 1).IPv4DefaultGateway.NextHop
  Check "  but the local network does (ping $gw)" { ping.exe -n 1 -w 1500 $gw | Select-String 'TTL=' }
  Start-Daemon
  Check "back with Moley" { Reachable 'http://1.1.1.1/' }
  & $m mode --kill-switch off | Out-Null
  & $m mode --tun off | Out-Null
  Check "tun off: adapter gone" { -not (Get-NetAdapter -Name moley -ErrorAction SilentlyContinue) }
  "windows system mode: $script:pass checks passed"
} catch {
  "$_"
} finally {
  if (Get-Service Moley -ErrorAction SilentlyContinue) {
    "a Moley service is installed: lift the block from the test daemon instead"
    if (-not $daemon -or $daemon.HasExited) { Start-Daemon }
    & $m mode --kill-switch off | Out-Null
  } else {
    & $m service uninstall --yes *> $null # lifts any block left behind
  }
  if ($daemon -and -not $daemon.HasExited) { Stop-Process -Id $daemon.Id -Force }
  Get-Process -Id $stack.Id -ErrorAction SilentlyContinue | Stop-Process -Force
  Check "nothing left blocking" { Reachable 'http://1.1.1.1/' }
  Stop-Transcript | Out-Null
}
