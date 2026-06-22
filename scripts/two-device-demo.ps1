#!/usr/bin/env pwsh
#
# two-device-demo.ps1 — a local, two-"device" CE Notes sync demo (Windows / PowerShell).
#
# PowerShell port of two-device-demo.sh. Simulates two devices on one machine by running two CE
# nodes with separate data dirs (and thus separate identities), then creating a space on device A,
# sharing it to device B by capability, and editing on both — converging over the mesh.
#
# Prereqs:
#   * a `ce` binary on PATH (the CE node), built from the ce repo
#   * this crate built: `cargo build` in this repo (produces target/debug/ce-notes.exe)
#
# Runs under PowerShell 7+ (pwsh) on Windows, macOS, and Linux. This is a demonstration harness,
# not a CI test (it starts real nodes and uses the live mesh). The pure-logic paths are covered by
# `cargo test`.

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

$Here = Split-Path -Parent $MyInvocation.MyCommand.Path
$Root = Split-Path -Parent $Here

# Binary name differs per OS (.exe on Windows). Honor CE_NOTES_BIN if set.
$ExeSuffix = if ($IsWindows) { '.exe' } else { '' }
$Notes = if ($env:CE_NOTES_BIN) { $env:CE_NOTES_BIN } else { Join-Path $Root "target/debug/ce-notes$ExeSuffix" }
$CeBin = if ($env:CE_BIN) { $env:CE_BIN } else { 'ce' }

$Work = Join-Path ([System.IO.Path]::GetTempPath()) ("ce-notes-demo." + [System.IO.Path]::GetRandomFileName())
$ADATA = Join-Path $Work 'deviceA'
$BDATA = Join-Path $Work 'deviceB'
New-Item -ItemType Directory -Force -Path $ADATA, $BDATA | Out-Null

# Two nodes need distinct ports.
$AAPI = 8844
$BAPI = 8855
$AP2P = 4101
$BP2P = 4102

$script:AProc = $null
$script:BProc = $null

function Stop-Nodes {
    Write-Host '>> stopping nodes'
    foreach ($p in @($script:AProc, $script:BProc)) {
        if ($p -and -not $p.HasExited) {
            try { $p.Kill() } catch { }
        }
    }
    Write-Host ">> work dir left at: $Work (remove when done)"
}

if (-not (Test-Path $Notes)) {
    Write-Error "ce-notes binary not found at $Notes — run 'cargo build' first"
    exit 1
}

try {
    Write-Host ">> starting device A node (api :$AAPI, p2p :$AP2P)"
    $script:AProc = Start-Process -FilePath $CeBin -PassThru -NoNewWindow `
        -ArgumentList @('start', '--data-dir', $ADATA, '--api-port', "$AAPI", '--p2p-port', "$AP2P", '--no-mine') `
        -RedirectStandardOutput (Join-Path $Work 'nodeA.out.log') `
        -RedirectStandardError  (Join-Path $Work 'nodeA.err.log')

    Write-Host ">> starting device B node (api :$BAPI, p2p :$BP2P)"
    $script:BProc = Start-Process -FilePath $CeBin -PassThru -NoNewWindow `
        -ArgumentList @('start', '--data-dir', $BDATA, '--api-port', "$BAPI", '--p2p-port', "$BP2P", '--no-mine') `
        -RedirectStandardOutput (Join-Path $Work 'nodeB.out.log') `
        -RedirectStandardError  (Join-Path $Work 'nodeB.err.log')

    Write-Host '>> waiting for both nodes to answer /health'
    foreach ($url in @("http://127.0.0.1:$AAPI/health", "http://127.0.0.1:$BAPI/health")) {
        for ($i = 0; $i -lt 30; $i++) {
            try { Invoke-WebRequest -UseBasicParsing -Uri $url -TimeoutSec 2 | Out-Null; break }
            catch { Start-Sleep -Seconds 1 }
        }
    }

    function Invoke-A { & $Notes --node-url "http://127.0.0.1:$AAPI" --data-dir $ADATA --identity-dir (Join-Path $ADATA 'identity') @args }
    function Invoke-B { & $Notes --node-url "http://127.0.0.1:$BAPI" --data-dir $BDATA --identity-dir (Join-Path $BDATA 'identity') @args }

    Write-Host (">> device A id: " + (Invoke-A whoami))
    $BID = (Invoke-B whoami)
    Write-Host ">> device B id: $BID"

    Write-Host '>> A creates a space'
    $ASpaceLine = Invoke-A space new 'Shared Work'
    Write-Host "   $ASpaceLine"
    $ASpace = ($ASpaceLine -split '\s+')[2]

    Write-Host '>> A creates a note and writes a body'
    $Note = Invoke-A new --space $ASpace 'Roadmap'
    Invoke-A set --space $ASpace $Note "# Roadmap`n`n- ship notes`n" | Out-Null
    Write-Host "   note id: $Note"

    Write-Host '>> A invites B as a writer'
    $InvitePath = Join-Path $Work 'invite.bin'
    Invoke-A invite --space $ASpace --to $BID --role writer --out $InvitePath | Out-Null
    Write-Host '>> B imports the invite'
    Invoke-B import $InvitePath

    Write-Host '>> giving the mesh a moment to converge'
    Start-Sleep -Seconds 3
    try { Invoke-B sync --space $ASpace } catch { }

    Write-Host '>> B reads the note A wrote:'
    try { Invoke-B cat --space $ASpace $Note } catch { Write-Host '   (not converged yet — check nodeA/B logs)' }

    Write-Host '>> B appends a concurrent edit'
    Invoke-B set --space $ASpace $Note "# Roadmap`n`n- ship notes`n- review from B`n" | Out-Null
    Start-Sleep -Seconds 3
    try { Invoke-A sync --space $ASpace } catch { }

    Write-Host '>> A reads back the merged note:'
    try { Invoke-A cat --space $ASpace $Note } catch { }

    Write-Host '>> done. Both devices should show the same merged body once converged.'
}
finally {
    Stop-Nodes
}
