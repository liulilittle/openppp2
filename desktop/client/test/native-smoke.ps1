$ErrorActionPreference = 'Stop'
$repo = (Resolve-Path (Join-Path $PSScriptRoot '../../..')).Path
$qaDirectory = Join-Path $repo 'build/gui-checks'
$previousData = $env:OPENPPP2_CLIENT_DATA_DIR
$previousArguments = $env:WEBVIEW2_ADDITIONAL_BROWSER_ARGUMENTS
$previousModule = $env:PLAYWRIGHT_MODULE
$gui = $null
function Get-ProxyFingerprint {
    $settings = Get-ItemProperty 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Internet Settings'
    $text = $settings | Select-Object ProxyEnable, ProxyServer, ProxyOverride, AutoConfigURL | ConvertTo-Json -Compress
    $hash = [System.Security.Cryptography.SHA256]::Create()
    try { return [Convert]::ToBase64String($hash.ComputeHash([Text.Encoding]::UTF8.GetBytes($text))) }
    finally { $hash.Dispose() }
}
$originalProxy = Get-ProxyFingerprint
try {
    $portCheck = [Net.Sockets.TcpListener]::new([Net.IPAddress]::Loopback, 9223)
    try { $portCheck.Start() } finally { $portCheck.Stop() }
    New-Item -ItemType Directory -Path $qaDirectory -Force | Out-Null
    $env:OPENPPP2_CLIENT_DATA_DIR = Join-Path $qaDirectory 'native-state'
    $env:WEBVIEW2_ADDITIONAL_BROWSER_ARGUMENTS = '--remote-debugging-port=9223'
    $env:PLAYWRIGHT_MODULE = Join-Path $repo 'build/gui-tools/node_modules/playwright/index.mjs'
    Add-Type -TypeDefinition 'public static class GuiSmokeWindow { [System.Runtime.InteropServices.DllImport("user32.dll")] public static extern bool ShowWindow(System.IntPtr window, int command); }'
    $gui = Start-Process -FilePath (Join-Path $repo 'desktop/client/src-tauri/target/debug/openppp2-client-app.exe') -WorkingDirectory $repo -WindowStyle Hidden -PassThru
    for ($attempt = 0; $attempt -lt 50; $attempt++) {
        $gui.Refresh()
        if ($gui.HasExited) { throw 'Native QA client exited during startup' }
        if ($gui.MainWindowHandle -ne [IntPtr]::Zero) {
            [GuiSmokeWindow]::ShowWindow($gui.MainWindowHandle, 0) | Out-Null
            break
        }
        Start-Sleep -Milliseconds 100
    }
    $check = Start-Process -FilePath (Get-Command node.exe).Source -ArgumentList 'desktop/client/test/native-smoke.mjs' -WorkingDirectory $repo -WindowStyle Hidden -Wait -PassThru -RedirectStandardOutput (Join-Path $qaDirectory 'native-smoke.log') -RedirectStandardError (Join-Path $qaDirectory 'native-smoke-error.log')
    if ($check.ExitCode -ne 0) { throw (Get-Content (Join-Path $qaDirectory 'native-smoke-error.log') -Raw) }
    Get-Content (Join-Path $qaDirectory 'native-smoke.log')
} finally {
    if ($gui -and !$gui.HasExited) { Stop-Process -Id $gui.Id }
    $env:OPENPPP2_CLIENT_DATA_DIR = $previousData
    $env:WEBVIEW2_ADDITIONAL_BROWSER_ARGUMENTS = $previousArguments
    $env:PLAYWRIGHT_MODULE = $previousModule
    if ((Get-ProxyFingerprint) -ne $originalProxy) { throw 'Host system proxy changed during isolated QA' }
}
