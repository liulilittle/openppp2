param(
    [ValidateRange(1, 15)][int]$Seconds = 3,
    [ValidateRange(1, 10)][int]$Rounds = 3,
    [string]$Binary = '',
    [string]$OutputDirectory = ''
)

$ErrorActionPreference = 'Stop'
$root = [IO.Path]::GetFullPath((Join-Path $PSScriptRoot '..'))
if (-not $Binary) {
    $Binary = Join-Path $root 'build\ninja-xtcp-validation\bin\xtcp_runtime_bridge_test.exe'
}
$Binary = [IO.Path]::GetFullPath($Binary)
if (-not (Test-Path -LiteralPath $Binary -PathType Leaf)) {
    throw 'Build the Windows xtcp_runtime_bridge_test target first.'
}
if (-not $OutputDirectory) {
    $OutputDirectory = Join-Path $root ('build\xtcp-validation\throughput-' + [DateTime]::UtcNow.ToString('yyyyMMdd-HHmmss-fff'))
}
$OutputDirectory = [IO.Path]::GetFullPath($OutputDirectory)
New-Item -ItemType Directory -Path $OutputDirectory -ErrorAction Stop | Out-Null

# Only the test executable is launched. Child settings never mutate the host's
# environment, routing, adapters, DNS, drivers or proxy configuration.
$rows = @()
for ($round = 1; $round -le $Rounds; $round++) {
    $modes = if ($round % 2 -eq 1) { @('winsock', 'xtcp') } else { @('xtcp', 'winsock') }
    foreach ($mode in $modes) {
        $info = New-Object Diagnostics.ProcessStartInfo
        $info.FileName = $Binary
        $info.Arguments = "--throughput $mode $Seconds"
        $info.WorkingDirectory = $root
        $info.UseShellExecute = $false
        $info.RedirectStandardOutput = $true
        $info.RedirectStandardError = $true
        foreach ($name in @($info.EnvironmentVariables.Keys)) {
            if ($name -like 'OPENPPP2_XTCP_*') { $info.EnvironmentVariables.Remove($name) }
        }
        $process = New-Object Diagnostics.Process
        $process.StartInfo = $info
        if (-not $process.Start()) { throw 'Could not start loopback benchmark.' }
        if (-not $process.WaitForExit(($Seconds + 20) * 1000)) {
            $process.Kill()
            $process.WaitForExit()
            throw "Timed out: round $round / $mode"
        }
        $stdout = $process.StandardOutput.ReadToEnd()
        $stderr = $process.StandardError.ReadToEnd()
        $code = $process.ExitCode
        $process.Dispose()
        $prefix = Join-Path $OutputDirectory ("round-$round-$mode")
        [IO.File]::WriteAllText("$prefix.stdout.json", $stdout)
        [IO.File]::WriteAllText("$prefix.stderr.log", $stderr)
        if ($code -ne 0) { throw "Benchmark failed: round $round / $mode; see $prefix.stderr.log" }
        $row = $stdout | ConvertFrom-Json
        if (-not $row.byte_exact -or $row.ingress_dropped -ne 0 -or
            $row.payload_bytes -le 0 -or $row.seconds -le 0) {
            throw "Unqualified result: round $round / $mode"
        }
        $row | Add-Member -NotePropertyName round -NotePropertyValue $round
        $row | Add-Member -NotePropertyName mode -NotePropertyValue $mode
        $rows += $row
        Write-Output ("round={0} mode={1} Mbps={2} CPU-ns/B={3} byte-exact={4}" -f
            $round, $mode, $row.mbps, $row.cpu_ns_per_byte, $row.byte_exact)
    }
}

function Get-Median($values) {
    $sorted = @($values | Sort-Object)
    $middle = [int][Math]::Floor($sorted.Count / 2)
    if ($sorted.Count % 2 -eq 1) { return [double]$sorted[$middle] }
    return ([double]$sorted[$middle - 1] + [double]$sorted[$middle]) / 2.0
}
$summary = @()
foreach ($mode in @('winsock', 'xtcp')) {
    $selected = @($rows | Where-Object mode -eq $mode)
    $summary += [PSCustomObject]@{
        mode = $mode
        median_mbps = Get-Median @($selected | ForEach-Object mbps)
        min_mbps = ($selected | Measure-Object mbps -Minimum).Minimum
        max_mbps = ($selected | Measure-Object mbps -Maximum).Maximum
        median_cpu_ns_per_byte = Get-Median @($selected | ForEach-Object cpu_ns_per_byte)
    }
}
$report = [PSCustomObject]@{
    scope = 'Windows loopback component reference; not native-vs-XTCP PPP/Wintun VPN throughput'
    binary_sha256 = (Get-FileHash -LiteralPath $Binary -Algorithm SHA256).Hash.ToLowerInvariant()
    warmup_seconds_per_connection = 1
    requested_measure_seconds = $Seconds
    rounds = $Rounds
    note = 'XTCP additionally includes synthetic IPv4/TCP generation, checksums, ACK driving, output copies and parsing. Drain is integrity-checked outside the timed window. Process CPU includes the harness and echo server. No VPN speedup ratio is valid.'
    summary = $summary
    samples = $rows
}
$report | ConvertTo-Json -Depth 6 | Set-Content -LiteralPath (Join-Path $OutputDirectory 'results.json') -Encoding UTF8
$summary | Format-Table -AutoSize
Write-Output (Join-Path $OutputDirectory 'results.json')
