<#
.SYNOPSIS
    Windows Server maintenance health-check script.

.DESCRIPTION
    Pre/post maintenance review covering: system health, CPU/memory, storage, OS, services,
    event logs, network, security, backup, virtualization, databases, performance, maintenance
    history, a triaged issue list (High/Medium/Low), and recommendations.

    Physical (hands-on) checks are intentionally omitted: cabling, bezel LEDs, console/video,
    drive-bay indicators. Remote-readable hardware health is attempted where Windows exposes it
    (SMART via WMI, physical disk health, Hyper-V status, etc.).
	
.AUTHOR
    Mike Perez
	
.GITHUB
	https://github.com/mik3p3r3z

.CREATED
    2026-08-2026

.NOTES
    Run from an elevated PowerShell console for full coverage.
    Requires PowerShell 3.0+ (Windows Server 2008 R2 SP1+ recommended, 2012 R2+ ideal).
    The script is read-only; it makes no configuration changes.

.EXAMPLE
    .\WindowsServer-MaintenanceHealthCheck.ps1

.EXAMPLE
    .\WindowsServer-MaintenanceHealthCheck.ps1 -ReportPath "C:\Reports\health-2026-08-05.log"
#>
[CmdletBinding()]
param(
    [string]$ReportPath
)

$ErrorActionPreference = 'Continue'
$script:StartTime = Get-Date

#==============================================================================#
# Output / report helpers
#==============================================================================#
$script:IssuesHigh = New-Object System.Collections.ArrayList
$script:IssuesMed  = New-Object System.Collections.ArrayList
$script:IssuesLow  = New-Object System.Collections.ArrayList

function Write-Line {
    param([string]$Text = "")
    $script:ReportWriter.WriteLine($Text)
    Write-Host $Text
}

function Write-Section {
    param([string]$Title)
    $line = ('=' * 72)
    Write-Line ""
    $script:ReportWriter.WriteLine($line)
    $script:ReportWriter.WriteLine("  $Title")
    $script:ReportWriter.WriteLine($line)
    Write-Host ""
    Write-Host $line -ForegroundColor Cyan
    Write-Host "  $Title" -ForegroundColor Cyan
    Write-Host $line -ForegroundColor Cyan
}

function Write-Info {
    param([string]$Message)
    $script:ReportWriter.WriteLine("  [INFO]  $Message")
    Write-Host ("  [INFO]  " + $Message) -ForegroundColor Blue
}

function Write-Ok {
    param([string]$Message)
    $script:ReportWriter.WriteLine("  [ OK ]  $Message")
    Write-Host ("  [ OK ]  " + $Message) -ForegroundColor Green
}

function Write-Warn {
    param([string]$Message)
    $script:ReportWriter.WriteLine("  [WARN]  $Message")
    Write-Host ("  [WARN]  " + $Message) -ForegroundColor Yellow
}

function Write-Fail {
    param([string]$Message)
    $script:ReportWriter.WriteLine("  [FAIL]  $Message")
    Write-Host ("  [FAIL]  " + $Message) -ForegroundColor Red
}

function Write-Table {
    param($InputObject)
    $rows = ($InputObject | Format-Table -AutoSize -Wrap | Out-String -Width 300) -split "`r?`n"
    foreach ($r in $rows) {
        if ($r.Trim()) {
            Write-Line ("    " + $r.TrimEnd())
        }
    }
}

function Add-Issue {
    param(
        [ValidateSet('High','Medium','Low')]
        [string]$Level,
        [string]$Message
    )
    switch ($Level) {
        'High'   { [void]$script:IssuesHigh.Add($Message) }
        'Medium' { [void]$script:IssuesMed.Add($Message) }
        'Low'    { [void]$script:IssuesLow.Add($Message) }
    }
}

function Test-IsAdmin {
    $principal = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
    return $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

function Get-PendingReboot {
    $keys = @(
        'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Component Based Servicing\RebootPending',
        'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update\RebootRequired',
        'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update\PostRebootReporting'
    )
    foreach ($k in $keys) {
        if (Test-Path $k) { return $true }
    }
    try {
        $sm = Get-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager' -Name PendingFileRenameOperations -ErrorAction SilentlyContinue
        if ($sm -and $sm.PendingFileRenameOperations) { return $true }
    } catch { }
    return $false
}

function Get-EventRecordCount {
    param([string]$LogName, [int]$EventId, [int]$Days)
    $start = (Get-Date).AddDays(-$Days)
    try {
        $events = Get-WinEvent -FilterHashtable @{ LogName = $LogName; Id = $EventId; StartTime = $start } -ErrorAction SilentlyContinue
        return @($events).Count
    } catch {
        return 0
    }
}

function Get-ElevatedNote {
    param([string]$What)
    Write-Info "$What - requires elevation, skipped (re-run as Administrator)."
}

#==============================================================================#
# 1. SYSTEM HEALTH
#==============================================================================#
function Test-SystemHealth {
    Write-Section "SYSTEM HEALTH"
    try {
        $os   = Get-CimInstance Win32_OperatingSystem
        $cs   = Get-CimInstance Win32_ComputerSystem
        $days = [math]::Round(((Get-Date) - $os.LastBootUpTime).TotalDays, 1)

        Write-Info ("Host: {0} | Domain/Workgroup: {1} | Model: {2} {3}" -f $env:COMPUTERNAME, $cs.Domain, $cs.Manufacturer, $cs.Model)
        Write-Info ("Last boot: {0} | Uptime: {1} days" -f $os.LastBootUpTime, $days)
        if ($days -gt 60) {
            Write-Warn "System uptime is $days days - schedule a reboot during next maintenance window."
            Add-Issue 'Low' "Uptime is $days days."
        }

        # WHEA hardware errors (corrected/uncorrected)
        $whea = Get-EventRecordCount 'System' 18 7 + (Get-EventRecordCount 'System' 19 7) + (Get-EventRecordCount 'System' 1 7)
        if ($whea -gt 0) {
            Write-Fail "$whea WHEA hardware error event(s) in the last 7 days (System log)."
            Add-Issue 'High' "$whea WHEA hardware error event(s) in last 7 days."
        } else {
            Write-Ok "No WHEA hardware errors in last 7 days."
        }

        # Disk / volume errors
        $diskErr = (Get-EventRecordCount 'System' 7 7) + (Get-EventRecordCount 'System' 51 7) + (Get-EventRecordCount 'System' 153 7)
        if ($diskErr -gt 0) {
            Write-Fail "$diskErr disk/controller error event(s) (IDs 7/51/153) in last 7 days."
            Add-Issue 'High' "$diskErr disk/controller errors in the last 7 days."
        } else {
            Write-Ok "No disk/controller errors in last 7 days."
        }

        # Unexpected shutdowns (Event 6008)
        $shut = Get-EventRecordCount 'System' 6008 90
        if ($shut -gt 0) {
            Write-Warn "$shut unexpected shutdown(s) recorded in the last 90 days."
            Add-Issue 'Medium' "$shut unexpected shutdown(s) in the last 90 days."
        }

        # Time service
        $timeSvc = Get-Service w32time -ErrorAction SilentlyContinue
        if ($timeSvc -and $timeSvc.Status -eq 'Running') {
            Write-Ok "Windows Time service is running."
            try {
                $w32 = & w32tm /query /status 2>$null | Out-String
                ($w32 -split "`r?`n") | Select-Object -First 6 | ForEach-Object { if ($_.Trim()) { Write-Line ("    " + $_.Trim()) } }
            } catch { }
        } else {
            Write-Warn "Windows Time service is NOT running - clock may drift."
            Add-Issue 'Medium' 'Windows Time service (w32time) is not running.'
        }

        # Temperature / hardware sensors (remote-readable only)
        Write-Info "Physical thermal monitoring requires vendor tools (Dell OpenManage, HP iLO/SSA, Lenovo XClarity)."
        Write-Info "WMI-based SMBIOS thermal readings are rarely exposed; see RECOMMENDATIONS for vendor tooling."
    } catch {
        Write-Warn "System health section encountered an error: $($_.Exception.Message)"
    }
}

#==============================================================================#
# 2. CPU / MEMORY
#==============================================================================#
function Test-CpuMemory {
    Write-Section "CPU / MEMORY"
    try {
        $procs = Get-CimInstance Win32_Processor
        $cores = ($procs | Measure-Object -Property NumberOfLogicalProcessors -Sum).Sum
        $cpuLoad = [math]::Round(($procs | Measure-Object -Property LoadPercentage -Average).Average, 1)

        $cpuSample = $null
        try {
            $cpuSample = Get-Counter '\Processor(_Total)\% Processor Time' -SampleInterval 2 -MaxSamples 3 -ErrorAction SilentlyContinue
            $cpuSample = [math]::Round(($cpuSample.CounterSamples.CookedValue | Measure-Object -Average).Average, 1)
        } catch { }

        $queue = $null
        try { $queue = (Get-Counter '\System\Processor Queue Length' -ErrorAction SilentlyContinue).CounterSamples[0].CookedValue } catch { }

        Write-Info ("Logical processors: {0} | CPU load (WMI): {1}% | CPU load (counter avg 3x2s): {2}%" -f $cores, $cpuLoad, $cpuSample)
        if ($queue -ne $null) { Write-Info "Processor Queue Length: $queue" }

        if ($cpuSample -gt 90) {
            Write-Fail "Sustained CPU usage is ${cpuSample}%."
            Add-Issue 'High' "CPU usage elevated (${cpuSample}%)."
        } elseif ($cpuSample -gt 75) {
            Write-Warn "CPU usage is ${cpuSample}%."
            Add-Issue 'Medium' "CPU usage at ${cpuSample}%."
        }
        if ($queue -ne $null -and $queue -gt ($cores * 2)) {
            Write-Warn "Processor queue length ($queue) exceeds 2x cores ($cores) - CPU saturation risk."
            Add-Issue 'Medium' "Processor queue length ($queue) vs cores ($cores)."
        }

        # Memory
        $os = Get-CimInstance Win32_OperatingSystem
        $totMB = [math]::Round($os.TotalVisibleMemorySize / 1024, 1)
        $freeMB = [math]::Round($os.FreePhysicalMemory / 1024, 1)
        $freePct = [math]::Round($freeMB * 100 / $totMB, 1)
        Write-Line ("  Memory: {0} MB total, {1} MB free ({2}% free)" -f $totMB, $freeMB, $freePct)
        if ($freePct -lt 10) {
            Write-Fail "Only ${freePct}% physical memory available - critical pressure."
            Add-Issue 'High' "Available memory is ${freePct}%."
        } elseif ($freePct -lt 20) {
            Write-Warn "Only ${freePct}% physical memory available."
            Add-Issue 'Medium' "Available memory is ${freePct}%."
        }

        # Pagefile usage
        $pf = $null
        try { $pf = (Get-Counter '\Paging File(_Total)\% Usage' -ErrorAction SilentlyContinue).CounterSamples[0].CookedValue } catch { }
        if ($pf -ne $null) {
            Write-Line ("  Pagefile usage: {0}%" -f [math]::Round($pf, 1))
            if ($pf -gt 80) {
                Write-Fail "Pagefile usage is ${pf}%."
                Add-Issue 'High' "Pagefile usage ${pf}%."
            } elseif ($pf -gt 50) {
                Write-Warn "Pagefile usage is ${pf}%."
                Add-Issue 'Medium' "Pagefile usage ${pf}%."
            }
        } else {
            Write-Info "No pagefile usage counter returned (pagefile may be disabled or system-managed)."
        }

        # Top consumers
        Write-Line "  Top CPU (cumulative CPU seconds):"
        Get-Process | Sort-Object CPU -Descending -ErrorAction SilentlyContinue | Select-Object -First 8 |
            ForEach-Object { Write-Line ("    PID {0,-8} {1,-30} CPU {2,10:N0}s  WS {3,10:N0} MB" -f $_.Id, $_.ProcessName, $_.CPU, ($_.WorkingSet64 / 1MB)) }
        Write-Line "  Top memory consumers:"
        Get-Process | Sort-Object WorkingSet64 -Descending -ErrorAction SilentlyContinue | Select-Object -First 8 |
            ForEach-Object { Write-Line ("    PID {0,-8} {1,-30} WS {2,10:N0} MB  Handles {3,6}" -f $_.Id, $_.ProcessName, ($_.WorkingSet64 / 1MB), $_.HandleCount) }
    } catch {
        Write-Warn "CPU/memory section encountered an error: $($_.Exception.Message)"
    }
}

#==============================================================================#
# 3. STORAGE
#==============================================================================#
function Test-Storage {
    Write-Section "STORAGE"
    try {
        $disks = Get-CimInstance Win32_LogicalDisk -Filter "DriveType=3"
        Write-Line "  Logical disks:"
        foreach ($d in $disks) {
            $sizeGB = [math]::Round($d.Size / 1GB, 1)
            $freeGB = [math]::Round($d.FreeSpace / 1GB, 1)
            $freePct = if ($d.Size -gt 0) { [math]::Round($d.FreeSpace * 100 / $d.Size, 1) } else { 0 }
            Write-Line ("    {0} ({1})  {2} {3}  Size: {4,8} GB  Free: {5,8} GB  ({6}% free)" -f `
                $d.DeviceID, $d.VolumeName, $d.FileSystem, $d.DriveType, $sizeGB, $freeGB, $freePct)
            if ($freePct -lt 10) {
                Write-Fail "Volume $($d.DeviceID) is ${freePct}% free - critical."
                Add-Issue 'High' "Volume $($d.DeviceID) only ${freePct}% free."
            } elseif ($freePct -lt 20) {
                Write-Warn "Volume $($d.DeviceID) is ${freePct}% free."
                Add-Issue 'Medium' "Volume $($d.DeviceID) only ${freePct}% free."
            }
        }

        # Physical disk health (Storage module, admin)
        try {
            $pdisks = Get-PhysicalDisk -ErrorAction Stop
            Write-Line "  Physical disks (Storage health):"
            $pdisks | Select-Object FriendlyName, MediaType, @{N='SizeGB';E={[math]::Round($_.Size/1GB,1)}}, HealthStatus, OperationalStatus |
                ForEach-Object { Write-Line ("    {0,-28} {1,-8} {2,8} GB  {3,-10} {4}" -f $_.FriendlyName, $_.MediaType, $_.SizeGB, $_.HealthStatus, $_.OperationalStatus) }
            foreach ($p in $pdisks) {
                if ($p.HealthStatus -ne 'Healthy') {
                    Write-Fail "Physical disk '$($p.FriendlyName)' health status: $($p.HealthStatus)"
                    Add-Issue 'High' "Physical disk '$($p.FriendlyName)' is $($p.HealthStatus)."
                }
            }
        } catch {
            Get-ElevatedNote "Physical disk health via Storage module (Get-PhysicalDisk)"
        }

        # SMART failure prediction via WMI
        try {
            $badSMART = Get-WmiObject -Namespace root\wmi -Class MSStorageDriver_FailurePredictStatus -ErrorAction SilentlyContinue |
                Where-Object { $_.PredictFailure -eq $true }
            if ($badSMART) {
                Write-Fail "SMART predicts failure on: $($badSMART.InstanceName -join ', ')"
                Add-Issue 'High' "SMART failure prediction active on one or more disks."
            } else {
                Write-Ok "SMART failure prediction reports no pending failures."
            }
        } catch { }

        # Dirty volumes (chkdsk pending)
        $dirtyVolumes = @()
        foreach ($d in $disks) {
            try {
                $out = fsutil dirty query "$($d.DeviceID)" 2>$null | Out-String
                if ($out -match 'dirty') {
                    Write-Fail "Volume $($d.DeviceID) is marked DIRTY - chkdsk required."
                    $dirtyVolumes += $($d.DeviceID)
                }
            } catch { }
        }
        if ($dirtyVolumes.Count -gt 0) { Add-Issue 'High' "Volumes marked dirty: $($dirtyVolumes -join ', ')" }
        elseif ($disks) { Write-Ok "No volumes marked dirty." }

        # Temp directory sizes
        $tempDirs = @($env:TEMP, "$($env:SystemRoot)\Temp")
        foreach ($t in $tempDirs) {
            try {
                if (Test-Path $t) {
                    $sz = (Get-ChildItem $t -Recurse -Force -ErrorAction SilentlyContinue | Measure-Object Length -Sum).Sum
                    
                    if ($sz -gt 5GB) {
                        # Pass the path as the first argument {0} and the size as {1}
                        Write-Warn ("Temp directory {0} is {1} GB - consider cleaning." -f $t, [math]::Round($sz/1GB,1))
                        Add-Issue 'Low' ("Temp directory {0} is large." -f $t)
                    } else {
                        Write-Info ("Temp directory {0}: {1} MB" -f $t, [math]::Round($sz/1MB,1))
                    }
                }
            } catch { }
        }

    } catch {
        Write-Warn "Storage section encountered an error: $($_.Exception.Message)"
    }
}

#==============================================================================#
# 4. OPERATING SYSTEM
#==============================================================================#
function Test-OperatingSystem {
    Write-Section "OPERATING SYSTEM"
    try {
        $os = Get-CimInstance Win32_OperatingSystem
        $edition = (Get-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion' -Name EditionID -ErrorAction SilentlyContinue).EditionID
        Write-Info ("OS: {0} ({1}) | Version {2} build {3}" -f $os.Caption, $edition, $os.Version, $os.BuildNumber)
        Write-Info "Architecture: $($os.OSArchitecture)"

        try {
            $installEpoch = (Get-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion' -Name InstallDate -ErrorAction SilentlyContinue).InstallDate
            if ($installEpoch) {
                $installDate = [DateTimeOffset]::FromUnixTimeSeconds($installEpoch).LocalDateTime
                Write-Info "OS install date: $installDate"
            }
        } catch { }

        Write-Info "Last boot: $($os.LastBootUpTime)"

        # Pending reboot
        $reboot = Get-PendingReboot
        if ($reboot) {
            Write-Warn "A reboot is PENDING for this server (CBS/WU/PendingFileRenameOperations)."
            Add-Issue 'Medium' 'Pending reboot detected.'
        } else {
            Write-Ok "No pending reboot detected."
        }

        # .NET Framework version (from registry)
        try {
            $ndp = Get-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\NET Framework Setup\NDP\v4\Full' -Name Release -ErrorAction SilentlyContinue
            if ($ndp) {
                $dotnet = switch ($ndp.Release) {
                    { $_ -ge 528040 } { '4.8+' }
                    { $_ -ge 461808 } { '4.7.2' }
                    { $_ -ge 461308 } { '4.7.1' }
                    { $_ -ge 460798 } { '4.7' }
                    { $_ -ge 394802 } { '4.6.2' }
                    { $_ -ge 394271 } { '4.6.1' }
                    { $_ -ge 393295 } { '4.6' }
                    default { '4.x' }
                }
                Write-Info ".NET Framework 4.x: $dotnet (Release $($ndp.Release))"
            }
        } catch { }

        Write-Info "PowerShell version: $($PSVersionTable.PSVersion)"

        # Windows Update / hotfix summary
        try {
            $hotfixes = Get-HotFix -ErrorAction SilentlyContinue
            Write-Info "Installed hotfixes: $($hotfixes.Count)"
            $latest = $hotfixes | Where-Object InstalledOn | Sort-Object InstalledOn -Descending | Select-Object -First 3
            foreach ($h in $latest) {
                Write-Line ("    {0}  {1}  installed {2}" -f $h.HotFixID, $h.Description, $h.InstalledOn)
            }
            $lastPatch = ($hotfixes | Sort-Object InstalledOn -Descending | Select-Object -First 1).InstalledOn
            if ($lastPatch -and ((Get-Date) - $lastPatch).Days -gt 90) {
                Write-Warn "Last hotfix installed over 90 days ago ($lastPatch)."
                Add-Issue 'Medium' "No Windows patches installed in over 90 days."
            }
        } catch {
            Get-ElevatedNote "Hotfix inventory (Get-HotFix)"
        }

        Write-Info "Time zone: $((Get-TimeZone).Id)"
    } catch {
        Write-Warn "OS section encountered an error: $($_.Exception.Message)"
    }
}

#==============================================================================#
# 5. SERVICES
#==============================================================================#
function Test-Services {
    Write-Section "SERVICES"
    try {
        # Automatic services that are stopped
        $autoStopped = Get-CimInstance Win32_Service -ErrorAction SilentlyContinue |
            Where-Object { $_.StartMode -eq 'Auto' -and $_.State -ne 'Running' }
        if ($autoStopped) {
            Write-Warn "Automatic services that are NOT running:"
            $autoStopped | Select-Object Name, DisplayName, State | ForEach-Object {
                Write-Line ("    {0,-32} {1,-50} {2}" -f $_.Name, $_.DisplayName, $_.State)
                Add-Issue 'High' "Automatic service stopped: $($_.Name)"
            }
        } else {
            Write-Ok "All automatic services are running."
        }

        # Critical services status report
        Write-Line "  Critical services:"
        $critical = @('TermService','WinRM','W32Time','BITS','EventLog','Dnscache','gpsvc','Dhcp','LanmanServer','LanmanWorkstation','Spooler')
        foreach ($svc in $critical) {
            $s = Get-Service -Name $svc -ErrorAction SilentlyContinue
            if ($s) {
                $color = if ($s.Status -eq 'Running') { 'Green' } else { 'Yellow' }
                Write-Line ("    {0,-24} {1}" -f $s.Name, $s.Status)
                if ($s.Status -ne 'Running') {
                    Write-Warn "Critical service $($s.Name) is not running."
                    Add-Issue 'High' "Critical service $($s.Name) not running."
                }
            }
        }

        # Device problems (PnP errors)
        try {
            $badDevices = Get-PnpDevice -PresentOnly -ErrorAction SilentlyContinue | Where-Object { $_.Status -and $_.Status -ne 'OK' -and $_.Status -ne 'Unknown' }
            if ($badDevices) {
                Write-Warn "Devices reporting problems:"
                $badDevices | Select-Object -First 10 | ForEach-Object { Write-Line ("    {0}  [{1}]" -f $_.FriendlyName, $_.Status) }
                Add-Issue 'Medium' "Devices with problems: $($badDevices.Count) (see SERVICES section)."
            } else {
                Write-Ok "No problem devices found."
            }
        } catch { }

        # Scheduled task errors (last 24h)
        $taskErr = Get-EventRecordCount 'Microsoft-Windows-TaskScheduler/Operational' 201 1
        if ($taskErr -gt 0) {
            Write-Warn "$taskErr scheduled task failure event(s) in the last 24 hours."
            Add-Issue 'Medium' "$taskErr scheduled task failures in last 24h."
        }

        # Listening ports
        Write-Line "  Listening TCP ports:"
        try {
            Get-NetTCPConnection -State Listen -ErrorAction SilentlyContinue |
                Select-Object LocalAddress, LocalPort, @{N='Process';E={(Get-Process -Id $_.OwningProcess -ErrorAction SilentlyContinue).ProcessName}} |
                Sort-Object LocalPort -Unique | Select-Object -First 40 |
                ForEach-Object { Write-Line ("    {0,-15} : {1,-6} {2}" -f $_.LocalAddress, $_.LocalPort, $_.Process) }
        } catch {
            # Fallback for older hosts
            netstat -an | Select-String 'LISTENING' | ForEach-Object { Write-Line ("    " + $_.Line.Trim()) } | Select-Object -First 30
        }
    } catch {
        Write-Warn "Services section encountered an error: $($_.Exception.Message)"
    }
}

#==============================================================================#
# 6. EVENT LOGS
#==============================================================================#
function Test-EventLogs {
    Write-Section "EVENT LOGS"
    try {
        # Event log configuration
        Get-WinEvent -ListLog System, Application, Security -ErrorAction SilentlyContinue |
            ForEach-Object {
                Write-Line ("    {0,-12} MaxSize: {1,8:N0} MB | IsFull: {2,-5} | Mode: {3}" -f $_.LogName, ($_.MaximumSizeInBytes/1MB), $_.IsFull, $_.LogMode)
                if ($_.IsFull) {
                    Write-Warn "Event log $($_.LogName) is FULL."
                    Add-Issue 'Low' "Event log $($_.LogName) is full."
                }
            }

        # Recent errors
        $sysErr = @(Get-WinEvent -FilterHashtable @{ LogName='System'; Level=2; StartTime=(Get-Date).AddHours(-24) } -ErrorAction SilentlyContinue)
        $appErr = @(Get-WinEvent -FilterHashtable @{ LogName='Application'; Level=2; StartTime=(Get-Date).AddHours(-24) } -ErrorAction SilentlyContinue)
        Write-Line "  Errors (last 24h): System=$($sysErr.Count), Application=$($appErr.Count)"
        if ($sysErr.Count -gt 0) {
            Write-Warn "Last System log errors (top 10):"
            $sysErr | Select-Object -First 10 | ForEach-Object {
                Write-Line ("    [{0}] {1}  {2}" -f $_.Id, $_.ProviderName, $_.Message.Substring(0, [math]::Min(120, $_.Message.Length)))
            }
            Add-Issue 'Medium' "$($sysErr.Count) System log errors in last 24h."
        } else {
            Write-Ok "No System log errors in last 24h."
        }

        # Failed logons
        $failLogons = Get-EventRecordCount 'Security' 4625 7
        Write-Line "  Failed logon attempts (Event 4625, 7 days): $failLogons"
        if ($failLogons -gt 500) {
            Write-Fail "SSH/remote brute-force scale activity: $failLogons failed logons in 7 days."
            Add-Issue 'High' "500+ failed logons in 7 days."
        } elseif ($failLogons -gt 50) {
            Write-Warn "$failLogons failed logons in 7 days."
            Add-Issue 'Medium' "Elevated failed logons ($failLogons in 7 days)."
        }

        # Service crash events
        $svcCrashes = Get-EventRecordCount 'System' 7034 7 + (Get-EventRecordCount 'System' 7031 7) + (Get-EventRecordCount 'System' 7032 7)
        if ($svcCrashes -gt 0) {
            Write-Fail "$svcCrashes service crash event(s) (7031/7032/7034) in last 7 days."
            Add-Issue 'High' "$svcCrashes service crash events in last 7 days."
        }
    } catch {
        Write-Warn "Event log section encountered an error: $($_.Exception.Message)"
    }
}

#==============================================================================#
# 7. NETWORK
#==============================================================================#
function Test-Network {
    Write-Section "NETWORK"
    try {
        # Adapters
        Write-Line "  Network adapters:"
        Get-NetAdapter -ErrorAction SilentlyContinue |
            Select-Object Name, InterfaceDescription, Status, LinkSpeed |
            ForEach-Object { Write-Line ("    {0,-12} {1,-40} {2,-10} {3}" -f $_.Name, $_.InterfaceDescription, $_.Status, $_.LinkSpeed) }

        # IP config
        Write-Line "  IP configuration:"
        Get-NetIPConfiguration -ErrorAction SilentlyContinue |
            Where-Object { $_.IPv4Address } |
            ForEach-Object {
                $gw = ($_.IPv4DefaultGateway.NextHop -join ',')
                $dns = ($_.DNSServer | Where-Object AddressFamily -eq 2 | ForEach-Object Address) -join ', '
                Write-Line ("    Adapter: {0} | IP: {1} | GW: {2} | DNS: {3}" -f $_.InterfaceAlias, ($_.IPv4Address.IPAddress -join ', '), $gw, $dns)
            }

        # Interface errors
        $adapterErrors = @(Get-NetAdapterStatistics -ErrorAction SilentlyContinue |
            Where-Object { $_.ReceivedDiscards -gt 100 -or $_.OutboundDiscards -gt 100 -or $_.ReceivedErrors -gt 0 -or $_.OutboundErrors -gt 0 })
        if ($adapterErrors.Count -gt 0) {
            Write-Warn "Adapter error/discard counters elevated:"
            $adapterErrors | Select-Object Name, ReceivedErrors, ReceivedDiscards, OutboundDiscards, OutboundErrors |
                ForEach-Object { Write-Line ("    {0}: RXerr={1} RXdisc={2} TXdisc={3} TXerr={4}" -f $_.Name, $_.ReceivedErrors, $_.ReceivedDiscards, $_.OutboundDiscards, $_.OutboundErrors) }
            Add-Issue 'Medium' "Network adapter errors/discards detected."
        } else {
            Write-Ok "No network adapter errors/discards."
        }

        # Gateway reachability
        $gw = (Get-NetIPConfiguration -ErrorAction SilentlyContinue | Where-Object IPv4DefaultGateway | Select-Object -First 1).IPv4DefaultGateway.NextHop
        if ($gw) {
            if (Test-Connection -ComputerName $gw -Count 1 -Quiet -ErrorAction SilentlyContinue) {
                Write-Ok "Default gateway $gw reachable (ICMP)."
            } else {
                Write-Warn "Default gateway $gw did not respond to ICMP (may be firewalled)."
            }
        } else {
            Write-Warn "No IPv4 default gateway found."
        }

        # DNS resolution
        try {
            $dns = Resolve-DnsName -Name google.com -Type A -ErrorAction Stop | Select-Object -First 1
            Write-Ok "External DNS resolution OK (google.com -> $($dns.IPAddress))."
        } catch {
            Write-Warn "External DNS resolution failed (google.com). May be normal on isolated networks."
            Add-Issue 'Medium' 'External DNS resolution failed.'
        }

        # External connectivity
        if (Test-Connection -ComputerName 1.1.1.1 -Count 1 -Quiet -ErrorAction SilentlyContinue) {
            Write-Ok "External connectivity OK (1.1.1.1 reachable)."
        } else {
            Write-Warn "1.1.1.1 not reachable - may be firewalled or an isolated network."
        }

        # TCP state summary
        try {
            $tcp = Get-NetTCPConnection -ErrorAction SilentlyContinue
            Write-Line ("  TCP connections: Established={0} TimeWait={1} SynSent={2} Closed={3}" -f `
                (@($tcp | Where-Object State -eq 'Established').Count),
                (@($tcp | Where-Object State -eq 'TimeWait').Count),
                (@($tcp | Where-Object State -eq 'SynSent').Count),
                (@($tcp | Where-Object State -eq 'Closed').Count))
        } catch { }
    } catch {
        Write-Warn "Network section encountered an error: $($_.Exception.Message)"
    }
}

#==============================================================================#
# 8. SECURITY
#==============================================================================#
function Test-Security {
    Write-Section "SECURITY"
    try {
        # Firewall
        try {
            $fw = Get-NetFirewallProfile -ErrorAction Stop
            $fwDisabled = $fw | Where-Object Enabled -eq $false
            foreach ($p in $fw) {
                $state = if ($p.Enabled) { 'Enabled' } else { 'DISABLED' }
                Write-Line ("    Firewall profile {0,-10}: {1}" -f $p.Name, $state)
            }
            if ($fwDisabled) {
                Write-Fail "Firewall profile(s) disabled: $($fwDisabled.Name -join ', ')"
                Add-Issue 'High' "Firewall profile disabled: $($fwDisabled.Name -join ', ')"
            }
        } catch {
            Get-ElevatedNote "Firewall profile check (Get-NetFirewallProfile)"
        }

        # Windows Defender (2016+)
        try {
            $mp = Get-MpComputerStatus -ErrorAction SilentlyContinue
            if ($mp) {
                Write-Line ("    Defender real-time protection: {0}" -f $(if ($mp.RealTimeProtectionEnabled) { 'Enabled' } else { 'OFF' }))
                Write-Line ("    Defender signature age (days): {0}" -f [math]::Round(((Get-Date) - $mp.AntivirusSignatureLastUpdated).TotalDays, 1))
                if (-not $mp.RealTimeProtectionEnabled) {
                    Write-Fail "Windows Defender real-time protection is OFF."
                    Add-Issue 'High' 'Windows Defender real-time protection disabled.'
                }
                if (((Get-Date) - $mp.AntivirusSignatureLastUpdated).TotalDays -gt 7) {
                    Write-Warn "Defender signatures older than 7 days."
                    Add-Issue 'Medium' 'Windows Defender signatures outdated.'
                }
            }
        } catch { }

        # UAC
        $uac = (Get-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System' -Name EnableLUA -ErrorAction SilentlyContinue).EnableLUA
        if ($uac -eq 0) {
            Write-Warn "UAC is DISABLED."
            Add-Issue 'Medium' 'UAC disabled.'
        } elseif ($uac -eq 1) {
            Write-Ok "UAC enabled."
        } else {
            Write-Info "UAC status unknown."
        }

        # Local users
        Write-Line "  Local user accounts:"
        Get-CimInstance Win32_UserAccount -Filter "LocalAccount=True" -ErrorAction SilentlyContinue |
            Select-Object Name, Disabled, PasswordRequired, PasswordExpires |
            ForEach-Object {
                Write-Line ("    {0,-24} Disabled={1,-5} PasswordRequired={2,-5} PasswordExpires={3}" -f $_.Name, $_.Disabled, $_.PasswordRequired, $_.PasswordExpires)
                if (-not $_.Disabled -and -not $_.PasswordRequired) {
                    Write-Fail "Enabled local account '$($_.Name)' has no password required."
                    Add-Issue 'High' "Local account $($_.Name) has no password required."
                }
                if (-not $_.PasswordExpires) {
                    Add-Issue 'Low' "Local account $($_.Name) has a non-expiring password."
                }
            }

        # Administrators group
        Write-Line "  Local Administrators group:"
        try {
            $group = [ADSI]"WinNT://$env:COMPUTERNAME/Administrators,group"
            $group.Invoke('Members') | ForEach-Object {
                $name = $_.GetType().InvokeMember('Name', 'GetProperty', $null, $_, $null)
                Write-Line ("    " + $name)
            }
        } catch { }

        # Password / lockout policy
        Write-Line "  Password policy (net accounts):"
        (net accounts 2>$null) | ForEach-Object { if ($_.Trim()) { Write-Line ("    " + $_.Trim()) } }

        # Audit policy (System category)
        Write-Line "  Audit policy (System category):"
        (auditpol /get /category:System 2>$null) | ForEach-Object { if ($_.Trim()) { Write-Line ("    " + $_.Trim()) } }

        # Shares
        try {
            $shares = Get-SmbShare -ErrorAction SilentlyContinue
            if ($shares) {
                Write-Line "  SMB shares:"
                $shares | ForEach-Object { Write-Line ("    {0,-24} {1}" -f $_.Name, $_.Path) }
                foreach ($s in $shares) {
                    try {
                        $ace = Get-SmbShareAccess -Name $s.Name -ErrorAction SilentlyContinue | Where-Object AccountName -eq 'Everyone'
                        if ($ace -and $ace.AccessRight -ne 'Deny') {
                            Write-Warn "Share '$($s.Name)' grants access to EVERYONE."
                            Add-Issue 'Medium' "Share $($s.Name) accessible by Everyone."
                        }
                    } catch { }
                }
            }
        } catch {
            Get-ElevatedNote "SMB share inventory (Get-SmbShare)"
        }

        # Startup entries (Run keys) - informational
        Write-Line "  HKLM Run keys:"
        (Get-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run' -ErrorAction SilentlyContinue).PSObject.Properties |
            Where-Object { $_.Name -notmatch '^PS' } |
            ForEach-Object { Write-Line ("    {0} = {1}" -f $_.Name, $_.Value) }
    } catch {
        Write-Warn "Security section encountered an error: $($_.Exception.Message)"
    }
}

#==============================================================================#
# 9. BACKUP
#==============================================================================#
function Test-Backup {
    Write-Section "BACKUP"
    try {
        # Windows Server Backup
        $wbadmin = Get-Command wbadmin.exe -ErrorAction SilentlyContinue
        if ($wbadmin) {
            Write-Line "  Windows Server Backup:"
            try {
                $versions = (& wbadmin get versions 2>$null) | Out-String
                $lines = $versions -split "`r?`n"
                $backupLines = $lines | Where-Object { $_ -match 'Backup|backup' }
                if ($backupLines) {
                    $backupLines | Select-Object -Last 8 | ForEach-Object { Write-Line ("    " + $_.Trim()) }
                } else {
                    Write-Info "wbadmin reports no backup versions found."
                    Add-Issue 'Medium' 'Windows Server Backup has no backup versions.'
                }
            } catch {
                Get-ElevatedNote "wbadmin backup inventory"
            }
        } else {
            Write-Info "wbadmin.exe not found - Windows Server Backup feature not installed."
        }

        # VSS writers
        try {
            $vss = vssadmin list writers 2>$null | Out-String
            $writerStates = ($vss -split "`r?`n" | Where-Object { $_ -match 'State: \[' })
            $badWriters = $writerStates | Where-Object { $_ -notmatch 'State: \[1\]' }
            if ($badWriters) {
                Write-Warn "VSS writers with errors:"
                $badWriters | ForEach-Object { Write-Line ("    " + $_.Trim()) }
                Add-Issue 'Medium' 'One or more VSS writers are not in Stable state.'
            } else {
                Write-Ok "VSS writers: $($writerStates.Count) writer(s), all Stable."
            }
        } catch {
            Get-ElevatedNote "VSS writer check (vssadmin)"
        }

        # Shadow copies
        try {
            $shadows = Get-CimInstance Win32_ShadowCopy -ErrorAction SilentlyContinue
            if ($shadows) {
                Write-Info "Shadow copies present: $($shadows.Count)"
                $latest = $shadows | Sort-Object InstallDate -Descending | Select-Object -First 1
                Write-Line ("    Latest shadow copy: {0} ({1})" -f $latest.InstallDate, $latest.VolumeName)
            } else {
                Write-Info "No shadow copies found on this server."
            }
        } catch {
            Get-ElevatedNote "Shadow copy inventory (Win32_ShadowCopy)"
        }

        # Backup-related scheduled tasks
        try {
            $backupTasks = Get-ScheduledTask -ErrorAction SilentlyContinue |
                Where-Object { $_.TaskName -match 'backup|shadow|vss|wbadmin' }
            if ($backupTasks) {
                Write-Line "  Backup-related scheduled tasks:"
                $backupTasks | ForEach-Object { Write-Line ("    {0,-40} {1}" -f $_.TaskName, $_.State) }
            } else {
                Write-Warn "No backup-related scheduled tasks found."
            }
        } catch { }

        # Common backup folders freshness
        $backupDirs = @('C:\backup','C:\Backups','D:\backup','E:\backup','C:\WindowsAzure\Backup')
        foreach ($bd in $backupDirs) {
            if (Test-Path $bd) {
                try {
                    $recent = Get-ChildItem $bd -Recurse -ErrorAction SilentlyContinue |
                        Where-Object { $_.LastWriteTime -gt (Get-Date).AddDays(-3) } | Select-Object -First 1
                    if ($recent) {
                        Write-Ok "Backup dir $bd has been modified in last 3 days."
                    } else {
                        Write-Warn "Backup dir $bd has NO changes in the last 3 days."
                        Add-Issue 'Medium' "Backup directory $bd stale (>3 days)."
                    }
                } catch { }
            }
        }
    } catch {
        Write-Warn "Backup section encountered an error: $($_.Exception.Message)"
    }
}

#==============================================================================#
# 10. VIRTUALIZATION
#==============================================================================#
function Test-Virtualization {
    Write-Section "VIRTUALIZATION"
    try {
        $cs = Get-CimInstance Win32_ComputerSystem
        $guestHint = ($cs.Manufacturer + ' ' + $cs.Model)
        Write-Info "System model: $guestHint"
        if ($guestHint -match 'Virtual Machine|VMware|VirtualBox|KVM|Xen|QEMU') {
            Write-Warn "This host IS a virtual machine guest."
        } else {
            Write-Info "This host is not an obvious virtual machine guest."
        }

        # Hyper-V host services
        $vmms = Get-Service vmms -ErrorAction SilentlyContinue
        if ($vmms) {
            Write-Line ("  Hyper-V Virtual Machine Management service: {0}" -f $vmms.Status)
            if ($vmms.Status -eq 'Running') {
                try {
                    $vms = Get-VM -ErrorAction SilentlyContinue
                    Write-Line "  Hyper-V virtual machines:"
                    $vms | Select-Object Name, State, Version, CPUUsage, @{N='MemGB';E={[math]::Round($_.MemoryAssigned/1GB,1)}}, Status, Uptime |
                        ForEach-Object { Write-Line ("    {0,-30} {1,-10} v{2,-4} CPU {3,3}% Mem {4,5} GB {5} Up {6}" -f $_.Name, $_.State, $_.Version, $_.CPUUsage, $_.MemGB, $_.Status, $_.Uptime) }
                    foreach ($vm in $vms) {
                        $snaps = @(Get-VMSnapshot -VMName $vm.Name -ErrorAction SilentlyContinue)
                        if ($snaps.Count -gt 10) {
                            Write-Warn "VM '$($vm.Name)' has $($snaps.Count) snapshots - consolidate."
                            Add-Issue 'Medium' "VM $($vm.Name) has $($snaps.Count) snapshots."
                        }
                        if ($vm.State -eq 'Saved' -or $vm.State -eq 'Off') {
                            Add-Issue 'Low' "VM $($vm.Name) is powered off ($($vm.State))."
                        }
                    }
                } catch {
                    Get-ElevatedNote "Hyper-V VM inventory (Get-VM)"
                }
            } else {
                Write-Warn "Hyper-V VMMS service exists but is not running."
                Add-Issue 'High' 'Hyper-V VMMS service not running.'
            }
        } else {
            Write-Info "Hyper-V not installed (vmms service not found)."
        }

        # Hyper-V event log errors
        try {
            $hvErr = @(Get-WinEvent -LogName 'Hyper-V-VMMS' -MaxEvents 20 -ErrorAction SilentlyContinue | Where-Object { $_.LevelDisplayName -match 'Error|Critical' })
            if ($hvErr.Count -gt 0) {
                Write-Warn "$($hvErr.Count) Hyper-V-VMMS error event(s) found (latest below)."
                $hvErr | Select-Object -First 3 | ForEach-Object { Write-Line ("    [{0}] {1}" -f $_.Id, $_.Message.Substring(0, [math]::Min(120, $_.Message.Length))) }
                Add-Issue 'Medium' 'Hyper-V VMMS events contain errors.'
            }
        } catch { }

        # Containers
        $docker = Get-Service docker -ErrorAction SilentlyContinue
        if ($docker) {
            Write-Line ("  Docker (Windows containers) service: {0}" -f $docker.Status)
            $dockerCmd = Get-Command docker.exe -ErrorAction SilentlyContinue
            if ($dockerCmd) {
                (& docker ps -a 2>$null) | ForEach-Object { Write-Line ("    " + $_.Substring(0, [math]::Min(160, $_.Length))) }
            }
        }
    } catch {
        Write-Warn "Virtualization section encountered an error: $($_.Exception.Message)"
    }
}

#==============================================================================#
# 11. DATABASE SERVERS
#==============================================================================#
function Test-Databases {
    Write-Section "DATABASE SERVERS"
    try {
        # Listening DB ports
        $dbPorts = @(1433, 3306, 5432, 6379, 27017, 1521, 9042)
        $listeners = @()
        try {
            $listeners = Get-NetTCPConnection -State Listen -ErrorAction SilentlyContinue |
                Where-Object { $_.LocalPort -in $dbPorts }
        } catch { }
        if ($listeners) {
            Write-Line "  Database listeners detected:"
            $listeners | Select-Object LocalAddress, LocalPort, @{N='Process';E={(Get-Process -Id $_.OwningProcess -ErrorAction SilentlyContinue).ProcessName}} |
                Sort-Object LocalPort -Unique |
                ForEach-Object { Write-Line ("    {0,-15} : {1,-6} {2}" -f $_.LocalAddress, $_.LocalPort, $_.Process) }
        } else {
            Write-Info "No active database listeners on common ports."
        }

        # SQL Server instance discovery (registry)
        try {
            $sqlInstances = Get-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Microsoft SQL Server\Instance Names\SQL' -ErrorAction SilentlyContinue
            if ($sqlInstances) {
                Write-Line "  SQL Server instances:"
                $sqlInstances.PSObject.Properties | Where-Object { $_.Name -notmatch '^PS' } |
                    ForEach-Object { Write-Line ("    {0}  (registry key {1})" -f $_.Name, $_.Value) }
                Get-Service -Name 'MSSQL*' -ErrorAction SilentlyContinue |
                    ForEach-Object { Write-Line ("    Service: {0,-24} {1}" -f $_.Name, $_.Status) }

                # SQL Server error log scan (best effort)
                $logDirs = Get-ChildItem 'C:\Program Files\Microsoft SQL Server\*\MSSQL\Log' -Directory -ErrorAction SilentlyContinue
                foreach ($dir in $logDirs) {
                    $latestLog = Get-ChildItem $dir -Filter 'ERRORLOG*' -ErrorAction SilentlyContinue | Sort-Object LastWriteTime -Descending | Select-Object -First 1
                    if ($latestLog) {
                        $errLines = Get-Content $latestLog.FullName -Tail 500 -ErrorAction SilentlyContinue |
                            Where-Object { $_ -match 'Severity: 1[6-9]|error:|Error:' } | Select-Object -First 5
                        if ($errLines) {
                            Write-Warn "  Recent severe SQL Server errors in $($latestLog.FullName):"
                            $errLines | ForEach-Object { Write-Line ("    " + $_) }
                            Add-Issue 'Medium' "SQL Server error log contains severe errors."
                        } else {
                            Write-Ok "SQL Server error log ($($latestLog.Name)): no severe errors in last 500 lines."
                        }
                    }
                }
            } else {
                Write-Info "No SQL Server instances found in registry."
            }
        } catch { }

        # Other DB engines via services + tools if present
        $dbServices = Get-Service -ErrorAction SilentlyContinue |
            Where-Object { $_.Name -match '^(mysql|mariadb|postgresql|redis|mongodb|influxdb|elasticsearch)' }
        if ($dbServices) {
            Write-Line "  Other database service(s):"
            $dbServices | ForEach-Object { Write-Line ("    {0,-30} {1}" -f $_.Name, $_.Status) }
            foreach ($s in $dbServices) {
                if ($s.Name -match 'mysql|mariadb') {
                    try {
                        $ver = (& mysqladmin --connect-timeout=3 ping 2>$null | Out-String).Trim()
                        if ($ver -match 'alive') { Write-Ok "MySQL/MariaDB responds to ping." }
                        else { Write-Warn "mysqladmin present but no usable response." }
                    } catch { }
                }
                if ($s.Name -match 'postgres') {
                    $pgReady = Get-Command pg_isready.exe -ErrorAction SilentlyContinue
                    if ($pgReady) {
                        $r = (& pg_isready 2>$null).Trim()
                        Write-Line ("    " + $r)
                    }
                }
                if ($s.Name -match 'redis') {
                    $rc = Get-Command redis-cli.exe -ErrorAction SilentlyContinue
                    if ($rc) {
                        $r = (& redis-cli ping 2>$null).Trim()
                        Write-Line ("    redis-cli ping: " + $r)
                    }
                }
                if ($s.Name -match 'mongodb') {
                    $mc = Get-Command mongosh.exe -ErrorAction SilentlyContinue; if (-not $mc) { $mc = Get-Command mongo.exe -ErrorAction SilentlyContinue }
                    if ($mc) {
                        $r = (& $mc.Source --quiet --eval 'db.runCommand({ping:1}).ok' 2>$null).Trim()
                        Write-Line ("    Mongo ping: {0}" -f $r)
                    }
                }
            }
        } else {
            Write-Info "No MySQL/PostgreSQL/Redis/Mongo services installed."
        }
    } catch {
        Write-Warn "Database section encountered an error: $($_.Exception.Message)"
    }
}

#==============================================================================#
# 12. PERFORMANCE
#==============================================================================#
function Test-Performance {
    Write-Section "PERFORMANCE"
    try {
        $counters = $null
        try {
            $counters = Get-Counter @(
                '\Processor(_Total)\% Processor Time',
                '\Memory\Available MBytes',
                '\Memory\Pages/sec',
                '\System\Processor Queue Length',
                '\Memory\Pool Nonpaged Bytes'
            ) -ErrorAction SilentlyContinue
        } catch { }

        if ($counters) {
            $map = @{}
            foreach ($sample in $counters.CounterSamples) {
                $map[$sample.Path] = [math]::Round($sample.CookedValue, 2)
            }
            foreach ($key in $map.Keys) {
                Write-Line ("    {0,-55} {1}" -f $key.Split('\')[-1], $map[$key])
            }
            if ($map['\Memory\Pages/sec'] -gt 1000) {
                Write-Warn "Page faults/sec high ($($map['\Memory\Pages/sec'])) - possible memory pressure."
                Add-Issue 'Medium' "Pages/sec counter elevated."
            }
        } else {
            Write-Warn "Perf counters unavailable (localized naming or permissions)."
        }

        # Average disk queue length per physical disk
        try {
            $diskQ = Get-Counter '\PhysicalDisk(*)\Avg. Disk Queue Length' -ErrorAction SilentlyContinue |
                Select-Object -ExpandProperty CounterSamples |
                Where-Object { $_.InstanceName -ne '_total' -and $_.CookedValue -gt 2 }
            if ($diskQ) {
                Write-Warn "  High disk queue length:"
                $diskQ | ForEach-Object { Write-Line ("    {0,-20} queue={1:N2}" -f $_.InstanceName, $_.CookedValue) }
                Add-Issue 'Medium' "High disk queue length on one or more disks."
            } else {
                Write-Ok "Disk queue lengths normal."
            }
        } catch { }

        # Non-responsive processes
        $hung = @(Get-Process -ErrorAction SilentlyContinue | Where-Object { -not $_.Responding -and -not $_.HasExited })
        if ($hung.Count -gt 0) {
            Write-Warn "$($hung.Count) process(es) not responding:"
            $hung | Select-Object -First 5 | ForEach-Object { Write-Line ("    {0,-30} PID {1}" -f $_.ProcessName, $_.Id) }
            Add-Issue 'Medium' "$($hung.Count) processes not responding."
        } else {
            Write-Ok "All interactive processes responding."
        }

        # Handle count total
        try {
            $handles = (Get-Process -ErrorAction SilentlyContinue | Measure-Object HandleCount -Sum).Sum
            Write-Info "Total open handles across processes: $handles"
        } catch { }
    } catch {
        Write-Warn "Performance section encountered an error: $($_.Exception.Message)"
    }
}

#==============================================================================#
# 13. MAINTENANCE PERFORMED / HISTORY
#==============================================================================#
function Test-Maintenance {
    Write-Section "MAINTENANCE PERFORMED / HISTORY"
    try {
        $os = Get-CimInstance Win32_OperatingSystem
        Write-Info "Last boot: $($os.LastBootUpTime)"
        Write-Info "OS build: $($os.BuildNumber) | Version: $($os.Version)"

        # Reboot history (Event 6005 = event log started at boot)
        $bootEvents = @(Get-WinEvent -FilterHashtable @{ LogName='System'; Id=6005; StartTime=(Get-Date).AddDays(-30) } -ErrorAction SilentlyContinue)
        Write-Info "Reboots in the last 30 days: $($bootEvents.Count)"
        $bootEvents | Select-Object -First 5 | ForEach-Object { Write-Line ("    Reboot at {0}" -f $_.TimeCreated) }

        # Last 5 hotfixes
        Write-Line "  Last 5 installed hotfixes:"
        Get-HotFix -ErrorAction SilentlyContinue |
            Where-Object InstalledOn | Sort-Object InstalledOn -Descending | Select-Object -First 5 |
            ForEach-Object { Write-Line ("    {0,-12} installed {1}  {2}" -f $_.HotFixID, $_.InstalledOn, $_.Description) }

        # Volume optimization (defrag) history
        try {
            Write-Line "  Volume optimization (defrag) history:"
            Get-Volume -ErrorAction SilentlyContinue | Where-Object DriveLetter |
                ForEach-Object {
                    $opt = $_ | Get-OptimizedVolume -ErrorAction SilentlyContinue
                    if ($opt) {
                        Write-Line ("    Volume {0}: last optimized {1} ({2} mode)" -f $_.DriveLetter, $opt.LastOptimized, $opt.OptimizeMode)
                    }
                }
        } catch {
            Get-ElevatedNote "Volume optimization history (Get-OptimizedVolume)"
        }

        # DISM image health - read-only CheckHealth
        if (Test-IsAdmin) {
            Write-Line "  DISM CheckHealth (read-only):"
            try {
                $dismOut = & dism /Online /Cleanup-Image /CheckHealth 2>&1 | Out-String
                $dismOut -split "`r?`n" | ForEach-Object { if ($_.Trim()) { Write-Line ("    " + $_.Trim()) } }
            } catch {
                Write-Warn "DISM CheckHealth failed: $($_.Exception.Message)"
            }
        } else {
            Get-ElevatedNote "DISM image check"
        }

        # Pagefile config
        $pfCfg = Get-CimInstance Win32_PageFileSetting -ErrorAction SilentlyContinue
        if ($pfCfg) {
            Write-Line "  Pagefile settings:"
            $pfCfg | ForEach-Object { Write-Line ("    {0}  Initial={1}MB Max={2}MB" -f $_.Name, $_.InitialSize, $_.MaximumSize) }
        } else {
            Write-Info "No explicit pagefile settings (system managed)."
        }
    } catch {
        Write-Warn "Maintenance section encountered an error: $($_.Exception.Message)"
    }
}

#==============================================================================#
# 14. ISSUES FOUND
#==============================================================================#
function Show-Issues {
    Write-Section "ISSUES FOUND"
    Write-Line ("  Severity tally: {0} High | {1} Medium | {2} Low" -f $script:IssuesHigh.Count, $script:IssuesMed.Count, $script:IssuesLow.Count)

    if ($script:IssuesHigh.Count -gt 0) {
        Write-Line ""
        Write-Host "  ---------- HIGH ----------" -ForegroundColor Red
        foreach ($msg in $script:IssuesHigh) {
            Write-Line ("    [HIGH] " + $msg)
        }
    }
    if ($script:IssuesMed.Count -gt 0) {
        Write-Line ""
        Write-Host "  ---------- MEDIUM ----------" -ForegroundColor Yellow
        foreach ($msg in $script:IssuesMed) {
            Write-Line ("    [MED]  " + $msg)
        }
    }
    if ($script:IssuesLow.Count -gt 0) {
        Write-Line ""
        Write-Host "  ---------- LOW ----------" -ForegroundColor Blue
        foreach ($msg in $script:IssuesLow) {
            Write-Line ("    [LOW]  " + $msg)
        }
    }
    if ($script:IssuesHigh.Count -eq 0 -and $script:IssuesMed.Count -eq 0 -and $script:IssuesLow.Count -eq 0) {
        Write-Ok "No issues detected."
    }
}

#==============================================================================#
# 15. RECOMMENDATIONS
#==============================================================================#
function Show-Recommendations {
    Write-Section "RECOMMENDATIONS"
    $n = 1

    if ($script:IssuesHigh.Count -gt 0) {
        Write-Line ("  $n) Open a maintenance window immediately to remediate HIGH-severity items above."); $n++
    }
    if ($script:IssuesMed.Count -gt 0) {
        Write-Line ("  $n) Schedule MEDIUM-severity items for the next maintenance window."); $n++
    }

    Write-Line ("  $n) Enable and verify automated patching (WSUS / Windows Update for Business / Azure Update Manager), and test in a staging group first."); $n++
    Write-Line ("  $n) Configure performance baseline monitoring: PerfMon Data Collector Sets, or agents (SCOM / Zabbix / Prometheus windows_exporter / PRTG)."); $n++
    Write-Line ("  $n) Enforce a real backup and restore-test schedule (e.g. monthly restore drills) - backup presence is not recovery proof."); $n++
    Write-Line ("  $n) Harden remote access: restrict who can RDP (Remote Desktop Users), enable NLA, disable overlong account lockout windows, and place RDP behind VPN/firewall."); $n++
    Write-Line ("  $n) Centralize logs: forward System/Application/Security logs to a SIEM or log collector to keep evidence after incidents."); $n++
    Write-Line ("  $n) Monitor pending reboot state and reboot during maintenance windows rather than letting servers drift."); $n++
    Write-Line ("  $n) For hardware monitoring, install vendor tools: Dell OpenManage, HP iLO/SSA/Agents, Lenovo XClarity, or use Server BMC/IPMI for out-of-band views."); $n++
    Write-Line ("  $n) Schedule this script weekly via Task Scheduler and have it write to a central share; track issue counts over time."); $n++

    Write-Line ""
    Write-Info "Physical checks intentionally omitted: cabling, bezel LEDs, console/video, physical drive-bay indicators."
    Write-Info "Use BMC/iDRAC/iLO remote console for out-of-band hardware review where available."
}

#==============================================================================#
# MAIN
#==============================================================================#
if (-not $ReportPath) {
    $ReportPath = Join-Path $env:TEMP ("WindowsServer-Maintenance-{0}-{1}.log" -f $env:COMPUTERNAME, (Get-Date -Format 'yyyyMMdd-HHmmss'))
}

try {
    $script:ReportWriter = New-Object System.IO.StreamWriter($ReportPath, $false, (New-Object System.Text.UTF8Encoding($false)))
} catch {
    Write-Error "Cannot create report file: $ReportPath - $($_.Exception.Message)"
    exit 1
}

$isAdmin = Test-IsAdmin

# Banner
$line = ('=' * 72)
Write-Line ""
Write-Host "$line" -ForegroundColor Cyan
Write-Host "  WINDOWS SERVER MAINTENANCE HEALTH CHECK v1.0" -ForegroundColor Cyan
Write-Host "  Host: $env:COMPUTERNAME | Date: $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss zzz')" -ForegroundColor Cyan
Write-Host "  PowerShell: $($PSVersionTable.PSVersion) | OS: $((Get-CimInstance Win32_OperatingSystem).Caption)" -ForegroundColor Cyan
Write-Host "$line" -ForegroundColor Cyan
Write-Line ""

if (-not $isAdmin) {
    Write-Warn "NOT RUNNING AS ADMINISTRATOR - physical disk health, VSS, wbadmin, auditpol, and DISM checks will be skipped or degraded."
    Write-Info "Re-run from an elevated PowerShell session:  Start-Process powershell -Verb RunAs"
}

try {
    Test-SystemHealth
    Test-CpuMemory
    Test-Storage
    Test-OperatingSystem
    Test-Services
    Test-EventLogs
    Test-Network
    Test-Security
    Test-Backup
    Test-Virtualization
    Test-Databases
    Test-Performance
    Test-Maintenance
    Show-Issues
    Show-Recommendations
} catch {
    Write-Warn "Unexpected error during main run: $($_.Exception.Message)"
    Write-Line $_.ScriptStackTrace
} finally {
    $elapsed = ((Get-Date) - $script:StartTime).TotalSeconds
    Write-Line ""
    Write-Line '=' * 72
    Write-Line "  Report complete. Duration: $([math]::Round($elapsed,1))s"
    Write-Line "  Report path: $ReportPath"
    Write-Line "  Generated: $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss') on $env:COMPUTERNAME"
    Write-Line '=' * 72
    $script:ReportWriter.Flush()
    $script:ReportWriter.Close()
}
