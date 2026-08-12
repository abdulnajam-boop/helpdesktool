$ErrorActionPreference = 'Stop'

$os = Get-CimInstance Win32_OperatingSystem
$cpu = Get-CimInstance Win32_Processor | Select-Object -First 1
$disks = Get-CimInstance Win32_LogicalDisk -Filter "DriveType=3" | ForEach-Object {
    [PSCustomObject]@{
        device = $_.DeviceID
        size_bytes = [int64]$_.Size
        free_bytes = [int64]$_.FreeSpace
        free_percent = if ($_.Size -gt 0) { [math]::Round(($_.FreeSpace / $_.Size) * 100, 2) } else { 0 }
    }
}

$result = [PSCustomObject]@{
    schema_version = '1.0'
    timestamp_utc = (Get-Date).ToUniversalTime().ToString('o')
    hostname = $env:COMPUTERNAME
    os = [PSCustomObject]@{
        caption = $os.Caption
        version = $os.Version
        build = $os.BuildNumber
        architecture = $os.OSArchitecture
        last_boot_utc = $os.LastBootUpTime.ToUniversalTime().ToString('o')
    }
    cpu = [PSCustomObject]@{
        name = $cpu.Name
        logical_processors = $cpu.NumberOfLogicalProcessors
        load_percent = $cpu.LoadPercentage
    }
    memory = [PSCustomObject]@{
        total_bytes = [int64]$os.TotalVisibleMemorySize * 1KB
        free_bytes = [int64]$os.FreePhysicalMemory * 1KB
    }
    disks = @($disks)
}

$result | ConvertTo-Json -Depth 6 -Compress
