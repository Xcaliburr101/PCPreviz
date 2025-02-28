# Clear the screen
Clear-Host

# Start the timer
$startTime = Get-Date

# Replace the current execution policy handling at the start of the file with:
try {
    # Check current execution policy
    $currentPolicy = Get-ExecutionPolicy -Scope Process
    if ($currentPolicy -ne 'Bypass') {
        # Try to set execution policy
        Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass -Force -ErrorAction Stop
        Write-Host "Successfully set execution policy to Bypass for current process" -ForegroundColor Green
    }
} catch {
    Write-Host "Warning: Could not set execution policy. You may need to run PowerShell as Administrator" -ForegroundColor Yellow
    Write-Host "You can try running: Set-ExecutionPolicy -Scope CurrentUser -ExecutionPolicy Bypass -Force" -ForegroundColor Yellow
    # Calculate elapsed time before first pause
    Pause
}

write-host "/==============================================\"
write-host "|| _____   _____ _____                _ ______||"
write-host "|||  __ \ / ____|  __ \              (_)___  /||"
write-host "||| |__) | |    | |__) | __ _____   ___   / / ||"
write-host "|||  ___/| |    |  ___/ '__/ _ \ \ / / | / /  ||"
write-host "||| |    | |____| |   | | |  __/\ V /| |/ /__ ||"
write-host "|||_|     \_____|_|   |_|  \___| \_/ |_/_____|||"
write-host "\==============================================/"


# Create a hashtable to store our jobs
$jobs = @{}
$outputOrder = @('HardwareInfo', 'AudioDevices', 'WebcamCheck', 'StorageInfo', 'ProblemsCheck')

# Display System Information first (since this is important basic info)
Write-Host "`n================ System Information ================" -ForegroundColor Cyan
Write-Host "System Model: " -NoNewline -ForegroundColor White
Write-Host (Get-CimInstance -ClassName Win32_ComputerSystem).Model -ForegroundColor Yellow
Write-Host "Serial Number: " -NoNewline -ForegroundColor White
Write-Host (Get-CimInstance -ClassName Win32_BIOS).SerialNumber -ForegroundColor Yellow
try {
    if (Confirm-SecureBootUEFI) {
        Write-Host "Secure Boot: " -NoNewline -ForegroundColor White
        Write-Host "True" -ForegroundColor Green
    } else {
        Write-Host "Secure Boot: " -NoNewline -ForegroundColor White
        Write-Host "Not in Secure Boot" -ForegroundColor Red
    }
} catch {
    Write-Host "Secure Boot: needs admin rights" -ForegroundColor Red
}

# Function to start all jobs in parallel
function Start-ParallelJobs {
    param (
        [hashtable]$JobScripts
    )

    foreach ($job in $JobScripts.GetEnumerator()) {
        Write-Verbose "Starting job: $($job.Key)"
        $jobs[$job.Key] = Start-Job -ScriptBlock $job.Value
    }
}

# Function to process results in order
function Wait-JobsInOrder {
    param (
        [string[]]$OrderedJobNames
    )

    foreach ($jobName in $OrderedJobNames) {
        Write-Verbose "Waiting for job: $jobName"
        if ($jobs.ContainsKey($jobName)) {
            $jobs[$jobName] | Wait-Job | Out-Null
            $jobs[$jobName] | Receive-Job
            $jobs[$jobName] | Remove-Job
            $jobs.Remove($jobName)
        }
    }
}

# Create a hashtable of all job scripts
$jobScripts = @{
    'HardwareInfo' = {
        # Hardware Info job content
        function Get-SystemHardwareInfo {
            # Create a hashtable to store our results.
            $systemInfo = @{
                Processor            = "Unknown"
                ProcessorSpeedMHz    = "Unknown"
                TotalRAMGB           = "Unknown"
                MicrophoneDetection  = "Unknown"
                ScreenSizeInches     = "Unknown"
                NetworkLinkSpeed     = "Unknown"
            }

            # --- Retrieve Processor Information ---
            try {
                $processor = Get-WmiObject -Class Win32_Processor -ErrorAction Stop | Select-Object -First 1
                if ($processor) {
                    $systemInfo.Processor         = $processor.Name
                    $systemInfo.ProcessorSpeedMHz = $processor.MaxClockSpeed
                }
            }
            catch {
                Write-Verbose "WMI query for processor info failed: $_"
                try {
                    $processor = Get-CimInstance -ClassName Win32_Processor -ErrorAction Stop | Select-Object -First 1
                    if ($processor) {
                        $systemInfo.Processor         = $processor.Name
                        $systemInfo.ProcessorSpeedMHz = $processor.MaxClockSpeed
                    }
                }
                catch {
                    Write-Verbose "CIM query for processor info also failed: $_"
                }
            }

            # --- Retrieve RAM Information ---
            try {
                $cs = Get-WmiObject -Class Win32_ComputerSystem -ErrorAction Stop
                if ($cs) {
                    $systemInfo.TotalRAMGB = [math]::Round($cs.TotalPhysicalMemory / 1GB, 2)
                }
            }
            catch {
                Write-Verbose "WMI query for computer system info failed: $_"
                try {
                    $cs = Get-CimInstance -ClassName Win32_ComputerSystem -ErrorAction Stop
                    if ($cs) {
                        $systemInfo.TotalRAMGB = [math]::Round($cs.TotalPhysicalMemory / 1GB, 2)
                    }
                }
                catch {
                    Write-Verbose "CIM query for computer system info also failed: $_"
                }
            }

            # --- Retrieve Microphone Information ---
            try {
                $microphoneFound = $false
                
                # Method 1: Check using Win32_PnPEntity
                if (-not $microphoneFound) {
                    $mic = Get-CimInstance -ClassName Win32_PnPEntity -ErrorAction Stop |
                           Where-Object { $_.Name -match "Microphone|mic" -or $_.PNPClass -eq "AudioEndpoint" } |
                           Select-Object -First 1
                    if ($mic) {
                        $systemInfo.MicrophoneDetection = $mic.Name
                        $microphoneFound = $true
                    }
                }

                if (-not $microphoneFound) {
                    $systemInfo.MicrophoneDetection = "Not Detected"
                }
            }
            catch {
                Write-Verbose "Microphone detection failed: $_"
                $systemInfo.MicrophoneDetection = "Detection Failed"
            }

            # --- Retrieve Screen Size ---
            try {
                $monitorParams = Get-CimInstance -Namespace root\wmi -ClassName WmiMonitorBasicDisplayParams -ErrorAction Stop
                $found = $false
                foreach ($monitor in $monitorParams) {
                    if ($monitor.MaxHorizontalImageSize -gt 0 -and $monitor.MaxVerticalImageSize -gt 0) {
                        $hInches = $monitor.MaxHorizontalImageSize / 2.54
                        $vInches = $monitor.MaxVerticalImageSize / 2.54
                        $diagonalInches = [math]::Round([math]::Sqrt(($hInches * $hInches) + ($vInches * $vInches)), 2)
                        $systemInfo.ScreenSizeInches = "$diagonalInches inches"
                        $found = $true
                        break
                    }
                }
                if (-not $found) {
                    $systemInfo.ScreenSizeInches = "Unknown"
                }
            }
            catch {
                $systemInfo.ScreenSizeInches = "Unknown"
            }

            # --- Retrieve Network Link Speed ---
            try {
                $networkAdapters = Get-NetAdapter | Where-Object { $_.Status -eq 'Up' }
                $networkInfo = @()

                foreach ($adapter in $networkAdapters) {
                    if ($adapter.InterfaceDescription -match 'Tailscale|VPN|Virtual') { continue }
                    
                    $speed = if ($adapter.LinkSpeed -match 'Gbps') {
                        [double]($adapter.LinkSpeed -replace '[^0-9.]',[string]::Empty) * 1000
                    } else {
                        [double]($adapter.LinkSpeed -replace '[^0-9.]',[string]::Empty)
                    }
                    
                    $networkInfo += "$($adapter.Name): $speed Mbps"
                }

                if ($networkInfo.Count -gt 0) {
                    $systemInfo.NetworkLinkSpeed = $networkInfo -join ' | '
                } else {
                    $systemInfo.NetworkLinkSpeed = "No active network connections"
                }
            }
            catch {
                $systemInfo.NetworkLinkSpeed = "Unknown"
            }

            return $systemInfo
        }

        # Now use the function
        $info = Get-SystemHardwareInfo
        
        Write-Host ""
        Write-Host "Screen Size: " -NoNewline -ForegroundColor White
        Write-Host $($info.ScreenSizeInches) -ForegroundColor Yellow
        Write-Host "Processor: " -NoNewline -ForegroundColor White
        Write-Host $($info.Processor) -ForegroundColor Yellow
        Write-Host "Total RAM (GB): " -NoNewline -ForegroundColor White
        Write-Host $($info.TotalRAMGB) -ForegroundColor Yellow
        Write-Host "Network Link Speed: " -NoNewline -ForegroundColor White
        Write-Host $($info.NetworkLinkSpeed) -ForegroundColor Yellow
        Write-Host "Microphone: " -NoNewline -ForegroundColor White
        Write-Host $($info.MicrophoneDetection) -ForegroundColor Yellow
    }
    'AudioDevices' = {
        Write-Host "`n================ Audio Devices ================" -ForegroundColor Cyan
        Write-Host "Audio Devices:" -ForegroundColor White
        $audioDevices = Get-CimInstance Win32_SoundDevice | Where-Object { $_.Status -eq "OK" }
        foreach ($device in $audioDevices) {
            Write-Host "  $($device.Name)" -ForegroundColor Yellow
        }
    }
    'WebcamCheck' = {
        Write-Host "`n================ Webcam Check ================" -ForegroundColor Cyan
        Write-Host "Webcam Device: " -NoNewline -ForegroundColor White
        Write-Host (Get-PnpDevice -Class Camera | Select-Object -ExpandProperty Name) -ForegroundColor Yellow
    }
    'StorageInfo' = {
        Write-Host "`n================ Storage Device Information ================" -ForegroundColor Cyan
        $DiskDrives = Get-WmiObject -Class Win32_DiskDrive | Where-Object {$_.MediaType -ne "Removable Media"}
        $PhysicalDisks = Get-PhysicalDisk -ErrorAction SilentlyContinue

        if ($DiskDrives -isnot [array]) { $DiskDrives = @($DiskDrives) }  # Ensure it's always an array

        $StorageInfo = foreach ($Disk in $DiskDrives) {
            # Find matching physical disk using device ID
            $PhysicalDisk = $PhysicalDisks | Where-Object { $_.DeviceId -eq $Disk.Index }

            # Determine drive type using PhysicalDisk if available
            if ($PhysicalDisk) {
                $DriveType = switch ($PhysicalDisk.MediaType) {
                    "HDD" { "HDD" }
                    "SSD" { if ($PhysicalDisk.BusType -eq "NVMe") { "NVMe" } else { "SSD" } }
                    default { "Unknown" }
                }
                $InterfaceType = $PhysicalDisk.BusType
            }
            else {
                # Fallback to Win32_DiskDrive method if Get-PhysicalDisk is unavailable
                $DriveType = switch ($Disk.BusType) {
                    17 { "NVMe" }  # BusType 17 = NVMe
                    7  { "SSD" }   # BusType 7  = SATA (SSD or HDD)
                    default {
                        if ($Disk.MediaType -match "Solid state drive") { "SSD" }
                        elseif ($Disk.MediaType -match "Fixed hard disk") { "HDD" }
                        else { "Unknown" }
                    }
                }
                $InterfaceType = $Disk.InterfaceType
            }

            [PSCustomObject]@{
                "Device" = $Disk.Caption
                "Model" = $Disk.Model
                "Type" = $DriveType
                "Size (GB)" = [Math]::Round($Disk.Size / 1GB)
                "Interface Type" = $InterfaceType
            }
        }

        foreach ($Disk in $StorageInfo) {
            Write-Host "Device: " -NoNewline -ForegroundColor White; Write-Host $Disk.Device -ForegroundColor Yellow
            Write-Host "  Model: " -NoNewline -ForegroundColor White; Write-Host $Disk.Model -ForegroundColor Yellow
            Write-Host "  Type: " -NoNewline -ForegroundColor White; Write-Host $Disk.Type -ForegroundColor Yellow
            Write-Host "  Size: " -NoNewline -ForegroundColor White; Write-Host "$($Disk.'Size (GB)') GB" -ForegroundColor Yellow
            Write-Host "  Interface: " -NoNewline -ForegroundColor White; Write-Host $Disk.'Interface Type' -ForegroundColor Yellow
            Write-Host "------------------------------------------------------------" -ForegroundColor DarkGray
        }
    }
    'ProblemsCheck' = {
        Write-Host "`n================ Problems ================" -ForegroundColor Cyan
        # Function to translate ConfigManagerErrorCode to a readable description
        function Get-ErrorDescription {
            param ($errorCode)
            switch ($errorCode) {
                1 { "This device is not configured correctly." }
                2 { "Windows cannot load the driver for this device." }
                3 { "The driver for this device might be corrupted, or your system may be running low on memory or other resources." }
                10 { "This device cannot start." }
                18 { "Reinstall the drivers for this device." }
                22 { "This device is disabled." }
                28 { "The drivers for this device are not installed." }
                31 { "This device is not working properly because Windows cannot load the drivers required for this device." }
                default { "Unknown error." }
            }
        }

        # Retrieve all Plug and Play devices
        $devices = Get-WmiObject -Class Win32_PnPEntity

        # Filter devices with a non-zero ConfigManagerErrorCode, excluding code 22 (disabled devices)
        $problematicDevices = $devices | Where-Object {
            $_.ConfigManagerErrorCode -ne 0 -and $_.ConfigManagerErrorCode -ne 22
        }

        # Display the problematic devices
        if ($problematicDevices) {
            Write-Host "Devices with driver issues (excluding disabled devices):" -ForegroundColor Yellow
            $problematicDevices | ForEach-Object {
                Write-Host "Device: " -NoNewline -ForegroundColor White; Write-Host $($_.Name) -ForegroundColor Yellow
                Write-Host "Error Code: " -NoNewline -ForegroundColor White; Write-Host $($_.ConfigManagerErrorCode) -ForegroundColor Yellow
                Write-Host "Error Description: " -NoNewline -ForegroundColor White; Write-Host (Get-ErrorDescription $_.ConfigManagerErrorCode) -ForegroundColor Yellow
                Write-Host "----------------------------------------" -ForegroundColor DarkGray
            }
        } else {
            Write-Host "All devices are functioning properly" -ForegroundColor Green
        }
    }
}

# Start all jobs in parallel
Start-ParallelJobs -JobScripts $jobScripts

# Wait for and display results in order
Wait-JobsInOrder -OrderedJobNames $outputOrder

#time check
write-host ""
write-host ""
$elapsedTime = (Get-Date) - $startTime
Write-Host "$($elapsedTime.TotalSeconds) seconds" -ForegroundColor Cyan

# Generate battery report
Write-Host "`n================ Battery Report ================" -ForegroundColor Cyan
Write-Host "Would you like to generate a battery report? (Y/N): " -NoNewline -ForegroundColor White
$batteryResponse = Read-Host
if ($batteryResponse -match "^[Yy]$") {
    Write-Host "Generating battery report..." -ForegroundColor Yellow
    $reportPath = "C:\battery-report.html"
    powercfg /batteryreport /output $reportPath
    if (Test-Path $reportPath) {
        Write-Host "Battery report generated successfully at: $reportPath" -ForegroundColor Green
        # Open the report in default browser
        Start-Process $reportPath
    } else {
        Write-Host "Battery report file not found after generation" -ForegroundColor Red
    }
} else {
    Write-Host "Skipping battery report generation" -ForegroundColor Yellow
}

Write-Host "----------------------------------------" -ForegroundColor DarkGray



# Ask about opening settings
Write-Host "`nWould you like to open Printers and Windows Update settings? (Y/N): " -NoNewline -ForegroundColor White
$settingsResponse = Read-Host

if ($settingsResponse -match "^[Yy]$") {
    Write-Host "Opening settings..." -ForegroundColor Yellow
    # Open printer settings
    Start-Process "cmd" -ArgumentList "/c start /min explorer.exe ms-settings:printers"
    
    # Delay Windows Update settings by 10 seconds and open in new window
    Write-Host "Windows Update settings will open in 10 seconds..." -ForegroundColor Yellow
    Start-Sleep -Seconds 10
    Start-Process "explorer.exe" -ArgumentList "ms-settings:windowsupdate"
} else {
    Write-Host "Skipping opening settings" -ForegroundColor Yellow
}



# Check for admin rights and ask if the user wants to reboot into BIOS, but ONLY if Secure Boot is disabled
$isAdmin = ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)

if (!$isAdmin) {
    Write-Host "`nAdmin rights required to check Secure Boot and reboot to BIOS" -ForegroundColor Red
} else {
    if (!(Confirm-SecureBootUEFI)) {
        Write-Host "`nWould you like to reboot into BIOS now? (Y/N)" -ForegroundColor Cyan
        $rebootResponse = Read-Host
        if ($rebootResponse -match "^[Yy]$") {
            Write-Host "Rebooting into BIOS..." -ForegroundColor Green
            try {
                # Try using shutdown.exe directly
                shutdown.exe /r /fw /t 0
            } catch {
                Write-Host "Failed to reboot: $_" -ForegroundColor Red
                Write-Host "Trying alternative method..." -ForegroundColor Yellow
                try {
                    # Alternative method using WMI
                    $computer = Get-WmiObject -Class Win32_OperatingSystem
                    $computer.Win32Shutdown(6)
                } catch {
                    Write-Host "Both reboot methods failed. Please restart manually and enter BIOS." -ForegroundColor Red
                }
            }
        } else {
            Write-Host "Skipping BIOS reboot." -ForegroundColor Yellow
        }
    }
}

# Reset Execution Policy
Set-ExecutionPolicy -Scope Process -ExecutionPolicy Default -Force
Pause