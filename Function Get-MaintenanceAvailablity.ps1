﻿Function Get-MaintenanceAvailablity {
    Param(
        [Parameter(Position=0,Mandatory=$true)]$ComputerName,
        [Parameter(Position=1,Mandatory=$true)]$MaintenanceWindowStart,
        [Parameter(Position=2,Mandatory=$true)]$MaintenanceWindowStop
    )

    $ComputerLocalTime = [datetime]::UtcNow.AddHours($(Invoke-Command -ComputerName $ComputerName {

                if ([System.TimeZoneInfo]::Local.IsDaylightSavingTime([datetime]::Now)) { 
                    [System.TimeZoneInfo]::Local.BaseUtcOffset.TotalHours + 1
                }
                Else {
                    [System.TimeZoneInfo]::Local.BaseUtcOffset.TotalHours 
                }

            }))

    $Report = [pscustomobject]@{
        ComputerName           = $Computername
        SystemsCurrentTime     = $ComputerLocalTime
        IsInMaintenanceWindow  = $false
        MaintenanceWindowStart = $null
        MaintenanceWindowEnd   = $null

    }
    if ((Get-Date $MaintenanceWindowStop).Hour -lt (Get-Date $MaintenanceWindowStart).hour) {
        $End = (Get-Date $MaintenanceWindowStop).AddDays(1)
        $Start = Get-Date $MaintenanceWindowStart  
    }
    Else {
        $End = (Get-Date $MaintenanceWindowStop)
        $Start = Get-Date $MaintenanceWindowStart  
    }

    $Report.MaintenanceWindowEnd = $end
    $Report.MaintenanceWindowStart = $Start

    if ($ComputerLocalTime -ge $Start -and $ComputerLocalTime -lt $end) {
        $Report.IsInMaintenanceWindow = $true
    }
    $Report

}

