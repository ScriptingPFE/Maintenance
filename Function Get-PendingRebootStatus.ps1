﻿Function Get-PendingRebootStatus {
    param([Parameter(Mandatory = $true,
            ValueFromPipelineByPropertyName = $true,
            Position = 0)]
        [String[]]$ComputerName
    )

    $CheckForRebootPending = [scriptblock]::Create( {
            $NeedsReboot = $False
            If ( Get-ItemProperty -Path 'HKLM:\System\CurrentControlSet\Control\Session Manager' -Name 'PendingFileRenameOperations' -ErrorAction SilentlyContinue) {
                $NeedsReboot = $True
            }
            If ( Test-Path 'HKLM:\Software\Microsoft\Windows\CurrentVersion\Component Based Servicing\RebootPending' -ErrorAction SilentlyContinue) {
                $NeedsReboot = $True
            }
            If ( Test-Path 'HKLM:SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update\RebootRequired' -ErrorAction SilentlyContinue) {
                $NeedsReboot = $True
            }
            $NeedsReboot 
        })
    $isLocalMachine = $false
    Write-Progress -Activity "Checking if a reboot is pending" -Status "Total No. Computers: $($ComputerName.Count) Completed: 0" -PercentComplete 1
    Foreach ($Computer in  $ComputerName) {
        if ($Computer -ne $env:COMPUTERNAME) {
            Invoke-Command -Computername  $Computer -ScriptBlock $CheckForRebootPending -asjob | Out-Null
        }
        Else {
            $isLocalMachine = $true
        }
    }
    if ($isLocalMachine) {
        [pscustomObject]@{
            Computername  = $ENV:Computername
            RebootPending = $(Invoke-Command -ScriptBlock $CheckForRebootPending)
        }
    }
    While ((Get-Job -State Running).count -gt 0) {
        $jobs = Get-Job
        Write-Progress -Activity "Checking if a reboot is pending" -Status "Total No. Computers: $($ComputerName.Count) Completed: $(($Jobs |where{$_.State -ne "running"}).Count)" -PercentComplete $((($Jobs | where { $_.State -ne "running" }).count / $Jobs.count) * 100)        
        Start-Sleep 1
    }
    (Get-Job | Receive-Job).foreach( {
            [pscustomObject]@{
                Computername  = $_.PsComputername
                RebootPending = $_
            }
        })
    Get-Job | Remove-Job

    Write-Progress -Activity "Checking if a reboot is pending" -Status "Total No. Computers: $($ComputerName.Count) Completed: $(($Jobs |where{$_.State -ne "running"}).Count)" -Completed      
}
