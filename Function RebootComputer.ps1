Function RebootComputer {
param([CmdletBinding()]
[String]$ComputerName,
[Parameter(ParameterSetName="ServiceOptions",
Position=0,
Mandatory = $False,
HelpMessage="Waits for Exchange Services to come online before completion")]
[Switch]$IsExchangeServer,
[Switch]$WaitForServicesToStart
)

<#
    .SYNOPSIS
        Reboots a system and ensures the system is operational before continuing
        NAME: RebootComputer
        AUTHOR: Eric Powers 
        VERSION: 2.0

    .DESCRIPTION
        This script first checks for connectivity to the system 
        
        If the connectivity check passes the script evaluates the IsExchangeServer and WaitForServicesToStart
        for a true setting. If either is set the script will wait for the required Exchange Services to start, 
        or the Serives that were in a running start at the start of the script before reporting the system is
        Operational.
     
    .Parameters
        [string]ComputerName Lists the name of the computer to reboot

        [Switch]WaitForServicesToStart. If this parameter is set the script will first query the system
               for running services with an automatic start up type, then issue the reboot to the system. Once
               the server has reported a reboot has completed via a system eventid 6013, the script will wait for
               the running services discovered at the start of the script to come on line
            
        [Switch]IsExchangeServer. If this parameter is set to true the script will then check for
               the required Exchange Services on the system before reporting the system is avialable.
     

               
    .Syntax
         
        RebootComputer -ComputerName XYX -IsExchangeServer:$true
        RebootComputer -ComputerName XYX -WaitForServicesToStart:$true
      

    .NOTES
        20200310: v1.0 - Initial Release
        20200601: v1.1 - Updated to improve test case success for Exchange Services
        20210201: v2.0 - Updated to include WaitForServicesToStart
#>


    $Timestamp = Get-Date
    $PercentComplete = 0
    $ActivityMessage = "$((Get-date).Tostring()): Rebooting computer: $Computername"
    $StatusMessage = "$((Get-date).Tostring()): Testing connectivity on computer: $computername"
    Write-Progress -Status $StatusMessage -Activity $ActivityMessage -PercentComplete $PercentComplete

    if(Test-Connection $ComputerName -Count 1 -ErrorAction SilentlyContinue -ErrorVariable TCER)    {
        $continuereboot= $True
    }
    Else {
        $continuereboot = $False
    }

    if($continuereboot) {
        if($WaitForServicesToStart) {
        
            $RunningServices =  Invoke-Command -ComputerName $computername -ScriptBlock {Get-Service  | Where-Object {$_.StartType -eq "automatic" -and $_.Status -eq "running" } | Select-Object -ExpandProperty name}
            
        }
        $PercentComplete = $PercentComplete + 5
        $StatusMessage = "$((Get-date).Tostring()): Issuing reboot to computer: $ComputerName "
        Write-Progress -Status $StatusMessage -Activity $ActivityMessage -PercentComplete $PercentComplete
     
         Try {
        
            Write-host -ForegroundColor yellow "$((Get-date).Tostring()): Issuing reboot for Computer: " -NoNewline; write-host $ComputerName 
            $rebootissued = $false
            $RebootTimeStamp = (Get-date).AddMinutes(-1)
            Invoke-command -ComputerName $ComputerName -ScriptBlock { Restart-Computer -Force} -ErrorVariable restarterr -ErrorAction SilentlyContinue
            if([string]$restarterr -notmatch "\w")        {
                Write-host -ForegroundColor yellow "$((Get-date).Tostring()): Reboot successfully issued reboot for Computer: " -NoNewline; write-host $ComputerName 
                $rebootissued = $True
            }
            Else{
                Write-host -ForegroundColor red "$((Get-date).Tostring()): Reboot failed being issued reboot for Computer: " -NoNewline; write-host $ComputerName 
                $rebootissued = $false
            }


         }
         Catch{
    
            $rebootissued = $False
            if([string]$restarterr -notmatch "\w")        {
                Write-host -ForegroundColor yellow "$((Get-date).Tostring()): Reboot successfully issued reboot for Computer: " -NoNewline; write-host $ComputerName 
                $rebootissued = $True
            }
            Else{
                Write-host -ForegroundColor red "$((Get-date).Tostring()): Reboot failed being issued reboot for Computer: " -NoNewline; write-host $ComputerName 
                $rebootissued = $false
            }

         }
         Finally {
            Start-Sleep 5
            If($rebootissued) {
            
                $StatusMessage = "$((Get-date).Tostring()): Waiting for reboot on computer: $Computername"
                $PercentComplete = $PercentComplete + 20 
                Write-Progress -Status $StatusMessage -Activity $ActivityMessage -PercentComplete $PercentComplete
                
                Do {
              
                      $CheckLastSystemReboot = Invoke-Command -ComputerName $ComputerName -ScriptBlock {
                               $Date= (Get-WmiObject Win32_operatingSystem | Select-Object -ExpandProperty LastBootUpTime)
                               Get-date "$($($Date.Split(".")[0]).substring(0,4))/$(($Date.Split(".")[0]).substring(4,2))/$(($Date.Split(".")[0]).substring(6,2)) $(($Date.Split(".")[0]).substring(8,2)):$(($Date.Split(".")[0]).substring(10,2)):$(($Date.Split(".")[0]).substring(12,2))"
                               $ErrorActionPreference = 'SilentlyContinue'
                               $ErrorActionPreference = 'Continue'
                           
                      } -ErrorAction SilentlyContinue
              
                      if($RebootTimeStamp -gt $CheckLastSystemReboot ) {
                          Start-Sleep 10
                      }

                }
                Until($CheckLastSystemReboot -gt $RebootTimeStamp)
                
                $StatusMessage = "$((Get-date).Tostring()): Reboot completed on system : $Computername"
                $PercentComplete = $PercentComplete + 50 
                Write-Progress -Status $StatusMessage -Activity $ActivityMessage -PercentComplete $PercentComplete
            
                $StatusMessage = "$((Get-date).Tostring()): Waiting for system services on computer: $Computername"
                Write-Progress -Status $StatusMessage -Activity $ActivityMessage -PercentComplete $PercentComplete
            
                $NetLogon= $false
                do{
                
                    if((Get-Service NetLogon -ComputerName $Computername -ErrorAction SilentlyContinue | Select-Object -ExpandProperty Status) -eq "Running") {
                        $NetLogon = $true
                    }
                    Else{
                        Start-Sleep -Seconds 10
                    }

                }
                Until($NetLogon)

                if($IsExchangeServer){
                        $StatusMessage = "$((Get-date).Tostring()): Waiting for Exchange services on computer: $Computername"
                        Write-Host "$((Get-date).Tostring()): Waiting for Exchange services on computer: $Computername"
                        Write-Progress -Status $StatusMessage -Activity $ActivityMessage -PercentComplete $PercentComplete
                        $ExchangeServiceHealthIsGood = $False
                        $HealthCntr = 0
                        $HealthCntrFail=$False 
                        $HealthState = $False
                        Start-Sleep 20
                    do{
                        $HealthState = (Test-ServiceHealth -Server $ComputerName  -ErrorVariable SerivceHeathErr -ErrorAction silentlycontinue | Where {$_.RequiredServicesRunning -ne $True})
                        if($HealthState.Count -eq 0 -and $SerivceHeathErr -eq $null) {
                            $ExchangeServiceHealthIsGood = $true
                            $HealthCntrFail=$False
                        }
                        Else {
                           Start-Sleep 60
                           Remove-Variable HealthState,SerivceHeathErr -ErrorAction SilentlyContinue
                        }

                        if($HealthCntr  -ge 15){
                            $HealthCntrFail=$true 
                            $ExchangeServiceHealthIsGood = $True
                        }
                        $HealthCntr ++
                    }
                    Until($ExchangeServiceHealthIsGood)
                    $SystemUp =Get-Date
                    Write-Host "$((Get-date).Tostring()): Exchange services verified on computer: $Computername"
                }
                Elseif($WaitForServicesToStart) {
                    $StatusMessage = "$((Get-date).Tostring()): Waiting for previously running services to start on computer: $Computername"
                    Write-Host "$((Get-date).Tostring()): Waiting for previously running services to start on computer: $Computername"
                    Write-Progress -Status $StatusMessage -Activity $ActivityMessage -PercentComplete $PercentComplete

                    $IndexedServices = @{}
                    $RequiredServiceUp= $False
                    $HealthCntrFail=$False 
                    $ReqSvcCntr = 0

                    Foreach ($RunningService in  $RunningServices){
                        $IndexedServices.add($RunningService,$False)
                    }

                    Do{
                        $CurrentRunningSvcs = Invoke-Command -ComputerName $computername -ScriptBlock {Get-Service  | where {$_.StartType -eq "automatic" -and $_.Status -eq "running" } | Select-Object -ExpandProperty name}
                         Foreach ($RunningService in  $CurrentRunningSvcs){
                            if ($IndexedServices[$RunningService] -eq $False){
                                $IndexedServices[$RunningService] = $true
                            }
                         }

                         if($ReqSvcCntr -ge 10){
                            $HealthCntrFail = $True
                         }

                         if(($IndexedServices.Values | Select-Object -Unique) -eq $true){
                            $RequiredServiceUp = $true
                         }
                         $ReqSvcCntr ++
                    } 
                    Until($RequiredServiceUp -or $HealthCntrFail)
                    $SystemUp =Get-Date

                }
                Else{
                    $HealthCntrFail = $false
                }

                if($HealthCntrFail){
                    $StatusMessage = "$((Get-date).Tostring()): Required Core Services have started but unable to verify Exchange Services on computer: $Computername"
                    $PercentComplete = $PercentComplete + 25 
                    Write-Progress -Status $StatusMessage -Activity $ActivityMessage -PercentComplete $PercentComplete
                    Start-Sleep 2
                    Write-Progress -Status $StatusMessage -Activity $ActivityMessage -Completed
                    Write-host -ForegroundColor yellow "$((Get-date).Tostring()): Reboot for Computer: " -NoNewline; write-host $ComputerName -NoNewline; Write-host -ForegroundColor yellow " initiated at " -NoNewline; write-host $Timestamp
                    Write-host -ForegroundColor yellow "$((Get-date).Tostring()): After reboot for Computer: " -NoNewline; write-host $ComputerName -NoNewline; Write-host -ForegroundColor yellow " the system was available at " -NoNewline;  write-host  $SystemUP
                    Write-host -ForegroundColor yellow "$((Get-date).Tostring()): Reboot was completed for Computer: " -NoNewline; $ComputerName
                    Write-host -ForegroundColor red "$((Get-date).Tostring()): Unable to verify Exchange Services for Computer: " -NoNewline; $ComputerName
                    Write-host -ForegroundColor red "$((Get-date).Tostring()): Please verify Exchange Services and press enter to continue processing."
                }
                Else{
                    $StatusMessage = "$((Get-date).Tostring()): Required services have started on computer: $Computername"
                    $PercentComplete = $PercentComplete + 25 
                    Write-Progress -Status $StatusMessage -Activity $ActivityMessage -PercentComplete $PercentComplete
                    Start-Sleep 2
                    Write-Progress -Status $StatusMessage -Activity $ActivityMessage -Completed
                    Write-host -ForegroundColor yellow "$((Get-date).Tostring()): Reboot for Computer: " -NoNewline; write-host $ComputerName -NoNewline; Write-host -ForegroundColor yellow " initiated at " -NoNewline; write-host $Timestamp
                    Write-host -ForegroundColor yellow "$((Get-date).Tostring()): After reboot for Computer: " -NoNewline; write-host $ComputerName -NoNewline; Write-host -ForegroundColor yellow " the system was available at " -NoNewline;  write-host  $SystemUP
                    Write-host -ForegroundColor yellow "$((Get-date).Tostring()): Reboot was completed for Computer: " -NoNewline; $ComputerName
                }
            }
            Else
            {
                Write-Host -ForegroundColor Yellow "$((Get-date).Tostring()): Warning - Unable to issue reboot to Computer: $Computername"
            }
            Write-host ""

        }
  
}
    Else
    {
        Write-host -ForegroundColor Yellow "Unable to communicate with host: $ComputerName"
    }
}
