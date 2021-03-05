Function Copy-PackageToSystem {
    param(
        [Parameter(Mandatory = $true,
            ValueFromPipelineByPropertyName = $true,
            Position = 0)] 
        [String[]]$ComputerName, 
        [Parameter(Mandatory = $true,
            ValueFromPipelineByPropertyName = $true,
            Position = 1)] 
        $SourceDirectory, 
        [Parameter(Mandatory = $true,
            ValueFromPipelineByPropertyName = $true,
            Position = 2)]
        $TargetDirectory,
        [Parameter(Mandatory = $true,
            ValueFromPipelineByPropertyName = $true,
            Position = 3)]
        $PackageFileName,
        [Parameter(Mandatory = $false,
            ValueFromPipelineByPropertyName = $false,
            Position = 4)]
        [Switch]$asjob,
        [Parameter(Mandatory = $false,
            ValueFromPipelineByPropertyName = $false,
            Position = 5)]
        $Credentials
    )
    $CopyPackageScript = [scriptblock]::Create({
    $TargetDirectory = $args[0]
    $PackageFileName = $args[1]
    $SourceDirectory  = $args[2]
    if (!$TargetDirectory.EndsWith('\')) {
        $TargetDirectory = $TargetDirectory + '\'
    }
    
    if (!(Test-Path $TargetDirectory -ErrorAction SilentlyContinue)) {   
        $Folders = $TargetDirectory.Substring(0, ([Regex]::matches($TargetDirectory, '\\').index )[-1]).split("\")
        if (Test-Path $folders[0] -ErrorAction SilentlyContinue) { 
            $RootFolderPresent = $true
            New-Item $TargetDirectory -ItemType Directory | Out-Null
            if (!(Test-Path $(Join-Path $TargetDirectory $PackageFileName) -ErrorAction SilentlyContinue)) {
                Write-Host -ForegroundColor DarkCyan "Copying required file " -NoNewline; Write-Host $PackageFileName -NoNewline; Write-Host -ForegroundColor DarkCyan " to server: " -NoNewline; Write-Host ($($TargetDirectory.Substring(2) -split "\\")[0])
                Copy-Item $(Join-Path $SourceDirectory $PackageFileName)   -Destination $TargetDirectory -Force
            }
            Else {
                Write-Host -ForegroundColor DarkCyan "The specified required file " -NoNewline; Write-Host $PackageFileName -NoNewline; Write-Host -ForegroundColor DarkCyan " already exists on server: " -NoNewline; Write-Host  ($($TargetDirectory.Substring(2) -split "\\")[0])
            }
        }
        Else {
            $RootFolderPresent = $false        
        }
    }
    Else {
        if ((Test-Path $SourceDirectory -ErrorAction SilentlyContinue)) {
            $RootFolderPresent = $true
            if (!(Test-Path $(Join-Path $TargetDirectory $PackageFileName) -ErrorAction SilentlyContinue)) {
                Write-Host -ForegroundColor DarkCyan "Copying required file " -NoNewline; Write-Host $PackageFileName -NoNewline; Write-Host -ForegroundColor DarkCyan " to server: " -NoNewline; Write-Host ($($TargetDirectory.Substring(2) -split "\\")[0])
                Copy-Item $(Join-Path $SourceDirectory $PackageFileName)   -Destination $TargetDirectory -Force
            }
            Else {
                Write-Host -ForegroundColor DarkCyan "The specified required file " -NoNewline; Write-Host $PackageFileName -NoNewline; Write-Host -ForegroundColor DarkCyan " already exists on server: " -NoNewline; Write-Host  ($($TargetDirectory.Substring(2) -split "\\")[0])
            }
        }
    }
    })
    
    
    if($asjob){
        Invoke-Command -ComputerName $ComputerName -ScriptBlock $copyPackageScript -Authentication Credssp -Credential $Credentials -ArgumentList $TargetDirectory, $PackageFileName,$SourceDirectory -AsJob -JobName CopyPackage | out-null
        Do{
            Start-Sleep 5
        }Until((Get-job -Name CopyPackage |Select-Object -ExpandProperty State) -ne 'Running')

        if(Get-Job -State Failed -ErrorAction SilentlyContinue | where {$_.Name -eq 'CopyPackage'}){
            Foreach ($FailedJob in (Get-Job -State Failed -ErrorAction SilentlyContinue | where {$_.Name -eq 'CopyPackage'} )){
                Write-host -ForegroundColor Yellow "Unable to copy package to host: $($FailedJob.location)"
            }
        }
        Else{
                Write-host -ForegroundColor DarkCyan "Copy package  $PackageFileName Completed on $($Computername|measure-object | Select-Object -ExpandProperty Count) Systems "
        }
    }
    else{
        Invoke-Command -ComputerName $ComputerName -ScriptBlock $copyPackageScript -Authentication Credssp -Credential $Credentials -ArgumentList $TargetDirectory, $PackageFileName,$SourceDirectory  -ena
    }
}
   
Function Install-UpdatePackage {   
param(
$ComputerName,
$PackageFileName,
$Directory,
$PackageOrHotFixID,
$Credentials
)        

    $outputObject= [pscustomobject]@{
            ComputerName = $ComputerName
            PackageToInstall = $PackageOrHotFixID
            StartTime = Get-date
            EndTime=$Null
            InstallSuccess = $false
    }

    Invoke-Command   -ComputerName $ComputerName -Scriptblock { 
        
        $Package = Join-path $Using:Directory $Using:PackageFileName
        Unblock-File $Package -Confirm:$False 
        $FileMetaData = (Get-ItemProperty $Package -Name Versioninfo).Versioninfo.ProductName 

        if($FileMetaData -eq $null) {

            if([regex]::match((Get-ItemProperty $Package -Name Name).Name,"KB\d{5,12}","ignorecase").Success){
                $FileMetaData = [regex]::match((Get-ItemProperty $Package -Name Name).Name,"KB\d{5,12}","ignorecase").Value
            }
            Else{
                $FileMetaData = "ThisIsNotAvalidArticleThatWillEverReturn"
            }

        }


        $InstallerExecuted = $true
        Write-host -BackgroundColor black  -ForegroundColor DarkCyan "ComputerName: $env:ComputerName`nTimeStamp: $(get-date)`nStatus: Software is not installed. `nAction: Installing Software: $FileMetaData" 
        $fileType = ($Package -split "\.")[-1]
        switch ($fileType){
            msp{
                    
                $Cmd= "$env:SystemRoot\System32\msiexec.EXE"
                $ArgumentList = "/update $package /quiet /norestart"

                break
            }
            msi{
                $Cmd= "$env:SystemRoot\System32\msiexec.EXE"
                $ArgumentList = "/package $package /quiet /norestart"
                break
            }
            Exe{
                   
                $Cmd= "WUSA.EXE"
                $ArgumentList = @( $Package; '/f /norestart')
                break
            }
        }
        $Status = Start-Process $Cmd -ArgumentList $ArgumentList -Wait -Verb Runas
       Write-host -BackgroundColor black  -ForegroundColor DarkCyan "ComputerName: $env:ComputerName`nTimeStamp: $(get-date)`nStatus: Software installer completed. `nAction: Validating Software Installed: $FileMetaData" 
        
    } -Credential $Credentials -Authentication Credssp -EnableNetworkAccess

    $InstallState = Get-UpdatePackageInstallState -ComputerName $ComputerName  -PackageOrHotFixID $PackageOrHotFixID
    $outputObject.EndTime = Get-date
    $outputobject.InstallSuccess = $InstallState.isinstalled
    $outputobject
}

Function Get-UpdatePackageInstallState { 
param(
$ComputerName,
$PackageOrHotFixID
)
    Invoke-Command   -ComputerName $ComputerName -Scriptblock { 
        
        $outputObject= [pscustomobject]@{
            ComputerName = $Env:ComputerName
            Package = $Using:PackageOrHotFixID
            IsInstalled = $false
        }

        $yesterday = (Get-date).AddDays(-1).ToShortDateString()
        $installs = $(Foreach  ($install in (Get-ItemProperty HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*)){
                if(($install | Select-Object -ExpandProperty Installdate -ErrorAction SilentlyContinue) -ne $null){
                    $Date= (Get-date "$($install.installdate.Substring(4,2))/$($install.installdate.Substring(6))/$($install.installdate.Substring(0,4))").ToShortDateString()
                    if ([datetime]$date -ge [datetime]$yesterday){
                        $install.displayname
                        $install.Comments
                    }

                }
            }


        Foreach  ($install in (Get-ItemProperty  HKLM:\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*)){
            if(($install | Select-Object -ExpandProperty Installdate -ErrorAction SilentlyContinue) -ne $null){
                $Date= (Get-date "$($install.installdate.Substring(4,2))/$($install.installdate.Substring(6))/$($install.installdate.Substring(0,4))").ToShortDateString()
                if ([datetime]$date -ge [datetime]$yesterday){
                    $install.displayname
                    $install.Comments
                }

            }
        }

        Foreach  ($install in (Get-WmiObject win32_quickfixengineering)){
            if(($install | Select-Object -ExpandProperty InstalledOn -ErrorAction SilentlyContinue) -ne $null){
                $Date= (Get-date "$($install.InstalledOn)").ToShortDateString()
                if ([datetime]$date -ge [datetime]$yesterday){
                    $install.hotfixid
                }

            }
        }

        Foreach  ($install in (Get-WmiObject win32_ReliabilityRecords)){
            if(($install | Select-Object -ExpandProperty TimeGenerated -ErrorAction SilentlyContinue) -ne $null){
                $Date= (Get-date "$($install.TimeGenerated.Substring(4,2))/$($install.TimeGenerated.Substring(6,2))/$($install.TimeGenerated.Substring(0,4))").ToShortDateString()
                if ([datetime]$date -ge [datetime]$yesterday){
                    $install.Message
                }

            }
        }


        $Setup = @{
            LogName='Application'
            ProviderName=  'MsiInstaller'
            StartTime= [datetime](Get-date).addhours(-2).ToShortDateString()
            ID= 1022
        }
        Get-WinEvent    -FilterHashtable $Setup -ErrorAction SilentlyContinue | Select-Object -ExpandProperty message
        )     
        
        foreach ($installsinceYesterday in $installs){
            if($installsinceYesterday -match $Using:PackageOrHotFixID){
                $outputObject.IsInstalled = $true
            }
        }           

        $outputObject
    }

}

Function Enable-CredsSP {
Param(
$ComputerName
)
    $Checklocalcredssp =  get-WSManCredSSP 
    if($Checklocalcredssp[0] -eq 'The machine is not configured to allow delegating fresh credentials.')
    {
         Enable-WSManCredSSP -Role Client -DelegateComputer * -force  | Out-Null
    } 

    $Checkcredssp = Invoke-Command -ScriptBlock { get-WSManCredSSP   } -ComputerName $Computername
    if($Checkcredssp[1] -eq 'This computer is not configured to receive credentials from a remote client computer.')
    {
         Invoke-Command -ScriptBlock { Enable-WSManCredSSP -Role Server -force  } -ComputerName $Computername | Out-Null
    } 
}

Function RebootComputer {
    param([CmdletBinding()]
        [String]$ComputerName,
        [Parameter(ParameterSetName = "ServiceOptions",
            Position = 0,
            Mandatory = $False,
            HelpMessage = "Waits for Exchange Services to come online before completion")]
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
         
        RebootComputer -ComputerName XYX -IsExchangeServer
        RebootComputer -ComputerName XYX -WaitForServicesToStart
      

    .NOTES
        20200310: v1.0 - Initial Release
        20200601: v1.1 - Updated to improve test case success for Exchange Services
        20210201: v2.0 - Updated to include WaitForServicesToStart
#>


    $Timestamp = Get-Date
    $PercentComplete = 0
    $ActivityMessage = "$((Get-Date).Tostring()): Rebooting computer: $Computername"
    $StatusMessage = "$((Get-Date).Tostring()): Testing connectivity on computer: $computername"
    Write-Progress -Status $StatusMessage -Activity $ActivityMessage -PercentComplete $PercentComplete

    if (Test-Connection $ComputerName -Count 1 -ErrorAction SilentlyContinue -ErrorVariable TCER) {
        $continuereboot = $True
    }
    Else {
        $continuereboot = $False
    }

    if ($continuereboot) {
        if ($WaitForServicesToStart) {
        
            $RunningServices = Invoke-Command -ComputerName $computername -ScriptBlock { Get-Service | where { $_.StartType -eq "automatic" -and $_.Status -eq "running" } | Select-Object -ExpandProperty name }
            
        }
        $PercentComplete = $PercentComplete + 5
        $StatusMessage = "$((Get-Date).Tostring()): Issuing reboot to computer: $ComputerName "
        Write-Progress -Status $StatusMessage -Activity $ActivityMessage -PercentComplete $PercentComplete
     
        Try {
        
            Write-Host -ForegroundColor yellow "$((Get-Date).Tostring()): Issuing reboot for Computer: " -NoNewline; Write-Host $ComputerName 
            $ExecutionTime = Get-Date
            $rebootissued = $false
            $RebootTimeStamp = (Get-Date).AddMinutes(-5).ToUniversalTime()
            Invoke-Command -ComputerName $ComputerName -ScriptBlock { Restart-Computer -Force } -ErrorVariable restarterr -ErrorAction SilentlyContinue
            if ([string]$restarterr -notmatch "\w") {
                Write-Host -ForegroundColor yellow "$((Get-Date).Tostring()): Reboot successfully issued reboot for Computer: " -NoNewline; Write-Host $ComputerName 
                $rebootissued = $True
            }
            Else {
                Write-Host -ForegroundColor red "$((Get-Date).Tostring()): Reboot failed being issued reboot for Computer: " -NoNewline; Write-Host $ComputerName 
                $rebootissued = $false
            }


        }
        Catch {
    
            $rebootissued = $False
            if ([string]$restarterr -notmatch "\w") {
                Write-Host -ForegroundColor yellow "$((Get-Date).Tostring()): Reboot successfully issued reboot for Computer: " -NoNewline; Write-Host $ComputerName 
                $rebootissued = $True
            }
            Else {
                Write-Host -ForegroundColor red "$((Get-Date).Tostring()): Reboot failed being issued reboot for Computer: " -NoNewline; Write-Host $ComputerName 
                $rebootissued = $false
            }

        }
        Finally {
            Start-Sleep 5
            If ($rebootissued) {
            
                $StatusMessage = "$((Get-Date).Tostring()): Waiting for reboot on computer: $Computername"
                $PercentComplete = $PercentComplete + 20 
                Write-Progress -Status $StatusMessage -Activity $ActivityMessage -PercentComplete $PercentComplete
                
                Do {
              
                    $CheckLastSystemReboot = Invoke-Command -ComputerName $ComputerName -ScriptBlock {
                        $Date = (Get-WmiObject Win32_operatingSystem | Select-Object -ExpandProperty LastBootUpTime)
                        (Get-Date "$($($Date.Split(".")[0]).substring(0,4))/$(($Date.Split(".")[0]).substring(4,2))/$(($Date.Split(".")[0]).substring(6,2)) $(($Date.Split(".")[0]).substring(8,2)):$(($Date.Split(".")[0]).substring(10,2)):$(($Date.Split(".")[0]).substring(12,2))").ToUniversalTime()
                           
                    } -ErrorAction SilentlyContinue
              
                    if ($RebootTimeStamp -gt $CheckLastSystemReboot ) {
                        Start-Sleep 10
                    }

                }
                Until($CheckLastSystemReboot -gt $RebootTimeStamp)
                
                $StatusMessage = "$((Get-Date).Tostring()): Reboot completed on system : $Computername"
                $PercentComplete = $PercentComplete + 50 
                Write-Progress -Status $StatusMessage -Activity $ActivityMessage -PercentComplete $PercentComplete
            
                $StatusMessage = "$((Get-Date).Tostring()): Waiting for system services on computer: $Computername"
                Write-Progress -Status $StatusMessage -Activity $ActivityMessage -PercentComplete $PercentComplete
            
                $NetLogon = $false
                do {
                
                    if ((Get-Service NetLogon -ComputerName $Computername -ErrorAction SilentlyContinue | Select-Object -ExpandProperty Status) -eq "Running") {
                        $NetLogon = $true
                    }
                    Else {
                        Start-Sleep -Seconds 10
                    }

                }
                Until($NetLogon)

                if ($IsExchangeServer) {
                    $StatusMessage = "$((Get-Date).Tostring()): Waiting for Exchange services on computer: $Computername"
                    Write-Host "$((Get-Date).Tostring()): Waiting for Exchange services on computer: $Computername"
                    Write-Progress -Status $StatusMessage -Activity $ActivityMessage -PercentComplete $PercentComplete
                    $ExchangeServiceHealthIsGood = $False
                    $HealthCntr = 0
                    $HealthCntrFail = $False 
                    $HealthState = $False
                    Start-Sleep 20
                    do {
                        $HealthState = (Test-ServiceHealth -Server $ComputerName  -ErrorVariable SerivceHeathErr -ErrorAction silentlycontinue | where { $_.RequiredServicesRunning -ne $True })
                        if ($HealthState.Count -eq 0 -and $SerivceHeathErr -eq $null) {
                            $ExchangeServiceHealthIsGood = $true
                            $HealthCntrFail = $False
                        }
                        Else {
                            Start-Sleep 60
                            Remove-Variable HealthState, SerivceHeathErr -ErrorAction SilentlyContinue
                        }

                        if ($HealthCntr -ge 15) {
                            $HealthCntrFail = $true 
                            $ExchangeServiceHealthIsGood = $True
                        }
                        $HealthCntr ++
                    }
                    Until($ExchangeServiceHealthIsGood)
                    $SystemUp = Get-Date
                    Write-Host "$((Get-Date).Tostring()): Exchange services verified on computer: $Computername"
                }
                Elseif ($WaitForServicesToStart) {
                    $StatusMessage = "$((Get-Date).Tostring()): Waiting for previously running services to start on computer: $Computername"
                    Write-Host "$((Get-Date).Tostring()): Waiting for previously running services to start on computer: $Computername"
                    Write-Progress -Status $StatusMessage -Activity $ActivityMessage -PercentComplete $PercentComplete

                    $IndexedServices = @{ }
                    $RequiredServiceUp = $False
                    $HealthCntrFail = $False 
                    $ReqSvcCntr = 0

                    Foreach ($RunningService in  $RunningServices) {
                        $IndexedServices.add($RunningService, $False)
                    }

                    Do {
                        $CurrentRunningSvcs = Invoke-Command -ComputerName $computername -ScriptBlock { Get-Service | where { $_.StartType -eq "automatic" -and $_.Status -eq "running" } | Select-Object -ExpandProperty name }
                        Foreach ($RunningService in  $CurrentRunningSvcs) {
                            if ($IndexedServices[$RunningService] -eq $False) {
                                $IndexedServices[$RunningService] = $true
                            }
                        }

                        if ($ReqSvcCntr -ge 10) {
                            $HealthCntrFail = $True
                        }

                        if (($IndexedServices.Values | Select-Object -Unique) -eq $true) {
                            $RequiredServiceUp = $true
                        }
                        $ReqSvcCntr ++
                    } 
                    Until($RequiredServiceUp -or $HealthCntrFail)
                    $SystemUp = Get-Date

                }
                Else {
                    $HealthCntrFail = $false
                }

                if ($HealthCntrFail) {
                    $StatusMessage = "$((Get-Date).Tostring()): Required Core Services have started but unable to verify Exchange Services on computer: $Computername"
                    $PercentComplete = $PercentComplete + 25 
                    Write-Progress -Status $StatusMessage -Activity $ActivityMessage -PercentComplete $PercentComplete
                    Start-Sleep 2
                    Write-Progress -Status $StatusMessage -Activity $ActivityMessage -Completed
                    Write-Host -ForegroundColor yellow "$((Get-Date).Tostring()): Reboot for Computer: " -NoNewline; Write-Host $ComputerName -NoNewline; Write-Host -ForegroundColor yellow " initiated at " -NoNewline; Write-Host $Timestamp
                    Write-Host -ForegroundColor yellow "$((Get-Date).Tostring()): After reboot for Computer: " -NoNewline; Write-Host $ComputerName -NoNewline; Write-Host -ForegroundColor yellow " the system was available at " -NoNewline; Write-Host  $SystemUP
                    Write-Host -ForegroundColor yellow "$((Get-Date).Tostring()): Reboot was completed for Computer: " -NoNewline; $ComputerName
                    Write-Host -ForegroundColor red "$((Get-Date).Tostring()): Unable to verify Exchange Services for Computer: " -NoNewline; $ComputerName
                    Write-Host -ForegroundColor red "$((Get-Date).Tostring()): Please verify Exchange Services and press enter to continue processing."
                    Pause
                }
                Else {
                    $StatusMessage = "$((Get-Date).Tostring()): Required services have started on computer: $Computername"
                    $PercentComplete = $PercentComplete + 25 
                    Write-Progress -Status $StatusMessage -Activity $ActivityMessage -PercentComplete $PercentComplete
                    Start-Sleep 2
                    Write-Progress -Status $StatusMessage -Activity $ActivityMessage -Completed
                    Write-Host -ForegroundColor yellow "$((Get-Date).Tostring()): Reboot for Computer: " -NoNewline; Write-Host $ComputerName -NoNewline; Write-Host -ForegroundColor yellow " initiated at " -NoNewline; Write-Host $Timestamp
                    Write-Host -ForegroundColor yellow "$((Get-Date).Tostring()): After reboot for Computer: " -NoNewline; Write-Host $ComputerName -NoNewline; Write-Host -ForegroundColor yellow " the system was available at " -NoNewline; Write-Host  $SystemUP
                    Write-Host -ForegroundColor yellow "$((Get-Date).Tostring()): Reboot was completed for Computer: " -NoNewline; $ComputerName
                }
            }
            Else {
                Write-Host -ForegroundColor Yellow "$((Get-Date).Tostring()): Warning - Unable to issue reboot to Computer: $Computername"
            }
            Write-Host ""

        }
  
    }
    Else {
        Write-Host -ForegroundColor Yellow "Unable to communicate with host: $ComputerName"
    }
}

Function Get-PendingRebootStatus {
    param([Parameter(Mandatory = $true,
            ValueFromPipelineByPropertyName = $true,
            Position = 0)]
        [Array]$ComputerName
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

Function Get-ExServers {
    $configPartition = [regex]::Replace(((New-Object DirectoryServices.DirectorySearcher).SearchRoot.Parent), "LDAP://", "LDAP://CN=Configuration,", "ignorecase")
    $Search = New-Object DirectoryServices.DirectorySearcher([ADSI]$configPartition)
    $Search.filter = “(objectClass=msExchExchangeServer)"
    $msExchServer = $Search.Findall()
    Foreach ($server in $msExchServer) { if ($server.properties.Keys -contains 'Admindisplayname') { $server.properties.admindisplayname } }
}


$ErrorActionPreference   = 'Stop'
$Credentials = Get-Credential -UserName "$($env:USERDNSDOMAIN.Substring(0,$($env:USERDNSDOMAIN.indexof("."))))\$env:username" -Message "Enter Credential"
$PackageFileName = Read-Host "Enter the Package File Name to install. Example Exchange2016-KB5000871-x64-en.msp"
$SourceDirectory = Read-Host "Enter the UNC path to the $ExchangeISO file for the install. Example \\ComputerName\NetworkShare"
$TargetDirectory  = Read-Host "Enter the target directory on the Server you wish to install the exchange CU on. Example: D:\Updates"
$PackageOrHotFixID = Read-Host "Enter the KB or Hotfixid. Example KB5000871"

[array]$ExchangeServers = Get-ExServers
$PSconnectionServer = [string]::Empty

$AvailableServers = foreach($ComputerName in $ExchangeServers){
    if(Test-Connection $ComputerName -Count 1 -ErrorAction SilentlyContinue){$ComputerName}

}
$PSconnectionServer = $AvailableServers[0]

Import-PSSession ( New-PSSession -ConfigurationName Microsoft.exchange -ConnectionUri "Http://$PSconnectionServer/Powershell" -WarningAction SilentlyContinue -InformationAction SilentlyContinue -Name ExGuid9999) -AllowClobber -WarningAction SilentlyContinue -InformationAction SilentlyContinue | Out-Null


$PSconnectionServer = $AvailableServers[0]
$AvailableServers = foreach($ComputerName in $servers){
    if(Test-Connection $ComputerName -Count 1 -ErrorAction SilentlyContinue){$ComputerName}

}

$PendingRebootStatuses = Get-PendingRebootStatus -ComputerName $AvailableServers
$ServersToUpdate = @{}
Foreach ($PendingRebootStatus in $PendingRebootStatuses){
    $ServersToUpdate.add($PendingRebootStatus.Computername,$PendingRebootStatus)
}

Copy-PackageToSystem -ComputerName $AvailableServers -SourceDirectory $SourceDirectory -PackageFileName $PackageFileName -TargetDirectory $TargetDirectory -asjob -Credentials $Credentials

Foreach ($Computername in $ServersToUpdate.keys){
    $InstallState = Get-UpdatePackageInstallState -ComputerName $ComputerName  -PackageOrHotFixID $PackageOrHotFixID
    if(!$InstallState.IsInstalled){

        if($ServersToUpdate[$Computername].RebootPending){
            RebootComputer -ComputerName $Computername -IsExchangeServer
            Start-Sleep -Seconds 10
        }
    
        Install-UpdatePackage -ComputerName $ComputerName -PackageFileName $PackageFileName -Directory $TargetDirectory -Credentials $Credentials -PackageOrHotFixID $PackageOrHotFixID
    }

}


