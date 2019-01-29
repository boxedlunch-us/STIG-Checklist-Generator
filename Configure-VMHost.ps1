<#
.SYNOPSIS
   Configure ESXi hosts according to the DISA STIG

.DESCRIPTION
    Settings can be automatically applied to a single host, or a group of hosts.  These settings put the machine(s) settings into compliance with the DISA STIG

.NOTES
    Author: Jeff Peters, VMware

.EXAMPLE
    .\script_name.ps1

.EXAMPLE
    .\script_name.ps1 -enclave "A"

.PARAMETER parameter
    The enclave parameter can be used to include/exclude systems based on customer-specific enclaves
#>


Param(
    [Parameter(Mandatory=$true)]
    [ValidateSet("A","B","C")]
        [String]$enclave
)

if ($enclave -ne "A") {
   Write-Host "This script currently only supports Enclave O"
   break
}

## Global Variables
##  Set these variables for the specific enclave
$ntpAddress1 = "192.168.0.11"
$ntpAddress2 = "192.168.0.12"
$syslogHost = "ssl://sysloghost:1514"

Clear-Host
Write-Host "What do you want to configure?"
Write-Host "1: Single ESXi Host"
Write-Host "2: List of ESXi Hosts"
Write-Host "3: Cluster of ESXi Hosts"
$choice = Read-Host 'Make a selection'

$domain = Read-Host 'Enter the domain name (ex. domain.com)'

switch ($choice)
{
    '1' {
        $vmhosts = get-vmhost ((Read-Host "Enter the ESXi hostname to configure (ex. hostname1)")+"."+$domain)
    }
    '2' {
        $hostList = Read-Host "Enter the comma separated list of host names (ex. hostname1, hostname2, hostname3)"
        $hostList = $hostList.Split(',').Trim()
        $vmhosts = @()
        $hostList | %{$vmhosts += get-vmhost ($_+'.'+$domain)}
    }
    '3' {
        $vmhosts = get-cluster (Read-Host "Enter the name of the cluster (ex. Cluster1)") | get-vmhost
    }
 } 


if ($vmhosts -eq $null) {
    Write-Host "No Hosts Found"
    Break
}


## Menu
function Show-Menu{
    param (
        [string]$Title= 'ESXi Configuration Menu'
    )
    Clear-Host
    Write-Host "======================== $Title ========================"

    Write-Host "1: Time Configuration"
    Write-Host "2: STIG Settings"
    Write-Host "3: Firewall Settings"
    Write-Host "A: All of the Above"
    Write-Host "Q: Quit"
}


## NTP Time Configuration Function
function Configure-Time{
    param (
        [VMware.VimAutomation.ViCore.Impl.V1.Inventory.VMHostImpl] $vmhost
    )
    
    ##Configure Firewall for NTP
    
       $esxcli = $vmhost | get-esxcli -v2
       $arguments = $esxcli.network.firewall.ruleset.set.CreateArgs()
       $arguments.rulesetid = "ntpClient"
       $arguments.allowedall = $false
       $arguments.enabled = $true
       $esxcli.network.firewall.ruleset.set.Invoke($arguments)

       $arguments = $esxcli.network.firewall.ruleset.allowedip.add.CreateArgs()
       $arguments.rulesetid = "ntpClient"
       $arguments.ipaddress = $ntpAddress1
       $esxcli.network.firewall.ruleset.allowedip.add.Invoke($arguments)
       $arguments.ipaddress = $ntpAddress2
       $esxcli.network.firewall.ruleset.allowedip.add.Invoke($arguments)
      
    
       $esxcli = $vmhost | get-esxcli -V2
       $timeArgs = $esxcli.system.time.set.CreateArgs()
   
       $t = get-date
       $t = $t.ToUniversalTime()

       $timeArgs.hour = $t.Hour
       $timeArgs.min = $t.Minute
       $timeArgs.month = $t.Month
       $timeArgs.year = $t.Year
       $timeArgs.sec = $t.Second
       $timeArgs.day = $t.Day
      
       $esxcli.system.time.set.Invoke($timeArgs)
       $esxcli.hardware.clock.set.Invoke($timeArgs)
       $vmhost | Get-VMHostService | ?{$_.key -eq "ntpd"} | Start-VMHostService
       $vmhost | Get-VMHostService | ?{$_.key -eq "ntpd"} | Set-VMHostService -Policy "on"
    
       
       $vmhost | Get-VMHostNtpServer | %{Remove-VMHostNtpServer -NtpServer $_ -VMHost $vmhost -Confirm:$false}
       $vmhost | Add-VMHostNtpServer $ntpAddress1
       $vmhost | Add-VMHostNtpServer $ntpAddress2
       


    ##Validate Date/Time
       $esxcli = $vmhost | get-esxcli -v2
       $time = $esxcli.system.time.get.Invoke()
       Write-Host $vmhost + " " + $time
}

## Apply STIG Settings to Host
function STIG-Host{
    param (
        [VMware.VimAutomation.ViCore.Impl.V1.Inventory.VMHostImpl] $esx
    )
   
        Write-Host "Configuring NTP Client Policy on $esx - VULN ID: V-63261" -ForegroundColor Green
        $esx | Get-VMHostService | where{$_.Key -eq "ntpd"}| Set-VMHostService -policy "on" -Confirm:$false

        Write-Host "Setting ESXi Shell to disabled $esx - VULN ID: V-63241 VULN ID: " -ForegroundColor Green
        $esx | Get-VMHostService | where{$_.Key -eq "TSM-SSH"}| Set-VMHostService -policy "off" -Confirm:$false

        Write-Host "Stopping ESXi Shell on $esx - VULN ID: 63241" -ForegroundColor Green
        $esx | Get-VMHostService | where{$_.Key -eq "TSM-SSH"}| Stop-VMHostService -Confirm:$false

        Write-Host "Setting consecutive invalid login attempts limit $esx - VULN ID: V-63179" -ForegroundColor Green
        $esx | Get-AdvancedSetting -Name Security.AccountLockFailures | Set-AdvancedSetting -Value 3 -Confirm:$false

        Write-Host "Setting lockout time for invalid login attempts $esx - VULN ID: V-63181" -ForegroundColor Green
        $esx | Get-AdvancedSetting -Name Security.AccountUnlockTime | Set-AdvancedSetting -Value 900 -Confirm:$false

        Write-Host "Setting audit logging event type $esx - VULN ID: V-63229 VULN ID: V-63509" -ForegroundColor Green
        $esx | Get-AdvancedSetting -Name Config.HostAgent.log.level | Set-AdvancedSetting -Value "info" -Confirm:$false

        Write-Host "Setting VMware Admins Group connection $esx - VULN ID: V-63247 VULN ID: V-63769 VULN ID: V-63907 VULN ID V-63911" -ForegroundColor Green
        $esx | Get-AdvancedSetting -Name "Config.HostAgent.plugins.hostsvc.esxAdminsGroup" | Set-AdvancedSetting -Value "D2-SG-vSphereESXiAdmins" -Confirm:$false

        Write-Host "Setting timeout to disconnect idle sessions $esx - VULN ID: V-63251 VULN ID: V-63773" -ForegroundColor Green
        $esx | Get-AdvancedSetting -Name UserVars.ESXiShellInteractiveTimeOut | Set-AdvancedSetting -Value 600 -Confirm:$false

        Write-Host "Setting timeout for ESXi Shell $esx - VULN ID: V-63253 VULN ID: V-63775" -ForegroundColor Green
        $esx | Get-AdvancedSetting -Name UserVars.ESXiShellTimeOut | Set-AdvancedSetting -Value 600 -Confirm:$false

        Write-Host "Setting timeout for DCUI $esx - VULN ID: V-63255 VULN ID: V-63777" -ForegroundColor Green
        $esx | Get-AdvancedSetting -Name UserVars.DcuiTimeOut | Set-AdvancedSetting -Value 600 -Confirm:$false

        Write-Host "Setting syslog location $esx - VULN ID: V-63259" -ForegroundColor Green
        $esx | Get-AdvancedSetting -Name Syslog.global.logDir | Set-AdvancedSetting -Value []/scratch/log -Confirm:$false

        Write-Host "Setting syslog location $esx - VULN ID: V-63259 VULN ID: V-63883 VULN ID: V-63903 VULN ID: V-63915 VULN ID: V-63921" -ForegroundColor Green
        $esx | Get-AdvancedSetting -Name Syslog.global.logHost | Set-AdvancedSetting -Value $syslogHost -Confirm:$false

        Write-Host "Setting to disable TSP $esx - VULN ID: V-63279" -ForegroundColor Green
        $esx | Get-AdvancedSetting -Name Mem.ShareForceSalting | Set-AdvancedSetting -Value 2 -Confirm:$false

        Write-Host "Setting to enable BPDU Guard $esx - VULN ID: V-63285" -ForegroundColor Green
        $esx | Get-AdvancedSetting -Name Net.BlockGuestBPDU | Set-AdvancedSetting -Value 1 -Confirm:$false

        Write-Host "Setting SSH to disabled $esx - VULN ID: V-63239 VULN ID: V-63553 VULN ID: V-63885" -ForegroundColor Green
        $esx | Get-VMHostService | where{$_.Key -eq "SSH"}| Set-VMHostService -policy "off" -Confirm:$false

        Write-Host "Stopping SSH Client on $esx - VULN ID: V-63239 VULN ID: V-63553 VULN ID: V-63885" -ForegroundColor Green
        $esx | Get-VMHostService | where{$_.Key -eq "SSH"}| Stop-VMHostService -Confirm:$false

        Write-Host "Setting dvFilter network APIs on $esx - VULN ID:  V-63293" -ForegroundColor Green
        $esx | Get-AdvancedSetting -Name Net.DVFilterBindIpAddress | Set-AdvancedSetting -Value "" -Confirm:$false

        Write-Host "Disabling MOB on $esx - VULN ID:  V-63237" -ForegroundColor Green
        $esx | Get-AdvancedSetting -Name Config.HostAgent.plugins.solo.enableMob | Set-AdvancedSetting -Value false -Confirm:$false

        Write-Host "Configuring DCUI.Access on $esx - VULN ID:  V-63173" -ForegroundColor Green
        $esx | Get-AdvancedSetting -Name DCUI.Access | Set-AdvancedSetting -Value "root" -Confirm:$false

        Write-Host "Configuring Password Policy on $esx - VULN ID:  V-63231" -ForegroundColor Green
        $esx | Get-AdvancedSetting -Name Security.PasswordQualityControl | Set-AdvancedSetting -Value "similar=deny retry=3 min=disabled,disabled,disabled,disabled,15" -Confirm:$false

        Write-Host "Enabling Core Dump Server on $esx - VULN ID:  V-63257" -ForegroundColor Green
        
        $esxcli = $esx | get-esxcli -V2
        $arguments = $esxcli.system.coredump.network.set.CreateArgs()
        $arguments.interfacename = "vmk0"
        if ($block -eq 1) {$arguments.serveripv4 = "192.168.0.112"}
        if ($block -eq 2) {$arguments.serveripv4 = "192.168.0.113"}
        if ($block -eq 3) {$arguments.serveripv4 = "192.168.0.114"}
        if ($block -eq 4) {$arguments.serveripv4 = "192.168.0.115"}
        $arguments.serverport = 6500
        $esxcli.system.coredump.network.set.Invoke($arguments)

        $arguments = $esxcli.system.coredump.network.set.CreateArgs()
        $arguments.enable = $true
        $esxcli.system.coredump.network.set.Invoke($arguments)

        Write-Host "Setting the DoD Logon Banner" -ForegroundColor Green
        $issue = "You are accessing a U.S. Government (USG) Information System (IS) that is provided for USG-authorized use only. By using this IS (which includes any device attached to this IS), you consent to the following conditions: -The USG routinely intercepts and monitors communications on this IS for purposes including, but not limited to, penetration testing, COMSEC monitoring, network operations and defense, personnel misconduct (PM), law enforcement (LE), and counterintelligence (CI) investigations. -At any time, the USG may inspect and seize data stored on this IS. -Communications using, or data stored on, this IS are not private, are subject to routine monitoring, interception, and search, and may be disclosed or used for any USG-authorized purpose. -This IS includes security measures (e.g., authentication and access controls) to protect USG interests--not for your personal benefit or privacy. -Notwithstanding the above, using this IS does not constitute consent to PM, LE or CI investigative searching or monitoring of the content of privileged communications, or work product, related to personal representation or services by attorneys, psychotherapists, or clergy, and their assistants. Such communications and work product are private and confidential. See User Agreement for details."
        $esx | get-advancedsetting -Name Config.Etc.issue | set-advancedsetting -value $issue -Confirm:$false
    
        #Additional Advanced Configurations
        $esx | get-advancedsetting -Name UserVars.HostClientCEIPOptIn | Set-AdvancedSetting -Value 2 -Confirm:$false
        $esx | Get-AdvancedSetting -Name UserVars.ToolsRamdisk | Set-AdvancedSetting -Value 1 -Confirm:$false 
        $esx | Get-AdvancedSetting -Name VSAN.SwapThickProvisionDisabled | Set-AdvancedSetting -Value 1 -Confirm:$false 
}

## Apply ESXi Firewall Settings
function Apply-Firewall{
    param (
       [VMware.VimAutomation.ViCore.Impl.V1.Inventory.VMHostImpl] $vmhost
    )

    $esxfw = ($vmhost | get-esxcli -v2).network.firewall
    
    #Disable the Firewall (It will be enabled at the end of this script)
    write "Disable the firewall on $vmhost"
    $arguments = $esxfw.set.CreateArgs()
    $arguments.enabled = $false
    $esxfw.set.Invoke($arguments)

    #Create and set global argument sets
    $rulesetArgument = $esxfw.ruleset.set.CreateArgs()
    $rulesetArgument.allowedall = $false
        
    $arguments = $esxfw.ruleset.allowedip.add.CreateArgs()
    $arguments.ipaddress
    $enabledServices = $esxfw.ruleset.list.Invoke() | ?{$_.Enabled -eq $true}
    
    #Add the allowed networks to all enabled rules that are set to ANY
    foreach ($fwservice in $enabledServices){
        $anotherArgument = $esxfw.ruleset.allowedip.list.CreateArgs()
        $anotherArgument.rulesetid = $fwservice.Name
        $rulesetArgument.rulesetid = $fwservice.Name
        $arguments.rulesetid = $fwservice.Name
        
        #Add the VSAN multicast addresses to the Virtual SAN Clustering service firewall rule
        if ($fwservice.Name -eq "cmmds"){
            write "Disallow all IP addresses for $($fwservice.Name)"
            $esxfw.ruleset.set.Invoke($rulesetArgument)

            $arguments.ipaddress = "192.168.0.0/16"
            write "Allow 192.168.0.0 on Virtual SAN Clustering Service"
            $esxfw.ruleset.allowedip.add.Invoke($arguments)
            
            $arguments.ipaddress = "192.168.1.4"
            write "Allow 192.168.1.4 on Virtual SAN Clustering Service"
            $esxfw.ruleset.allowedip.add.Invoke($arguments)
            
            $arguments.ipaddress = "192.168.3.3"
            write "Allow 192.168.3.3 on Virtual SAN Clustering Service"
            $esxfw.ruleset.allowedip.add.Invoke($arguments)

            
        }
        if ($fwservice.Name -eq "rdt"){
            write "Disallow all IP addresses for $($fwservice.Name)"
            $esxfw.ruleset.set.Invoke($rulesetArgument)

            $arguments.ipaddress = "192.168.0.0/16"
            write "Allow 192.168.0.0 on $($fwservice.Name)"
            $esxfw.ruleset.allowedip.add.Invoke($arguments)
            
            
        }
        if ($fwservice.Name -eq "vsanvp"){
            write "Disallow all IP addresses for $($fwservice.Name)"
            $esxfw.ruleset.set.Invoke($rulesetArgument)

            write "Allow 192.168.0/16 on $($fwservice.Name)"
            $arguments.ipaddress = "192.168.0/16"
            $esxfw.ruleset.allowedip.add.Invoke($arguments)

            $arguments.ipaddress = "192.168.0.0/16"
            write "Allow 192.168.0.0 on $($fwservice.Name)"
            $esxfw.ruleset.allowedip.add.Invoke($arguments)
            
           
        }
        
        #Add Guest Introspection rules
        if ($fwservice.Name -eq "vShield-Endpoint-Mux"){
            write "Disallow all IP addresses for $($fwservice.Name)"
            $esxfw.ruleset.set.Invoke($rulesetArgument)

            write "Allow 192.168.0/16 on $($fwservice.Name)"
            $arguments.ipaddress = "192.168.0/16"
            $esxfw.ruleset.allowedip.add.Invoke($arguments)

            $arguments.ipaddress = "169.254.0.0/16"
            write "Allow 169.254.0.0 on $($fwservice.Name)"
            $esxfw.ruleset.allowedip.add.Invoke($arguments)
            
        }
        
        #Add the local networks to all remaining Allowed Rules
        $allowedIPList = $esxfw.ruleset.allowedip.list.Invoke($anotherArgument) | Select AllowedIPAddresses
        if ($allowedIPList.AllowedIPAddresses -eq "All"){
            write "Disallow all IP addresses for $($fwservice.Name)"
            $esxfw.ruleset.set.Invoke($rulesetArgument)
            
            write "Allow 192.168.0/16 on $($fwservice.Name)"
            $arguments.ipaddress = "192.168.0/16"
            $esxfw.ruleset.allowedip.add.Invoke($arguments)
            
            write "Allow 192.168.0.0/16 on $($fwservice.Name)"
            $arguments.ipaddress = "192.168.0.0/16"
            $esxfw.ruleset.allowedip.add.Invoke($arguments)   
          
            write "Allow 192.168.0.0/16 on $($fwservice.Name)"
            $arguments.ipaddress = "192.168.0.0/16"
            $esxfw.ruleset.allowedip.add.Invoke($arguments)   
        }
      
    }

    #Enable the Firewall
    write "Enable the Firewall on $vmhost"
    $arguments = $esxfw.set.CreateArgs()
    $arguments.enabled = $true
    $esxfw.set.Invoke($arguments)

}


## Main Script
do
{
    Show-Menu -Title 'ESXi Configuration Menu'
    $selection = Read-Host "Please make a selection"
    $selection.ToUpper()

    switch ($selection)
    {
        '1' {
                foreach ($vmhost in $vmhosts) {Configure-Time $vmhost}
            }
        '2' {
                foreach ($vmhost in $vmhosts) {STIG-Host $vmhost}
            }
        '3' {
                foreach ($vmhost in $vmhosts) {Apply-Firewall $vmhost}
            }
        'A' {
                foreach ($vmhost in $vmhosts) {
                    Configure-Time $vmhost
                    STIG-Host $vmhost
                    Apply-Firewall $vmhost
                }
            }
    }
}
until ($selection -eq 'Q')

