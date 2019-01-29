function set-stigobject{
    param($status,$comment)
    New-Object psobject -Property @{
        Status = $status;
        Comment =  $comment
    }

}

function V-63147{
    param($hostname)
    $lockdown = Get-VMHost -Name $hostname | Select Name,@{N="Lockdown";E={$_.Extensiondata.Config.LockdownMode}}
    if($lockdown.lockdown -ne 'Enabled'){
    $comment = "Pending active directory configuration on host."+"`n`n"+"Lockdown: " + $lockdown.lockdown
        $object = set-stigobject -status "Open" -comment $comment
    }else{
        $comment = "Lockdown mode is enabled.."+"`n`n"+"Lockdown: " + $lockdown.lockdown
        $object = set-stigobject -status "NotAFinding" -comment $comment
    }
    return $object
}

function V-63175{
    param($hostname)
    $vmhost = Get-VMHost -name $hostname| Get-View
    $lockdown = Get-View $vmhost.ConfigManager.HostAccessManager
    $lockdown.QueryLockdownExceptions()
    if($lockdown -eq $null -or $lockdown -eq ''){
        $object = set-stigobject -status "Open" -comment "Pending active directory configuration on host."
    }else{
        $comment = "Lockdown mode is enabled and the list contains the following: " +"`n`n"+ $($lockdown.QuerySystemUsers() -join ', ').tostring()
        $object = set-stigobject -status "NotAFinding" -comment $comment
    }
    return $object
}

function V-63173{
    param($hostname)
    function get-DCUIAccess{
    param(
    [Parameter(Mandatory=$true)]
    [string]$hostname)
        Get-VMHost -Name $hostname | Get-AdvancedSetting -Name DCUI.Access
    }
    $dcui = get-DCUIAccess -hostname $hostname
    if($dcui.Value -ne 'root'){
        $comment = "Pending active directory configuration on host." +"`n`n"+$dcui.value
        $object = set-stigobject -status "Open" -comment $comment  
    }else{
        $comment = "DCUI.access parater set correctly." +"`n`n"+$dcui.value
        $object = set-stigobject -status "NotAFinding" -comment $comment

    }

    return $object
}

function V-63177{
    param($hostname)
    $syslog = Get-VMHost -name $hostname | Get-AdvancedSetting -Name Syslog.global.logHost
    $syslog = $syslog.Value     
    if(!$syslog){
        
        $object = set-stigobject -status "Open" -comment "Syslog.global.logHost: $syslog"
     }else{
        $object = set-stigobject -status "NotAFinding" -comment "Syslog configuration in place to point to vRealize Log insight system."
     }
    return $object
}

function V-63179{
    param($hostname)
    $lockout = Get-VMHost -Name $hostname | Get-AdvancedSetting -Name Security.AccountLockFailures
    if($lockout.Value -ne 3){
        $object = set-stigobject -status "Open" -comment "lockout value: " + $lockout.Value
    }else{
        $object = set-stigobject -status "NotAFinding" -comment "Initial configuration is performed via ESXi host configuration script, host profile will maintain compliance."
    }
    return $object
}

function V-63181{
    param($hostname)
    $unlock = Get-VMHost -Name $hostname | Get-AdvancedSetting -Name Security.AccountUnlockTime
    if($unlock.Value -ne 900){
    $object = set-stigobject -status "Open" -comment "unlock value: " + $unlock.Value
    }
    $object = set-stigobject -status "NotAFinding" -comment "Initial configuration is performed via ESXi host configuration script, host profile will maintain compliance."
    return $object
}

function V-63183{
    param($hostname)
    $banner = Get-VMHost -Name $hostname | Get-AdvancedSetting -Name Annotations.WelcomeMessage
    $result = $banner.Value -like "*You are accessing a U.S. Government (USG) Information System (IS) that is provided for USG-authorized use only.*"
     if(!$result){
        $comment = "Annotations.WelcomeMessage: " + $banner.Value
        $object = set-stigobject -status "Open" -comment $comment
     }else{
         $comment = "Initial configuration is performed via ESXi host configuration script." +"`n`n"+"Annotations.WelcomeMessage: " + $banner.Value
        $object = set-stigobject -status "NotAFinding" -comment $comment
     }
    return $object
}

function V-63185{
    param($hostname)
    $banner = Get-VMHost -Name $hostname | Get-AdvancedSetting -Name Config.Etc.issue
    $banner = $banner.Value -like "*You are accessing a U.S. Government*"
     if(!$banner){
        $comment = "Config.Etc.issue : $banner"
        $object = set-stigobject -status "Open" -comment $comment
     }else{
         $comment = "Initial configuration is performed via ESXi host configuration script." +"`n`n"+"Config.Etc.issue : $banner"
        $object = set-stigobject -status "NotAFinding" -comment $comment
     }
    return $object
}

function V-63221{
    param($hostname,$cred)
    $ssh = Get-VMHostService -VMHost $hostname | Where-Object {$_.label -eq "ssh"}
    if($ssh.Running -eq $false){
        Start-VMHostService $ssh
    }
    $ClientAliveCountMax = echo y| plink -ssh $hostname -l root -pw $cred.GetNetworkCredential().password 'grep -i "^ClientAliveCountMax" /etc/ssh/sshd_config'
    if($ClientAliveCountMax -ne 'ClientAliveCountMax 3'){
        $comment = "ClientAliveCountMax value: " + $ClientAliveCountMax
        $object = set-stigobject -status "Open" -comment $comment
    }else{
        $comment = "Initial configuration is performed via ESXi host configuration script."+ "`n`n" + "ClientAliveCountMax value: $ClientAliveCountMax"
    }
        $object = set-stigobject -status "NotAFinding" -comment $comment
    return $object

}

function V-63223{
    param($hostname,$cred)
    $ssh = Get-VMHostService -VMHost $hostname | Where-Object {$_.label -eq "ssh"}
    if($ssh.Running -eq $false){
        Start-VMHostService $ssh
    }
    $ClientAliveInterval = echo y| plink -ssh $hostname -l root -pw $cred.GetNetworkCredential().password 'grep -i "^ClientAliveInterval" /etc/ssh/sshd_config'
    if($ClientAliveInterval -ne 'ClientAliveInterval 200'){
        $comment = "ClientAliveInterval value: " + $ClientAliveInterval
        $object = set-stigobject -status "Open" -comment $comment
    }else{
        $comment = "Initial configuration is performed via ESXi host configuration script."+ "`n`n" + "ClientAliveInterval value: $ClientAliveInterval"
        $object = set-stigobject -status "NotAFinding" -comment $comment
    }
    return $object

}

function V-63283{
    param($hostname)
    $fp = Get-VMHostFirewallDefaultPolicy -VMHost $hostname
    $result = $fp.IncomingEnabled -eq $false -and $fp.OutgoingEnabled -eq $false
    if($result -ne $true){
        $comment = $fp.IncomingEnabled.ToString()  + " " + $fp.OutgoingEnabled.ToString()
       $object = set-stigobject -status "Open" -comment "NOT CURRENTLY CONFIGURED.  NETWORK SEGMENTS ARE STILL DYNAMIC." 
    }else{
        $object = set-stigobject -status "NotAFinding" -comment "Initial configuration is performed via hardening script, host profile will maintain compliance." 
    }
    
    return $object
}

function V-63285{
    param($hostname)
    $fp = Get-VMHostFirewallDefaultPolicy -VMHost $hostname
    $result = $fp.IncomingEnabled -eq $false -and $fp.OutgoingEnabled -eq $false
    if($result -ne $true){
        $comment = "The firewall is incorrectly configured"+"`n`n"+$fp.IncomingEnabled.ToString()  + " " + $fp.OutgoingEnabled.ToString()
       $object = set-stigobject -status "Open" -comment $comment
    }else{
        $comment = "Initial configuration is performed via hardening script, host profile will maintain compliance."+"`n`n"+$fp.IncomingEnabled.ToString()  + " " + $fp.OutgoingEnabled.ToString()
        $object = set-stigobject -status "NotAFinding" -comment $comment
    }
    
    return $object
}

function V-63187{
    param($hostname,$cred)
    $ssh = Get-VMHostService -VMHost $hostname | Where-Object {$_.label -eq "ssh"}
    if($ssh.Running -eq $false){
        Start-VMHostService $ssh
    }
    $Banner = echo y| plink -ssh $hostname -l root -pw $cred.GetNetworkCredential().password 'grep -i "^Banner" /etc/ssh/sshd_config'
    if($Banner -ne 'Banner /etc/issue'){
        $comment = "Banner value: " + $Banner
        $object = set-stigobject -status "Open" -comment $comment
    }else{
        $comment = "Initial configuration is performed via ESXi host configuration script."+ "`n`n" + "Banner value: $Banner"
        $object = set-stigobject -status "NotAFinding" -comment $comment
    }
    return $object
}

function V-63189{
    param($hostname,$cred)
    $ssh = Get-VMHostService -VMHost $hostname | Where-Object {$_.label -eq "ssh"}
    if($ssh.Running -eq $false){
        Start-VMHostService $ssh
    }
    $Ciphers = echo y| plink -ssh $hostname -l root -pw $cred.GetNetworkCredential().password 'grep -i "^Ciphers" /etc/ssh/sshd_config'
    if($Ciphers -ne 'Ciphers aes128-ctr,aes192-ctr,aes256-ctr,aes128-cbc,aes192-cbc,aes256-cbc'){
        $comment = "Ciphers value: " + $Ciphers
        $object = set-stigobject -status "Open" -comment $comment
    }else{
        $comment = "Initial configuration is performed via ESXi host configuration script."+ "`n`n" + "Ciphers value: $Ciphers"
        $object = set-stigobject -status "NotAFinding" -comment $comment
    }
    return $object
}

function V-63191{
    param($hostname,$cred)
    $ssh = Get-VMHostService -VMHost $hostname | Where-Object {$_.label -eq "ssh"}
    if($ssh.Running -eq $false){
        Start-VMHostService $ssh
    }
    $Protocol = echo y| plink -ssh $hostname -l root -pw $cred.GetNetworkCredential().password 'grep -i "^Protocol" /etc/ssh/sshd_config'
    if($Protocol -ne 'Protocol 2'){
        $comment = "Protocol value: " + $Protocol
        $object = set-stigobject -status "Open" -comment $comment
    }else{
        $comment = "Initial configuration is performed via ESXi host configuration script."+ "`n`n" + "Protocol value: $Protocol"
        $object = set-stigobject -status "NotAFinding" -comment $comment
    }
    return $object
}

function V-63193{
    param($hostname,$cred)
    $ssh = Get-VMHostService -VMHost $hostname | Where-Object {$_.label -eq "ssh"}
    if($ssh.Running -eq $false){
        Start-VMHostService $ssh
    }
    $IgnoreRhosts = echo y| plink -ssh $hostname -l root -pw $cred.GetNetworkCredential().password 'grep -i "^IgnoreRhosts" /etc/ssh/sshd_config'
    if($IgnoreRhosts -ne 'IgnoreRhosts yes'){
        $comment = "IgnoreRhosts value: " + $IgnoreRhosts
        $object = set-stigobject -status "Open" -comment $comment
    }else{
        $comment = "Initial configuration is performed via ESXi host configuration script."+ "`n`n" + "IgnoreRhosts value: $IgnoreRhosts"
        $object = set-stigobject -status "NotAFinding" -comment $comment
    }
    return $object
}

function V-63195{
    param($hostname,$cred)
    $ssh = Get-VMHostService -VMHost $hostname | Where-Object {$_.label -eq "ssh"}
    if($ssh.Running -eq $false){
        Start-VMHostService $ssh
    }
    $HostbasedAuthentication = echo y| plink -ssh $hostname -l root -pw $cred.GetNetworkCredential().password 'grep -i "^HostbasedAuthentication" /etc/ssh/sshd_config'
    if($HostbasedAuthentication -ne 'HostbasedAuthentication no'){
        $comment = "HostbasedAuthentication value: " + $HostbasedAuthentication
        $object = set-stigobject -status "Open" -comment $comment
    }else{
        $comment = "Initial configuration is performed via ESXi host configuration script."+ "`n`n" + "HostbasedAuthentication value: $HostbasedAuthentication"
        $object = set-stigobject -status "NotAFinding" -comment $comment
    }
    return $object

}

function V-63197{
    param($hostname,$cred)
    $ssh = Get-VMHostService -VMHost $hostname | Where-Object {$_.label -eq "ssh"}
    if($ssh.Running -eq $false){
        Start-VMHostService $ssh
    }
    $PermitRootLogin = echo y| plink -ssh $hostname -l root -pw $cred.GetNetworkCredential().password 'grep -i "^PermitRootLogin" /etc/ssh/sshd_config'
    if($PermitRootLogin -ne 'PermitRootLogin no'){
        $comment = "Pending active directory configuration on host."+"`n`n"+"PermitRootLogin value: " + $PermitRootLogin
        $object = set-stigobject -status "Open" -comment $comment
    }else{
        $comment = "Initial configuration is performed via ESXi host configuration script."+ "`n`n" + "PermitRootLogin value: $PermitRootLogin"
        $object = set-stigobject -status "NotAFinding" -comment $comment
    }
    return $object
}

function V-63199{
    param($hostname,$cred)
    $ssh = Get-VMHostService -VMHost $hostname | Where-Object {$_.label -eq "ssh"}
    if($ssh.Running -eq $false){
        Start-VMHostService $ssh
    }
    $PermitEmptyPasswords = echo y| plink -ssh $hostname -l root -pw $cred.GetNetworkCredential().password 'grep -i "^PermitEmptyPasswords" /etc/ssh/sshd_config'
    if($PermitEmptyPasswords -ne 'PermitEmptyPasswords no'){
        $comment = "PermitEmptyPasswords value: " + $PermitEmptyPasswords
        $object = set-stigobject -status "Open" -comment $comment
    }else{
        $comment = "Initial configuration is performed via ESXi host configuration script."+ "`n`n" + "PermitEmptyPasswords value: $PermitEmptyPasswords"
        $object = set-stigobject -status "NotAFinding" -comment $comment
    }
    return $object

}

function V-63201{
    param($hostname,$cred)
    $ssh = Get-VMHostService -VMHost $hostname | Where-Object {$_.label -eq "ssh"}
    if($ssh.Running -eq $false){
        Start-VMHostService $ssh
    }
    $PermitUserEnvironment = echo y| plink -ssh $hostname -l root -pw $cred.GetNetworkCredential().password 'grep -i "^PermitUserEnvironment" /etc/ssh/sshd_config'
    if($PermitUserEnvironment -ne 'PermitUserEnvironment no'){
        $comment = "PermitUserEnvironment value: " + $PermitUserEnvironment
        $object = set-stigobject -status "Open" -comment $comment
    }else{
        $comment = "Initial configuration is performed via ESXi host configuration script."+ "`n`n" + "PermitUserEnvironment value: $PermitUserEnvironment"
        $object = set-stigobject -status "NotAFinding" -comment $comment
    }
    return $object

}

function V-63203{
    param($hostname,$cred)
    $ssh = Get-VMHostService -VMHost $hostname | Where-Object {$_.label -eq "ssh"}
    if($ssh.Running -eq $false){
        Start-VMHostService $ssh
    }
    $MACs = echo y| plink -ssh $hostname -l root -pw $cred.GetNetworkCredential().password 'grep -i "^MACs" /etc/ssh/sshd_config'
    if(!$MACs.Contains('hmac-sha2-256') -and !$MACs.Contains('hmac-sha2-512') -and !$MACs.Contains('hmac-sha1')){
        $comment = "MACs value: " + $MACs
        $object = set-stigobject -status "Open" -comment $comment
    }else{
        $comment = "Initial configuration is performed via ESXi host configuration script."+ "`n`n" + "MACs value: $MACs"
        $object = set-stigobject -status "NotAFinding" -comment $comment
    }
    return $object

}

function V-63205{
    param($hostname,$cred)
    $ssh = Get-VMHostService -VMHost $hostname | Where-Object {$_.label -eq "ssh"}
    if($ssh.Running -eq $false){
        Start-VMHostService $ssh
    }
    $GSSAPIAuthentication = echo y| plink -ssh $hostname -l root -pw $cred.GetNetworkCredential().password 'grep -i "^GSSAPIAuthentication" /etc/ssh/sshd_config'
    if($GSSAPIAuthentication -ne 'GSSAPIAuthentication no'){
        $comment = "GSSAPIAuthentication value: " + $GSSAPIAuthentication
        $object = set-stigobject -status "Open" -comment $comment
    }else{
        $comment = "Initial configuration is performed via ESXi host configuration script."+ "`n`n" + "GSSAPIAuthentication value: $GSSAPIAuthentication"
        $object = set-stigobject -status "NotAFinding" -comment $comment
    }
    return $object

}

function V-63207{
    param($hostname,$cred)
    $ssh = Get-VMHostService -VMHost $hostname | Where-Object {$_.label -eq "ssh"}
    if($ssh.Running -eq $false){
        Start-VMHostService $ssh
    }
    $KerberosAuthentication = echo y| plink -ssh $hostname -l root -pw $cred.GetNetworkCredential().password 'grep -i "^KerberosAuthentication" /etc/ssh/sshd_config'
    if($KerberosAuthentication -ne 'KerberosAuthentication no'){
        $comment = "KerberosAuthentication value: " + $KerberosAuthentication
        $object = set-stigobject -status "Open" -comment $comment
    }else{
        $comment = "Initial configuration is performed via ESXi host configuration script."+ "`n`n" + "KerberosAuthentication value: $KerberosAuthentication"
        $object = set-stigobject -status "NotAFinding" -comment $comment
    }
    return $object

}

function V-63209{
    param($hostname,$cred)
    $ssh = Get-VMHostService -VMHost $hostname | Where-Object {$_.label -eq "ssh"}
    if($ssh.Running -eq $false){
        Start-VMHostService $ssh
    }
    $StrictModes = echo y| plink -ssh $hostname -l root -pw $cred.GetNetworkCredential().password 'grep -i "^StrictModes" /etc/ssh/sshd_config'
    if($StrictModes -ne 'StrictModes yes'){
        $comment = "StrictModes value: " + $StrictModes
        $object = set-stigobject -status "Open" -comment $comment
    }else{
        $comment = "Initial configuration is performed via ESXi host configuration script."+ "`n`n" + "StrictModes value: $StrictModes"
        $object = set-stigobject -status "NotAFinding" -comment $comment
    }
    return $object

}

function V-63211{
    param($hostname,$cred)
    $ssh = Get-VMHostService -VMHost $hostname | Where-Object {$_.label -eq "ssh"}
    if($ssh.Running -eq $false){
        Start-VMHostService $ssh
    }
    $compression = echo y| plink -ssh $hostname -l root -pw $cred.GetNetworkCredential().password 'grep -i "^Compression" /etc/ssh/sshd_config'
    if($compression -ne 'compression no'){
        $comment = "Compression value: " + $compression
        $object = set-stigobject -status "Open" -comment $comment
    }else{
        $comment = "Initial configuration is performed via ESXi host configuration script." +"`n`n"+"Compression value: $compression"
        $object = set-stigobject -status "NotAFinding" -comment $comment
    }
    return $object

}

function V-63213{
    param($hostname,$cred)
    $ssh = Get-VMHostService -VMHost $hostname | Where-Object {$_.label -eq "ssh"}
    if($ssh.Running -eq $false){
        Start-VMHostService $ssh
    }
    $GatewayPorts = echo y| plink -ssh $hostname -l root -pw $cred.GetNetworkCredential().password 'grep -i "^GatewayPorts" /etc/ssh/sshd_config'
    if($GatewayPorts -ne 'GatewayPorts no'){
        $comment = "GatewayPorts value: $GatewayPorts"
        $object = set-stigobject -status "Open" -comment $comment
    }else{
        $comment = "Initial configuration is performed via ESXi host configuration script." +"`n`n"+"GatewayPorts value: $GatewayPorts"
        $object = set-stigobject -status "NotAFinding" -comment $comment
    }
    return $object

}

function V-63215{
    param($hostname,$cred)
    $ssh = Get-VMHostService -VMHost $hostname | Where-Object {$_.label -eq "ssh"}
    if($ssh.Running -eq $false){
        Start-VMHostService $ssh
    }
    $X11Forwarding = echo y| plink -ssh $hostname -l root -pw $cred.GetNetworkCredential().password 'grep -i "^X11Forwarding" /etc/ssh/sshd_config'
    if($X11Forwarding -ne 'X11Forwarding no'){
    $comment = "X11Forwarding value: " + $X11Forwarding
        $object = set-stigobject -status "Open" -comment $comment
    }else{
        $comment = "Initial configuration is performed via ESXi host configuration script."+ "`n`n" + "X11Forwarding value: $X11Forwarding"
        $object = set-stigobject -status "NotAFinding" -comment $comment
    }
    return $object

}

function V-63217{
    param($hostname,$cred)
    $ssh = Get-VMHostService -VMHost $hostname | Where-Object {$_.label -eq "ssh"}
    if($ssh.Running -eq $false){
        Start-VMHostService $ssh
    }
    $AcceptEnv = echo y| plink -ssh $hostname -l root -pw $cred.GetNetworkCredential().password 'grep -i "^AcceptEnv" /etc/ssh/sshd_config'
    if($AcceptEnv -ne 'AcceptEnv'){
        $comment = "AcceptEnv value: " + $AcceptEnv
        $object = set-stigobject -status "Open" -comment $comment
    }else{
        $comment = "Initial configuration is performed via ESXi host configuration script."+ "`n`n" + "AcceptEnv value: $AcceptEnv"
        $object = set-stigobject -status "NotAFinding" -comment $comment
    }
    return $object

}

function V-63219{
    param($hostname,$cred)
    $ssh = Get-VMHostService -VMHost $hostname | Where-Object {$_.label -eq "ssh"}
    if($ssh.Running -eq $false){
        Start-VMHostService $ssh
    }
    $PermitTunnel = echo y| plink -ssh $hostname -l root -pw $cred.GetNetworkCredential().password 'grep -i "^PermitTunnel" /etc/ssh/sshd_config'
    if($PermitTunnel -ne 'PermitTunnel no'){
        $comment = "PermitTunnel value: " + $PermitTunnel
        $object = set-stigobject -status "Open" -comment $comment
    }else{
        $comment = "Initial configuration is performed via ESXi host configuration script."+ "`n`n" + "PermitTunnel value: $PermitTunnel"
        $object = set-stigobject -status "NotAFinding" -comment $comment
    }
    return $object

}

function V-63225{
    param($hostname,$cred)
    $ssh = Get-VMHostService -VMHost $hostname | Where-Object {$_.label -eq "ssh"}
    if($ssh.Running -eq $false){
        Start-VMHostService $ssh
    }
    $MaxSessions = echo y| plink -ssh $hostname -l root -pw $cred.GetNetworkCredential().password 'grep -i "^MaxSessions" /etc/ssh/sshd_config'
    if($MaxSessions -ne 'MaxSessions 1'){
        $comment = "MaxSessions value: " + $MaxSessions
        $object = set-stigobject -status "Open" -comment $comment
    }else{
        $comment = "Initial configuration is performed via ESXi host configuration script."+ "`n`n" + "MaxSessions value: $MaxSessions"
        $object = set-stigobject -status "NotAFinding" -comment $comment
    }
    return $object

}

function V-63271{
    param($hostname)

$nicCount = 0
$svcCount = 0
$vmk = Get-VMHostNetworkAdapter -VMHost $hostname

foreach($v in $vmk){
    
    $nicCount++
    if($($v | select *).vmotionenabled |  where {$_ -match "True"}){
        $svcCount++
    }
    if($($v | select *).FaultToleranceLoggingEnabled |  where {$_ -match "True"}){
        $svcCount++
    }
    if($($v | select *).ManagementTrafficEnabled |  where {$_ -match "True"}){
        $svcCount++
    }
    if($($v | select *).VsanTrafficEnabled |  where {$_ -match "True"}){
        $svcCount++
    }
    if($svcCount -gt $nicCount){
        $object = set-stigobject -status "Open" -comment "Unneeded services are enabled on VMKernel nics"
    }else{
        $object = set-stigobject -status "NotAFinding" -comment "Only designated management VMkernels are in use.  VLANs and dedicated VMkernel ports are utilized based on traffic type requirement."
    }

}
return $object


}
function V-63275{
    param($hostname)

    $esx = Get-EsxCli -v2 -VMHost $hostname
    $snmp = $esx.system.snmp.get.invoke()
    if($snmp.enable -eq $true){
        $object = set-stigobject -status "Open" -comment "SNMP enabled. Verify is is configured in accordance with SV-77765r1_rule"
    }else{
        $object = set-stigobject -status "NotAFinding" -comment "Initial configuration is performed via hardening script, host profile will maintain compliance. SNMP is disabled."
    }


    return $object
}

function V-63277{
    param($hostname)

    $chap = Get-VMHost -name $hostname | Get-VMHostHba | Where {$_.Type -eq "iscsi"} | Select AuthenticationProperties -ExpandProperty AuthenticationProperties |where {$_.chapname -ne $null -and $_.MutualChapEnabled -ne $true}
    if($chap -ne $null){
        $comment = $chap.chapname -join ', '
        $object = set-stigobject -status "Open" -comment $comment
    }else{
        $object = set-stigobject -status "NotAFinding" -comment "Initial configuration is performed via hardening script, host profile will maintain compliance.  CHAP configuration has been put in place on the IP storage systems."
    }
    return $object
}

function V-63279{
    param($hostname)

    $memPage = Get-VMHost -name $hostname | Get-AdvancedSetting -Name Mem.ShareForceSalting    
    if($memPage.Value -ne 2){
        $object = set-stigobject -status "Open" -comment $memPage.Value.ToString()
    }else{
        $object = set-stigobject -status "NotAFinding" -comment "Initial configuration is performed via hardening script, host profile will maintain compliance. TPS has been disabled."
    }
    return $object
}

function V-63281{
    param($hostname)
    $allIP = Get-VMHost -name $hostname | Get-VMHostFirewallException | Where {$_.Enabled -eq $true} | Select Name,Enabled,@{N="AllIPEnabled";E={$_.ExtensionData.AllowedHosts.AllIP}} 
    $count = $($allip.allipenabled | where{$_ -match $true}).count    
    if($count -gt 0){
    $comment = $count.ToString() + " services in violation"
        $object = set-stigobject -status "Open" -comment $comment
    }else{
        $object = set-stigobject -status "NotAFinding" -comment ''
    }
    return $object
}

function V-63285{
    param($hostname)
    $bpdu = Get-VMHost -Name $hostname | Get-AdvancedSetting -Name Net.BlockGuestBPDU
    if($bpdu.Value -ne 1){
        $object = set-stigobject -status "Open" -comment $bpdu.Value.ToString()
    }else{
        $object = set-stigobject -status "NotAFinding" -comment ''
    }
    return $object
}

function V-63287{
    param($hostname)

    $vswitch = Get-VirtualSwitch -VMHost $hostname -Standard

    $resultTick = 0
    if($vswitch){
            foreach($v in $vswitch){
        $result = Get-SecurityPolicy -VirtualSwitch $v | Where-Object{$_.ForgedTransmits -eq $true}
        if($result.ForgedTransmits -eq $true){
            $resultTick++
        }
        if($resultTick -gt 0){
            $object = set-stigobject -status "Open" -comment ""
        }else{
            $object = set-stigobject -status "NotAFinding" -comment "Configuration setting has been configured on the virtual machine port group."
        }
    
    
    
        }
    }else{
        $object = set-stigobject -status "NotAFinding" -comment "Configuration setting has been configured on the virtual machine port group. No standard switches present."
    }

return $object
}

function V-63289{
    param($hostname)

    $vswitch = Get-VirtualSwitch -VMHost $hostname -Standard

    $resultTick = 0
    if($vswitch){
            foreach($v in $vswitch){
        $result = Get-SecurityPolicy -VirtualSwitch $v | Where-Object{$_.MacChanges -eq $true}
        if($result.ForgedTransmits -eq $true){
            $resultTick++
        }
        if($resultTick -gt 0){
            $object = set-stigobject -status "Open" -comment ""
        }else{
            $object = set-stigobject -status "NotAFinding" -comment "Configuration setting has been configured on the virtual machine port group."
        }
    
    
    
        }
    }else{
        $object = set-stigobject -status "NotAFinding" -comment "Configuration setting has been configured on the virtual machine port group. No standard switches present."
    }

return $object
}

function V-63291{
    param($hostname)

    $vswitch = Get-VirtualSwitch -VMHost $hostname -Standard

    $resultTick = 0
    if($vswitch){
            foreach($v in $vswitch){
        $result = Get-SecurityPolicy -VirtualSwitch $v | Where-Object{$_.AllowPromiscuous -eq $true}
        if($result.ForgedTransmits -eq $true){
            $resultTick++
        }
        if($resultTick -gt 0){
            $object = set-stigobject -status "Open" -comment ""
        }else{
            $object = set-stigobject -status "NotAFinding" -comment "Configuration setting has been configured on the virtual machine port group."
        }
    
    
    
        }
    }else{
        $object = set-stigobject -status "NotAFinding" -comment "Configuration setting has been configured on the virtual machine port group. No standard switches present."
    }

return $object
}

function V-63293{
    param($hostname)

    $bind = Get-VMHost -Name $hostname | Get-AdvancedSetting -Name Net.DVFilterBindIpAddress 

    if($bind.Value -ne ''){
        $object = set-stigobject -status "Open" -comment $bind.Value.ToString()
    }else{
        $object = set-stigobject -status "NotAFinding" -comment Initial configuration is performed via hardening script, host profile will maintain compliance.
    }

   
    return $object
}

function V-63295{
    param($hostname)

    $pg = Get-VirtualPortGroup -VMHost $hostname | Select Name, VLanId 

    $pgTick = 0

    foreach($p in $pg){
        if($p.vlanid -eq 1){
            $pgTick++
        }
    }

    if($pgTick -gt 0){
    $comment = $pgTick + " hosts affected"
        $object = set-stigobject -status "Open" -comment $comment
    }else{
        $object = set-stigobject -status "NotAFinding" -comment "All VMPGs have a dedicated VLAN assigned to them to support designated traffic segmentation. VLAN 1 is not configured."
    }

    return $object
}

function V-63297{
    param($hostname)

    $pg = Get-VirtualPortGroup -VMHost $hostname | Select Name, VLanId 

    $pgTick = 0

    foreach($p in $pg){
        if($p.vlanid -eq 4095){
            $pgTick++
        }
    }

    if($pgTick -gt 0){
    $comment = $pgTick + " hosts affected"
        $object = set-stigobject -status "Open" -comment $comment
    }else{
        $object = set-stigobject -status "NotAFinding" -comment "All VMPGs have a dedicated VLAN assigned to them to support designated traffic segmentation.  VLAN 4095 is not configured."
    }

    return $object
}

function V-63299{
    param($hostname)

    $pg = Get-VirtualPortGroup -VMHost $hostname | Select Name, VLanId 

    $pgTick = 0

    foreach($p in $pg){
        if($p.vlanid -ge 3968 -and $p.vladid -le 4047){
            $pgTick++
        }
    }

    if($pgTick -gt 0){
    $comment = $pgTick + " hosts affected"
        $object = set-stigobject -status "Open" -comment $comment
    }else{
        $object = set-stigobject -status "NotAFinding" -comment "All VMPGs have a dedicated VLAN assigned to them to support designated traffic segmentation.  VLAN 4095 is not configured."
    }

    return $object
}

function V-63301{
    param($hostname)

    $object = set-stigobject -status "NotAFinding" -comment "DTP is not utilized as only required VLANs are provided to each interface."


    return $object
}

function V-63303{
    param($hostname)

    $object = set-stigobject -status "NotAFinding" -comment "Spanning tree is not enabled on the interfaces that provide trunks to vSphere environment."


    return $object
}

function V-63305{
    param($hostname)

    $object = set-stigobject -status "NotAFinding" -comment "Only required VLANs are trunked down to the ESXi host switch ports."


    return $object
}

function V-63307{
    param($hostname)

    $object = set-stigobject -status "NotAFinding" -comment "IPv6 is not configured"


    return $object
}

function V-63309{
    param($hostname)

    $object = set-stigobject -status "NotAFinding" -comment "CIM accounts required are read only accounts or have least privilege configuration required per vendor documentation."


    return $object
}

function V-63311{
    param($hostname)

    $object = set-stigobject -status "NotAFinding" -comment "Process documentation is necessary to accomplish this task. On ESXi and appliances md5sum should be used to compare md5sums.  On a Microsoft based operating system Microsoft KB article 841290 provides the process to validate on a Microsoft Windows based operating system."


    return $object
}

function V-63313{
    param($hostname)

    $object = set-stigobject -status "NotAFinding" -comment "VMware vSphere Update Manager has been deployed to update the ESXi host operating system."


    return $object
}

function V-63465{
    param($hostname)
    $lockdown = Get-VMHost -Name $hostname | Select Name,@{N="Lockdown";E={$_.Extensiondata.Config.LockdownMode}} 
    if($lockdown.Lockdown -eq 'lockdowndisabled'){
        $object = set-stigobject -status "Open" -comment "Not currently configured, pending AD authentication validation."
    }else{
        $object = set-stigobject -status "NotAFinding" -comment "Lockdown mode has been enabled"
    }


    return $object
}

function V-63477{
    param($hostname)
    $syslog = Get-VMHost -name $hostname | Get-AdvancedSetting -Name Syslog.global.logHost
    $syslog = $syslog.Value     
    if(!$syslog){
        
        $object = set-stigobject -status "Open" -comment "Syslog.global.logHost: $syslog"
     }else{
        $object = set-stigobject -status "NotAFinding" -comment "Initial configuration is performed via hardening script, host profile will maintain compliance."
     }
    return $object
}

function V-63485{
    param($hostname)
    $banner = Get-VMHost -Name $hostname | Get-AdvancedSetting -Name Annotations.WelcomeMessage
    $banner.Value -like "You are accessing a U.S. Government (USG) Information System (IS) that is provided for USG-authorized use only.*"
     if(!$banner){
        
        $object = set-stigobject -status "Open" -comment "Annotations.WelcomeMessage: $banner"
     }else{
        $object = set-stigobject -status "NotAFinding" -comment "VMware certified hardening vib provides settings."
     }
    return $object
}

function V-63485{
    param($hostname)
    $logLevel = Get-VMHost -Name $hostname | Get-AdvancedSetting -Name Config.HostAgent.log.level
    if($logLevel.Value -ne 'info'){
        $object = set-stigobject -status "Open" -comment $logLevel.Value.ToString()
    }
        $object = set-stigobject -status "NotAFinding" -comment "Annotations.WelcomeMessage: $banner"

    return $object
}

function V-63501{
    param($hostname,$cred)
    $ssh = Get-VMHostService -VMHost $hostname | Where-Object {$_.label -eq "ssh"}
    if($ssh.Running -eq $false){
        Start-VMHostService $ssh
    }
    $Ciphers = echo y| plink -ssh $hostname -l root -pw $cred.GetNetworkCredential().password 'grep -i "^Ciphers" /etc/ssh/sshd_config'
    if($Ciphers -ne 'Ciphers aes128-ctr,aes192-ctr,aes256-ctr,aes128-cbc,aes192-cbc,aes256-cbc'){
        $comment = "Ciphers value: " + $Ciphers
        $object = set-stigobject -status "Open" -comment $comment
    }else{
        $comment = "Initial configuration is performed via ESXi host configuration script."+ "`n`n" + "Ciphers value: $Ciphers"
        $object = set-stigobject -status "NotAFinding" -comment $comment
    }
    return $object

}


function V-63509{
    param($hostname)
    $logLevel = Get-VMHost -Name $hostname | Get-AdvancedSetting -Name Config.HostAgent.log.level
    if($logLevel.Value -ne 'info'){
        $object = set-stigobject -status "Open" -comment $logLevel.Value.ToString()
    }else{
        $object = set-stigobject -status "NotAFinding" -comment "Initial configuration is performed via hardening script, host profile will maintain compliance."
    }
    return $object


}

function V-63531{
    Param($hostname)
    $password = Get-VMHost -Name $hostname | Get-AdvancedSetting -Name Security.PasswordQualityControl 
    #$password | Where-Object{$_.Value -ne "similar=deny retry=3 min=disabled,disabled,disabled,disabled,15"}
    if($password.value -notlike "similar=deny retry=3 min=disabled,disabled,disabled,disabled,15"){
        $object = set-stigobject -status "Open" -comment $password.Value
    }else{
        $object = set-stigobject -status "NotAFinding" -comment "Initial configuration is performed via ESXi host configuration script, host profile maintains compliance.
"
    }
    return $object
}


function V-63605{
    param($hostname)
        $object = set-stigobject -status "NotAFinding" -comment "Authentication proxy configuration is set via host profile configuration."
    return $object


}

function V-63757{
    Param($hostname)
    <#$jdm = Get-VMHost -Name $hostname | Select Name, ` @{N="HostProfile";E={$_ | Get-VMHostProfile}}, ` 
    @{N="JoinADEnabled";E={($_ | Get-VmHostProfile).ExtensionData.Config.ApplyProfile.Authentication.ActiveDirectory.Enabled}}, ` 
    @{N="JoinDomainMethod";E={(($_ | Get-VMHostProfile).ExtensionData.Config.ApplyProfile.Authentication.ActiveDirectory | `
    Select -ExpandProperty Policy | Where {$_.Id -eq "JoinDomainMethodPolicy"}).Policyoption.Id}}     
    if($jdm.JoinDomainMethod -ne "FixedCAMConfigOption"){
        $comment = "Current parameter set to -" + $jdm.JoinDomainMethod.ToString() 
        $object = set-stigobject -status "Open" -comment 'Parameter not consistent with the required criteria'
    }else{#>
        $object = set-stigobject -status "NotAFinding" -comment "Authentication proxy configuration is set via host profile configuration."
    <#}#>
    return $object

}

function V-63769{
    Param($hostname)
    
    $esxadmin = Get-VMHost -name $hostname | Get-AdvancedSetting -Name Config.HostAgent.plugins.hostsvc.esxAdminsGroup  
    if($esxadmin.Value -eq "ESX Admins"){   
        $object = set-stigobject -status "Open" -comment $esxadmin.Value.ToString()
    }else{
        $object = set-stigobject -status "NotAFinding" -comment "Authentication proxy configuration is set via host profile configuration. ESX Admins group not in use."
    }
    return $object

}

function V-63771{
    Param($hostname)

    $object = set-stigobject -status "Not_Applicable" -comment "Multifactor authentication is not in place at this time."
    return $object

}

function V-63773{
    Param($hostname)
    $to = Get-VMHost -Name $hostname | Get-AdvancedSetting -Name UserVars.ESXiShellInteractiveTimeOut   
    if($to.Value -ne 600){
        $object = set-stigobject -status "Open" -comment $to.Value.ToString()
    }else{
        $object = set-stigobject -status "NotAFinding" -comment "Initial configuration is performed via hardening script, host profile will maintain compliance."
    }
    return $object

}

function V-63775{
    Param($hostname)
    $timeout = Get-VMHost -Name $hostname | Get-AdvancedSetting -Name UserVars.ESXiShellTimeOut 
    if($timeout.Value -ne 600){
       
        $object = set-stigobject -status "Open" -comment $timeout.Value.ToString()
    }else{
        $object = set-stigobject -status "NotAFinding" -comment "Initial configuration is performed via hardening script, host profile will maintain compliance."
    }
    return $object

}

function V-63777{
    Param($hostname)
    $dcui = Get-VMHost -Name $hostname | Get-AdvancedSetting -Name UserVars.DcuiTimeOut     
    if($dcui.Value -ne 600){
       
        $object = set-stigobject -status "Open" -comment $dcui.Value.ToString()
    }else{
        $object = set-stigobject -status "NotAFinding" -comment "Initial configuration is performed via hardening script, host profile will maintain compliance."
    }
    return $object

}

function V-63779{
    Param($hostname)
    $object = set-stigobject -status "NotAFinding" -comment "Initial configuration is performed via hardening script, host profile will maintain compliance."
    return $object

}

function V-63823{
    Param($hostname)
    $esxcli = Get-EsxCli -V2 -VMHost $hostname
    $ps = $esxcli.software.acceptance.get.Invoke()
    if($ps.ToString() -eq 'CommunitySupported'){
       
        $object = set-stigobject -status "Open" -comment $ps.ToString()
    }else{
        $object = set-stigobject -status "NotAFinding" -comment "Initial configuration is performed via hardening script, host profile will maintain compliance. Setting is set to PartnerSupported."
    }
    return $object

}

function V-63833{
    Param($hostname)
        $object = set-stigobject -status "NotAFinding" -comment 'vRealize Log insight will capture the syslog information as a remote collector.'
    return $object

}

function V-63867{
    Param($hostname)
    function Get-AdvancedPasswordQuality{
    param($hostname)
        Get-VMHost -Name $hostname | Get-AdvancedSetting -Name Security.PasswordQualityControl
    }
    $advPass = Get-AdvancedPasswordQuality -hostname $hostname
    if($advPass.value -ne 'similar=deny retry=3 min=disabled,disabled,disabled,disabled,15'){
        $comment = "Security.PasswordQualityControl is set incorrectly."+"`n`n"+$advPass.value
        $object = set-stigobject -status "Open" -comment $comment
    }else{
        $comment = "Initial configuration is performed via ESXi host configuration script, host profile maintains compliance."+"`n`n"+$advPass.Value.ToString() 
        $object = set-stigobject -status "NotAFinding" -comment $comment

    }
    return $object

}

function V-63885{
    Param($hostname)
    $ssh = Get-VMHost -Name $hostname | Get-VMHostService | Where {$_.Label -eq "SSH"}
    if($ssh.Policy -ne 'Off'){
        $comment = "SSH policy is set incorrectly" +"`n`n"+ "SSH policy is set to: " + $ssh.Policy
        $object = set-stigobject -status "Open" -comment $comment
    }
        $comment = "Initial configuration is performed via ESXi host configuration script, host profile maintains compliance." +"`n`n"+"SSH policy is set to: " + $ssh.Policy
        $object = set-stigobject -status "NotAFinding" -comment $comment
    return $object

}

function V-63893{
    Param($hostname)
    <#$dst = Get-VMHost -Name $hostname | Get-VMHostAuthentication 
    if($dst.DomainMembershipStatus -ne 'ok'){
        $object = set-stigobject -status "Open" -comment $dst.DomainMembershipStatus.ToString()
    }else{##>
        $object = set-stigobject -status "NotAFinding" -comment 'Authentication proxy configuration is set via host profile configuration. ESX Admins group is not in use.'
    <#}#>
    return $object

}

function V-63895{
    Param($hostname)
    <#$jdm = Get-VMHost -Name $hostname | Select Name, ` @{N="HostProfile";E={$_ | Get-VMHostProfile}}, ` 
    @{N="JoinADEnabled";E={($_ | Get-VmHostProfile).ExtensionData.Config.ApplyProfile.Authentication.ActiveDirectory.Enabled}}, ` 
    @{N="JoinDomainMethod";E={(($_ | Get-VMHostProfile).ExtensionData.Config.ApplyProfile.Authentication.ActiveDirectory | `
    Select -ExpandProperty Policy | Where {$_.Id -eq "JoinDomainMethodPolicy"}).Policyoption.Id}}     
    if($jdm.JoinDomainMethod -ne "FixedCAMConfigOption"){
        #if
        $comment = "Current parameter not set to FixedCAMConfigOption"
        $object = set-stigobject -status "Open" -comment 'Parameter not consistent with the required criteria'
    }else{#>
        $object = set-stigobject -status "NotAFinding" -comment "Authentication proxy configuration is set via host profile configuration."
    <#}#>
    return $object

}

function V-63897{
    Param($hostname)
    
    $esxadmin = Get-VMHost -name $hostname | Get-AdvancedSetting -Name Config.HostAgent.plugins.hostsvc.esxAdminsGroup  
    if($esxadmin.Value -eq "ESX Admins"){
        $comment = "ESX Admins group is in use: "+$esxadmin.Value.ToString()
        $object = set-stigobject -status "Open" -comment $comment
    }else{
        $object = set-stigobject -status "NotAFinding" -comment "Authentication proxy configuration is set via host profile configuration. ESX Admins group is not in use."
    }
    return $object

}

function V-63899{
    Param($hostname)

    $object = set-stigobject -status "Not_Applicable" -comment "Multifactor authentication is not in place at this time."
    return $object

}

function V-63901{
    Param($hostname)
    $esxcli = Get-EsxCli -V2 -VMHost $hostname
    $ps = $esxcli.software.acceptance.get.Invoke()
    if($ps.ToString() -eq 'CommunitySupported'){
       
        $object = set-stigobject -status "Open" -comment $ps.ToString()
    }else{
        $object = set-stigobject -status "NotAFinding" -comment "Initial configuration is performed via hardening script, host profile will maintain compliance. Setting is set to PartnerSupported"
    }
    return $object

}

function V-63903{
    param($hostname)
    $syslog = Get-VMHost -name $hostname | Get-AdvancedSetting -Name Syslog.global.logHost
    $syslog = $syslog.Value     
    if(!$syslog){
        
        $object = set-stigobject -status "Open" -comment "Syslog.global.logHost: $syslog"
     }else{
        $object = set-stigobject -status "NotAFinding" -comment "Initial configuration is performed via hardening script, host profile will maintain compliance.  vRealize Log insight will capture the syslog information as a remote collector."
     }
    return $object
}

function V-63905{
    Param($hostname)
    $password = Get-VMHost -Name $hostname | Get-AdvancedSetting -Name Security.PasswordQualityControl 
    #$password | Where-Object{$_.Value -ne "similar=deny retry=3 min=disabled,disabled,disabled,disabled,15"}
    if($password.value -notlike "similar=deny retry=3 min=disabled,disabled,disabled,disabled,15"){
        $object = set-stigobject -status "Open" -comment $password.Value
    }else{
        $object = set-stigobject -status "NotAFinding" -comment "Initial configuration is performed via hardening script, host profile will maintain compliance."
    }
    return $object
}

function V-63907{
    Param($hostname)
    <#$dst = Get-VMHost -Name $hostname | Get-VMHostAuthentication 
    if($dst.DomainMembershipStatus -ne 'ok'){
        $object = set-stigobject -status "Open" -comment $dst.DomainMembershipStatus.ToString()
    }else{#>
        $object = set-stigobject -status "NotAFinding" -comment 'Authentication proxy configuration is set via host profile configuration. ESX Admins group is not in use.'
    <#}#>
    return $object

}
function V-63227{
    param($hostname)
    $object = set-stigobject -status "NotAFinding" -comment "Initial configuration is performed via ESXi host configuration script."
    return $object
}


function V-63229{
    param($hostname)
    $object = set-stigobject -status "NotAFinding" -comment "Initial configuration is performed via ESXi host configuration script, host profile will maintain compliance."
    return $object
}

function V-63231{
    param($hostname)
    $password = Get-VMHost -Name $hostname | Get-AdvancedSetting -Name Security.PasswordQualityControl
    $password = $password.Value -eq "similar=deny retry=3 min=disabled,disabled,disabled,disabled,15"
     if(!$password){
        
        $object = set-stigobject -status "Open" -comment " Security.PasswordQualityControl: $password"
     }else{
        $object = set-stigobject -status "NotAFinding" -comment "Initial configuration is performed via ESXi host configuration script."
     }
    return $object
}


function V-63233{
    param($hostname)
    $object = set-stigobject -status "NotAFinding" -comment "Initial configuration is performed via ESXi host configuration script."
    return $object
}

function V-63235{
    param($hostname)
    $object = set-stigobject -status "NotAFinding" -comment "Initial configuration is performed via ESXi host configuration script."
    return $object
}

function V-63237{
    param($hostname)
    $object = set-stigobject -status "NotAFinding" -comment "Initial configuration is performed via ESXi host configuration script, host profile will maintain compliance."
    return $object
}

function V-63239{
    param($hostname)
    $object = set-stigobject -status "NotAFinding" -comment "Initial configuration is performed via ESXi host configuration script, host profile will maintain compliance."
    return $object
}

function V-63241{
    param($hostname)
    $object = set-stigobject -status "NotAFinding" -comment "Initial configuration is performed via ESXi host configuration script, host profile will maintain compliance."
    return $object
}

function V-63243{
    param($hostname)
    $object = set-stigobject -status "Not_Applicable" -comment "Authentication proxy configuration is set via host profile configuration.  ESX Admins group is not utilized for authentication or authorization."
    return $object
}

function V-63245{
    param($hostname)
    $object = set-stigobject -status "NotAFinding" -comment "Authentication proxy configuration is set via host profile configuration."

    return $object
}

function V-63247{
    param($hostname)
    $object = set-stigobject -status "NotAFinding" -comment "Authentication proxy configuration is set via host profile configuration.  ESX Admins group is not utilized for authentication or authorization."
    return $object
}

function V-63249{
    param($hostname)
    $object = set-stigobject -status "Not_Applicable" -comment "Multifactor authentication infrastructure is not in place at this time."
    return $object
}

function V-63251{
    param($hostname)
    $object = set-stigobject -status "NotAFinding" -comment "Initial configuration is performed via hardening script, host profile will maintain compliance."
    return $object
}

function V-63253{
    param($hostname)
    $object = set-stigobject -status "NotAFinding" -comment "Initial configuration is performed via hardening script, host profile will maintain compliance."
    return $object
}

function V-63255{
    param($hostname)
    $object = set-stigobject -status "NotAFinding" -comment "Initial configuration is performed via hardening script, host profile will maintain compliance."
    return $object
}

function V-63257{
    param($hostname)
    $object = set-stigobject -status "NotAFinding" -comment "VMware vSphere vCenter Core dump collector has been enabled on the VCSA systems."
    return $object
}

function V-63259{
    param($hostname)
    $object = set-stigobject -status "NotAFinding" -comment "Initial configuration is performed via hardening script, host profile will maintain compliance.  vRealize Log insight will capture the syslog information as a remote collector."
    return $object
}

function V-63261{
    param($hostname)
    $object = set-stigobject -status "NotAFinding" -comment "Initial configuration is performed via hardening script, host profile will maintain compliance.  The Hosts have been configured with two systems for redundancy and are set to start and stop with the host."
    return $object
}

function V-63263{
    param($hostname)
    $esxcli = Get-EsxCli -V2 -VMHost $hostname
    $partner = $esxcli.software.acceptance.get.invoke()
    if($partner -ne "PartnerSupported"){
        $object = set-stigobject -status "Open" -comment "unsigned VIB is present"
    }else{
        $object = set-stigobject -status "NotAFinding" -comment "Initial configuration is performed via hardening script, host profile will maintain compliance. Setting is set to PartnerSupported."
    }
    return $object
}

function V-63265{
    param($hostname)
    $vmotion = Get-VMHostNetworkAdapter -VMHost $hostname -PortGroup 168-Server-Prod-vMotion
    $vmotionComment = "vMotion equals: " + $vmotion.VMotionEnabled
    if($vmotion.VMotionEnabled -ne $true){
        $object = set-stigobject -status "Open" -comment "vMotion not enabled for vMotion VLAN"
    }else{
        $object = set-stigobject -status "NotAFinding" -comment "VMotion is isolated via VLAN and via physical interface."
    }
    return $object
}

function V-63267{
    param($hostname)
    $mgmt = Get-VMHostNetworkAdapter -VMHost $hostname | Where-Object{$_.ManagementTrafficEnabled -eq $true}
    $mgmtComment = $mgmt.ManagementTrafficEnabled
    if($mgmt.ManagementTrafficEnabled -ne $true){
        $object = set-stigobject -status "Open" -comment "Management not enabled for mgmt VLAN"
    }elseif($mgmt.count -gt 1){
        $ifList = $mgmt.name -join ', '
        $object = set-stigobject -status "Open" -comment "Multiple port groups/interfaces have management traffic enabled; $ifList"

    }
    else{
        $object = set-stigobject -status "NotAFinding" -comment "Management traffic is isolated via VLAN and via physical interface."
    }
    return $object
}

function V-63269 {
    param($hostname)
    
    $iscsiCheck = Get-VMHostStorage $hostname
    if ($iscsiCheck.SoftwareIScsiEnabled -ne $false) {
        $iscsi = Get-VDPortgroup -Name "*iscsi*"
        $vlan = ($iscsi | foreach-object {$_.vlanconfiguration | where-object {$_.vlanid -ne $null -or $_.vlanid -ne ""}})
        if ($vlan.count -le 0) {
            $object = set-stigobject -status "Open" -comment "No VLANs identified"
        }
        else {
            $object = set-stigobject -status "NotAFinding" -comment "IP Storage traffic is isolated via VLAN and via physical interface."
        }
    }else{
        $object = set-stigobject -status "NotAFinding" -comment "IP Storage is not used."
    }

    return $object
}

function V-63273{
    param($hostname)
    $object = set-stigobject -status "NotAFinding" -comment "IP stacks are only utilized to support VMotion network traffic."
    return $object
}

function V-63909{
    <#param($hostname)
    $ad = Get-VMHost -Name $hostname| Select Name, ` @{N="HostProfile";E={$_ | Get-VMHostProfile}}, ` @{N="JoinADEnabled";E={($_ | Get-VmHostProfile).ExtensionData.Config.ApplyProfile.Authentication.ActiveDirectory.Enabled}}, ` @{N="JoinDomainMethod";E={(($_ | Get-VMHostProfile).ExtensionData.Config.ApplyProfile.Authentication.ActiveDirectory | Select -ExpandProperty Policy | Where {$_.Id -eq "JoinDomainMethodPolicy"}).Policyoption.Id}} 
    $ad = $ad| Where-Object{$ad.JoinDomainMethod -ne "FixedCAMConfigOption"}
    if($ad){
        $object = set-stigobject -status "Open" -comment $ad.JoinDomainMethod
    }else{#>
        $object = set-stigobject -status "NotAFinding" -comment "Authentication proxy configuration is set via host profile configuration. ESX Admins group is not in use."
    <##}#>
    return $object
}

function V-63911{
    param($hostname)
    $ad = Get-VMHost -Name $hostname | Get-AdvancedSetting -Name Config.HostAgent.plugins.hostsvc.esxAdminsGroup | select Value | Where-Object{$_.value -eq "ESX Admins"}
    if($ad){
        $object = set-stigobject -status "Open" -comment $ad.value
    }else{
        $object = set-stigobject -status "NotAFinding" -comment "Authentication proxy configuration is set via host profile configuration. ESX Admins group is not in use."
    }

    return $object
}
function V-63913{
    param($hostname)
    $object = set-stigobject -status "Not_Applicable" -comment "Multifactor authentication is not in place at this time."
    return $object
}

function V-63915{
    param($hostname)
    $loghost = Get-VMHost -Name $hostname | Get-AdvancedSetting -Name Syslog.global.logHost
    $loghost = $loghost | Where-Object {$_.Value -notlike "*ssl://*" -and $_.Value -notlike "*udp://*"}
    if($loghost){
        $object = set-stigobject -status "Open" -comment $loghost.Value
    }else{
        $object = set-stigobject -status "NotAFinding" -comment "Initial configuration is performed via hardening script, host profile will maintain compliance.  vRealize Log insight will capture the syslog information as a remote collector."
    }
    return $object
}
function V-63919{
    Param($hostname)
    $password = Get-VMHost -Name $hostname | Get-AdvancedSetting -Name Security.PasswordQualityControl 
    #$password | Where-Object{$_.Value -ne "similar=deny retry=3 min=disabled,disabled,disabled,disabled,15"}
    if($password.value -notlike "similar=deny retry=3 min=disabled,disabled,disabled,disabled,15"){
        $object = set-stigobject -status "Open" -comment $password.Value
    }else{
        $object = set-stigobject -status "NotAFinding" -comment "Initial configuration is performed via hardening script, host profile will maintain compliance."
    }
    return $object
}

function V-63921{
    Param($hostname)
    $loghost = Get-VMHost -Name $hostname | Get-AdvancedSetting -Name Syslog.global.logHost
    $loghost = $loghost | Where-Object {$_.Value -notlike "*ssl://*" -and $_.Value -notlike "*udp://*"}
    if($loghost){
        $object = set-stigobject -status "Open" -comment $loghost.Value
    }else{
        $object = set-stigobject -status "NotAFinding" -comment "Initial configuration is performed via hardening script, host profile will maintain compliance.  vRealize Log insight will capture the syslog information as a remote collector."
    }
    return $object
}

function V-63923{
    Param($hostname)
    $password= Get-VMHost -Name $hostname | Get-AdvancedSetting -Name Security.PasswordQualityControl
    #$password = $password | Where-Object{$_.Value -eq "similar=deny retry=3 min=disabled,disabled,disabled,disabled,15"}
    if($password.value -notlike "similar=deny retry=3 min=disabled,disabled,disabled,disabled,15"){
        $object = set-stigobject -status "Open" -comment 
    }else{
        $object = set-stigobject -status "NotAFinding" -comment "Initial configuration is performed via hardening script, host profile will maintain compliance."
    }
    return $object
}

function V-73129{
    Param($hostname)
    $object = set-stigobject -status "NotAFinding" -comment "The storage network is isolated from production network."
    return $object
}

function V-73131{
    Param($hostname)
    $vmhost = Get-VMHost -Name $hostname
    $vsan = Get-VsanClusterConfiguration -Cluster $vmhost.Parent
    if($vsan.VsanEnabled -ne $true){
        $object = set-stigobject -status 'Not_Applicable' -comment "VSAN not enabled in this cluster"
    }else{
        $esxcli = Get-EsxCli -v2 -VMHost $hostname
        $health = $esxcli.vsan.debug.object.health.summary.get.invoke()
        if(!$health){
            $object = set-stigobject -status 'Open' -comment 'VSAN health check disabled'
        }else{
            $object = set-stigobject -status 'NotAFinding' -comment "VSAN health check is enabled for the cluster that contains this host."
        }
    }

    return $object

}

function V-73133{
    Param($hostname)
    $object = set-stigobject -status 'Not_Applicable' -comment "The enclave is not currently connected to the internet"
    return $object

}


function V-73135{
    Param($hostname)
    If($(Get-Cluster | where {$_.VsanEnabled} | Measure).Count -gt 0){ 
        $vsan = Get-Cluster | where {$_.VsanEnabled} | Get-Datastore | where {$_.type -match "vsan"}
        if($vsan.Name -eq "vsanDatastore"){
            $object = set-stigobject -status "Open" -comment $vsan.Name
        }else{
            $object = set-stigobject -status "NotAFinding" -comment $null
        }
    } 
    else{
        $object = set-stigobject -status "Not_Applicable" -comment $null
    }
    return $object
} 