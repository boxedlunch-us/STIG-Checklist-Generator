<#
.SYNOPSIS
    Checks hosts/clusters of hosts against a list of STIG items and generates a checklist

.DESCRIPTION
    Utilizing the .ckl file that DISA STIG Viewer consumes, the script compares the settings on the hosts against the criteria in the STIG
.EXAMPLE
    ##Example of use##
.PARAMETER vCenterArray
    Any number of vCenter servers
.PARAMETER clusterName
    Isolate the scan to a single cluster
.PARAMETER AdCred
    Credentials for Active Directory; might be the same as the ESXi hosts if AD-joined
.PARAMETER esxiCred
    Credentials for ESXi host
.NOTES
    Author: Ricky Nelson
    Date:  20180307
#>
param(
    # vCenter Array
    [Parameter(Mandatory=$true)]
    [string[]]
    $vCenterArray,
    # Cluster to be scanned
    [Parameter(Mandatory=$false,HelpMessage="This doesn't need to be specified unless you want to restrict the scan to a single cluster")]
    [string]
    $clusterName,
    # Active Directory credentials
    [Parameter(Mandatory=$false)]
    [pscredential]
    $AdCred = $AdCred,
    # ESXi host credentials
    [Parameter(Mandatory=$false)]
    [pscredential]
    $esxiCred = $vcred

)
if(!$vcred){
    $vcred = Get-Credential -Message "Enter username and password for ESXi servers (this will change when AD auth implemented)"
}
if(!$ADCred){
    $ADCred = Get-Credential -Message "Enter Active Directory credentials."
}
$vds = Get-Module "VMware.VimAutomation.Vds"
if(!$vds){
    Import-Module VMware.VimAutomation.Vds
}

$vas = Get-Module VMware.VimAutomation.Storage
if(!$vas){
    Import-Module VMware.VimAutomation.Storage
}

# Get script directory
$scriptdir = split-path $script:Myinvocation.mycommand.path

# Import required Modules
Import-Module "$scriptdir\ESXi6.0_STIG_Module.psm1"
$module = Get-Module -Name ESXi6.0_STIG_Module
$commandList = $module.ExportedCommands.Values | Where-Object {$_.Name -like "*V-*"}

# Create wildcard if clustername is blank
if(!$clusterName){
    $clusterName = "**"
}

# loop through vcenters
foreach($vcenter in $vCenterArray){

    #create output folder structure
    $vcPath = test-path "$scriptdir\Output\$vcenter\"
    if(!$vcPath){
        new-item -Path "$scriptdir\Output\$vcenter\" -ItemType Directory
    }

    #connect to the vCenter and get cluster name to loop through
    Connect-VIServer $vCenter -Credential $ADCred
    $clusters = Get-Cluster -Name $clusterName
    foreach($c in $clusters){

        # check cluster path and create if neccessary
        $cPath = "$scriptdir\Output\$vcenter\"+$c.name+"\"
        $clusterPath = test-path $cPath
        if(!$clusterPath){
            new-item -Path $cPath -ItemType Directory
        }
        $hosts = Get-VMHost -Location $c.name -State Connected,Maintenance
        $deadhosts = Get-VMHost -Location $c.name -State NotResponding,Disconnected

        foreach($h in $hosts){

            # import the checklist file; this file is a special XML file that is readable by the DISA StigViewer product
            [xml]$checklist = Get-Content -Path "$scriptdir\Resources\ESXi6_Blank.ckl"
            $xml.Dispose() #Will error on the first go, as there is nothing to dispose; I'll write an exception when I'm less lazy
            Write-host "Generating checklist for " $h.Name

            ## Create outgoing xml ckl
            $outputFile = "$cPath\ESXi_"+$h.Name+".ckl"
            if($xml){
                $xml.Dispose()
            }
            $xml = [System.Xml.XmlWriter]::Create("$cPath\ESXi_"+$h.name+".ckl")
            $checklist.CHECKLIST.ASSET.HOST_NAME = $h.name.ToString()
            foreach($command in $commandList){
                Start-Sleep -Milliseconds 100 # had to add this to keep powershell from skipping over functions in the module

                # List and run all commands in module related to STIG checks
                # Change status and comment on STIG checklist as each check is performed
                write-host "Performing check" $command.name
                $jogatize = (Get-Command $command -CommandType Function).ScriptBlock
                $check = Invoke-Command $jogatize -ArgumentList $h.Name, $vcred
                $finding = ($checklist.CHECKLIST.STIGS.iSTIG.VULN.stig_data | Where-Object{$_.attribute_data -eq $command.Name}).parentnode
                $finding.STATUS = $check.Status
                if($check.Comment){
                    $finding.COMMENTS = $check.Comment.ToString()
                }

            } #<--End Foreach commandlist

            # Writing in this format allows for correct parsing by STIG Viewer at this time.
            $checklist.Save($xml)

            write-host $h.name " checklist complete!" -ForegroundColor Green

        }#<--End Foreach hosts

        foreach($d in $deadhosts){
            [xml]$checklist = Get-Content -Path "$scriptdir\Resources\ESXi6_Blank.ckl"
            $xml.Dispose()
            Write-host "Generating checklist for " $d.Name
            ## Create outgoing xml ckl
            $outputFile = "$cPath\DisconnectedHost_ESXi_"+$d.Name+".ckl"
            if($xml){
                $xml.Dispose()
            }
            $xml = [System.Xml.XmlWriter]::Create("$cPath\DisconnectedHost_ESXi_"+$d.name+".ckl")
            $checklist.CHECKLIST.ASSET.HOST_NAME = $d.name.ToString()
            # Writing in this format allows for correct parsing by STIG Viewer at this time.
            $checklist.Save($xml)

            write-host $d.name " checklist complete!" -ForegroundColor Green
        }#<--End Foreach deadhosts

    }#<-- End Foreach clusters


    Disconnect-VIServer $vCenter -Confirm:$false
}#<-- End Foreach vcenters