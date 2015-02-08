<#
    CheckWhatsGood.ps1
    Ben Smith

    .SYNOPSIS
    Script contains a series of functions and an interface to call them. All of which make it easier to 
    identify malicious or suspicious activity on a Windows PC.
    Much data from SANS Find Evil poster: http://digital-forensics.sans.org/media/poster_2014_find_evil.pdf
    
#>

# Do some funky checks to see if we're local admin. if not, spawn a new process.
If (-NOT ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator"))
{   
    $arguments = "& '" + $myinvocation.mycommand.definition + "'"
    Start-Process powershell -Verb runAs -ArgumentList $arguments
    Break
}


Function Get-Browsers($netstat, $processlist)
{
    <#    
    .SYNOPSIS
    Obtains a list of processes that are common browsers.

    .DESCRIPTION
    This function filters the process list to only common browsers. It is mostly for use with other functions.

    .PARAMETER netstat
    Output of Get-Netstat from the Kansa framework.

    .PARAMETER processlist
    List of processes running on the system. `Get-Process -User` typically.

    #>
    $browsers = $processlist | Where-Object {$_.ProcessName -eq "chrome" -or $_.ProcessName -eq "firefox" -or $_.ProcessName -eq "iexplore" -or $_.ProcessName -eq "safari"} # filter processes for common browser names
    return $browsers
}
Function Check-Browsers($netstat)
{
    <#
    .SYNOPSIS
    Checks any running browsers to see if they are communicating on non-standard ports.

    .DESCRIPTION
    This function will take a list of currently running browsers on the system and check to see 
    if they are talking or listening on ports other than 21,80,443,8080,8443.

    .PARAMETER netstat
    Output of Get-Netstat from the Kansa framework.

    .NOTES
    Browser plugins and auto-update features may cause false positives here. 
    #>
    $browsers = $netstat | Where-Object {$_.Process -match "chrome" -or $_.Process -match "firefox" -or $_.Process -match "iexplore" -or $_.Process -match "safari"} # filter netstat for common browser names. the nestat object is an array of a string and array, so take the second element.
    $browsers = $browsers | Where-Object{$_.ForeignPort -ne 80 -and $_.ForeignPort -ne 443 -and $_.ForeignPort -ne 8080 -and $_.ForeignPort -ne 8443}
    return $browsers
}

Function Check-HTTP($netstat)
{
    <#

    .SYNOPSIS
    Checks non-browser processes for communication on common browser ports.
        
    .DESCRIPTION
    This function will check processes that don't match common browsers to see if they are talking or listening
    on ports 21,22,23,80,443,8080,8443. This may be an indication that the process is exfiltrating data.

    .PARAMETER netstat
    Output of Get-Netstat from the Kansa framework.

    .NOTES
    False positives will include (legitimate) FTP clients
    #>

    $notbrowsers = $netstat | Where-Object{$_.Process -notmatch "chrome" -and $_.Process -notmatch "firefox" -and $_.Process -notmatch "iexplore" -and $_.Process -notmatch "safari"}
    $arewetalking = $notbrowsers | Where-Object{$_.ForeignPort -eq 80 -or $_.ForeignPort -eq 443 -or $_.ForeignPort -eq 8080 -or $_.ForeignPort -eq 8443 -or $_.ForeignPort -eq 21 -or $_.ForeignPort -eq 23}
    
    return $arewetalking
}

Function Check-Listeners($netstat)
{
    <#

    .SYNOPSIS
    Check processes that are listening on various common ports. 
        
    .DESCRIPTION
    This function will check processes to see if anything is listening on 80, 443, 8080, 8443, 21, 23

    .PARAMETER netstat
    Output of Get-Netstat from the Kansa framework.

    #>
    $arewelistening = $netstat | Where-Object{$_.LocalPort -eq 80 -or $_.LocalPort -eq 443 -or $_.LocalPort -eq 8080 -or $_.LocalPort -eq 8443 -or $_.LocalPort -eq 21 -or $_.LocalPort -eq 23}
    
    return $arewelistening
}

Function Check-SSH ($netstat)
{
    <#

    .SYNOPSIS
    Check for processes that are communicating on port 22.
    
    .DESCRIPTION
    This should show anything that may be making outbound SSH connections. Average users wouldn't be running 
    things like Putty, so this may be an indicator of malicious activity.

    .PARAMETER netstat
    Output of Get-Netstat from the Kansa framework.

    #>

    $ssh = $netstat | Where-Object{$_.LocalPort -eq 22 -or $_.ForeignPort -eq 22}
    Return $ssh
}

Function Check-DNS ($netstat)
{
    <#

    .SYNOPSIS
    Are processes communicating out on TCP or UDP 53?

    .DESCRIPTION
    On a home PC, only the OS should be talking out on 53. On a corporate PC, there should really only be connections with 1 DNS server.
    Anything else can be considered malicious.

    .PARAMETER netstat
    Output of Get-Netstat from the Kansa framework.

    .NOTES
    Can add a place to check for valid DNS servers.
    #>

    $dns = $netstat | Where-Object{$_.LocalPort -eq 53 -or $_.ForeignPort -eq 53}
    Return $dns
}

Function Check-BrowserPaths($processlist)
{
    <#

    .SYNOPSIS
    Make sure browsers are run from known good paths.

    .DESCRIPTION
    Take a list of known good path pairs and validate that any browser processes running paths match.

    .PARAMETER processlist
    List of processes running on the system. `Get-Process -User` typically.

    #>
    #check that the paths to the executables make sense.
    $browsers = $processlist | Where-Object {$_.ProcessName -match "chrome" -or $_.ProcessName -match "firefox" -or $_.ProcessName -match "iexplore"}
    $browsers | ForEach-Object{$browserpaths += @($_.Path)}
    $browserpaths = $browserpaths | Sort-Object -Unique
    Return $browserpaths
}

Function UserCheck-Spelling($processlist)
{    
    <#

    .SYNOPSIS
    Display a list of all processes removing common ones spelled correctly.

    .DESCRIPTION
    This should allow a reader to eyeball any processes that may use non-English Unicode characters to masquerade as legit procs.

    .PARAMETER processlist
    List of processes running on the system. `Get-Process -User` typically.

    #>
    $SystemProcesses | ForEach-Object{$name = $_; $processlist = $processlist | Where-Object{$_.Name -ne $name}} # take out system procs that are spelled correctly
    $processlist | ForEach-Object{$output += @($_.ProcessName)} # just grab the process names.
    Return $output
}

Function Check-ImagePath($processlist)
{
    <#

    .SYNOPSIS
    Check the paths of common windows processes against known good paths.

    .PARAMETER processlist
    List of processes running on the system. `Get-Process -User` typically.

    #>

    foreach ($proc in $processlist)
    {
        if($proc.Path -eq $null)
        {
            write-host $proc.ProcessName " has no path listed"
            continue
            # TODO: call WMI to get better process information. Get-WMIObject win32_process
        }
        foreach ($procsig in $SystemProcessSignatures)
        {
            if($proc.ProcessName -match $procsig[0].Replace(".exe",""))
            {
                foreach ($i in $procsig[1])
                {
                    try
                    {

                        $goodpath = $(Convert-Path $procsig[1] -ErrorAction Stop).ToLower() # convert to path and then all lowercase for matching
                        $actualpath = $(Convert-Path $proc.Path -ErrorAction Stop).ToLower() # convert to path and then all lowercase for matching
                    }
                    catch [System.Management.Automation.SessionStateException]
                    {
                        write-host $procsig[1] " or " $proc.Path " doesn't exist."
                    }
                    if($actualpath.CompareTo($goodpath) -ne 0)
                    {
                        $output += @($proc)
                        write-host $proc.path " does not match " $procsig[1] " for process ID "$proc.ID " / " $proc.name
                    }
                }
            }
        }
    }
    Return $output | Select-Object Id,ProcessName,UserName,Path
}

Function Check-ProcessParent($processlist)
{
    <#

    .SYNOPSIS
    Checks the parent for common windows processes against a known good list.

    .DESCRIPTION
    Makes sure that common windows processes are launched from the correct places. THis will also check to see if any processes have 
    "cmd.exe" or "powershell.exe" as a parent, as this is extremely unusual for home users.

    .PARAMETER processlist
    List of processes running on the system. `Get-Process -User` typically.
    #>

   foreach ($proc in $processlist)
    {
        $ProcID = $proc.Id
        $CurrentProc = (Get-WmiObject win32_process -Filter "processid='$ProcId'") # query WMI for current proc
        $ParentProcID = $CurrentProc.ParentProcessId
        $ParentProc = (Get-WmiObject win32_process -Filter "processid='$ParentProcID'") # query WMI for parent proc
        if($ParentProc.ProcessName -match "cmd.exe" -or $ParentProc.ProcessName -match "powershell.exe")
        {
            $output += @($CurrentProc)
            write-host $CurrentProc.ProcessID " / " $CurrentProc.ProcessName " was started from a command line!"
        }
        if($proc.ProcessName -match "System Idle Process")
        {
            continue
            #move along, nothing to see here. Couldn't get the next if to not match this for "System" so I handled it this way.
        }
        if($SystemProcesses -contains $proc.ProcessName)
        {
            if($proc.Id -eq $null)
            {
                # this isn't necessarily a bad thing. let the user know.
                write-host $proc.ProcessName " has no Id listed so a parent cannot be found."
                continue
            }
            foreach ($procsig in $SystemProcessSignatures)
            {
                if(($proc.ProcessName -match $procsig[0].Replace(".exe","")) -and ($procsig[2] -ne ""))
                {
                    if($ParentProc.ProcessName -ne $procsig[2]) # does the parent process match the signature? (remove '.exe' for matching")
                    {
                        $output += @($CurrentProc)
                        write-host $ParentProc.ProcessName " does not match " $procsig[2] " for process ID "$CurrentProc.ProcessID " / " $CurrentProc.ProcessName ". NOTE: " $procsig[3]
                    }
                 }
            }
        }
    }
    Return $output | Select-Object Id,ProcessName,UserName,Path
}

Function Check-ProcessUser($processlist)
{
    <#

    .SYNOPSIS
    Checks the user that launched common windows processes against a known good list.

    .PARAMETER processlist
    List of processes running on the system. `Get-Process -User` typically.

    .EXAMPLE
    svchost running as a standard user is malicious.
    #>
    foreach($proc in $processlist)
    {
        if($SystemProcesses -contains $proc.ProcessName)
        {
            if($proc.Id -eq $null)
            {
                write-host $proc.ProcessName " has no Id listed so a user cannot be found."
                continue
            }
            foreach ($procsig in $SystemProcessSignatures)
            {
                if(($proc.ProcessName -match $procsig[0].Replace(".exe","")) -and ($procsig[6] -ne "")) #match process in the signature AND check that a parent is listed
                {
                    try
                    {
                        $ProcID = $proc.ID
                        $CurrentProc = (Get-WmiObject win32_process -Filter "processid='$ProcId'")
                        $CurrentProcUserBlock = $CurrentProc.GetOwner()
                        $CurrentProcUser = $CurrentProcUserBlock.User
                        $CurrentProcDomain = $CurrentProcUserBlock.Domain
                    }
                    catch
                    {
                        write-host "Couldn't get process info for " $proc.ProcessName   
                        write-host "error: " $_.Exception.ItemName " `t " $_.Exception.Message
                    }

                    if($procsig[6] -eq "1") # 1 signifies local logged on user
                    {
                        # get locally logged on user
                        # results may be skewed if logged on remotely as a different user
                        $CurrentLoggedOnUser = $env:USERNAME
                        if($CurrentProcUser -ne $CurrentLoggedOnUser)
                        {
                            $output += @($CurrentProc)
                            write-host $CurrentLoggedOnUser " does not match " $CurrentProcUser " for process ID "$CurrentProc.ProcessID " / "$CurrentProc.ProcessName ". NOTE: " $procsig[7]
                        }
                        continue
                    }
                    if($procsig[6] -notcontains $CurrentProcUser) # contains operator handles both lists and single items. i.e., string "alpha" -contains "alpha" is true.
                    {
                        $output += @($CurrentProc)
                        write-host $procsig[6] " does not match " $CurrentProcUser " for process ID "$CurrentProc.ProcessID " / "$CurrentProc.ProcessName ". NOTE: " $procsig[7]
                    }
                }
            }
        }
    }

    Return $output
}

Function Check-StartTime($processlist, $boottime)
{
    <#

    .SYNOPSIS
    Checks the start times of common windows processes against a known goodlist.

    .DESCRIPTION
    This will really be an offset of system start time in most cases and will be a bit of a fuzzy match. It should be able to find a process that normally starts on boot
    but has started much later due to malware.

    .PARAMETER processlist
    List of processes running on the system. `Get-Process -User` typically.

    .PARAMETER boottime
    This is the time that the system booted.

    #>

    foreach($proc in $processlist)
    {
        if($SystemProcesses -contains $proc.ProcessName)
        {
            $diff = $proc.StartTime - $boottime
            if($proc.Id -eq $null)
            {
                write-host $proc.ProcessName " has no Id listed so a start time cannot be found."
                continue
            }
            foreach ($procsig in $SystemProcessSignatures)
            {
                if($proc.ProcessName -match $procsig[0].Replace(".exe","")) #match process in the signature 
                {                
                    $boottimetype = $procsig[8]
                    switch ($boottimetype)
                    {
                        "" # no time differential defined
                        {
                            break
                        }
                        "boot" #process starts at boot. give it 60 seconds
                        {
                            if ($diff.TotalSeconds -gt 60)
                            {
                                $output += @($proc)
                                write-host "Process started " $diff.TotalSeconds " seconds after boot. Should be within 60 seconds. for process ID "$proc.ID " / "$proc.Name 
                            }
                            break
                        }
                        "boot10" #process starts within seconds of boot. Give it 90 seconds
                        {
                            if($diff.TotalSeconds -gt 90)
                            {
                                $output += @($proc)
                                write-host "Process started " $diff.TotalSeconds " seconds after boot. Should be within 90 seconds. for process ID "$proc.ID " / "$proc.Name
                            }
                            break
                        }
                        default
                        {
                            write-host "Something went wrong. need to define new condition for " $boottimetype " in the SystemProcessSignatures block"
                            break
                        }
                    }
                }
            }
        }
    }
    return $output
}

Function Check-CommonExfil($netstat)
{
    <#

    .SYNOPSIS
    Check all processes for communication on 20,21,22,23,25,3389 (unless associated with mstsc.exe),4444 and others potentially common ports used for data exfiltration.
    .DESCRIPTION
    
    .PARAMETER netstat
    Output of Get-Netstat from the Kansa framework.

    .NOTES
    Thist list is not complete, and we're really only looking at this from a layer 3 perspective. 
    We can't detect tunneling over non-standard ports and we don't really have any way to do protocol detection.
    #>
    $portDescriptions = @{
    20 = "FTP Data (for active ftp): "
    21 = "FTP: "
    22 = "SSH: "
    23 = "Telnet: "
    25 = "SMTP: Probably not something you'd ever have on an end user machine."
    3389 = "RDP: mstsc.exe is generally the process for windows RDP. Unusual processes here may be an attack pivot."
    4444 = "Meterpreter default."
    # what else?
    }

    $exfil = $netstat | Where-Object {$portDescriptions.Keys -contains $_.ForeignPort}
    return $exfil
}

Function Refresh-ProcessList()
{
<#

    .SYNOPSIS
    Refreshes process list variables.

    .DESCRIPTION
    This will simply refresh the process list variables. It may be useful to work with a snapshot of processes that may have ended so this is left to the 
    discretion of the user.

#>
    $processlistcommand = 'Get-Process -IncludeUserName' # this will store a list of all processes and user they run as when run through Start-Process for elevated privs
    $processlist = Get-Process -IncludeUserName   # Start-Process -FilePath powershell.exe -ArgumentList "-noprofile -command $processlistcommand" -Verb runas # we need elevated privileges to get the user context. this should get them without having to run current script as admin
    $processlistsystem = $processlist | Where-Object{$_.ProcessName -eq "System" -or $_.ProcessName -eq "smss" -or $_.ProcessName -eq "wininit" -or $_.ProcessName -eq "taskhost" -or $_.ProcessName -eq "lsass" -or $_.ProcessName -eq "winlogon" -or $_.ProcessName -eq "iexplore" -or $_.ProcessName -eq "csrss" -or $_.ProcessName -eq "services" -or $_.ProcessName -eq "svchost" -or $_.ProcessName -eq "lsm" -or $_.ProcessName -eq "explorer"} # Filter any non-system processes. TODO: utilize the SystemProcessSignature block to get this.    
    $netstat = & $($KansaPath + $NetstatPath)
    return $processlist, $processlistsystem, $netstat
}

<# Declare variables #>

$KansaPath = "$HOME\Documents\WindowsPowerShell\Modules\Kansa-master\" # FIX ME!!! check for existence of Kansa files first
$NetstatPath = "Modules\Net\Get-Netstat.ps1"
$separator = "----------------------------------"
$processlistcommand = 'Get-Process -IncludeUserName' # this will store a list of all processes and user they run as when run through Start-Process for elevated privs
$processlist = Get-Process -IncludeUserName   # Start-Process -FilePath powershell.exe -ArgumentList "-noprofile -command $processlistcommand" -Verb runas # we need elevated privileges to get the user context. this should get them without having to run current script as admin
$processlistsystem = $processlist | Where-Object{$_.ProcessName -eq "System" -or $_.ProcessName -eq "smss" -or $_.ProcessName -eq "wininit" -or $_.ProcessName -eq "taskhost" -or $_.ProcessName -eq "lsass" -or $_.ProcessName -eq "winlogon" -or $_.ProcessName -eq "iexplore" -or $_.ProcessName -eq "csrss" -or $_.ProcessName -eq "services" -or $_.ProcessName -eq "svchost" -or $_.ProcessName -eq "lsm" -or $_.ProcessName -eq "explorer"} # Filter any non-system processes. TODO: utilize the SystemProcessSignature block to get this.
$SystemProcesses = @("System","smss","wininit","taskhost","lsass","winlogon","iexplore","csrss","services","svchost","lsm","explorer")
$SystemBootTime = $(Get-CimInstance -ClassName win32_operatingsystem | select csname, lastbootuptime).lastbootuptime # for PS 2.0 use: Get-WmiObject win32_operatingsystem | select csname, @{LABEL='LastBootUpTime';EXPRESSION={$_.ConverttoDateTime($_.lastbootuptime)}}
$windir = $env:SystemRoot
$CommonBrowsers = @("chrome", "firefox", "iexplore", "safari")  #maybe make this a hash table with name/path
$netstatcommand = $($KansaPath + $NetstatPath)
$netstat = Invoke-Expression $netstatcommand # Start-Process -FilePath powershell.exe -ArgumentLIst "-noprofile -command & $netstatcommand" -Verb runas

<# Common Processes Array 
    $SystemProcessSignatures is the list of common Windows system processes and the metadata surrounding them.
    That metadata is laid out as follows:
    ("Process","Path","Parent","ParentNotes","NumOfInstances","NumOfInstancesNotes","User","UserNotes","StartTime","StartTimeNotes")
#>
# changed from `\ to \\ for escaping backslash since `l seemed to cause issues in match operations (-match causes to be interpreted as regex)
$SystemProcessSignatures = @( #@("Process","Path","Parent","ParentNotes","NumOfInstances","NumOfInstancesNotes","User","UserNotes","StartTime","StartTimeNotes") # a 1 in 'User' indicates locally logged on user
@("System","","","","1","",("Local System","SYSTEM"),"System process may not show user","boot",""),
@("smss.exe","$env:SystemRoot\\System32\\smss.exe","System","","1","One master instance and another child instance per session. Children exit after creating their session.",("Local System","SYSTEM"),"","boot10",""),
@("wininit.exe","$env:SystemRoot\\System32\\wininit.exe","","(smss.exe but tools won't show this)","1","",("Local System","SYSTEM"),"","boot10",""),
@("taskhost.exe","$env:SystemRoot\\System32\\taskhost.exe","services.exe","","1+","","","Logged on user or service accounts","","varies greatly"),
@("lsass.exe","$env:SystemRoot\\System32\\lsass.exe","wininit.exe","","1","",("Local System","SYSTEM"),"","boot10",""),
@("winlogon.exe","$env:SystemRoot\\System32\\winlogon.exe","","(smss.exe but tools won't show this)","1+","",("Local System","SYSTEM"),"","","Within seconds of boot time for the first instance (for Session 1). Start times for additional instances occur as new sessions are created, typically through Remote Desktop or Fast User Switching logons"),
@("iexplore.exe",("$env:HOMEDRIVE\\Program Files\\Internet Explorer\\iexplore.exe","$env:SystemRoot\\Program Files (x86)\\Internet Explorer\\iexplore.exe"),"explorer.exe","","0+","","1","Logged on users","",""),
@("csrss.exe","$env:SystemRoot\\System32\\csrss.exe","","(smss.exe but tools won't show this)","2+","",("Local System","SYSTEM"),"","","Within seconds of boot time for the first 2 instances (for Session 0 and 1). Start times for additional instances occur as new sessions are created, although often only Sessions 0 and 1 are created."),
@("services.exe","$env:SystemRoot\\System32\\services.exe","wininit.exe","","1","",("Local System","SYSTEM"),"","boot10",""),
@("svchost.exe","$env:SystemRoot\\System32\\svchost.exe","services.exe","","5+","",("Local System","SYSTEM", "Network Service", "Local Service"),"Varies depending on svchost instance, though it typically will be Local System, Network Service, or Local Service accounts. Instances running under any other account should be investigated.","","Typically within seconds of boot time. However, services can be started after boot, which might result in new instances of svchost.exe well after boot time."),
@("lsm.exe","$env:SystemRoot\\System32\\lsm.exe","wininit.exe","","1","",("Local System","SYSTEM"),"","boot10",""),
@("explorer.exe","$env:SystemRoot\\explorer.exe","","(userinit.exe but tools won't show this)","","One per interactively logged on user","1","Logged on users","","Starts when the owner's interactive logon begins")
)




<# Start Main #>

Write-Output $separator

while($true)
{
    Write-Output "[*]  1. Get-Browsers "
    Write-Output "[*]  2. Check-Browsers"
    Write-Output "[*]  3. Check-HTTP"
    Write-Output "[*]  4. Check-Listeners"
    Write-Output "[*]  5. Check-SSH "
    Write-Output "[*]  6. Check-DNS "
    Write-Output "[*]  7. Check-BrowserPaths"
    Write-Output "[*]  8. UserCheck-Spelling"
    Write-Output "[*]  9. Check-ImagePath"
    Write-Output "[*] 10. Check-ProcessParent"
    Write-Output "[*] 11. Check-ProcessUser"
    Write-Output "[*] 12. Check-StartTime"
    Write-Output "[*] 13. Check-CommonExfil"
    Write-Output "[*] 14. Refresh-ProcessList"
    $choice = Read-Host "Select a function: "

    Switch($choice)
    {
        1
        {
            Write-Output "[*] These browsers running in memory."
            Get-Browsers -netstat $netstat -processlist $processlist
            break
        }
        2
        {
            Write-Output "[*] These browsers are talking on non-standard ports:"
            Check-Browsers -netstat $netstat
            break
        }
        3
        {
            Write-Output "[*] These processes are talking on unusual ports:"
            Check-HTTP -netstat $netstat
            break
        }
        4
        {
            Write-Output "[*] These processes are listening on web or ftp or ssh or telnet ports:"
            Check-Listeners -netstat $netstat
            break
        }
        5
        {
            Write-Output "[*] These processes are doing SSH"
            Check-SSH -netstat $netstat
            break
        }
        6
        {
            Write-Output "[*] These processes are doing DNS"
            Check-DNS -netstat $netstat
            break
        }
        7
        {
            Write-Output "[*] These are the paths of the browsers you have running. Check for multiple paths for same browser OR for browsers you don't have installed."
            Check-BrowserPaths -processlist $processlist
            break
        }
        8
        {
            Write-Output "[*] Check the below processes. If anything looks like `"System`",`"smss.exe`",`"wininit.exe`",`"taskhost.exe`",`"lsass.exe`",`"winlogon.exe`",`"iexplore.exe`",`"csrss.exe`",`"services.exe`",`"svchost.exe`",`"lsm.exe`", or `"explorer.exe`" it is likely misspelled and malicious."
            UserCheck-Spelling -processlist $processlist
            break
        }
        9
        {
            Write-Output "[*] The below system processes appear to be loaded from non-standard paths"
            Check-ImagePath -processlist $processlistsystem
            break
        }
        10
        {
            Write-Output "[*] These system processes have non-standard parent processes."
            Check-ProcessParent -processlist $processlistsystem
            break
        }
        11
        {
            Write-Output "[*] These system processes are run as non-standard users."
            Check-ProcessUser -processlist $processlistsystem | Format-Table
            break
        }
        12
        {
            Write-Output "[*] These system processes have odd start times."
            Check-StartTime -processlist $processlistsystem -boottime $SystemBootTime
            break
        }
        13
        {
            Write-Output "[*] These processes have ports open that are commonly used for exfiltration. This function does not filter to remove things that may make sense."
            Check-CommonExfil -netstat $netstat
            break
        }
        14
        {
            Write-Output "[*] Refreshing the current processes lists."
            $refresh = Refresh-ProcessList
            $processlist = $refresh[0]
            $processlistsystem = $refresh[1]
            $netstat = $refresh[2]
            break
        }
        default
        {
            write-output "Enter a valid option."
        }
    }
    Write-Output ""
}
