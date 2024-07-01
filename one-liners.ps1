Search for PowerShell commands by string
Get-Command *proce*

Get your current OS Language, like en-GB”
(Get-WMIObject Win32_OperatingSystem).MUILanguages

List all certificates for current user under root
Set-Location Cert:\CurrentUser\Root ; Get-ChildItem

Get all desktop users
 

(Get-WmiObject Win32_Desktop).name
Show GUI Gridview of all available WmiObject classes.
 

Get-WmiObject -list | out-gridview
Display PowerShell version information
 

$PSVersionTable
Display current location (non-UNC paths)
 

Get-Location or $pwd
Change current location (to drive or folder or data store)
 

Set-Location target or cd
Clear the console window
 

Clear-Host Or CLR
Display current location (UNC paths)
 

$pwd.ProviderPath
View the command history for the current session
 

get-history | more
Repeat a command in the history
 

invoke-history [id from output of get-history]
Save the history to a csv file
 

invoke-history | export-csv [output path & filename]
Save the history to a csv file (alternative option)
 

Get-History | export-csv [output path & filename] not invoke-history | export-csv [output path & filename]
Save session input and output to a file
 

start-transcript [output path & filename] -IncludeInvocationHeader
Stop saving the transcript
 

stop-transcript
Get Installed .NET Framework versions
 

Get-ChildItem 'HKLM:\SOFTWARE\Microsoft\NET Framework Setup\NDP' -Recurse `
| Get-ItemProperty -Name version -EA 0 | Where { $_.PSChildName -Match '^(?!S)\p{L}'} | Select PSChildName, version
List all cmdlets/functions filtered by noun


 

gcm -noun type*


Get installed modules and available modules
 

Get-Module -ListAvailable
Get gets all of the exported files for all available modules.
 

Get-Module -ListAvailable -All
List files in module directory
 

dir (get-module -ListAvailable -Name Importexcel).ModuleBase
Clear Application and System event logs
 

Clear-EventLog -LogName "Application", "System"
Export information in neat/simple looking GUI with filtering options.
 

Get-Process | Out-GridView 
First loop example
 

for ($i=0; $i -le 99; $i++)  { write-host $i }
Average CPU Usage Memory Usage
 

Get-WmiObject win32_processor | Measure-Object -property LoadPercentage -Average | Select Average
Get top 10 process, utilizing max CPU
 

gwmi Win32_PerfFormattedData_PerfProc_Process| sort PercentProcessorTime -desc | select Name,PercentProcessorTime | Select -First 10 | ft -auto
GetMemory Usage Stats
 

gwmi -Class win32_operatingsystem| select CSname, @{N='TotalMemory';E={$.TotalVisibleMemorySize /1MB}},@{N='FreeMemory';E={$.FreePhysicalMemory/1MB}} |ft -AutoSize
Get install app info via GWMI
 

gwmi -namespace "root\cimv2" -class "Win32_Product" | select Name,Vendor,Version,InstallLocation,IdentifyingNumber,InstallSource,PackageName | where { $_.Name -match "^Ui*" }
Active Directory Info
 

 

Set Password
 

$UserAccount = get-credential | $UserAccount.username | Set-LocalUser -Password $UserAccount.Password
Quick way to get a users racf id
 

type Get-ADUser -Filter {EmailAddress -eq 'Prasath.ChandraSekaran@natwest.com'} 
Get AD user by Surname (using wildcard)
 

get-aduser -filter 'surname -like "*scotcher"'
Find Domain Controllers on Your Domain 
 

Resolve-DnsName -Type ALL -Name _ldap._tcp.dc._msdcs.$env:userdnsdomain
Search for a user in Active Directory
 

Get-ADUser -Filter {name -like 'powell*'}
Get AD users created in the last 30 days 
 

Get-ADUser -Filter * -Properties whenCreated, description | Where-Object {$_.whenCreated -ge ((Get-Date).AddDays(-30)).Date} |select samaccountname, description
Return AD user info in a table format by select columns
 

get-aduser -filter 'GivenName -eq "Simon" -and Surname -like "Powell"' -Properties * | ft Name, GivenName, Surname, EmailAddress, SamAccountName
Search all DCs for account lockout events and output to file
 

ipmo activedirectory;$(Get-ADDomainController -Filter  {(OperatingSystem -ne "") -and (IsReadOnly -ne "True")} | %{Get-WinEvent -ComputerName $_.name -LogName security -FilterX
Discover your domains domain controller
 

Get-ADDomainController -Discover -DomainName europa.rbsgrp.net
Find group by partial name
 

Get-ADGroup -server europa.rbsgrp.net -Filter {name -like "rAppEng-FSLED*"} | Select SamAccountName 
Get List of users/Groups under Local Administrators
 

([ADSI]"WinNT://Localhost/Administrators").Members() | Select-Object @{n='Name';e={ $.GetType().InvokeMember('Name', 'GetProperty', $Null, $, $Null) }},@{n='ADSPath';e={ $.GetType().InvokeMember('ADSPath', 'GetProperty', $Null, $, $Null) }},@{n='Class';e={ $.GetType().InvokeMember('class', 'GetProperty', $Null, $, $Null) }} |fl
List of Disabled Users from AD
 

Get-ADUser -Filter {Enabled -eq "False"}
Get your domain name 
 

(Get-WmiObject Win32_ComputerSystem).domain
Performance Info
 

 

Counters to get CPU usage
 

"\Processor(*)\% Processor Time" | Get-Counter -Computer XXXXXXXXX -MaxSamples 2 -SampleInterval 10
Counters to get virtual processor utilization
 

"\VM Processor(*)\% Processor Time" | Get-Counter -Computer XXXXXXXXX -MaxSamples 2 -SampleInterval 10
Counters to get Virtual Memory Usage
 

"\Processor(*)\Interrupts/sec" | Get-Counter -Computer XXXXXXXXX -MaxSamples 2 -SampleInterval 10
Counters to get Paging File Usage
 

"\Memory\% Committed Bytes In Use" | Get-Counter -Computer XXXXXXXXX -MaxSamples 2 -SampleInterval 10
Counters to get Number of Interrupts
 

"\Paging File(*)\% Usage" | Get-Counter -Computer XXXXXXXXX -MaxSamples 2 -SampleInterval 10
Working with Files and Folders
Displays file contents
 

get-content
Find out how big a folder is
 

dir -Path C:\Temp -File -Recurse -force | Measure-Object -Property Length -Maximum -Average -Sum | Select-Object @{name="Total Files";Expression={$.Count}},@{name="Largest File(MB)";Expression={"{0:F2}" -f ($.Maximum/1MB)}},@{name="Average Size(MB)";Expression={"{0:F2}" -f ($.Average/1MB)}},@{name="Total Size(MB)";Expression={"{0:F2}" -f ($.Sum/1MB)}}
Find all files having the word "log" in the filename.
 

Get-childItem C:\ -Recurse -Filter "log.txt"
Find out how big a folder is
 

dir -path C:\Scripts -file -recurse -force | measure-object length -sum -max -average | Select-Object @{name="Total Files";Expression={$.count}},@{name="Largest File(MB)";Expression={"{0:F2}" -f ($.maximum/1MB)}},@{name="Average Size(MB)";Expression={"{0:F2}" -f ($.average/1MB)}},@{name="Total Size(MB)";Expression={"{0:F2}" -f ($.sum/1MB)}}
List all .txt files in a location including sub directories
 

Get-ChildItem -Path [Drive]:[Path] -Recurse -Include *.txt
Map a network drive
 

New-SmbMapping -LocalPath [drive_letter]: -RemotePath [UNC Path]
Copy files from one location to another
 

Copy-Item [path, optionally including file reference] -Destination [path] -Verbose
Move files from one location to another
 

Move-Item [path] -Destination [path] -Verbose
Rename a file or folder
 

Rename-Item [path] -NewName [path]
Download file
 

(New-Object System.Net.WebClient).DownloadFile("http://192.168.119.155/PowerUp.ps1", "C:\Windows\Temp\PowerUp.ps1")
Download File (alternative option)
 

Invoke-WebRequest -Uri http://192.168.119.155/PowerUp.ps1 -OutFile $env:USERPROFILE\Downloads\PowerUp.ps1
Search for the keyword 'error' or 'warning' 
 

Get-ChildItem -Path C:\Windows update.log -Recurse | Get-Content -Wait | Select-String "warning|error"
Read the contents of a text file, and create an output file with only lines that contain the phrase  “natwest.com”
 

Get-Content yourinputfile.txt | Where-Object {$_ -match “natwest.com”} | Out-File youroutputfile.txt
Tail (grep) a File 
 

Get-Content ./logfile.log -Tail 5 –Wait
List Subdirectories in the Current Directory 
 

Get-ChildItem -Directory
Get Free Space for System Drive
 

(Get-PSDrive $Env:SystemDrive.Trim(':')).Free/1GB
List only directories
 

Get-ChildItem c:\media |Where-Object {$_.PSIsContainer -eq $True}
filter processes by parameters
 

get-process |where handles -gt 900 | sort handles
get-process |where {$_.handles -ge 1000}
Adding days to or from Today
 

[DateTime]::Today.AddDays(350)
[DateTime]::Today.AddDays(-350)
List all the commands which accept -Computername as parameter
 

Get-Command –ParameterName ComputerName
Show-Command Get-Process (interactive command)
 

show-command get-childitem
Return all .exe files in C:\Windows\System32 starting with “d”, “g” or “n”
 

Get-ChildItem C:\Windows\System32\[dgn]*
Get all folders that end with “n” in C:\Windows\System32
 

Get-ChildItem C:\Windows\System32\*n -Directory
Convert to MB Megabyte
 

$total = (Get-ChildItem C:\windows\System32 -file | Measure-Object -Property length –sum).Sum
Convert to GB GigaBytes
 

$total = (Get-ChildItem -Recurse C:\Windows\System32 -ErrorAction SilentlyContinue | Measure-Object -Property length -sum).Sum
Find all .txt files in C:\Windows\System32\WindowsPowerShell\v1.0, recursively. Use the Get-ChildItem Cmdlet’s –filter parameter
 

gci C:\Windows\System32\WindowsPowerShell\v1.0\ -Recurse -File -Filter *.txt
Get all files modified more than a month ago
 

Get-Childitem -File -Path $docs\Finance -Recurse | Where LastWriteTime -lt (Get-Date).addDays(-30)
Rename file extensions from '.log' to '.old'
 

Get-ChildItem -Path $docs\Archive\Finance -File -Recurse | Rename-Item -NewName { $_.fullname.replace(".log",".old") }
Networking General
Get Information - ipconfig /all equivalent gip is short for Get-NetIPConfiguration
 

gip  or Get-NetIPConfiguration -All -Detailed
Show network adapters
 

get-netadapter
Print routing table
 

get-netadapter [name] | get-netroute [[-addressfamily ipv4]]
Show active network connections
 

Get-NetTCPConnection | ? State -eq Established | sort Localport | FT -Autosize
Show client’s DNS Cache
 

Get-DnsClientCache
Show the client’s mapped drives
 

Get-SmbMapping
DNS Lookup
 

resolve-dnsname [computer]
DNS lookup by type
 

Resolve-Dnsname -Name -Type [a/cname/txt/aaaa]
If you want the second command to be executed only if the previous one was successful, use the && format.
 

ipconfig /flushdns && ipconfig /renew
The second command will be executed only if the first one returned an error.
 

net stop wuauserv6 || net start wuauserv
Find hostname from IP address from DNS record (without reverse lookup zone)
 

Get-DnsServerResourceRecord -ZoneName domain.local -ComputerName DNSServerName | select hostName -ExpandProperty RecordData | where {$_.IPv4Address -like "192.168.100.200"}
Ping with timestamp
 

Test-Connection 192.168.192.1 -count 999 |format-table -property Address,buffersize,ipv4address,ResponseTime,TimeToLive,@{N='Timestamp';E={get-date -uformat %T}}
Get Process information on remote computers
 

get-WmiObject -class win32_process -computername ServerName | Select-Object -prop __Server,Name,WorkingSetSize,@{n='Owner';e={$_.getowner().user}} |ft -AutoSize
How to get all groups that a user is a member of? (Single line, no modules necessary, uses current logged user)
 

(New-Object System.DirectoryServices.DirectorySearcher("(&(objectCategory=User)(samAccountName=myusername))")).FindOne().GetDirectoryEntry().memberOf
A more concise version….
([ADSISEARCHER]"samaccountname=FPTRPAMP").Findone().Properties.memberof
GET workstation FQDN
 

[System.Net.Dns]::GetHostByName($env:computerName)
Network Tests
Ping equivalent
 

test-connection [computer]
‘Continuous’ ping (999999999 pings)
 

test-connection [computer] -count 999999999
Traceroute tnc is short for Test-NetConnection. -tr is short for -TraceRoute.
 

tnc [computer] -tr
Test if a remote port is accessible / open
 

tnc [computer] -p [port]
Test if a remote port is accessible / open (more info)
 

tnc [computer] -p [port] -inf detailed
Find all the processes that are using a specific port
 

Get-NetTCPConnection | Where-Object { $_.LocalPort -eq 80 } | Select-Object OwningProcess, RemoteAddress, RemotePort | Sort-Object OwningProcess | Get-Unique
Port Scanner
 

0..65535 | Foreach-Object { Test-NetConnection -Port $_ Go ahead and ScanMe!  -WA SilentlyContinue | Format-Table -Property ComputerName,RemoteAddress,RemotePort,TcpTestSucceeded }
Computer & Hardware
Get local computer name
 

$env:computername
Get last bootup time of a remote computer
 

[Management.ManagementDateTimeConverter]::ToDateTime((Get-WmiObject Win32_OperatingSystem `-Property LastBootUpTime -ComputerName [computer]).LastBootUpTime)



 

Get-WmiObject win32_operatingsystem -ComputerName [computer] | `select @{Name="Last Boot Time"; Expression={$_.ConvertToDateTime($_.LastBootUpTime)}}, PSComputerName
Restart computer
 

restart-computer
Get your OS name like “Microsoft Windows 10 Enterprise”
 

(Get-WmiObject win32_operatingsystem).name.split("|")[0]
Get your OS architecture like “64-bit”
 

(Get-WmiObject win32_operatingsystem).OSArchitecture
Restart remote computer
 

restart-computer -computername [computer]
Stop computer by name
 

stop-computer -name "notepad" [-Force]
Start a process
 

Start-Process -FilePath [executable] -Wait -WindowStyle Maximized
Get all processes
 

Get-process
Show the details of a running process
 

Get-Process *explorer* | Format-List *
Get total number of running processes
 

Get-Process | Measure-Object
Rename a computer
 

rename-computer -name [original_name] -newname [new_name]
Remove Windows feature
 

disable-windowsoptionalfeature -feature [featurename]
Find installed Windows Updates


 

Get-HotFix -ComputerName "hostname" | Where-Object {$_.InstalledOn -gt (Get-Date).AddDays(-30)} 
 

 

Get-WmiObject -Class win32_quickfixengineering | Where-Object {$_.InstalledOn -gt (Get-Date).AddDays(-30)}
Get last Successful Windows update checked and installed date
 

New-Object -ComObject "Microsoft.Update.autoupdate").Results
Get logged on user in a remote system
 

Get-WmiObject -Class Win32_ComputerSystem -ComputerName hostname | select username
 

 

QUERY USER /servername:hostname
Find Scheduled tasks that are running.
 

(get-scheduledtask).where({$_.state -eq 'running'}) 
Free Disk space information
 

gwmi Win32_LogicalDisk -Filter "DeviceID='C:'" | Select Name, FileSystem,FreeSpace,BlockSize,Size | % {$.BlockSize=(($.FreeSpace)/($.Size))*100;$.FreeSpace=($.FreeSpace/1GB);$.Size=($.Size/1GB);$}| Format-Table Name, @{n='FS';e={$.FileSystem}},@{n='Free, Gb';e={'{0:N2}'-f $.FreeSpace}}, @{n='Free,%';e={'{0:N2}'-f $_.BlockSize}} -AutoSize
RegEx to find local admin shares
 

Gwmi Win32_Share|%{"\\$($|% P*e)\$($.Name)"}
Invoke command on / from remote computers.
 

invoke-command -computername dc1,dc2,serv1,serv2 {get-eventlog -logname system -new 3}
Windows Registry
To display all keys from the path down, include the -recurse parameter.
 

Get-ChildItem -Path [path e.g. hkcu:\]
Browse the registry like a file system
 

Set-Location hkcu: ; cd SOFTWARE
Create a new registry key
 

New-Item -Path [path and key, e.g. hkcu:\new_key]
Search the registry
 

Get-ChildItem -path HKLM:\SYSTEM\ -Recurse -ErrorAction SilentlyContinue | where { $_.Name -like "USBSTOR" }
Delete a key
 

Remove-Item -Path [path and key, e.g. hkcu:\new_key]
Set a registry value
 

Set-ItemProperty -Path [path and key, e.g. hkcu:\key] -Name [PropertyName] -Value [New Value]
Get details from registry
 

Get-ItemProperty HKLM:\SYSTEM\CurrentControlSet\Services\USBSTOR\ | Select Start
Get registry information from remote computers
 

Invoke-Command -ComputerName "Server1","Server2" -ScriptBlock { Get-ItemProperty HKLM:\SYSTEM\CurrentControlSet\Services\USBSTOR\ | Select Start }
List of all installed applications on a Windows device
 

Get-ItemProperty HKLM:\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall\* | Select-Object DisplayName, DisplayVersion, Publisher, InstallDate | Format-Table –AutoSize  
list all installed Windows Updates files (KB)
 

Get-ItemProperty HKLM:\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall\* | Select-Object DisplayName, DisplayVersion, Publisher, InstallDate | Format-Table –AutoSize  
Windows Services
List all services
 

Get-Service  | Sort DisplayName
List Services and filter by DisplayName
 

Get-Service -DisplayName "Windows*"
List Services and sort by Status
 

Get-Service -DisplayName "Windows*" | sort Status
List running services
 

Get-Service | ? {$_.Status -eq "Running"} | sort Name
Search for a service running on a remote computer, search based on Display Name
 

Get-service -computername [hostname] | where DisplayName -match [search_expression]
Start service
 

start-service  [service name]
Stop service
 

stop-service [service name] [-Force]  
Restart service
 

Restart-service [service name]
List service properties of service that can pause or continue
 

Get-Service |  Where-Object CanPauseAndContinue -eq $true |   Select-Object -Property *
Show properties of a specific Windows service
 

Get-Service -Name w32time | Select-Object -Property *
Loop processes for service starting with later A* Version 1
 

Get-Service -Name a* | ? { $.Status -eq 'Running' } | ForEach-Object -process {$.start;$_}
Loop processes for service starting with later A* Version 2
 

Get-Service -Name a* | ? { $.Status -eq 'Running' } | ForEach-Object -process {$.start(); Start-Sleep 5; $_}
Count service items in an array 
 

Get-Service | foreach -Begin {"Counting Services..." ; $count=0} -Process {$count++} -End {“$count services were found”}
Filtering commands
Pipe command to Where-Object to perform the filtering
 

Get-Service | Where-Object Name -eq w32time
String Manipulation
Each row would be assigned to the $string variable via loop process 
 

$($string -replace '\s+', ' ').split()[-1]
Splitting strings at “, ”, give a array of [0] “Hello” [1] “world”
 

("Hello, world").split(",")
Extracting substring gives “Hello”
 

("Hello world").Substring(0,5)
Remove and replace character. Remove “Hello “ and capitalize “w”  in “World”
 

(("Hello world").Remove(0,6)).Replace("w","W")
Remove and replace character. Remove “Hello “ and capitalize “world” in “WORLD”
 

(("Hello world").Remove(0,6)).ToUpper()
UiPath Orchestrator REST API
 

Between 2 & 4 liners
UiPath Rest API requires an access token, so I’m going to temporarily break the one-liner rule. Always this before any other UiPath Rest API this is critical.
 

$logindetails = @{"tenancyName"="QCoE_NFT";
                    "usernameOrEmailAddress"="feuser";
                    "password"="Testing@123456789"}
$LoginResult = Invoke-RestMethod -Method POST -Uri "https://iaglz08s01s.api.banksvcs.net/rpacoe-auth-nft" -Body ($logindetails|ConvertTo-Json) -ContentType "application/json"
$auth = "Bearer " + $LoginResult.result
$header = @{"X-UIPATH-OrganizationUnitId"="281";  # Use the $header 
                "Authorization"=$auth}
$ct = "application/json"
Get all package libraries filter by key column
 

$RestUrl = "https://uipathorchestrator-nfte.webdev.banksvcs.net/odata/Libraries"
$gLib = irm -Method Get -Uri $RestUrl -Headers $header -ContentType $ct
$gLib.value | select key | where key -Like "Uipath.*" | sort key 
Get Test Executions and filter by Name
 

$RestUrl = "https://uipathorchestrator-nfte.webdev.banksvcs.net/odata/TestSetExecutions"
$gExecutions = irm -Method Get -Uri $RestUrl -Headers $header -ContentType $ct
$gExecutions.value | select Name, status,startTime | where Name -Like "SimonPowellTestTestSet" | sort StartTime
Get Processes (automations) by Owner
 

$RestUrl = "https://uipathorchestrator-nfte.webdev.banksvcs.net/odata/Processes"
$getproc = irm -Method Get -Uri $RestUrl -Headers $header -ContentType $ct
$getproc.value | where Authors -EQ "powells" | Format-Table
Get-WMIObject (Deprecated) replaced by Get-CIMInstance
 

One-liners brought to you by Damon Welch, (Colleague Platforms, NatWest Digital X)

Listing WMI classes
 

Get-CimClass -Namespace root/CIMV2 | Where-Object CimClassName -like Win32* |  Select-Object CimClassName
Retrieve WMI class info from a remote computer
 

Get-CimClass -Namespace root/CIMV2 -ComputerName 192.168.1.29
Display WMI class details
 

Get-CimInstance -Class Win32_OperatingSystem
Get-Member to see all the properties of a WMI Class
 

Get-CimInstance -Class Win32_OperatingSystem | Get-Member -MemberType Property
Displaying non-default properties for WMI Class
 

Get-CimInstance -Class Win32_OperatingSystem | Format-Table -Property TotalVirtualMemorySize, TotalVisibleMemorySize, FreePhysicalMemory, FreeVirtualMemory, FreeSpaceInPagingFiles
Display system memory data
 

Get-CimInstance -Class Win32_OperatingSystem | Format-List TotalMemory, Free*
Parse a list of system names and use Get-CIMInstance
 

Get-CIMInstance Win32_NetworkAdapterConfiguration -Filter 'IPEnabled = true' -ComputerName (Get-Content C:SERVERLIST.TXT) | Select-Object pscomputername,ipaddress,defaultipgateway,ipsubnet,dnsserversearchorder,winsprimaryserver | Format-Table -AutoSize | out-file c:IPSettings.txt
Get a list of namespaces from a WMI server
 

Get-CimInstance -Namespace root -ClassName __Namespace
Get instances of a class filtered by using a query
 

Get-CimInstance -Query "SELECT * from Win32_Process WHERE name LIKE 'P%'"
Get the CIM instances with only key properties filled in
 

$x = New-CimInstance -ClassName Win32_Process -Namespace root\cimv2 -Property @{ "Handle"=0 } -Key Handle -ClientOnly
Get-CimInstance -CimInstance $x
Time of the Last Reboot
 

(Get-CimInstance Win32_OperatingSystem).LastBootUpTime
Get free space from the system drive c:\ in GB (Rounded)
 

[math]::Round((Get-CimInstance Win32_LogicalDisk -Filter "DeviceID = 'C:'").FreeSpace/1GB)
Get Parent Process(es)
 

foreach ($prid in ($ppid = foreach ($process in (Get-Process -Name "powershell")) { (Get-CimInstance Win32_Process | Where-Object processid -EQ $process.Id).parentprocessid })) { Get-Process -Id $prid }
Get BIOS version
 

(Get-CimInstance Win32_BIOS).SMBIOSBIOSVersion
Get system Serial Number
 

(Get-CimInstance Win32_BIOS).SerialNumber
Get System Model
 

(Get-CimInstance Win32_ComputerSystem).Model
Get Logical Disk info
 

Get-CimInstance -ClassName Win32_LogicalDisk | Select DeviceID, FileSystem, FreeSpace
Get eventlog files avail. and statuses
 

Get-CimInstance -Class Win32_NTEventlogFile | Select -Unique CreationDate, CSName, Description, LogFileName, Readable, Writeable | format-table
Currently logged on user info
 

Get-CimInstance -ClassName Win32_NetworkLoginProfile -Namespace "root\cimv2" | Select {$_}
