set-location C:\mark\git\windows-image
Import-Module PSReadLine
git config http.sslCAInfo C:\mark\ca-bundle-new.crt
set-location C:\mark\git
$env:VAULT_ADDR='https://vault.domain.com'
$env:PROJECT_ID = "mod-rob-111"
$env:SA = "project-resource-editor"
$env:TF_VAR_project_resource_sa_key = $(get-content C:\mark\service-account-key.json)
#gcloud auth activate-service-account --key-file=C:\mark\service-account-key.json --project=mod-rob-111
#gcloud config set proxy/password ppppppp

[Net.ServicePointManager]::SecurityProtocol = "tls12, tls11, tls"

Add-Type -AssemblyName System.Windows.Forms
# $screens = [System.Windows.Forms.Screen]::AllScreens
# $scrHeight = ([System.Windows.Forms.SystemInformation]::PrimaryMonitorSize).Height
# $scrWidth = ([System.Windows.Forms.SystemInformation]::PrimaryMonitorSize).Width

#SIMON
# Width 384
# Height 138
# Bounds       : {X=0,Y=0,Width=3072,Height=1728}
# WorkingArea  : {X=0,Y=0,Width=3072,Height=1688}

#ME
#231x88
# Bounds       : {X=0,Y=0,Width=1920,Height=1080}
# WorkingArea  : {X=65,Y=0,Width=1855,Height=1080}

# Bounds       : {X=1920,Y=0,Width=1920,Height=1080}
# WorkingArea  : {X=1920,Y=0,Width=1920,Height=1080}

# Colours
# Black White Gray DarkGray Red DarkRed Blue DarkBlue Magenta
# Green DarkGreen Yellow DarkYellow Cyan DarkCyan DarkMagenta

$Shell = $Host.UI.RawUI
$Shell.backgroundcolor = "Black"
$size = $Shell.WindowSize
$size.width=140
$size.height=65
$Shell.WindowSize = $size
$size = $Shell.BufferSize
$size.width=140
$size.height=9999
$Shell.BufferSize = $size

$Global:CurrentUser = [System.Security.Principal.WindowsIdentity]::GetCurrent()
$UserType = "User"
$CurrentUser.Groups | ForEach-Object {
    if ($_.value -eq "S-1-5-32-544") {
        $UserType = "Admin"
    }
}

function Write-BranchName () {
    try {
        $branch = git rev-parse --abbrev-ref HEAD
        if ($branch -eq "HEAD") {
            # we're probably in detached HEAD state, so print the SHA
            $branch = git rev-parse --short HEAD
            Write-Host " ($branch)" -ForegroundColor Red
        }
        else {
            # we're on an actual branch, so print it
            Write-Host " ($branch)" -ForegroundColor DarkGreen
        }
    }
    catch {
        # we'll end up here if we're in a newly initiated git repo
        Write-Host " (no branches yet)" -ForegroundColor DarkGray
    }
}

function prompt {
    if ($UserType -eq "Admin") {
        $host.UI.RawUI.WindowTitle = "* * * " + $(get-location) + ""
    #     $host.UI.RawUI.ForegroundColor = "white"
    }
    else {
        $host.ui.rawui.WindowTitle = $(get-location)
        # Setup Home so that Git doesn't freak out.
        [System.Environment]::SetEnvironmentVariable("HOME", (Join-Path $Env:HomeDrive $Env:HomePath), "Process")
    }
    $time = [system.datetime]::Now.tostring("HH:mm:ss")
    $pl = $pwd.path.split("\")
    $PLoc = $pl[-1..-7]
    $PRoot = $pl[0]
    if ($pl.count -gt 8) {
        $PromptPwd = [string]::format('{0}..\{1}\{2}\{3}\{4}\{5}\{6}\{7}', $PRoot,$PLoc[6],$PLoc[5],$PLoc[4],$PLoc[3],$PLoc[2],$PLoc[1],$PLoc[0])
    }
    else {
        $PromptPwd = [string]::format('{0}', $pwd)
    }

    if ($PSDebugContext) {
        $ifDBG = "[DBG]"
    }

    try {
        $lastCommand = Get-History -id ($MyInvocation.HistoryId - 1)
        $timeTakenToExecute = New-TimeSpan -Start  $lastCommand.StartExecutionTime -End $lastCommand.EndExecutionTime
    }
    catch {
        $timeTakenToExecute = [pscustomobject]@{TotalSeconds=0}
    }
    Write-Host
    [Console]::ForegroundColor = [System.ConsoleColor]::DarkGray
    [Console]::Write([string]::format('[{0}{1}', $time, $ifDBG))
    [Console]::ResetColor()

    [Console]::ForegroundColor = [ConsoleColor]::DarkGray
    [Console]::Write([string]::format('|+{0}s]',[Math]::Round($timeTakenToExecute.TotalSeconds,0)))
    [Console]::ResetColor()

    [Console]::ForegroundColor = [ConsoleColor]::White
    [Console]::Write([string]::format(' {0}', $PromptPwd))
    [Console]::ResetColor()
    if (Test-Path .git) {
        Write-BranchName
    }
    else {
        [Console]::Write([System.Environment]::NewLine)
    }

    [Console]::ResetColor()
    write-output "PS > "
}

function Get-MountedDives {
    get-psdrive | Where-Object {$_.Provider -like "*FileSystem*"} | Select-Object Name, @{n='Free';e={ [math]::Round($_.Free / 1gb, 2) }}, Root, Description
}

function Touch {
    New-Item -ItemType File -Path "$args"
}

function Find-String {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $True)]
        [Alias('s')]
        [String] $string,

        [Parameter(Mandatory = $False)]
        [Alias('g')]
        [Switch]$grep
    )
    $results = (Get-ChildItem -Recurse | Select-String $string -List | Select-Object Path).path
    if ($grep){
        $results | ForEach-Object {
            select-string -Path $_ -pattern $string
        }
        # $results | ForEach-Object {
        #     $a = select-string -Path $_ -pattern $string
        #     $ln = $a.linenumber
        #     $line = $a.line
        #     $apath = $a.path
        #     $fn = $a.filename
        #     write-host "$line`t$fn"
        # }
    }
    else {
        $results
    }
}

function Find-File {
    param (
        [Parameter(Mandatory = $True)][String] $string,
        [Parameter(Mandatory = $True)][String] $path
    )
    Get-ChildItem -Path $path -Filter $string -Recurse -ErrorAction SilentlyContinue -Force
}

function Set-Password {
    param (
        [Parameter(Mandatory = $false)]
        [switch]$changeProxy
    )
    Write-Warning "Don't forget to use switch -changeProxy if you're changing your main account"
    write-host "Enter username (no domain name):"
    $AccountName = Read-Host
    $OldPW = Read-Host -AsSecureString
    $NewPW = Read-Host -AsSecureString
    Set-ADAccountPassword -Identity $AccountName -OldPassword $OldPW -NewPassword $NewPW
    if ($changeProxy){
        $env:HTTP_PROXY  = "http://user:$NewPW@proxy.domain.com:8080"
        $env:HTTPS_PROXY = "http://user:$NewPW@proxy.domain.com:8080"
        gcloud config set proxy/password $NewPW
        write-host "Don't forget to change these:"
        write-host "F:\.bashrc"
        #Get-Content F:\.bashrc | % { if ($_-match ".*https?:\/\/(?<user>[^:]+):(?<password>[^@]+)@.*"){$_}}
        write-host "C:\dev\ubuntu_2004.2020.424.0_x64\rootfs\etc\apt\apt.conf.d\proxy.conf"
        #Get-Content "C:\dev\ubuntu_2004.2020.424.0_x64\rootfs\etc\apt\apt.conf.d\proxy.conf" | % { if ($_-match ".*https?:\/\/(?<user>[^:]+):(?<password>[^@]+)@.*"){$_}}
        #Get-Content F:\.bashrc | select-string -pattern ".*https?:\/\/(?<user>[^:]+):(?<password>[^@]+)@.*" | % {$_.matches }
    }
}

function Get-Created {
    param (
        [Parameter(Mandatory = $false)][String] $path = "."
    )
    Get-ChildItem $path | Sort-Object CreationTime | Select-Object name,creationtime
}

function Save-Git {
    param(
        [Parameter(Mandatory = $True)]
        [ValidateNotNullOrEmpty()]
        [string]$mes
    )
    begin {
        $mes = $mes -replace " ","-"
        $jiraRef = $null
        $branch = git rev-parse --abbrev-ref HEAD
        if ($branch) {
            switch -wildcard ($branch) {
                'master' {
                    if ($(git config --get remote.origin.url) -eq "https://git.domain.com/myrepo/scripts"){
                        write-host "Marks master branch - don't panic"
                        $jiraRef = $_
                    } else {
                        write-host "MASTER BRANCH!!" -ForegroundColor Yellow
                        $title = 'This is the master branch - are you sure you want to commit directly to master?'
                        $prompt = '[Y]es or [N]o?'
                        $abort = New-Object System.Management.Automation.Host.ChoiceDescription '&No','Stops the commit'
                        $retry = New-Object System.Management.Automation.Host.ChoiceDescription '&Yes','Commits'
                        $options = [System.Management.Automation.Host.ChoiceDescription[]] ($abort,$retry)
                        $choice = $host.ui.PromptForChoice($title,$prompt,$options,0)
                        if ($choice -eq 0) {
                            $jiraRef = $null
                            break
                        }
                        if ($choice -eq 1) {
                            $jiraRef = $_
                        }
                    }
                }
                'feature*' {
                    write-host "feature-branch: $_" -ForegroundColor cyan
                    $jiraRef = [regex]::Match($_, 'JIR(A|E)-[0-9]{4,5}').captures.groups[0].value
                    $jiraRef = "feature-$jiraRef"
                    continue
                }
                'release*' {
                    write-host "release-branch: $_" -ForegroundColor cyan
                    $jiraRef = "release"
                    continue
                }
                { $_ -match '^NWMP(E|O)-[0-9]{4,5}' } {
                    $jiraRef = [regex]::Match($_, '^JIR(A|E)-[0-9]{4,5}').captures.groups[0].value
                    continue
                }
                Default {
                    write-host "No matching branch name found: $_" -ForegroundColor Yellow
                    $title = 'Are you sure you want to continue?'
                    $prompt = '[Y]es or [N]o?'
                    $abort = New-Object System.Management.Automation.Host.ChoiceDescription '&No','Stops the commit'
                    $retry = New-Object System.Management.Automation.Host.ChoiceDescription '&Yes','Commits'
                    $options = [System.Management.Automation.Host.ChoiceDescription[]] ($abort,$retry)
                    $choice = $host.ui.PromptForChoice($title,$prompt,$options,0)
                    if ($choice -eq 0) {
                        $jiraRef = $null
                        break
                    }
                    if ($choice -eq 1) {
                        $jiraRef = $_
                    }
                }
            }
            $mes = "$jiraRef-$mes"
        }
    }
    process {
        if ($jiraRef) {
            if (git status --porcelain){
                write-host "Commit message: $mes" -ForegroundColor cyan
                git add *
                git commit -am $mes
                git push
            }
            else {
                write-host "Your branch is up to date" -ForegroundColor green
                write-host "nothing to commit, working tree clean."
            }
        }
    }
}

function unzip {
    param (
        [string]$ziparchive,
        [string]$extractpath
    )
    begin {
        Add-Type -AssemblyName System.IO.Compression.FileSystem
    }
    process{
        [System.IO.Compression.ZipFile]::ExtractToDirectory( $ziparchive, $extractpath )
    }
}

function Invoke-SSH {
    param (
        #[Parameter(Mandatory = $True)]
        [string]$instance = "dev-win-999",

        #[Parameter(Mandatory = $True)]
        [string]$zone = "europe-west2-a",

        #[Parameter(Mandatory = $True)]
        [string]$project = "rel-kit-111"
    )
    begin {
        Write-Host $instance -ForegroundColor cyan -NoNewline
        write-host " : $zone : $project"
        $command = "gcloud compute ssh $instance --project $project --zone $zone --internal-ip"
    }
    process{
        $process = start-process powershell -ArgumentList "-noExit -NoProfile -command $command" -PassThru
        do {
            Start-Sleep -Seconds 5
        } while (!$(Get-Process -ProcessName 'putty'))
        Stop-Process -Id $process.Id -Force
    }
}

function Set-GCloud {
    param (
        [Parameter(Mandatory = $True)]
        [string]$name
    )
    begin {
        switch ($name) {
            'mark' { $account = "user.name@address.com" }
            'admin' { $account = "user@mod-rob-111.iam.gserviceaccount.com" }
        }
        $command = "C:\dev\google-cloud-sdk\bin\gcloud.cmd"
        $GCEarguments = "config set account $account"
        $authList = "auth list"
    }
    process{
        $process = start-process $command -ArgumentList $GCEarguments -PassThru -NoNewWindow -Wait
        $process2 = start-process $command -ArgumentList $authList -PassThru -NoNewWindow -Wait
        continue
    }
}

function Set-GCEInstance {
    param (
        [Parameter(Mandatory = $True)]
        [string]$name,

        [Parameter(Mandatory = $True)]
        [ValidateSet("start","stop","reset","delete")]
        [string]$action,

        [Parameter(Mandatory = $False)]
        [string]$project="rel-kit-111",

        [Parameter(Mandatory = $False)]
        [string]$zone="europe-west2-a"

    )
    begin {
        Set-GCloud -name 'Mark'
        $command = "C:\Dev\Programs\google-cloud-sdk\bin\gcloud.cmd"
        $GCEarguments = "compute instances $action $name --zone=$zone --project=$project"
    }
    process{
        $process = start-process $command -ArgumentList $GCEarguments -PassThru -NoNewWindow
    }
}

function Import-GceModules {
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory=$false)]
        [Alias('l')]
        [string]$log,

        [Parameter(Mandatory = $False)]
        [Alias('n')]
        [String]$name
    )
    begin {
        $gmod = "C:\Program Files\Google\Compute Engine\sysprep\gce_base.psm1"
    }
    process {
        try {
            Import-Module $gmod -ErrorAction Stop 3> $null
        }
        catch [System.Management.Automation.ActionPreferenceStopException] {
            Write-Host $_.Exception.GetBaseException().Message
            Write-Host ("Unable to import GCE module from $PSScriptRoot. " +
                'Check error message, or ensure module is present.')
            exit 2
        }
    }
    end {}
}

function set-iac {
    param (
        [Parameter(Mandatory = $True)]
        [Alias('c')]
        [string]$comment
    )
    begin {
        $currentLocation = Get-Location
    }
    process{
        Set-Location C:\Mark\git\iac
        git pull
        Save-Git -mes $comment
    }
    end {
        Set-Location $currentLocation
    }
}

function Get-SaKey {
    <#
    .SYNOPSIS
        Retrieves SA Keys from Hashicorp Vault that you are permissioned to view

    .DESCRIPTION
        Retrieves valid SA Keys from Hashicorp Vault and saves the key to an ascii json file in c:\temp (default)

    .EXAMPLE
        PS C:\> Get-SaKey -timeLived long
        PS C:\> Get-SaKey -timeLived short
        PS C:\> Get-SaKey -timeLived long -outFolder "C:\Mark\keys"
        PS C:\> Get-SaKey -timeLived long -vaultEXE "C:\Mark\git\vault.exe"

    .PARAMETER timeLived
        Specifies the type of key. Short Lived or Long lived
        The choices are validated and can only be "short" or "long"

    .PARAMETER userName
        The default is the logged on user
        If you are running in a session logged on as another user, you can specify your own user here.

    .PARAMETER vaultAddr
        You should not need to change this unless you wish to point to a dev location

    .PARAMETER outFolder
        The default is c:\temp
        Specify an alternate location
        for example: -outFolder "C:\Mark\keys"

    .PARAMETER vaultEXE
        The default is vault.exe
        Specify the vault.exe location if the folder containing vault.exe is not in your path
        for example: -vaultEXE "C:\Mark\git\vault.exe"

    .OUTPUTS
        SCREEN OUTPUT
        =============

        PS C:\temp> Get-SaKey.ps1
        Vault v1.6.0

        Listing available long-lived keys for <username>
        1 : dev-vault
        2 : shd-found
        3 : shd-terra

        FILE OUTPUT
        ===========

        json. Returns the SA key in json ascii format in the default location of c:\temp (unless otherwise specified)
    #>
    param (
        [Parameter(Mandatory = $True)]
        [ValidateSet("short","long")]
        [string]$timeLived,

        [Parameter(Mandatory = $False)]
        [string]$userName=$env:USERNAME,

        [Parameter(Mandatory = $False)]
        [string]$vaultAddr='https://vault.domain.com',

        [Parameter(Mandatory = $False)]
        [string]$outFolder="c:\temp",

        [Parameter(Mandatory = $False)]
        [string]$vaultEXE="vault.exe"
    )
    begin {
        write-host `n"Version: " -NoNewline -ForegroundColor Gray
        $env:VAULT_ADDR=$vaultAddr
        if (!(Test-Path $outFolder)){
            Write-Log "Folder $outFolder does not exist, please rerun this function with a valid folder name"
        }
        try { vault -version } catch {
            Write-Host 'Please ensure vault is installed from here:' -ForegroundColor Red
            Write-Host 'https://confluence.domain.com/Vault+-+Desktop+setup' -ForegroundColor Red
            Write-Host 'and ONE the following:' -ForegroundColor Red
            Write-Host '- The folder containing vault.exe is set in your $env:PATH' -ForegroundColor Red
            Write-Host '- You are running this function from the folder that contains vault.exe' -ForegroundColor Red
            Write-Host '- Run the function with the -vaultEXE "c:\vaultfolder\vault.exe" switch' -ForegroundColor Red
            break
        }
        if (!(Get-ChildItem $HOME | Where-Object { $_.Name -match "^\.vault-token" })) {
            write-host "`nEnter the password for $userName`n" -ForegroundColor Cyan
            vault login -method=ldap -path=domain/ldap username=$userName
        }
        else {
            $process = Start-Process $vaultEXE `
                    -ArgumentList "policy list" `
                    -NoNewWindow `
                    -Wait `
                    -PassThru `
                    -RedirectStandardOutput ".\NUL" `
                    -RedirectStandardError "c:\temp\NUL"

            if ($process.ExitCode) {
                write-host "`nEnter the password for $userName`n" -ForegroundColor Cyan
                vault login -method=ldap -path=domain/ldap username=$userName
            }
        }
    }
    process {
        # List the secrets
        $menu = @{}
        $itemNumber = 1
        $availableKeys = vault kv list gcp-users/kv/$userName/gcp-sa-keys-$timeLived-lived
        if ($availableKeys.length -gt 2){
            For ($i=2; $i -lt $availableKeys.length; $i++) {
                $($availableKeys[$i]) | ForEach-Object {
                    if (vault kv get -field=key gcp-users/kv/$userName/gcp-sa-keys-$timeLived-lived/$_ 2> $nul) {
                        Write-Host "`nListing available $timeLived-lived keys for $userName`n" -ForegroundColor Cyan
                        write-output "$itemNumber : $($availableKeys[$i])"
                        $menu.Add($itemNumber, ($availableKeys[$i]))
                        $itemNumber++
                    }
                }
            }
            if ($menu.count -gt 0) {
                [int]$ans = Read-Host `n'Enter selection'
                $selection = $menu.Item($ans)
                Write-Host "`nYou have selected: " -NoNewline
                Write-Host "$selection`n" -ForegroundColor Green
                $outFile = "$outFolder\$selection.json"

                # Download the SA key from gcp-users/kv/<username>/gcp-sa-keys-(short|long)-lived path
                vault kv get -field=key gcp-users/kv/$userName/gcp-sa-keys-$timeLived-lived/$selection | Out-File -FilePath $outFile -Encoding ascii

                write-host "The SA Key has been downloaded to " -NoNewline
                write-host $outFile -ForegroundColor Green
                write-host "`nTo login using the supplied file, run the following command:`n"
                write-host "gcloud auth activate-service-account --key-file=$outFile" -ForegroundColor Yellow
            }
            else {
                Write-Host "`nNo $timeLived-lived keys are available to $userName`n" -ForegroundColor Yellow
            }
        }
        else {
            Write-Host "`nNo $timeLived-lived keys are available to $userName`n" -ForegroundColor Yellow
        }
    }
    end {}
}

function vault-login {
    begin {
    }
    process{
        write-host "Enter username (no domain name)"
        vault login -method=ldap -path=domain/ldap username=user
    }
    end {
    }
}

Import-GceModules

#gcloud compute instances start dev-win-111 --zone=europe-west2-a --project=rel-kit-111
#gcloud config set proxy/password ppppppp

New-Alias -Name change-password -Value Set-Password -Option AllScope
New-Alias -Name mnt -Value Get-MountedDives -Option AllScope
New-Alias -Name created -Value Get-Created -Option AllScope
New-Alias -Name grep -Value Find-String -Option AllScope
New-Alias -Name np -Value C:\Windows\System32\notepad.exe -Option AllScope
New-Alias -Name g -Value 'C:\Program Files\Git\mingw64\bin\git.exe' -Option AllScope
New-Alias -Name vault -Value C:\tools\vault.exe -Option AllScope
New-Alias -Name gs -Value Save-Git -Option AllScope
New-Alias -Name gssh -Value Invoke-SSH -Option AllScope
New-Alias -Name vl -Value vault-login -Option AllScope
New-Alias -Name swap -Value Set-GCloud -Option AllScope
New-Alias -Name start111 -Value "gcloud.cmd compute instances start dev-win-111 --zone=europe-west2-a --project=rel-kit-111" -Option AllScope
New-Alias -Name tf12 -Value c:\tools\tf-12-29.exe -Option AllScope
New-Alias -Name tf11 -Value c:\tools\tf-11-14.exe -Option AllScope


# Chocolatey profile
$ChocolateyProfile = "$env:ChocolateyInstall\helpers\chocolateyProfile.psm1"
if (Test-Path($ChocolateyProfile)) {
  Import-Module "$ChocolateyProfile"
}


(New-Object System.Net.WebClient).Proxy.Credentials = [System.Net.CredentialCache]::DefaultNetworkCredentials

$env:HTTP_PROXY = 'http://user:pw@proxy.domain.com:8080'
$env:HTTPS_PROXY = 'http://user:pw@proxy.domain.com:8080'
$env:NO_PROXY = 'localhost,127.0.0.1,domain.com'
$env:HTTPLIB2_CA_CERTS = "C:\dev\certs\gcloud_ca_bundle.pem"
$env:REQUESTS_CA_BUNDLE = "C:\dev\certs\gcloud_ca_bundle.pem"
$env:HTTPLIB_CA_CERTS_PATH = "C:\dev\certs\gcloud_ca_bundle.pem"
#"C:\dev\ubuntu_2004.2020.424.0_x64\rootfs\etc\apt\apt.conf.d\proxy.conf"
