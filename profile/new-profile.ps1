# -----------------------------------------------------------------------------------------------

#region functions
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
    $PromptPwd = [string]::format('{0}..\{1}\{2}\{3}\{4}\{5}\{6}\{7}', $PRoot, $PLoc[6], $PLoc[5], $PLoc[4], $PLoc[3], $PLoc[2], $PLoc[1], $PLoc[0])
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
    $timeTakenToExecute = [pscustomobject]@{TotalSeconds = 0 }
  }
  Write-Host
  [Console]::ForegroundColor = [System.ConsoleColor]::DarkGray
  [Console]::Write([string]::format('[{0}{1}', $time, $ifDBG))
  [Console]::ResetColor()

  [Console]::ForegroundColor = [ConsoleColor]::DarkGray
  [Console]::Write([string]::format('|+{0}s]', [Math]::Round($timeTakenToExecute.TotalSeconds, 0)))
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
  get-psdrive | Where-Object { $_.Provider -like "*FileSystem*" } | Select-Object Name, @{n = 'Free'; e = { [math]::Round($_.Free / 1gb, 2) } }, Root, Description
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
    [Alias('e')]
    [String] $extension,

    [Parameter(Mandatory = $False)]
    [Alias('g')]
    [Switch]$grep
  )
  if ($extension) {
    $results = (Get-ChildItem -Filter *.$extension -Recurse -ErrorAction SilentlyContinue | Select-String $string -List -ErrorAction SilentlyContinue | Select-Object Path).path
  }
  else {
    $results = (Get-ChildItem -Recurse -ErrorAction SilentlyContinue | Select-String $string -List -ErrorAction SilentlyContinue | Select-Object Path).path
    #Get-ChildItem *.sh -Recurse | ForEach-Object { Select-String '#\!\/bin\/sh' -Path $_.FullName }
  }
  if ($grep) {
    $results | ForEach-Object {
      select-string -Path $_ -pattern $string -ErrorAction SilentlyContinue
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
  if ($changeProxy) {
    $env:http_proxy = "http://username:$NewPW@userproxy.domain.net:8080"
    $env:https_proxy = "http://username:$NewPW@userproxy.domain.net:8080"
    $env:HTTP_PROXY = "http://username:$NewPW@userproxy.domain.net:8080"
    $env:HTTPS_PROXY = "http://username:$NewPW@userproxy.domain.net:8080"
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
  Get-ChildItem $path | Sort-Object CreationTime | Select-Object name, creationtime
}

function Save-Git {
  param(
    [Parameter(Mandatory = $False)]
    #[ValidateNotNullOrEmpty()]
    [string]$mes
  )
  begin {
    $jiraRef = $null
    $branch = git rev-parse --abbrev-ref HEAD
    if ($branch) {
      switch -wildcard ($branch) {
        'master' {
          if ($(git config --get remote.origin.url) -eq "https://gitlab.platform.domain.net/username/scripts") {
            write-host "Marks master branch - don't panic"
            $jiraRef = $_
          }
          else {
            write-host "MASTER BRANCH!!" -ForegroundColor Yellow
            $title = 'This is the master branch - are you sure you want to commit directly to master?'
            $prompt = '[Y]es or [N]o?'
            $abort = New-Object System.Management.Automation.Host.ChoiceDescription '&No', 'Stops the commit'
            $retry = New-Object System.Management.Automation.Host.ChoiceDescription '&Yes', 'Commits'
            $options = [System.Management.Automation.Host.ChoiceDescription[]] ($abort, $retry)
            $choice = $host.ui.PromptForChoice($title, $prompt, $options, 0)
            if ($choice -eq 0) {
              $jiraRef = $null
              break
            }
            if ($choice -eq 1) {
              $jiraRef = $_
            }
          }
        }
        '*initial-commit*' {
          write-host "initial-commit: $_" -ForegroundColor cyan
          $jiraRef = "initial-commit"
          continue
        }
        'feature*' {
          write-host "feature-branch: $_" -ForegroundColor cyan
          $jiraRef = [regex]::Match($_, 'NWMP(E|O)-[0-9]{4,5}').captures.groups[0].value
          $jiraRef = "feature-$jiraRef"
          continue
        }
        'release*' {
          write-host "release-branch: $_" -ForegroundColor cyan
          $jiraRef = "release"
          continue
        }
        { $_ -match '^NWMP(E|O)-[0-9]{4,5}' } {
          $jiraRef = [regex]::Match($_, '^NWMP(E|O)-[0-9]{4,5}').captures.groups[0].value
          continue
        }
        Default {
          write-host "No matching branch name found: $_" -ForegroundColor Yellow
          $title = 'Are you sure you want to continue?'
          $prompt = '[Y]es or [N]o?'
          $abort = New-Object System.Management.Automation.Host.ChoiceDescription '&No', 'Stops the commit'
          $retry = New-Object System.Management.Automation.Host.ChoiceDescription '&Yes', 'Commits'
          $options = [System.Management.Automation.Host.ChoiceDescription[]] ($abort, $retry)
          $choice = $host.ui.PromptForChoice($title, $prompt, $options, 0)
          if ($choice -eq 0) {
            $jiraRef = $null
            break
          }
          if ($choice -eq 1) {
            $jiraRef = $_
          }
        }
      }
    }
    else {
      $jiraRef = "first-write"
    }
    if ($mes) { $mes = $mes -replace " ", "-" }
    else { $mes = "saving..." }
    $mes = "$jiraRef-$mes"
  }
  process {
    if ($jiraRef) {
      if (git status --porcelain) {
        write-host "Commit message: $mes" -ForegroundColor cyan
        git pull
        git add -A
        git commit -am $mes
        git push
      }
      else {
        git status
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
  process {
    [System.IO.Compression.ZipFile]::ExtractToDirectory( $ziparchive, $extractpath )
  }
}

function start-Chrome {
  param (
    [string]$url = "https://gitlab.platform.domain.net/team-name/subteam/subteam-bakery/subteam-windows2016-image",
    [string]$ref = "master",
    # feature/MMMMM-11052-Windows-Image-v1.0.8    #master
    [hashtable]$variables = @{UPDATES = "no"}
    # @{One = 1; Two = 2}
    # [COMMAND]=TRIGGER
    # &var[COMMAND]=TRIGGER&var[UPDATES]=no
  )
  begin {
    if ($variables){
      foreach ($Key in $variables.Keys) {
        "The value of '$Key' is: $($variables[$Key])"
        $varStringArray += "&var[$Key]=$($variables[$Key])"
      }
      $varString = $varStringArray
    }
    else {
      $varString = ""
    }
    $runUrl = "$url/-/pipelines/new?ref=$ref" + "$varString"
  }
  process {
    [system.Diagnostics.Process]::Start("chrome","$runUrl")
  }
}

function Invoke-SSH {
  param (
    #[Parameter(Mandatory = $True)]
    [string]$instance = "dev-sit-002",

    #[Parameter(Mandatory = $True)]
    [string]$zone = "europe-west2-a",

    #[Parameter(Mandatory = $True)]
    [string]$project = "project"
  )
  begin {
    Write-Host $instance -ForegroundColor cyan -NoNewline
    write-host " : $zone : $project"
    $command = "gcloud compute ssh $instance --project $project --zone $zone --internal-ip"
  }
  process {
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
      'mark' { $account = "user.name@domain.com" }
      'admin' { $account = "admin@project.iam.gserviceaccount.com" }
    }
    $command = "C:\dev\google-cloud-sdk\bin\gcloud.cmd"
    $GCEarguments = "config set account $account"
    $authList = "auth list"
  }
  process {
    $process = start-process $command -ArgumentList $GCEarguments -PassThru -NoNewWindow -Wait
    $process2 = start-process $command -ArgumentList $authList -PassThru -NoNewWindow -Wait
    continue
  }
}

function Get-GCloudConfigDir {
  param ()
  process {
    $out = . "C:\dev\google-cloud-sdk\bin\gcloud.cmd" info | Select-String "User Config Directory"
    $out.ToString()
  }
}

# Set-Config {
#   . "C:\dev\google-cloud-sdk\bin\gcloud.cmd" config configurations list

#   $menu = @{}
#   $itemNumber = 1
#   $availableKeys = . "C:\dev\google-cloud-sdk\bin\gcloud.cmd" config configurations list
#   if ($availableKeys.length -gt 2) {
#     For ($i = 2; $i -lt $availableKeys.length; $i++) {
#       $($availableKeys[$i]) | ForEach-Object {
#         if (vault kv get -field=key gcp-users/kv/$userName/gcp-sa-keys-$timeLived-lived/$_ 2> $nul) {
#           Write-Host "`nListing available $timeLived-lived keys for $userName`n" -ForegroundColor Cyan
#           write-output "$itemNumber : $($availableKeys[$i])"
#           $menu.Add($itemNumber, ($availableKeys[$i]))
#           $itemNumber++
#         }
#       }
#     }
#     if ($menu.count -gt 0) {
#       [int]$ans = Read-Host `n'Enter selection'
#       $selection = $menu.Item($ans)
#       Write-Host "`nYou have selected: " -NoNewline
#       Write-Host "$selection`n" -ForegroundColor Green
#       $outFile = "$outFolder\$selection.json"

#       # Download the SA key from gcp-users/kv/<username>/gcp-sa-keys-(short|long)-lived path
#       vault kv get -field=key gcp-users/kv/$userName/gcp-sa-keys-$timeLived-lived/$selection | Out-File -FilePath $outFile -Encoding ascii

#       write-host "The SA Key has been downloaded to " -NoNewline
#       write-host $outFile -ForegroundColor Green
#       write-host "`nTo login using the supplied file, run the following command:`n"
#       write-host "gcloud auth activate-service-account --key-file=$outFile" -ForegroundColor Yellow
#     }
#     else {
#       Write-Host "`nNo $timeLived-lived keys are available to $userName`n" -ForegroundColor Yellow
#     }
#   }
#   else {
#     Write-Host "`nNo $timeLived-lived keys are available to $userName`n" -ForegroundColor Yellow
#   }
# }

function Set-GCEInstance {
  param (
    [Parameter(Mandatory = $True)]
    [string]$name,

    [Parameter(Mandatory = $True)]
    [ValidateSet("start", "stop", "reset", "delete")]
    [string]$action,

    [Parameter(Mandatory = $False)]
    [string]$project = "project",

    [Parameter(Mandatory = $False)]
    [string]$zone = "europe-west2-a"

  )
  begin {
    Set-GCloud -name 'Mark'
    $command = "C:\Dev\Programs\google-cloud-sdk\bin\gcloud.cmd"
    $GCEarguments = "compute instances $action $name --zone=$zone --project=$project"
  }
  process {
    $process = start-process $command -ArgumentList $GCEarguments -PassThru -NoNewWindow
  }
}

function Import-GceModules {
  [CmdletBinding()]
  Param(
    [Parameter(Mandatory = $false)]
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
  process {
    Set-Location "C:\git\team-name\subteam\subteam-iac"
    git pull
    Save-Git -mes $comment
  }
  end {
    Set-Location $currentLocation
  }
}

function vault-login {
  begin {
  }
  process {
    write-host "Enter username (no domain name)"
    vault login -method=ldap -path=domain/ldap username=username
  }
  end {
  }
}

function start-timer {
  begin {
  }
  process {
    F:\start-mouse.ps1 -time 17:00
  }
  end {
  }
}

function set-proxy {
  begin {
    $userName = $env:USERNAME
    $title = "Do you want to set the proxy for $($userName)? (prompts for password)"
    $prompt = '[Y]es or [N]o?'
    $abort = New-Object System.Management.Automation.Host.ChoiceDescription '&No', 'Exits'
    $yesman = New-Object System.Management.Automation.Host.ChoiceDescription '&Yes', 'Set the password'
    $options = [System.Management.Automation.Host.ChoiceDescription[]] ($abort, $yesman)
    $choice = $host.ui.PromptForChoice($title, $prompt, $options, 1)
  }
  process {
    if ($choice -eq 0) {
      write-host "HTTP_PROXY(S) not set" -ForegroundColor Yellow
      break
    }
    if ($choice -eq 1) {
      $securePwd = read-host "Enter password" -AsSecureString
      $plainPwd = [Runtime.InteropServices.Marshal]::PtrToStringAuto([Runtime.InteropServices.Marshal]::SecureStringToBSTR($securePwd))
      $env:HTTP_PROXY = "http://$($userName):$plainPwd@userproxy.domain.net:8080"
      $env:HTTPS_PROXY = "http://$($userName):$plainPwd@userproxy.domain.net:8080"
    }
  }
  end { 
    $plainPwd = $null
    $securePwd = $null
  }
}

function get-randompw {
  param (
    [Parameter(Position = 0, Mandatory = $False)]
    [int]$length = 16,

    [Parameter(Position = 1, Mandatory = $False)]
    [int]$spChars = 3
  )
  # Import System.Web assembly
  Add-Type -AssemblyName System.Web
  # Generate random password
  [System.Web.Security.Membership]::GeneratePassword($length,$spChars)
}

function set-gcloudConfig {
  param (
    [Parameter(Mandatory = $False)]
    [string]$config
  )
  begin {}
  process {
    Write-Host "Running: gcloud config configurations activate $config"
    gcloud config configurations activate $config
    gcloud config configurations describe $config
  }
  end {}
}

function get-gcloudConfigsList {
  param (
    [Parameter(Mandatory = $False)]
    [string]$config
  )
  begin {}
  process {
    Write-Host "Running: gcloud config configurations list"
    gcloud config configurations list
  }
  end {}
}



function set-window {
  set-location C:\git
  Add-Type -AssemblyName System.Windows.Forms

  # to add https://learn.microsoft.com/en-us/powershell/scripting/learn/shell/creating-profiles?view=powershell-7.3
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

  $Global:CurrentUser = [System.Security.Principal.WindowsIdentity]::GetCurrent()
  $UserType = "User"
  $CurrentUser.Groups | ForEach-Object {
    if ($_.value -eq "S-1-5-32-544") {
      $UserType = "Admin"
    }
  }

  # Chocolatey profile
  $ChocolateyProfile = "$env:ChocolateyInstall\helpers\chocolateyProfile.psm1"
  if (Test-Path($ChocolateyProfile)) {
    Import-Module "$ChocolateyProfile"
  }
  $Shell = $Host.UI.RawUI
  $Shell.backgroundcolor = "Black"
  $wsize = $Shell.WindowSize
  $bsize = $Shell.BufferSize
  $wsize.width = 140
  $wsize.height = 65
  $bsize.width = 140
  $bsize.height = 9999
  $Shell.BufferSize = $bsize
  $Shell.WindowSize = $wsize
}

function dev-image-domain {
  $env = "dev"
  $url = "https://gitlab.platform.domain.net/team-name/services/thing"
  $ref = "feature/branchname"
  $scope = "image-vm"
  $region = "euw2"
  $ou = "domain"
  [system.Diagnostics.Process]::Start("chrome","$url/-/pipelines/new?ref=$ref&var[CMD]=$scope&var[OU]=$ou&var[REGION]=$region&var[TARGET_ENV]=$env&var[SA_KEY]")
}

#endregion functions

# -----------------------------------------------------------------------------------------------

Import-GceModules
Import-Module PSReadLine

# -----------------------------------------------------------------------------------------------

#region variables

$certPath = "C:\dev\certs"
$certFile = "$certPath\2021-ca-bundle.pem"
$env:HTTPLIB_CA_CERTS_PATH = $certFile
$env:HTTPLIB2_CA_CERTS = $certFile
$env:REQUESTS_CA_BUNDLE = $certFile
$env:SSL_CERT_FILE = $certFile
$env:NO_PROXY = 'localhost,127.0.0.1,.domain.net,.domain.net,.domain.net'
$env:VAULT_ADDR = 'https://vault.platform.domain.net'
$env:PROJECT_ID = "project"
$env:SA = "project-resource-editor"
$2016 = "C:\git\team-name\subteam\subteam-bakery\subteam-windows2016-image"
$git = "C:\git"
$env:TF_VAR_project_resource_sa_key = $(get-content C:\mark\service-account-key.json)
$FormatEnumerationLimit = 200 # expands truncated output for properties which contain arrays in list formatted views. E.g. Get-Module Microsoft.PowerShell.Utility | fl

#endregion variables

# -----------------------------------------------------------------------------------------------

# git config http.sslCAInfo C:\mark\ca-bundle-new.crt
# git config http.sslCAInfo $certPath\2021-ca-bundle.pem
#gcloud auth activate-service-account --key-file=C:\mark\service-account-key.json --project=project
#gcloud config set proxy/password ppppppp

[Net.ServicePointManager]::SecurityProtocol = "tls12, tls11, tls"

# Don't set window size etc in vscode terminal or windows terminal
if ( $env:WT_SESSION ) {
  "Windows Terminal"
}
elseif ( $env:TERM_PROGRAM -eq "vscode" ) {
  Write-Output "VSCode Terminal"
}
else {
  set-window
}

#gcloud compute instances start dev-win-888 --zone=europe-west2-a --project=project
# gcloud config set proxy/password ppppppp

# -----------------------------------------------------------------------------------------------

#region aliases

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
New-Alias -Name start7 -Value "gcloud.cmd compute instances start dev-win-777 --zone=europe-west2-a --project=project" -Option AllScope
New-Alias -Name tf11 -Value c:\tools\tf-11-14.exe -Option AllScope
New-Alias -Name "tf12-29" -Value c:\tools\tf-12-29.exe -Option AllScope
New-Alias -Name "tf12-31" -Value c:\tools\tf-12-31.exe -Option AllScope
New-Alias -Name tf13 -Value c:\tools\tf-13-5.exe -Option AllScope
New-Alias -Name tf14 -Value c:\tools\tf-14-10.exe -Option AllScope

#endregion aliases

# -----------------------------------------------------------------------------------------------

(New-Object System.Net.WebClient).Proxy.Credentials = [System.Net.CredentialCache]::DefaultNetworkCredentials

gcloud config set core/custom_ca_certs_file $certFile

$HistFile = Join-Path ([Environment]::GetFolderPath('UserProfile')) .ps_history
Register-EngineEvent PowerShell.Exiting -Action { Get-History | Export-Clixml $HistFile } | out-null
if (Test-path $HistFile) { Import-Clixml $HistFile | Add-History }

set-proxy

#Set-PSReadlineKeyHandler -Key Tab -Function MenuComplete


# Register-ArgumentCompleter -Native -CommandName winget -ScriptBlock {
#     param($wordToComplete, $commandAst, $cursorPosition)
#         [Console]::InputEncoding = [Console]::OutputEncoding = $OutputEncoding = [System.Text.Utf8Encoding]::new()
#         $Local:word = $wordToComplete.Replace('"', '""')
#         $Local:ast = $commandAst.ToString().Replace('"', '""')
#         winget complete --word="$Local:word" --commandline "$Local:ast" --position $cursorPosition | ForEach-Object {
#             [System.Management.Automation.CompletionResult]::new($_, $_, 'ParameterValue', $_)
#         }
# }

#"C:\dev\ubuntu_2004.2020.424.0_x64\rootfs\etc\apt\apt.conf.d\proxy.conf"
#Set-Location C:\Mark\git\subteam-common-utils\ ; gs mark ; Set-Location C:\Mark\git\subteam-windows2019-image\ ; git pull ; gs mark ; Set-Location C:\Mark\git\subteam-common-utils\

#$env:VAULT_ADDR='https://vault.platform.domain.net'
#vault login -method=ldap -path=domain/ldap username=username
#vault login -method=ldap -path=europs/ldap username=username
#vault kv list non-prod/kv/subteam/dev1
#vault kv get -field=key non-prod/kv/subteam/dev1/windows-server-2016
#gcloud config set project project
