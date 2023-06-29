param (
  [Parameter(Mandatory = $False)]
  [Alias('m')]
  [int] $minutes,

  [Parameter(Mandatory = $False)]
  [Alias('h')]
  [int]$hours,

  [Parameter(Mandatory = $False)]
  [Alias('t')]
  [String] $time
)

function Test-Time {
  [CmdletBinding()]
  Param(
      [Parameter(Mandatory=$true)]
      [string]$time
  )
  $time -match '^([0-9]|0[0-9]|1[0-9]|2[0-3]):?[0-5][0-9]$'
}

If ($hours){
  $hoursToMin = $(New-TimeSpan -Hours $hours).TotalMinutes
} else {
  $hoursToMin = 0
}
If ($minutes){
  $minToMin = $minutes
}
else {
  if ($hours){ $minToMin = 00 }
  else { $minToMin = 30 }
}
if ($time){
  if (Test-Time $time){
    $hoursToMin = 0 # in case someone mixes them - do something better at some point
    $minToMin = 0 # in case someone mixes them - do something better at some point

    write-host "time: $time"
    $hrs = ($time.split(":"))[0]
    $mins = ($time.split(":"))[1]
    $timeToMin = $(New-TimeSpan -Start (get-date -DisplayHint time) -End (get-date -DisplayHint time -Hour $hrs -Minute $mins)).TotalMinutes
    write-host "timeToMin: $timeToMin"
  }
  else {
    Write-Host "Time not in correct format. 00:00 - 23:59"
    exit 1
  }
} else {
  $timeToMin=0
}

$totalminutes = [math]::Round($hoursToMin + $minToMin + $timeToMin)

$start = $($(Get-Date).ToString("HH:mm:ss"))
$predictedEnd = $($(get-date) + $(New-TimeSpan -Minutes $totalminutes)).ToString("HH:mm:ss")
write-host "Start....: $start"
write-host "Ending...: $predictedEnd"
write-host "Minutes..: $totalminutes"

$myshell = New-Object -com "Wscript.Shell"

for ($i = 0; $i -lt $totalminutes; $i++) {
  Start-Sleep -Milliseconds 59900
  $myshell.sendkeys("{SCROLLLOCK}") | out-null
  Start-Sleep -Milliseconds 100
  $myshell.sendkeys("{SCROLLLOCK}") | out-null
  Write-Host "$i," -NoNewline
}
Write-Host "$i"
write-host "Start....: $start"
write-host "End......: $($(Get-Date).ToString("HH:mm:ss"))"

# Some people get success using $WShell.sendkeys("SCROLLLOCK") instead of $WShell.sendkeys("{SCROLLLOCK}")
# query scroll
# [System.Windows.Forms.Control]::IsKeyLocked('Scroll')
