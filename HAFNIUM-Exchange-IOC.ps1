<# 
.SYNOPSIS
    Searches Exchange logs and ASPX files for indicators related to Hafnium as noted in 
    https://www.microsoft.com/security/blog/2021/03/02/hafnium-targeting-exchange-servers/
    Author: Soteria (https://soteria.io)
    License: Apache-2.0 (https://www.apache.org/licenses/LICENSE-2.0.txt)
    Required Dependencies: None
    Optional Dependencies: None
    Last Update: 2021-03-02
 
.DESCRIPTION
    Searches for IOCs related to Exchange exploitation by Hafnium as document by Microsoft.
    Script assumes default Exchange install and creates a log file in the present working directory.
    If using a non-default install, please change variables under the variables heading below.


#>


<##############################
 #
 #              Variables
 #
 ##############################>

#Location and name of log generated from script
$logPath = "$pwd\$(Get-Date -Format 'yyyy_MM_dd HH.mm.ss')-Hafnium_IOCs.txt"

#Customize if not using default options for Exchange
$webRootDir = "C:\inetpub\wwwroot\aspnet_client"
$owaPath1 = "$env:PROGRAMFILES\Microsoft\Exchange Server\V15\FrontEnd\HttpProxy\owa\auth\"
$owaPath2 = "C:\Exchange\FrontEnd\HttpProxy\owa\auth\"
$excHTTPProxyLogs = "$env:PROGRAMFILES\Microsoft\Exchange Server\V15\Logging\HttpProxy"
$excOABGeneratorLogs = "$env:PROGRAMFILES\Microsoft\Exchange Server\V15\Logging\OABGeneratorLog\*.log"
$exECPLogs = "$env:PROGRAMFILES\Microsoft\Exchange Server\V15\Logging\ECP\Server\*.log"

<##############################
 # Checking for CVE-2021-26855 exploitation via the following Exchange HttpProxy logs as outlined 
 # in https://www.microsoft.com/security/blog/2021/03/02/hafnium-targeting-exchange-servers/
 ###############################>
New-Item -Path "$logPath" -ItemType "file"
Write-Host "Checking for CVE-2021-26855"
Add-Content -Path "$logPath" -Value "Checking for CVE-2021-26855"
$CVE_2021_26855 = @()
$myLogs = Get-ChildItem -Recurse -Path "$excHTTPProxyLogs" -Filter '*.log'
$l = 0

#Searching each log for AuthenticatedUser being empty and AnchorMailbox containing ServerInfo~*/*
foreach ($log in $Mylogs) {

$l=$l+1
$prc = ([Math]::Round(($l / $Mylogs.Count) * 100))
Write-Progress -Activity "Searching for Log Files for CVE-2021-26855..." -Status "$prc% Complete:" -PercentComplete $prc
$CVE_2021_26855 += Import-Csv -Path $log.FullName | Where-Object {  $log.AuthenticatedUser -eq "" -and $log.AnchorMailbox -like 'ServerInfo~*/*' } | Select-Object DateTime, AnchorMailbox

}


#Returning Results
if($CVE_2021_26855.Count -eq 0){

  Write-Host "No indicators for CVE-2021-26855 found"
  Add-Content -Path "$logPath" -Value "No indicators for CVE-2021-26855 found"

} else {

   Write-Warning -Message "Indicators for CVE-2021-26855 found!"
   Add-Content -Path "$logPath" -Value "Indicators for CVE-2021-26855 found!"
   $CVE_2021_26855 | ForEach-Object { 

     Add-Content -Path "$logPath" -Value "$_"

  }
}

<##############################
Checking for CVE-2021-26858 exploitation via Exchange log files as outlined 
in https://www.microsoft.com/security/blog/2021/03/02/hafnium-targeting-exchange-servers/
#>

Add-Content -Path "$logPath" -Value ""
Clear-Variable myLogs
Write-Host "Checking for CVE-2021-26858"
Add-Content -Path "$logPath" -Value "Checking for CVE-2021-26858"
$CVE_2021_26858 = @()
$myLogs = Get-ChildItem -Path "$excOABGeneratorLogs"
$l = 0

#Searching OABGenerator logs for the string 'Download failed and temporary file'
foreach ($log in $Mylogs) {

$l=$l+1
$prc = ([Math]::Round(($l / $Mylogs.Count) * 100))
Write-Progress -Activity "Searching for Log Files for CVE-2021-26858..." -Status "$prc% Complete:" -PercentComplete $prc
$CVE_2021_26858 += $log | Select-String  -Pattern 'Download failed and temporary file'

}

#Returning Results
if($CVE_2021_26858.Count -eq 0){

  Write-Host "No indicators for CVE_2021_26858 found"
  Add-Content -Path "$logPath" -Value "No indicators for CVE_2021_26858 found"

} else {

   Write-Warning -Message "Indicators for CVE_2021_26858 found!"
   Add-Content -Path "$logPath" -Value "Indicators for CVE_2021_26858 found!"
   $CVE_2021_26858 | ForEach-Object { 

     Add-Content -Path "$logPath" -Value "$_"

  }
}


<##############################
Checking for CVE-2021-26857 exploitation via MSExchange Unified Messaging logs as outlined 
in https://www.microsoft.com/security/blog/2021/03/02/hafnium-targeting-exchange-servers/
#>

Add-Content -Path "$logPath" -Value ""
Clear-Variable myLogs
Write-Host "Checking for CVE-2021-26857"
Add-Content -Path "$logPath" -Value "Checking for CVE-2021-26857"
$myLogs = Get-EventLog -LogName Application -Source "MSExchange Unified Messaging" -EntryType Error | Where-Object { $_.Message -like "*System.InvalidCastException*" }

#Returning Results
if($myLogs -eq ""){

  Write-Host "No indicators for CVE-2021-26857 found"
  Add-Content -Path "$logPath" -Value "No indicators for CVE-2021-26857 found"

} else {

   Write-Warning -Message "Indicators for CVE-2021-26857 found!"
   Add-Content -Path "$logPath" -Value "Indicators for CVE-2021-26857 found!"
   Add-Content -Path "$logPath" -Value "$myLogs"

}
  
<##############################
Checking for CVE-2021-27065 exploitation via Exchange Admin Center log files as outlined 
in https://www.microsoft.com/security/blog/2021/03/02/hafnium-targeting-exchange-servers/
#>

Add-Content -Path "$logPath" -Value ""
Clear-Variable myLogs
Write-Host "Checking for CVE-2021-27065"
Add-Content -Path "$logPath" -Value "Checking for CVE-2021-27065"
$CVE_2021_27065 = @()
$myLogs = Get-ChildItem -Path "$exECPLogs"
$l = 0

#Searching OABGenerator logs for the string 'Download failed and temporary file'
foreach ($log in $Mylogs) {

$l=$l+1
$prc = ([Math]::Round(($l / $Mylogs.Count) * 100))
Write-Progress -Activity "Searching for Log Files for CVE-2021-27065..." -Status "$prc% Complete:" -PercentComplete $prc
$CVE_2021_27065 += $log | Select-String  -Pattern 'Set-.+VirtualDirectory'

}

#Returning Results
if($CVE_2021_27065.Count -eq 0){

  Write-Host "No indicators for CVE-2021-27065 found"
  Add-Content -Path "$logPath" -Value "No indicators for CVE-2021-27065 found"

} else {

   Write-Warning -Message "Indicators for CVE-2021-27065 found!"
   Add-Content -Path "$logPath" -Value "Indicators for CVE-2021-27065 found!"
   $CVE_2021_27065 | ForEach-Object { 

     Add-Content -Path "$logPath" -Value "$_"

  }
}


<##############################
Checking for Web shells
#>

$shellHits = @()
$shellHashes = @("b75f163ca9b9240bf4b37ad92bc7556b40a17e27c2b8ed5c8991385fe07d17d0","097549cf7d0f76f0d99edf8b2d91c60977fd6a96e4b8c3c94b0b1733dc026d3","2b6f1ebb2208e93ade4a6424555d6a8341fd6d9f60c25e44afe11008f5c1aad1", "65149e036fff06026d80ac9ad4d156332822dc93142cf1a122b1841ec8de34b5", "511df0e2df9bfa5521b588cc4bb5f8c5a321801b803394ebc493db1ef3c78fa1", "4edc7770464a14f54d17f36dc9d0fe854f68b346b27b35a6f5839adf1f13f8ea", "811157f9c7003ba8d17b45eb3cf09bef2cecd2701cedb675274949296a6a183d", "b75f163ca9b9240bf4b37ad92bc7556b40a17e27c2b8ed5c8991385fe07d17d0")
$shellNames = @("web.aspx","help.aspx","document.aspx", "errorEE.aspx", "errorEEE.aspx", "errorEW.aspx", "errorEWW.aspx", "errorFF.aspx", "errorFFF.aspx", "healthcheck.aspx", "aspnet_www.aspx","xx.aspx", "aspnet_client.aspx","aspnet_iisstart.aspx","shell.aspx", "one.aspx" )
$webShellPaths = @("$webRootDir", "$owaPath1", "$owaPath2" )
Foreach ($p in $webShellPaths) {
  
  Write-Host "Checking $p for web shell IOCs"
  Add-Content -Path "$logPath" -Value "Checking $p for web shell IOCs"
  $myFiles = Get-ChildItem -Path "$p" -Recurse
  $l = 0

  foreach ($file in $myFiles) {
  
  $l=$l+1
  $prc = ([Math]::Round(($l / $myFiles.Count) * 100))
  Write-Progress -Activity "Searching for web shells..." -Status "$prc% Complete:" -PercentComplete $prc
  
  
  foreach ($hash in $shellHashes){ 

  if (($file | Get-FileHash).Hash -eq  "$hash"){

     $shellHits += $file.FullName
     break

  }
  
  }
  

  foreach ($name in $shellNames){ 

  if ($file.name  -eq  "$name"){

     $shellHits += $file.FullName
     break

  }
  
  }
  
  }
  

}

#Returning Results
if($shellHits.Count -eq 0){

  Write-Host "No web shell IOCs found"
  Add-Content -Path "$logPath" -Value "No web shell IOCs found"

} else {

   Write-Warning -Message "Web shell IOCs found!"
   Add-Content -Path "$logPath" -Value "Web shell IOCs found!"
   $shellHits | ForEach-Object { 

     Add-Content -Path "$logPath" -Value "$_"

  }
}
