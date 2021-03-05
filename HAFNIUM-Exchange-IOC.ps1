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

param ($logPath="$env:HOMEPATH\$(Get-Date -Format 'yyyy_MM_dd HH.mm.ss')-Hafnium_IOCs.txt")

<##############################
 #
 #            Fuctions
 #
 ##############################>

<#
 Test for CVE-2021-26855
 For more info see https://msrc.microsoft.com/update-guide/vulnerability/CVE-2021-26855
 #>
 function Check-CVE_2021_26855 {

  [cmdletbinding()]
  Param (
    [Parameter (Mandatory = $True)][string]$logPath
  )
  $CVE_2021_26855 = @()
  #Checking to see if path exist
  if (test-path "$env:ExchangeInstallPath\V15\Logging\HttpProxy") {
    $l = 0
    $myLogs = Get-ChildItem -Recurse -Path "$env:ExchangeInstallPath\V15\Logging\HttpProxy" -Filter '*.log' -ErrorAction SilentlyContinue
    foreach ($log in $Mylogs) {

      $l = $l + 1
      $prc = ([Math]::Round(($l / $Mylogs.Count) * 100))
      Write-Progress -Activity "Searching for Log Files for CVE-2021-26855..." -Status "$prc% Complete:" -PercentComplete $prc
      $CVE_2021_26855 += Import-Csv -Path $log.FullName | Where-Object { $log.AuthenticatedUser -eq "" -and $log.AnchorMailbox -like 'ServerInfo~*/*' } | Select-Object DateTime, AnchorMailbox
    
    }

  }
  #Checking to see if path exist
  elseif (test-path $env:ExchangeInstallPath\Logging\HttpProxy) {

    $l = 0
    $myLogs = Get-ChildItem -Recurse -Path "$env:ExchangeInstallPath\Logging\HttpProxy" -Filter '*.log' -ErrorAction SilentlyContinue
    foreach ($log in $Mylogs) {

      $l = $l + 1
      $prc = ([Math]::Round(($l / $Mylogs.Count) * 100))
      Write-Progress -Activity "Searching for Log Files for CVE-2021-26855..." -Status "$prc% Complete:" -PercentComplete $prc
      $CVE_2021_26855 += Import-Csv -Path $log.FullName | Where-Object { $log.AuthenticatedUser -eq "" -and $log.AnchorMailbox -like 'ServerInfo~*/*' } | Select-Object DateTime, AnchorMailbox

    }
  }
  #Returning Results
  if ($CVE_2021_26855.Count -eq 0) {

    Write-Host "No indicators for CVE-2021-26855 found"
    Add-Content -Path "$logPath" -Value "No indicators for CVE-2021-26855 found"

  }
  else {

    Write-Warning -Message "Indicators for CVE-2021-26855 found!"
    Add-Content -Path "$logPath" -Value "Indicators for CVE-2021-26855 found!"
    $CVE_2021_26855 | ForEach-Object { 

      Add-Content -Path "$logPath" -Value "$_"

    }
  }

}

<#
Test for CVE-2021-26858
For more info see https://msrc.microsoft.com/update-guide/vulnerability/CVE-2021-26858
#>
function Check-CVE_2021_26858 {
  
  [cmdletbinding()]
  Param (
    [Parameter (Mandatory = $True)][string]$logPath
  )
  $CVE_2021_26858 = @()
  #Checking to see if path exist
  if (test-path "$env:ExchangeInstallPath\V15\Logging\OABGeneratorLog\*.log") {
    $l = 0
    $myLogs = Get-ChildItem -Path "$env:ExchangeInstallPath\V15\Logging\OABGeneratorLog\*.log" -ErrorAction SilentlyContinue

    foreach ($log in $Mylogs) {

      $l = $l + 1
      $prc = ([Math]::Round(($l / $Mylogs.Count) * 100))
      Write-Progress -Activity "Searching for Log Files for CVE-2021-26858..." -Status "$prc% Complete:" -PercentComplete $prc
      $CVE_2021_26858 += $log | Select-String  -Pattern 'Download failed and temporary file'
    
    } 
  }
  #Checking to see if path exist
  elseif (test-path "$env:ExchangeInstallPath\Logging\OABGeneratorLog\*.log") {
    $l = 0
    $myLogs = Get-ChildItem -Path "$env:ExchangeInstallPath\Logging\OABGeneratorLog\*.log" -ErrorAction SilentlyContinue

    foreach ($log in $Mylogs) {

      $l = $l + 1
      $prc = ([Math]::Round(($l / $Mylogs.Count) * 100))
      Write-Progress -Activity "Searching for Log Files for CVE-2021-26858..." -Status "$prc% Complete:" -PercentComplete $prc
      $CVE_2021_26858 += $log | Select-String  -Pattern 'Download failed and temporary file'
    
    } 
  }
  #Returning Results
  if ($CVE_2021_26858.Count -eq 0) {

    Write-Host "No indicators for CVE_2021_26858 found"
    Add-Content -Path "$logPath" -Value "No indicators for CVE_2021_26858 found"

  }
  else {

    Write-Warning -Message "Indicators for CVE_2021_26858 found!"
    Add-Content -Path "$logPath" -Value "Indicators for CVE_2021_26858 found!"
    $CVE_2021_26858 | ForEach-Object { 

      Add-Content -Path "$logPath" -Value "$_"

    }
  }



}

<#
Test for CVE-2021-26857
For more info see https://msrc.microsoft.com/update-guide/vulnerability/CVE-2021-26857
#>
function Check-CVE_2021_26857 {

  [cmdletbinding()]
  Param (
    [Parameter (Mandatory = $True)][string]$logPath
  )
  $myLogs = Get-EventLog -LogName Application -Source "MSExchange Unified Messaging" -EntryType Error -ErrorAction Ignore | Where-Object { $_.Message -like "*System.InvalidCastException*" }

  #Returning Results
  if ($myLogs -eq $null) {

    Write-Host "No indicators for CVE-2021-26857 found"
    Add-Content -Path "$logPath" -Value "No indicators for CVE-2021-26857 found"

  }
  else {

    Write-Warning -Message "Indicators for CVE-2021-26857 found!"
    Add-Content -Path "$logPath" -Value "Indicators for CVE-2021-26857 found!"
    Add-Content -Path "$logPath" -Value "$myLogs"

  }
}
<#
Test for CVE-2021-27065
For more info see https://msrc.microsoft.com/update-guide/vulnerability/CVE-2021-27065
#>
function Check-CVE_2021_27065 {
  [cmdletbinding()]
  Param (
    [Parameter (Mandatory = $True)][string]$logPath
  )
  
  $CVE_2021_27065 = @()
  $myLogs = Get-ChildItem -Path "$exECPLogs"
  $l = 0
  #Checking to see if path exist
  if (test-path "$env:ExchangeInstallPath\V15\Logging\ECP\Server\*.log") {
    $l = 0
    $myLogs = Get-ChildItem -Path "$env:ExchangeInstallPath\V15\Logging\ECP\Server\*.log" -ErrorAction SilentlyContinue
    
    foreach ($log in $Mylogs) {

      $l = $l + 1
      $prc = ([Math]::Round(($l / $Mylogs.Count) * 100))
      Write-Progress -Activity "Searching for Log Files for CVE-2021-27065..." -Status "$prc% Complete:" -PercentComplete $prc
      $CVE_2021_27065 += $log | Select-String  -Pattern 'Set-.+VirtualDirectory'
    
    }

  }
  #Checking to see if path exist
  elseif (test-path "$env:ExchangeInstallPath\Logging\ECP\Server\*.log") {
    $l = 0
    $myLogs = Get-ChildItem -Path "$env:ExchangeInstallPath\Logging\ECP\Server\*.log" -ErrorAction SilentlyContinue
      
    foreach ($log in $Mylogs) {
  
      $l = $l + 1
      $prc = ([Math]::Round(($l / $Mylogs.Count) * 100))
      Write-Progress -Activity "Searching for Log Files for CVE-2021-27065..." -Status "$prc% Complete:" -PercentComplete $prc
      $CVE_2021_27065 += $log | Select-String  -Pattern 'Set-.+VirtualDirectory'
      
    }
  
  }
  #Returning Results
  if ($CVE_2021_27065.Count -eq 0) {

    Write-Host "No indicators for CVE-2021-27065 found"
    Add-Content -Path "$logPath" -Value "No indicators for CVE-2021-27065 found"

  }
  else {

    Write-Warning -Message "Indicators for CVE-2021-27065 found!"
    Add-Content -Path "$logPath" -Value "Indicators for CVE-2021-27065 found!"
    $CVE_2021_27065 | ForEach-Object { 

      Add-Content -Path "$logPath" -Value "$_"

    }
  }
}

<#
Checking for matches on web shell IOCs
#>
function Check-Web_Shell {

  [cmdletbinding()]
  Param (
    [Parameter (Mandatory = $True)][string]$logPath
  )
  $shellHits = @()
  #Hash list provide by MS
  $shellHashes = @("b75f163ca9b9240bf4b37ad92bc7556b40a17e27c2b8ed5c8991385fe07d17d0", "097549cf7d0f76f0d99edf8b2d91c60977fd6a96e4b8c3c94b0b1733dc026d3", "2b6f1ebb2208e93ade4a6424555d6a8341fd6d9f60c25e44afe11008f5c1aad1", "65149e036fff06026d80ac9ad4d156332822dc93142cf1a122b1841ec8de34b5", "511df0e2df9bfa5521b588cc4bb5f8c5a321801b803394ebc493db1ef3c78fa1", "4edc7770464a14f54d17f36dc9d0fe854f68b346b27b35a6f5839adf1f13f8ea", "811157f9c7003ba8d17b45eb3cf09bef2cecd2701cedb675274949296a6a183d", "b75f163ca9b9240bf4b37ad92bc7556b40a17e27c2b8ed5c8991385fe07d17d0")
  #Paths web shell may be droped for different versions of Exchange
  $webShellPaths = @("C:\inetpub\wwwroot\aspnet_client\", "C:\inetpub\wwwroot\aspnet_client\system_web\", "$env:ExchangeInstallPath\V15\FrontEnd\HttpProxy\owa\auth\", "$env:ExchangeInstallPath\FrontEnd\HttpProxy\owa\auth\", "C:\Exchange\FrontEnd\HttpProxy\owa\auth\", "$env:ExchangeInstallPath\FrontEnd\HttpProxy\owa\auth\")
  #Really nasty bubble sort
  Foreach ($p in $webShellPaths) {
    if (test-path $p) {
      $myFiles = (Get-ChildItem $Paths -Recurse -Filter "*.aspx" -ErrorAction SilentlyContinue).FullName
      $l = 0
      foreach ($file in $myFiles) {
  
        $l = $l + 1
        $prc = ([Math]::Round(($l / $myFiles.Count) * 100))
        Write-Progress -Activity "Searching for web shells..." -Status "$prc% Complete:" -PercentComplete $prc
        foreach ($hash in $shellHashes) { 

          if ((Get-FileHash $file).Hash -eq "$hash") {
  
            $shellHits += $file
            break
  
          }
        }
        #Checking Content for web shell matches
        $fileContent = Get-Content $file
        #See https://www.volexity.com/blog/2021/03/02/active-exploitation-of-microsoft-exchange-zero-day-vulnerabilities/ 
        if ($fileContent.Contains("<%System.IO.File.WriteAllText(Request.Item[`"p`"],Request.Item[`"c`"]);%>") -or $fileContent.Contains('<% HttpPostedFile thisFile = Request.Files[0];thisFile.SaveAs(Path.Combine') -or ($fileContent.Contains('System.Text.Encoding.Default.GetString(Convert.FromBase64String(StrTr(Request.Headers.Get') -and $fileContent.Contains('System.Net.Sockets')) -or $fileContent.Contains('HttpCookie newcook = new HttpCookie(”fqrspt”') -or $fileContent.Contains('ZN2aDAB4rXsszEvCLrzgcvQ4oi5J1TuiRULlQbYwldE=')) {
        
          $shellHits += $file

        } 
      }
    }
  }
  #Returning Results
  if ($shellHits.Count -eq 0) {

    Write-Host "No web shell IOCs found"
    Add-Content -Path "$logPath" -Value "No web shell IOCs found"

  }
  else {

    Write-Warning -Message "Web shell IOCs found!"
    Add-Content -Path "$logPath" -Value "Web shell IOCs found!"
    $shellHits | ForEach-Object { 

      Add-Content -Path "$logPath" -Value "$_"

    }
  }
}

<##############################
 #
 #              Main
 #
 ##############################>

#Creating Log File
New-Item -Path "$logPath" -ItemType "file"

#CVE-2021-26855 Check
Write-Host "Checking for CVE-2021-26855"
Add-Content -Path "$logPath" -Value "Checking for CVE-2021-26855"
Check-CVE_2021_26855 $logPath
Add-Content -Path "$logPath" -Value ""
Add-Content -Path "$logPath" -Value "________________________"
Add-Content -Path "$logPath" -Value ""

#CVE-2021-26858 Check
Write-Host "Checking for CVE-2021-26858"
Add-Content -Path "$logPath" -Value "Checking for CVE-2021-26858"
Check-CVE_2021_26858 $logPath
Add-Content -Path "$logPath" -Value ""
Add-Content -Path "$logPath" -Value "________________________"
Add-Content -Path "$logPath" -Value ""

#CVE-2021-26857 Check
Write-Host "Checking for CVE-2021-26857"
Add-Content -Path "$logPath" -Value "Checking for CVE-2021-26857"
Check-CVE_2021_26857 $logPath
Add-Content -Path "$logPath" -Value ""
Add-Content -Path "$logPath" -Value "________________________"
Add-Content -Path "$logPath" -Value ""

#CVE-2021-27065 Check
Write-Host "Checking for CVE-2021-27065"
Add-Content -Path "$logPath" -Value "Checking for CVE-2021-27065"
Check-CVE_2021_27065 $logPath
Add-Content -Path "$logPath" -Value ""
Add-Content -Path "$logPath" -Value "________________________"
Add-Content -Path "$logPath" -Value ""

#Web Shell IOC Check
Write-Host "Checking for web shell IOCs"
Add-Content -Path "$logPath" -Value "Checking for web shell IOCs"
Check-Web_Shell $logPath
Add-Content -Path "$logPath" -Value ""
Add-Content -Path "$logPath" -Value "________________________"
Add-Content -Path "$logPath" -Value ""