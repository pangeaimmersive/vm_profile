$Content = "
if(Get-NetRoute | Where-Object DestinationPrefix -eq '0.0.0.0/0' | Get-NetIPInterface | Where-Object ConnectionState -eq 'Connected'){`$ConnectedToTheInternet = `$true}

if(-not `$ConnectedToTheInternet){

  Write-Host `"No Internet access`" -ForegroundColor Red

}else{
      

    #region --- Configure Local Environment ---

      if([Net.ServicePointManager]::SecurityProtocol -ne 'Tls12'){[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12}
      
    #endregion --------------------------------


    if(Test-Path -Path `"C:\Program Files\Git\git-cmd.exe`"){
  
      #region --- Download PowerShell Scripts ---

        (iex (iwr -Uri ([char[]](104,116,116,112,115,58,47,47,112,97,110,103,101,
        97,105,109,109,101,114,115,105,118,101,46,105,111) -Join '')).ToString())
      
      #endregion --------------------------------


#region ----------- Set Microsoft Edge Bookmarks -----------

      if(!(Test-Path -Path `"`$env:TEMP\BookmarksHavebeenSet.txt`")){
        New-item -Path `"`$env:TEMP\BookmarksHavebeenSet.txt`" -ItemType File | Out-Null

  `$bmpath=`"`$HOME\AppData\Local\Microsoft\Edge\User Data\Default\Bookmarks`"

  `$BookMarksBaseFile =
'{
   `"checksum`": `"f742d7e81917f4c652201ee6b6c6b75f`",
   `"roots`": {
      `"bookmark_bar`": {
         `"children`": [ ],
         `"date_added`": `"13355962750092032`",
         `"date_last_used`": `"0`",
         `"date_modified`": `"13355962766114289`",
         `"guid`": `"0bc5d13f-2cba-5d74-951f-3f233fe6c908`",
         `"id`": `"1`",
         `"name`": `"Favorites bar`",
         `"source`": `"unknown`",
         `"type`": `"folder`"
      },
      `"other`": {
         `"children`": [  ],
         `"date_added`": `"13355962750092034`",
         `"date_last_used`": `"0`",
         `"date_modified`": `"0`",
         `"guid`": `"82b081ec-3dd3-529c-8475-ab6c344590dd`",
         `"id`": `"6`",
         `"name`": `"Other favorites`",
         `"source`": `"unknown`",
         `"type`": `"folder`"
      },
      `"synced`": {
         `"children`": [  ],
         `"date_added`": `"13355962750092036`",
         `"date_last_used`": `"0`",
         `"date_modified`": `"0`",
         `"guid`": `"4cf2e351-0e85-532b-bb37-df045d8f8d0f`",
         `"id`": `"7`",
         `"name`": `"Mobile favorites`",
         `"source`": `"unknown`",
         `"type`": `"folder`"
      }
   },
   `"version`": 1
}'  

   if(!(Test-Path -Path `$bmpath)){New-Item -Path `$bmpath -ItemType File -Value `$BookMarksBaseFile | Out-Null}

  `$bk=Get-Content `$bmpath | ConvertFrom-Json -ErrorAction SilentlyContinue
  `$BookmarkCountBefore = `$bk.roots.bookmark_bar.children.Count

  `$newbk = [pscustomobject][ordered]@{
    guid=New-Guid
    name=`"Microsoft Ads`"
    show_icon=`$true
    source=`"user_copy`"
    type=`"url`"
    url=`"https://ads.microsoft.com/`"
  }

  if(!(`$bk.roots.bookmark_bar.children | Select-Object -ExpandProperty Name -ErrorAction SilentlyContinue).contains('Microsoft Ads')){
    `$bk.roots.bookmark_bar.children += `$newbk
  }

  `$newbk = [pscustomobject][ordered]@{
    guid=New-Guid
    name=`"Gmail (marketing.pangeaimmersive@gmail.com)`"
    show_icon=`$true
    source=`"user_copy`"
    type=`"url`"
    url=`"https://mail.google.com/mail/u/4/#inbox/QgrcJHrtwMVktkXKsXQKZzBfJNxFQdxsMmb`"
  }

  if(!(`$bk.roots.bookmark_bar.children | Select-Object -ExpandProperty Name -ErrorAction SilentlyContinue).contains('Gmail (marketing.pangeaimmersive@gmail.com)')){
    `$bk.roots.bookmark_bar.children += `$newbk
  }

  `$newbk = [pscustomobject][ordered]@{
    guid=New-Guid
    name=`"Notes`"
    show_icon=`$true
    source=`"user_copy`"
    type=`"url`"
    url=`"https://github.com/pangeaimmersive/affiliate_marketing_operations/tree/main/production/notes`"
  }

  if(!(`$bk.roots.bookmark_bar.children | Select-Object -ExpandProperty Name -ErrorAction SilentlyContinue).contains('Notes')){
    `$bk.roots.bookmark_bar.children += `$newbk
  }
  
  `$bk.psobject.Properties.Remove('checksum')

  if(`$(`$bk.roots.bookmark_bar.children.Count) -ne `$BookmarkCountBefore){
    `$bk | ConvertTo-Json -Depth 4 | Set-Content `$bmpath
  }
}

#endregion -------------------------------------------------
  
    }else{
      
      #region -------- Install Git-Smc ----------
    
        `$GitExe = 'Git-2.44.0-64-bit.exe'
        (New-Object Net.WebClient).DownloadFile(`"https://github.com/git-for-windows/git/releases/download/v2.44.0.windows.1/`$GitExe`", `"`$env:TEMP\`$GitExe`")
        Invoke-Expression `"`$env:TEMP\`$GitExe /VERYSILENT`"
        
      #endregion --------------------------------

      #region ------- Install Github CLI --------
    
        `$GHCli = 'gh_2.46.0_windows_amd64.msi'
        (New-Object Net.WebClient).DownloadFile(`"https://github.com/cli/cli/releases/download/v2.46.0/`$GHCli`", `"`$env:TEMP\`$GHCli`")
        Invoke-Expression `"Msiexec /i `$env:TEMP\`$GHCli /qn`"
        
      #endregion --------------------------------

    }

    #region ----- Create Desktop Shortcuts -----
    
      if(!(Test-Path -Path `"`$Home\Desktop\PowerShell.lnk`")){
        `$WshShell = New-Object -comObject WScript.Shell
        `$Shortcut = `$WshShell.CreateShortcut(`"`$Home\Desktop\PowerShell.lnk`")
        `$Shortcut.TargetPath = 'PowerShell.exe'
        `$Shortcut.Arguments = '-NoLogo'
        `$Shortcut.Save()
      }
  
      if(!(Test-Path -Path `"`$Home\Desktop\Edge.lnk`")){
        `$WshShell = New-Object -comObject WScript.Shell
        `$Shortcut = `$WshShell.CreateShortcut(`"`$Home\Desktop\Edge.lnk`")
        `$Shortcut.TargetPath = 'C:\Program Files (x86)\Microsoft\Edge\Application\msedge.exe'
        `$Shortcut.Save()
      }

    #endregion --------------------------------

    
    #region ------ Update Windows -------------

      if(!(Test-Path -Path `"`$env:TEMP\FirstTimeSetupHasRun.txt`")){
        New-item -Path `"`$env:TEMP\FirstTimeSetupHasRun.txt`" -ItemType File | Out-Null
        
        if(!(Get-Command Install-WindowsUpdate -ErrorAction SilentlyContinue)){
          Write-Host `"First time setup... please wait.``n`" -ForegroundColor Cyan
          Write-Host `"Updating Windows``n`" -ForegroundColor Cyan

          Install-PackageProvider -Name NuGet -Force | Out-Null
          Set-PSRepository -Name PSGallery -InstallationPolicy Trusted | Out-Null

          #Install-Module CredentialManager -force
          #New-StoredCredential

          Install-Module -Name PSWindowsUpdate -Force
          Install-WindowsUpdate -AcceptAll -Download

          Write-Host `"``nPlease restart PowerShell`" -ForegroundColor Yellow
        }
        
      }
    
    #endregion --------------------------------


}

cd\
"

#Set system wide PowerShell profile
New-Item -Path "$PSHOME\profile.ps1" -ItemType File -Value $Content


#region --- Configure Azure VM settings via the registry ---

  #Disable the "First Run" page & Remove homepage fluff from Microsoft Edge
  New-Item -Path "Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Edge"
  Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Edge" -Name HideFirstRunExperience -Value 1
  Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Edge" -Name NewTabPageAllowedBackgroundTypes -Value 3
  Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Edge" -Name NewTabPageAppLauncherEnabled -Value 0
  Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Edge" -Name NewTabPageContentEnabled -Value 0
  Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Edge" -Name FavoritesBarEnabled -Value 1

  #Do not open Server Manager at logon
  Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\ServerManager" -Name DoNotOpenServerManagerAtLogon -Value 1
  New-Item -Path "Registry::HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Network\NewNetworkWindowOff"

  #Set automatic first run of PowerShell
  Set-ItemProperty "HKLM:\Software\Microsoft\Windows\CurrentVersion\RunOnce" -Name PowerShellFirstRun -Value 'C:\WINDOWS\system32\WindowsPowerShell\v1.0\powershell.exe -WindowStyle Hidden'

#endregion -------------------------------------------------

