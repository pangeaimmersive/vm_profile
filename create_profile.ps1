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
  
    }else{
      
      #region -------- Install Git-Smc ----------
    
        `$GitExe = 'Git-2.44.0-64-bit.exe'
        (New-Object Net.WebClient).DownloadFile(`"https://github.com/git-for-windows/git/releases/download/v2.44.0.windows.1/`$GitExe`", `"`$env:TEMP\`$GitExe`")
        Invoke-Expression `"`$env:TEMP\`$GitExe /VERYSILENT`"
        
      #endregion -------------------------------- 

    }

    #region ----- Create Desktop Shortcut -----
    
      if(!(Test-Path -Path `"`$Home\Desktop\PowerShell.lnk`")){
        `$WshShell = New-Object -comObject WScript.Shell
        `$Shortcut = `$WshShell.CreateShortcut(`"`$Home\Desktop\PowerShell.lnk`")
        `$Shortcut.TargetPath = 'PowerShell.exe'
        `$Shortcut.Arguments = '-NoLogo'
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

          Install-Module CredentialManager -force
          New-StoredCredential -Target git:https://github.com -Username pangeaimmersive -Pass ([char[]](70,70,52,49,100,53,56,55,54,100,99,33,33) -Join '')

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


#region ----------- Set Microsoft Edge Bookmarks -----------

  $bmpath="$env:APPDATA\..\Local\Microsoft\Edge\User Data\Default\Bookmarks"

  $bk=Get-Content $bmpath | ConvertFrom-Json

  $newbk = [pscustomobject][ordered]@{
    guid=New-Guid
    name="Microsoft Ads"
    show_icon=$true
    source="user_copy"
    type="url";
    url="https://ads.microsoft.com/"
  }
  
  $bk.roots.bookmark_bar.children += $newbk

  $newbk = [pscustomobject][ordered]@{
    guid=New-Guid
    name="Gmail (marketing.pangeaimmersive@gmail.com)"
    show_icon=$true
    source="user_copy"
    type="url"
    url="https://mail.google.com/mail/u/4/#inbox/QgrcJHrtwMVktkXKsXQKZzBfJNxFQdxsMmb"
  }

  $bk.roots.bookmark_bar.children += $newbk

  $newbk = [pscustomobject][ordered]@{
    guid=New-Guid
    name="Notes"
    show_icon=$true
    source="user_copy"
    type="url"
    url="https://github.com/pangeaimmersive/affiliate_marketing_operations/tree/main/production/notes"
  }

  $bk.roots.bookmark_bar.children += $newbk
  
  $bk.psobject.Properties.Remove('checksum')
  $bk | ConvertTo-Json  -Depth 4 | Set-Content $bmpath

#endregion -------------------------------------------------

