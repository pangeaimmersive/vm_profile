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

      if(!(Test-Path -Path `"`$env:TEMP\SetBookmarksHasRun.txt`")){
        New-item -Path `"`$env:TEMP\SetBookmarksHasRun.txt`" -ItemType File | Out-Null
        
        #Set Microsoft Edge Bookmarks
        $Bookmarks =
        '{
           "checksum": "8f869805b41521ce1d85096ea48498ec",
           "roots": {
              "bookmark_bar": {
                 "children": [ {
                    "date_added": "13355882491996907",
                    "date_last_used": "0",
                    "guid": "b57df2a8-aa82-45a4-93db-d3b9680197ce",
                    "id": "7",
                    "meta_info": {
                       "power_bookmark_meta": ""
                    },
                    "name": "Microsoft Ads",
                    "show_icon": false,
                    "source": "unknown",
                    "type": "url",
                    "url": "https://ads.microsoft.com/"
                 }, {
                    "date_added": "13355883173243545",
                    "date_last_used": "0",
                    "guid": "b1e590bb-73a0-4c00-9b31-c17fbc11a8b0",
                    "id": "8",
                    "meta_info": {
                       "power_bookmark_meta": ""
                    },
                    "name": "Gmail (marketing.pangeaimmersive@gmail.com)",
                    "show_icon": false,
                    "source": "unknown",
                    "type": "url",
                    "url": "https://mail.google.com/mail/u/4/#inbox/QgrcJHrtwMVktkXKsXQKZzBfJNxFQdxsMmb"
                 }, {
                    "date_added": "13355883372076036",
                    "date_last_used": "0",
                    "guid": "db61dac0-d29e-4a4f-afaa-93f47aecc7eb",
                    "id": "11",
                    "meta_info": {
                       "power_bookmark_meta": ""
                    },
                    "name": "Notes",
                    "show_icon": false,
                    "source": "unknown",
                    "type": "url",
                    "url": "https://github.com/pangeaimmersive/affiliate_marketing_operations/tree/main/production/notes"
                 } ],
                 "date_added": "13355882457184478",
                 "date_last_used": "0",
                 "date_modified": "13355883372076036",
                 "guid": "0bc5d13f-2cba-5d74-951f-3f233fe6c908",
                 "id": "1",
                 "name": "Favorites bar",
                 "source": "unknown",
                 "type": "folder"
              },
              "other": {
                 "children": [  ],
                 "date_added": "13355882457184480",
                 "date_last_used": "0",
                 "date_modified": "0",
                 "guid": "82b081ec-3dd3-529c-8475-ab6c344590dd",
                 "id": "2",
                 "name": "Other favorites",
                 "source": "unknown",
                 "type": "folder"
              },
              "synced": {
                 "children": [  ],
                 "date_added": "13355882457184482",
                 "date_last_used": "0",
                 "date_modified": "0",
                 "guid": "4cf2e351-0e85-532b-bb37-df045d8f8d0f",
                 "id": "3",
                 "name": "Mobile favorites",
                 "source": "unknown",
                 "type": "folder"
              }
           },
           "version": 1
        }'

        New-Item -Path `"$HOME\AppData\Local\Microsoft\Edge\User Data\Default\Bookmarks`" -ItemType File -Value `$Bookmarks -Force | Out-Null
      
      }
  
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

