#Predefined Vars
$autoLoginUser = "Administrator" #Username to be used in autologin (AWS uses Administrator)
$path = "C:\ParsecTemp" #Path for installer
$parsecName = '';


#get our parsec version from s3
function download-mini-parsec {
    Read-S3Object -BucketName demo-parsec -Key miniParsec.zip -File $path\miniParsec.zip
}

function extract-mini-parsec {
    Expand-Archive -Path $path\miniParsec.zip -DestinationPath $path
}

Function create-mini-parsec-service {
    #Creates Mini Parsec Service
    Write-host "Creating Mini Parsec Service"
    & sc.exe Create "Mini Parsec" binPath= "$path\miniParsec.exe (gc $path\parsec-session-id.txt)" start= "auto" | Out-Null
    sc.exe Start 'Mini Parsec' | Out-Null
}

function setup-mini-parsec {
    New-ItemProperty -path HKCU:\Software\Microsoft\Windows\CurrentVersion\Run -Name "Mini Parsec" -Value "$path\miniParsec.exe (gc $path\parsec-session-id.txt | Out-String)" | Out-Null
    $parsecSessionId = (gc $path\parsec-session-id.txt | Out-String);
    Start-Process -FilePath "$path\miniParsec.exe" -ArgumentList "$parsecSessionId"
}

Function unblock-parsec {
    #Creates Parsec Firewall Rule in Windows Firewall
    Write-host "Creating Parsec Firewall Rule"
    New-NetFirewallRule -DisplayName "Parsec" -Direction Inbound -Program "$path\miniParsec.exe" -Profile Private,Public -Action Allow -Enabled True | Out-Null
}


#download-mini-parsec
#extract-mini-parsec
#setup-mini-parsec