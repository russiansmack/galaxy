#Predefined Vars
$autoLoginUser = "Administrator" #Username to be used in autologin (AWS uses Administrator)
$path = "C:\ParsecTemp" #Path for installer
$parsecName = '';

#enable auto login
function windows-auto-login { 
    (New-Object System.Net.WebClient).DownloadFile("https://download.sysinternals.com/files/AutoLogon.zip", "$path\Autologon.zip") | Unblock-File
    Expand-Archive "$path\Autologon.zip" -DestinationPath "$path" -Force
    
    $token = Invoke-RestMethod -Headers @{"X-aws-ec2-metadata-token-ttl-seconds" = "21600"} -Method PUT -Uri http://169.254.169.254/latest/api/token
    $instanceId = Invoke-RestMethod -Headers @{"X-aws-ec2-metadata-token" = $token} -Method GET -Uri http://169.254.169.254/latest/meta-data/instance-id
    Read-S3Object -BucketName demo-parsec -Key herpderp.pem -File $path\herpderp.pem
    $winPass = Get-EC2PasswordData -InstanceId $instanceId -PemFile $path\herpderp.pem
    $autoLoginP = Start-Process "$path\Autologon.exe" -ArgumentList "/accepteula", $autoLoginUser, $env:Computername, $winPass -PassThru -Wait
    If ($autoLoginP.ExitCode -eq 0) {
        Write-Host "Windows AutoLogin Enabled" -ForegroundColor green 
    } Else {
        Write-Host "Windows AutoLogin ERROR" -ForegroundColor red 
    }
}

#let's get our parsec session id
#make sessions persist etc on the backend
function __parsec-get-session-id {
    $parsecSessionId = '';

    $apiKey = "BkeFd7ROYH5rh5hmtnoXp2BFuPgG6Z7sa6G2JadX"
    $resource = "https://0pzg655b2l.execute-api.us-west-2.amazonaws.com/default/parsecLogin"

    $retries = 0
    while (($parsecSessionId -eq '') -and ($retries -lt 5)) {
        Start-Sleep -s (10*$retries)
        $parsecSessionId = Invoke-RestMethod -Method Get -Uri $resource -Headers @{ "x-api-key" = $apiKey } 
        Write-Host "Getting Parsec Key - Retry: $retries"
        $retries++
    }

    if($parsecSessionId -eq '')
    {
        Write-Host "NO PARSEC SESSION KEY"
        return false;
    }
    else {
        Write-Host "Parsec Key recieved"
        return $parsecSessionId
    }
}

function parsec-save-session-id {
    $parsecSessionId = __parsec-get-session-id
    Write-Output $parsecSessionId | Out-File -FilePath $path\parsec-session-id.txt -Encoding ascii
}

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

Write-Host -foregroundcolor red "
THIS IS GALAXY.
We are installing all the needed essentials to make this machine stream games
"

#We are assuming that create-directories was run in setup.ps1
#windows-auto-login
#parsec-save-session-id
#download-mini-parsec
#extract-mini-parsec
setup-mini-parsec