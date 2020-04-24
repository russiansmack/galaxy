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

function __Get-MachineGUID {
    try {
        (Get-ItemProperty registry::HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Cryptography\ -Name MachineGuid).MachineGUID
    }
    catch{
            Write-Warning "Failed to get Machine GUID from HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Cryptography\"
    }
}

#let's get our parsec magical login file
function __parsec-download-login-file {
    $parsecSessionId = '';

    $apiKey = "BkeFd7ROYH5rh5hmtnoXp2BFuPgG6Z7sa6G2JadX"
    $resource = "https://0pzg655b2l.execute-api.us-west-2.amazonaws.com/default/parsecLogin"

    $retries = 0
    while (($parsecSessionId -eq '') -and ($retries -lt 5)) {
        Start-Sleep -s (10*$retries)
        $headers =  @{ 
            "x-api-key" = $apiKey 
            "winguid" = __Get-MachineGUID
        }
        $parsecSessionId = Invoke-RestMethod -Method Get -Uri $resource -Headers $headers
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

#TOFIX: This has a lot of variables in path that might change - not good
function parsec-save-login-file {
    $parsecSessionId = __parsec-download-login-file
    Write-Output $parsecSessionId | Out-File -FilePath "C:\Users\Administrator\AppData\Roaming\Parsec\user.bin" -Encoding ascii
}

#TODO: Add uniq hostname IDs etc here..?
function parsec-save-settings {
    #SERGEY SETTINGS - AKA 50mbps :)
    <# 
    app_host=1
    app_run_level = 3
    encoder_h265 = 1
    encoder_min_bitrate = 50
    encoder_bitrate = 50
    server_resolution_x=2560
    server_resolution_x=1440
    server_refresh_rate=60
    #>

    $parsecOptions = @"
app_host=1
app_run_level = 3
encoder_h265 = 1
encoder_min_bitrate = 50
encoder_bitrate = 50
"@
    Write-Output $parsecOptions | Out-File -FilePath "C:\Users\Administrator\AppData\Roaming\Parsec\config.txt" -Encoding ascii
}

Write-Host -foregroundcolor red "
THIS IS GALAXY.
We are installing all the needed essentials to make this machine stream games
"

#We are assuming that create-directories was run in setup.ps1
windows-auto-login
parsec-save-login-file
parsec-save-settings

##TOFIX: DELETE THIS install-choco ONCE YOU CREATE A NEW GOLD IMAGE
function install-choco {
    Set-ExecutionPolicy Bypass -Scope Process -Force; [System.Net.ServicePointManager]::SecurityProtocol = [System.Net.ServicePointManager]::SecurityProtocol -bor 3072; iex ((New-Object System.Net.WebClient).DownloadString('https://chocolatey.org/install.ps1'))
    choco feature enable -n allowGlobalConfirmation
}
install-choco

###Launcher Installs###

function Install-Battlenet {
    (New-Object System.Net.WebClient).DownloadFile("https://www.battle.net/download/getInstallerForGame?os=win&locale=enUS&version=LIVE&gameProgram=BATTLENET_APP", "$path\Battle-net.exe") | Unblock-File
    Start-Process "$path\Battle-net.exe" -ArgumentList "--installpath=C:/Battle.net --locale=enUS"
}

function Install-Origin {
    choco install origin
}

function Install-Epicgames {
    choco install epicgameslauncher
}

Install-Battlenet
Install-Origin
Install-Epicgames

#This is unfortunately required as autologin initializes only on reboot
#In future there will be a separate autologin account and this won't be required

Restart-Computer