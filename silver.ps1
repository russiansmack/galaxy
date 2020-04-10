#Predefined Vars
$autoLoginUser = "Administrator" #Username to be used in autologin (AWS uses Administrator)
$path = "C:\ParsecTemp" #Path for installer

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

function parsec-auto-login {
    
}

Write-Host -foregroundcolor red "
THIS IS GALAXY.
We are installing all the needed essentials to make this machine stream games
"

#We are assuming that create-directories was run in setup.ps1
windows-auto-login
parsec-auto-login