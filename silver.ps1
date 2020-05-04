#Predefined Vars
$autoLoginUser = "Administrator" #Username to be used in autologin (AWS uses Administrator)

#Common Utility Module START
function New-TemporaryDirectory {
    $parent = [System.IO.Path]::GetTempPath()
    [string] $name = [System.Guid]::NewGuid()
    $tempPath = Join-Path $parent $name
    Write-Verbose "New Temp Folder: $tempPath"
    New-Item -ItemType Directory -Path $tempPath
}

#Cleanup
function Remove-TemporaryDirectory {

    While ( Test-Path($path) ){
        Try{
            Remove-Item -Path $path -Force -Recurse -ErrorAction Stop
        }catch{
            Write-Warning "Clean up: File locked, trying again in 5"
            Start-Sleep -seconds 5
        }
    }
    Write-Host "The royal penis is clean, your highness!"
}

function __Test-RegistryValue {
    # https://www.jonathanmedd.net/2014/02/testing-for-the-presence-of-a-registry-key-and-value.html
    #This specifies parameters for this function
    param ([parameter(Mandatory=$true)][ValidateNotNullOrEmpty()]$Path, [parameter(Mandatory=$true)][ValidateNotNullOrEmpty()]$Value)
    
    try {
        Get-ItemProperty -Path $Path | Select-Object -ExpandProperty $Value -ErrorAction Stop | Out-Null
        return $true
    }
    catch {
        return $false
    }
}
#Common Utility Module END

#enable auto login
function Enable-WindowsAutoLogin { 
    (New-Object System.Net.WebClient).DownloadFile("https://download.sysinternals.com/files/AutoLogon.zip", "$path\Autologon.zip") | Unblock-File
    Expand-Archive "$path\Autologon.zip" -DestinationPath "$path" -Force
    
    $token = Invoke-RestMethod -Headers @{"X-aws-ec2-metadata-token-ttl-seconds" = "21600"} -Method PUT -Uri http://169.254.169.254/latest/api/token
    $instanceId = Invoke-RestMethod -Headers @{"X-aws-ec2-metadata-token" = $token} -Method GET -Uri http://169.254.169.254/latest/meta-data/instance-id
    Read-S3Object -BucketName demo-parsec -Key herpderp.pem -File $path\herpderp.pem
    $winPass = Get-EC2PasswordData -InstanceId $instanceId -PemFile $path\herpderp.pem
    $autoLoginP = Start-Process "$path\Autologon.exe" -ArgumentList "/accepteula", $autoLoginUser, $env:Computername, $winPass -PassThru -Wait
    If ($autoLoginP.ExitCode -eq 0) {
        Write-Host "Windows AutoLogin Enabled"
    } Else {
        Write-Error "Enable-WindowsAutoLogin FAILED"
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
function __Download-ParsecLoginFile {
    $parsecSessionId = '';

    $apiKey = "BkeFd7ROYH5rh5hmtnoXp2BFuPgG6Z7sa6G2JadX"
    $resource = "https://0pzg655b2l.execute-api.us-west-2.amazonaws.com/default/parsecLogin"

    $retries = 0
    while (($parsecSessionId -eq '') -and ($retries -lt 5)) {
        Start-Sleep -s (10*$retries) #anti-spam
        Write-Verbose "Getting Parsec Key - Retry: $retries"

        try{
            $headers =  @{ 
                "x-api-key" = $apiKey 
                "winguid" = __Get-MachineGUID
            }
            $parsecSessionId = Invoke-RestMethod -Method Get -Uri $resource -Headers $headers    
        } catch {
            Write-Verbose "Unable to get Parsec Key - Retry: $retries"
        }

        $retries++
    }

    if($parsecSessionId -eq '')
    {
        Write-Error "No Parsec Login File"
        return false;
    }
    else {
        Write-Host "Parsec Key recieved"
        return $parsecSessionId
    }
}

function Install-ParsecLoginFile {
    try {
        (__Download-ParsecLoginFile) | Out-File -FilePath "C:\Users\$autoLoginUser\AppData\Roaming\Parsec\user.bin" -Encoding ascii
        Write-Host "Parsec Login File Installed"
    }
    catch {
        Write-Error "Install-ParsecLoginFile FAILED"
    }
}

#TODO: Add uniq hostname IDs etc here..?
function Install-ParsecSettings {
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

    #SHERVIN SETTINGS AKA 25mbps
    <#
    app_host=1
    app_run_level = 3
    encoder_h265 = 1
    encoder_min_bitrate = 15
    encoder_bitrate = 25
    server_resolution_x=1920
    server_resolution_x=1080
    server_refresh_rate=60
    #>

    $parsecOptions = @"
app_host=1
app_run_level = 3
encoder_h265 = 1
encoder_min_bitrate = 15
encoder_bitrate = 25
server_resolution_x=1920
server_resolution_x=1080
server_refresh_rate=60
"@
    try{
        Write-Output $parsecOptions | Out-File -FilePath "C:\Users\Administrator\AppData\Roaming\Parsec\config.txt" -Encoding ascii
        Write-Host "Parsec Settings Installed"
    }
    catch {
        Write-Error "Install-ParsecSettings FAILED"
    }
}

Clear-Host

Write-Host -foregroundcolor red "
THIS IS GALAXY.
We are installing all the needed essentials to make this machine stream games
"

##Create Temp Folder
$path = New-TemporaryDirectory

Enable-WindowsAutoLogin
Install-ParsecLoginFile
Install-ParsecSettings

#Clean Up
Remove-TemporaryDirectory

#This is unfortunately required as autologin initializes only on reboot
#In future there will be a separate autologin account and this won't be required
Restart-Computer