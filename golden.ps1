#Useful commands go here
# & "C:\Program Files\NVIDIA Corporation\NVSMI\nvidia-smi.exe" -q #query nvidia driver

#Predefined Vars
$autoLoginUser = "Administrator" #Username to be used in autologin (AWS uses Administrator)
$path = "C:\ParsecTemp" #Path for installer

####GOLDEN IMAGE SETUP START

function Install-SSM {
    Write-Host "Installing AWS SSM"
    (New-Object System.Net.WebClient).DownloadFile("https://s3.amazonaws.com/ec2-downloads-windows/SSMAgent/latest/windows_amd64/AmazonSSMAgentSetup.exe", "$path\SSMAgent_latest.exe") | Unblock-File
    Start-Process -FilePath "$path\SSMAgent_latest.exe" -ArgumentList "/S"
}

function Install-Chocolatey {
    Set-ExecutionPolicy Bypass -Scope Process -Force; [System.Net.ServicePointManager]::SecurityProtocol = [System.Net.ServicePointManager]::SecurityProtocol -bor 3072; iex ((New-Object System.Net.WebClient).DownloadString('https://chocolatey.org/install.ps1'))
    choco feature enable -n allowGlobalConfirmation
}

# Reference: https://docs.aws.amazon.com/AWSEC2/latest/WindowsGuide/install-nvidia-driver.html#nvidia-gaming-driver
# Notes: Required s3.getobject, s3.list-objects api calls
function download-nvidia {
    $Bucket = "nvidia-gaming"
    $KeyPrefix = "windows/latest"
    $LocalPath = "$path\NVIDIA"

    #Download drivers & Extract archives
    $Objects = Get-S3Object -BucketName $Bucket -KeyPrefix $KeyPrefix -Region us-east-1
    foreach ($Object in $Objects) {
        $LocalFileName = $Object.Key
        if ($LocalFileName -ne '' -and $Object.Size -ne 0) {
            $LocalFilePath = Join-Path $LocalPath $LocalFileName
            Copy-S3Object -BucketName $Bucket -Key $Object.Key -LocalFile $LocalFilePath -Region us-east-1

            $LocalFileDir = Join-Path $LocalPath $KeyPrefix
            Expand-Archive -Path $LocalFilePath -DestinationPath $LocalFileDir
        }
    }
}

function download-nvidia-grid {
    $Bucket = "ec2-windows-nvidia-drivers"
    $KeyPrefix = "g4/latest"
    $LocalPath = "$path\NVIDIA"

    #Download drivers & Extract archives
    $Objects = Get-S3Object -BucketName $Bucket -KeyPrefix $KeyPrefix -Region us-east-1
    foreach ($Object in $Objects) {
        $LocalFileName = $Object.Key
        if ($LocalFileName -ne '' -and $Object.Size -ne 0) {
            $LocalFilePath = Join-Path $LocalPath $LocalFileName
            Copy-S3Object -BucketName $Bucket -Key $Object.Key -LocalFile $LocalFilePath -Region us-east-1

            $LocalFileDir = Join-Path $LocalPath $KeyPrefix
            Expand-Archive -Path $LocalFilePath -DestinationPath $LocalFileDir
        }
    }
}

function download-old-nvidia {
    $Bucket = "nvidia-gaming"
    $KeyPrefix = "windows/latest"
    $LocalPath = "$path\NVIDIA"

    #Download drivers & Extract archives

        $LocalFileName = "windows/GRID-436.30-Feb2020-vGaming-Windows-Guest-Drivers.zip"
        $LocalFilePath = Join-Path $LocalPath $LocalFileName
        Copy-S3Object -BucketName $Bucket -Key $LocalFileName -LocalFile $LocalFilePath -Region us-east-1

        $LocalFileDir = Join-Path $LocalPath $KeyPrefix
        Expand-Archive -Path $LocalFilePath -DestinationPath $LocalFileDir
}

function install-nvidia {
    $KeyPrefix = "windows/latest"
    $LocalPath = "$path\NVIDIA"

    # Install Drivers
    $ArchiveFileDir = Join-Path $LocalPath $KeyPrefix
    $Installer = Get-ChildItem -Path $ArchiveFileDir\* -Include *win10*.exe

    Write-Host "Installing NVIDIA Drivers" -NoNewline
    Start-Process -FilePath $Installer -ArgumentList '/s' -wait

    # TODO bug with existing key error
    New-ItemProperty -Path "HKLM:\SOFTWARE\NVIDIA Corporation\Global" -Name "vGamingMarketplace" -Value "2" -PropertyType DWord

    # Download & Install Certification File
    $CertFileURL = "https://s3.amazonaws.com/nvidia-gaming/GridSwCert-Windows.cert"
    $CertFilePath = "$path\GridSwCert.txt"
    $CertFileInstallPath = "C:\Users\Public\Documents"

    Write-Host "Downloading CertFile" -NoNewline
    (New-Object System.Net.WebClient).DownloadFile($CertFileURL, $CertFilePath) | Unblock-File

    Copy-Item -Path $CertFilePath -Destination $CertFileInstallPath

    # Activate & Validate NVIDIA Gaming License
    $NvidiaAppPath = "C:\Program Files\NVIDIA Corporation\NVSMI\nvidia-smi.exe"
    $NvsmiLogFilePath = "$path\nvsmi.log"

    # TODO upload this file to something to validate and test build
    & $NvidiaAppPath -q | Out-File -FilePath $NvsmiLogFilePath

    # TODO bug with existing key error
    #New-ItemProperty -Path "HKLM:\SOFTWARE\NVIDIA Corporation\Global\GridLicensing" -Name "FeatureType" -Value "0" -PropertyType DWord
    #New-ItemProperty -Path "HKLM:\SOFTWARE\NVIDIA Corporation\Global\GridLicensing" -Name "IgnoreSP" -Value "1" -PropertyType DWord

    # Optimizing GPU
    Write-Host "Optimizing GPU"

    # Disable autoboost
    & $NvidiaAppPath --auto-boost-default=0 | Out-File -FilePath $NvsmiLogFilePath -Append

    # Set GPU to max freq on G4 instances
    # TODO optimize for each GPU
    & $NvidiaAppPath -ac "5001,1590" | Out-File -FilePath $NvsmiLogFilePath -Append
}

function take-my-money {
    Write-Host "Downloading NVIDIA TAKE MY MONEY DEMO"
    (New-Object System.Net.WebClient).DownloadFile("https://us.download.nvidia.com/downloads/cool_stuff/demos/SetupFaceWorks.exe", "$path\Apps\SetupFaceWorks.exe") | Unblock-File
    Start-Process -FilePath "$path\Apps\SetupFaceWorks.exe" -ArgumentList "/S" -wait
}


####GOLDEN IMAGE SETUP END

#Create ParsecTemp folder in C Drive
function create-directories {
    Write-Output "Creating Directories in $path"
    if((Test-Path -Path $path )-eq $true){} Else {New-Item -Path $path -ItemType directory | Out-Null}
    if((Test-Path -Path $path\Apps) -eq $true) {} Else {New-Item -Path $path\Apps -ItemType directory | Out-Null}
    if((Test-Path -Path $path\DirectX) -eq $true) {} Else {New-Item -Path $path\DirectX -ItemType directory | Out-Null}
    if((Test-Path -Path $path\Drivers) -eq $true) {} Else {New-Item -Path $path\Drivers -ItemType Directory | Out-Null}
    if((Test-Path -Path $path\Devcon) -eq $true) {} Else {New-Item -Path $path\Devcon -ItemType Directory | Out-Null}

    #Unblock all the things
    Unblock-File -Path $path\*
    Get-ChildItem -Path $path -Recurse | Unblock-File
}

#download-files-S3
function download-resources {
    Write-Host "Installing Devcon"
    cinst devcon.portable
    Write-Host "Downloading Parsec"
    (New-Object System.Net.WebClient).DownloadFile("https://builds.parsecgaming.com/package/parsec-windows.exe", "$path\parsec-windows.exe") | Unblock-File
    Write-Host "Installing Chrome"
    cinst googlechrome -ignore-checksums
}

function Install-7zip {
    #7Zip is required to extract the installers
    Write-Host "Downloading and Installing 7Zip"
    cinst 7zip
}

#install-base-files-silently
function install-windows-features {
    Write-Output "Installing .Net 3.5, Direct Play and DirectX Redist 2010"
    cinst directx
    Install-WindowsFeature Direct-Play | Out-Null
    Install-WindowsFeature Net-Framework-Core | Out-Null
}

function Test-RegistryValue {
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

#set update policy
function Disable-Updates {
    Write-Output "Disabling Windows Update"
    if((Test-RegistryValue -path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate' -value 'DoNotConnectToWindowsUpdateInternetLocations') -eq $true) {Set-itemproperty -path HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate -Name "DoNotConnectToWindowsUpdateInternetLocations" -Value "1" | Out-Null} else {new-itemproperty -path HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate -Name "DoNotConnectToWindowsUpdateInternetLocations" -Value "1" | Out-Null}
    if((Test-RegistryValue -path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate' -value 'UpdateServiceURLAlternative') -eq $true) {Set-itemproperty -path HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate -Name "UpdateServiceURLAlternative" -Value "http://intentionally.disabled" | Out-Null} else {new-itemproperty -path HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate -Name "UpdateServiceURLAlternative" -Value "http://intentionally.disabled" | Out-Null}
    if((Test-RegistryValue -path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate' -value 'WUServer') -eq $true) {Set-itemproperty -path HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate -Name "WUServer" -Value "http://intentionally.disabled" | Out-Null} else {new-itemproperty -path HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate -Name "WUServer" -Value "http://intentionally.disabled" | Out-Null}
    if((Test-RegistryValue -path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate' -value 'WUSatusServer') -eq $true) {Set-itemproperty -path HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate -Name "WUSatusServer" -Value "http://intentionally.disabled" | Out-Null} else {new-itemproperty -path HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate -Name "WUSatusServer" -Value "http://intentionally.disabled" | Out-Null}
    Set-ItemProperty -Path HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU -Name "AUOptions" -Value 1 | Out-Null
    if((Test-RegistryValue -path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU' -value 'UseWUServer') -eq $true) {Set-itemproperty -path HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU -Name "UseWUServer" -Value 1 | Out-Null} else {new-ItemProperty -Path HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU -Name "UseWUServer" -Value 1 | Out-Null}
}
    
#Sets all applications to force close on shutdown
function Set-RegistryForceCloseApps 
{
    if (((Get-Item -Path "HKCU:\Control Panel\Desktop").GetValue("AutoEndTasks") -ne $null) -eq $true) 
    {
        Set-ItemProperty -path "HKCU:\Control Panel\Desktop" -Name "AutoEndTasks" -Value "1"
    }
    Else 
    {
        New-ItemProperty -path "HKCU:\Control Panel\Desktop" -Name "AutoEndTasks" -Value "1"
    }
}

#disable new network window - a popup that windows does when it detects "new networks"
function Disable-NewNetworkWindow {
    Write-Output "Disabling New Network Window"
    if((Test-RegistryValue -path HKLM:\SYSTEM\CurrentControlSet\Control\Network -Value NewNetworkWindowOff)-eq $true) {} Else {new-itemproperty -path HKLM:\SYSTEM\CurrentControlSet\Control\Network -name "NewNetworkWindowOff" | Out-Null}
}

#disable logout start menu
function Disable-Logout {
    Write-Output "Disabling Logout"
    if((Test-RegistryValue -Path HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer -Value StartMenuLogOff )-eq $true) {Set-ItemProperty -Path HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer -Name StartMenuLogOff -Value 1 | Out-Null} Else {New-ItemProperty -Path HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer -Name StartMenuLogOff -Value 1 | Out-Null}
}

#disable lock start menu
function Disable-Lock {
    Write-Output "Disable Lock"
    if((Test-Path -Path HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System) -eq $true) {} Else {New-Item -Path HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies -Name Software | Out-Null}
    if((Test-RegistryValue -Path HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System -Value DisableLockWorkstation) -eq $true) {Set-ItemProperty -Path HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System -Name DisableLockWorkstation -Value 1 | Out-Null } Else {New-ItemProperty -Path HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System -Name DisableLockWorkstation -Value 1 | Out-Null}
}
    
#set automatic time and timezone
function Set-Time {
    Write-Output "Setting Time to Automatic"
    Set-ItemProperty -path HKLM:\SYSTEM\CurrentControlSet\Services\W32Time\Parameters -Name Type -Value NTP | Out-Null
    Set-ItemProperty -Path HKLM:\SYSTEM\CurrentControlSet\Services\tzautoupdate -Name Start -Value 00000003 | Out-Null
}

#Disables Server Manager opening on Startup
function Disable-Server-Manager {
    Write-Output "Disable Auto Opening Server Manager"
    Get-ScheduledTask -TaskName ServerManager | Disable-ScheduledTask | Out-Null
}

#Disable Devices
function Disable-Devices {
    write-output "Disabling not required devices"
    devcon64 /r disable "HDAUDIO\FUNC_01&VEN_10DE&DEV_0083&SUBSYS_10DE11A3*"
    Get-PnpDevice| where {$_.friendlyname -like "Generic Non-PNP Monitor" -and $_.status -eq "OK"} | Disable-PnpDevice -confirm:$false
    Get-PnpDevice| where {$_.friendlyname -like "Microsoft Basic Display Adapter" -and $_.status -eq "OK"} | Disable-PnpDevice -confirm:$false
    devcon64 /r disable "PCI\VEN_1013&DEV_00B8*"
}

function Install-Parsec
{
    & $path\parsec-windows.exe /S
}

#Audio Drivers
function Install-AudioDriver {
    Write-Output "Installing audio driver"
    Read-S3Object -BucketName demo-parsec -Key aws_audio.zip -File $path\aws_audio.zip
    Expand-Archive -Path $path\aws_audio.zip -DestinationPath $path\aws_audio\
    devcon64 install $path\aws_audio\rzsurroundvad.inf *rzsurroundvad
}

#creating a separate user to autologin and persist with ami
function new-autostart {
    $user = 'Gamer'
    $pass = 'CoolP455'
    # Create the local user
    net user $user $pass /ADD /expires:never

    # Set the above local user to not have an expiring password
    Get-WmiObject Win32_UserAccount -filter "LocalAccount=True"| Where-Object {$_.name -eq $user} | Set-WmiInstance -Arguments @{PasswordExpires=$false}

    # Create registry keys for local login
    New-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" -Name "DefaultUserName" -PropertyType "String" -Value $user
    New-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" -Name "DefaultPassword" -PropertyType "String" -Value $pass
    New-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" -Name "DefaultDomainName" -PropertyType "String" -Value '.\'
    New-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" -Name "AutoAdminLogon" -PropertyType "String" -Value '1'

    Remove-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" -Name "AutoLogonSID"
}


###Launcher Installs###
function Install-Battlenet {
    (New-Object System.Net.WebClient).DownloadFile("https://www.battle.net/download/getInstallerForGame?os=win&locale=enUS&version=LIVE&gameProgram=BATTLENET_APP", "$path\Battle-net.exe") | Unblock-File
    Start-Process "$path\Battle-net.exe" -ArgumentList "--installpath=C:/Battle.net --locale=enUS"
}

function Install-Origin {
    cinst origin
}

function Install-Epicgames {
    cinst epicgameslauncher
}

#Cleanup
function clean-up {
    Write-Output "Cleaning up!"
    Remove-Item -Path $path -force -Recurse
}

Write-Host -foregroundcolor red "
THIS IS GALAXY.
We are installing all the needed essentials to make this machine stream games
"

create-directories

#Golden image start
Install-SSM
Install-Chocolatey

#download-nvidia
#install-nvidia
#Golden image end

download-resources
Install-7zip
install-windows-features
Disable-Updates
Set-RegistryForceCloseApps
Disable-NewNetworkWindow
Disable-Logout
Disable-Llock
Set-Time
Disable-Server-Manager
Install-Battlenet
Install-Origin
Install-Epicgames
Install-Parsec
Disable-Devices
Install-AudioDriver
#clean-up
Write-Host "Script ended. It's over. Stop looking at me." -ForegroundColor Green


#TODO: Maybe it's already installed with new parsec installer? Test controller
#Checks for Server 2019 and asks user to install Windows Xbox Accessories in order to let their controller work
#USE THIS TO EXTRACT LATER: https://social.technet.microsoft.com/Forums/office/en-US/f5bd7dd6-36f4-4309-8dd5-7d746cb161d2/silent-install-of-xbox-360-controller-drivers?forum=w7itproinstall
