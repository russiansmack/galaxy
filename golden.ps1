#Create Temp Folder
$path = "C:\ParsecTemp"
if((Test-Path -Path $path )-eq $true){} Else {New-Item -Path $path -ItemType directory | Out-Null}

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

function Install-SSM {
    Write-Host "Installing AWS SSM"
    (New-Object System.Net.WebClient).DownloadFile("https://s3.amazonaws.com/ec2-downloads-windows/SSMAgent/latest/windows_amd64/AmazonSSMAgentSetup.exe", "$path\SSMAgent_latest.exe") | Unblock-File
    Start-Process -FilePath "$path\SSMAgent_latest.exe" -ArgumentList "/S"
}

function Install-Chocolatey {
    Write-Host "Installing Chocolatey"
    Set-ExecutionPolicy Bypass -Scope Process -Force; [System.Net.ServicePointManager]::SecurityProtocol = [System.Net.ServicePointManager]::SecurityProtocol -bor 3072; iex ((New-Object System.Net.WebClient).DownloadString('https://chocolatey.org/install.ps1'))
    choco feature enable -n allowGlobalConfirmation
}


#download-files-S3
function Install-Base {
    Write-Host "Installing Devcon"
    cinst devcon.portable

    Write-Host "Installing Chrome"
    cinst googlechrome -ignore-checksums
    
    Write-Host "Installing DirectX Redist 2010"
    cinst directx

    Write-Host "Installing Direct Play"
    Install-WindowsFeature Direct-Play | Out-Null
    
    Write-Host "Installing .Net 3.5"
    Install-WindowsFeature Net-Framework-Core | Out-Null
}

#set update policy
function Disable-Updates {
    Write-Host "Disabling Windows Update"
    if((__Test-RegistryValue -path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate' -value 'DoNotConnectToWindowsUpdateInternetLocations') -eq $true) {Set-itemproperty -path HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate -Name "DoNotConnectToWindowsUpdateInternetLocations" -Value "1" | Out-Null} else {new-itemproperty -path HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate -Name "DoNotConnectToWindowsUpdateInternetLocations" -Value "1" | Out-Null}
    if((__Test-RegistryValue -path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate' -value 'UpdateServiceURLAlternative') -eq $true) {Set-itemproperty -path HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate -Name "UpdateServiceURLAlternative" -Value "http://intentionally.disabled" | Out-Null} else {new-itemproperty -path HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate -Name "UpdateServiceURLAlternative" -Value "http://intentionally.disabled" | Out-Null}
    if((__Test-RegistryValue -path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate' -value 'WUServer') -eq $true) {Set-itemproperty -path HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate -Name "WUServer" -Value "http://intentionally.disabled" | Out-Null} else {new-itemproperty -path HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate -Name "WUServer" -Value "http://intentionally.disabled" | Out-Null}
    if((__Test-RegistryValue -path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate' -value 'WUSatusServer') -eq $true) {Set-itemproperty -path HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate -Name "WUSatusServer" -Value "http://intentionally.disabled" | Out-Null} else {new-itemproperty -path HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate -Name "WUSatusServer" -Value "http://intentionally.disabled" | Out-Null}
    Set-ItemProperty -Path HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU -Name "AUOptions" -Value 1 | Out-Null
    if((__Test-RegistryValue -path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU' -value 'UseWUServer') -eq $true) {Set-itemproperty -path HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU -Name "UseWUServer" -Value 1 | Out-Null} else {new-ItemProperty -Path HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU -Name "UseWUServer" -Value 1 | Out-Null}
}
    
#Sets all applications to force close on shutdown
function Set-RegistryForceCloseApps 
{
    Write-Host "Enabling Force Closure of Apps on Shutdown"
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
    Write-Host "Disabling New Network Window"
    if((__Test-RegistryValue -path HKLM:\SYSTEM\CurrentControlSet\Control\Network -Value NewNetworkWindowOff)-eq $true) {} Else {new-itemproperty -path HKLM:\SYSTEM\CurrentControlSet\Control\Network -name "NewNetworkWindowOff" | Out-Null}
}

#disable logout start menu
function Disable-Logout {
    Write-Host "Disabling Logout"
    if((__Test-RegistryValue -Path HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer -Value StartMenuLogOff )-eq $true) {Set-ItemProperty -Path HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer -Name StartMenuLogOff -Value 1 | Out-Null} Else {New-ItemProperty -Path HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer -Name StartMenuLogOff -Value 1 | Out-Null}
}

#disable lock start menu
function Disable-Lock {
    Write-Host "Disable Lock"
    if((Test-Path -Path HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System) -eq $true) {} Else {New-Item -Path HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies -Name Software | Out-Null}
    if((__Test-RegistryValue -Path HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System -Value DisableLockWorkstation) -eq $true) {Set-ItemProperty -Path HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System -Name DisableLockWorkstation -Value 1 | Out-Null } Else {New-ItemProperty -Path HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System -Name DisableLockWorkstation -Value 1 | Out-Null}
}
    
#set automatic time and timezone
function Set-Time {
    Write-Host "Setting Time to Automatic"
    Set-ItemProperty -path HKLM:\SYSTEM\CurrentControlSet\Services\W32Time\Parameters -Name Type -Value NTP | Out-Null
    Set-ItemProperty -Path HKLM:\SYSTEM\CurrentControlSet\Services\tzautoupdate -Name Start -Value 00000003 | Out-Null
}

#Disables Server Manager opening on Startup
function Disable-ServerManager {
    Write-Host "Disable Auto Opening Server Manager"
    Get-ScheduledTask -TaskName ServerManager | Disable-ScheduledTask | Out-Null
}

#Disable Devices
function Disable-Devices {
    Write-Host "Disabling not required devices"
    devcon64 /r disable "HDAUDIO\FUNC_01&VEN_10DE&DEV_0083&SUBSYS_10DE11A3*"
    Get-PnpDevice| where {$_.friendlyname -like "Generic Non-PNP Monitor" -and $_.status -eq "OK"} | Disable-PnpDevice -confirm:$false
    Get-PnpDevice| where {$_.friendlyname -like "Microsoft Basic Display Adapter" -and $_.status -eq "OK"} | Disable-PnpDevice -confirm:$false
    devcon64 /r disable "PCI\VEN_1013&DEV_00B8*"
}

function Install-Parsec
{
    Write-Host "Installing Parsec"
    (New-Object System.Net.WebClient).DownloadFile("https://builds.parsecgaming.com/package/parsec-windows.exe", "$path\parsec-windows.exe") | Unblock-File
    & $path\parsec-windows.exe /S
}

#Audio Drivers
function Install-AudioDriver {
    Write-Output "Installing audio driver"
    #Download Audio driver extracted from Razer Surround Sound
    Read-S3Object -BucketName demo-parsec -Key aws_audio.zip -File $path\aws_audio.zip
    Expand-Archive -Path $path\aws_audio.zip -DestinationPath $path -Force
    #Installing virtual sound device
    devcon64 install $path\aws_audio\rzsurroundvad.inf *rzsurroundvad
    #Initializing Audio Service
    Set-Service -Name audiosrv -StartupType Automatic
}

###Launcher Installs###
function Install-Battlenet {
    (New-Object System.Net.WebClient).DownloadFile("https://www.battle.net/download/getInstallerForGame?os=win&locale=enUS&version=LIVE&gameProgram=BATTLENET_APP", "$path\Battle-net.exe") | Unblock-File
    Start-Process "$path\Battle-net.exe" -ArgumentList "--installpath=C:/Battle.net --locale=enUS"
}

function Install-Origin {
    cinst origin
}

function Install-EpicGames {
    cinst epicgameslauncher
}

#Cleanup
function Remove-TempFolder {
    Write-Output "Cleaning up!"
    Remove-Item -Path $path -force -Recurse
}

Write-Host -foregroundcolor red "
THIS IS GALAXY.
We are installing all the needed essentials to make this machine stream games
"

#Tooling
Install-SSM
Install-Chocolatey

#Essentials
Install-Base

#Registry
Disable-Updates
Set-RegistryForceCloseApps
Disable-NewNetworkWindow
Disable-Logout
Disable-Lock
Set-Time
Disable-ServerManager

#Devices
Disable-Devices
Install-AudioDriver

#Launchers
Install-Battlenet
Install-Origin
Install-EpicGames

#Streaming Tech
Install-Parsec

Remove-TempFolder

Write-Host "Script ended. It's over. Stop looking at me." -ForegroundColor Green


#TODO: Maybe it's already installed with new parsec installer? Test controller
#Checks for Server 2019 and asks user to install Windows Xbox Accessories in order to let their controller work
#USE THIS TO EXTRACT LATER: https://social.technet.microsoft.com/Forums/office/en-US/f5bd7dd6-36f4-4309-8dd5-7d746cb161d2/silent-install-of-xbox-360-controller-drivers?forum=w7itproinstall
