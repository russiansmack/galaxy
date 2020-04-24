#Useful commands go here
# & "C:\Program Files\NVIDIA Corporation\NVSMI\nvidia-smi.exe" -q #query nvidia driver

#Predefined Vars
$autoLoginUser = "Administrator" #Username to be used in autologin (AWS uses Administrator)
$path = "C:\ParsecTemp" #Path for installer

####GOLDEN IMAGE SETUP START

function install-ssm {
    Write-Host "Installing AWS SSM"
    (New-Object System.Net.WebClient).DownloadFile("https://s3.amazonaws.com/ec2-downloads-windows/SSMAgent/latest/windows_amd64/AmazonSSMAgentSetup.exe", "$path\SSMAgent_latest.exe") | Unblock-File
    Start-Process -FilePath "$path\SSMAgent_latest.exe" -ArgumentList "/S"
}

function install-choco {
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
    Write-Output "Downloading Parsec, DirectX June 2010 Redist, DevCon and Google Chrome."
    Write-Host "Downloading DirectX"
    (New-Object System.Net.WebClient).DownloadFile("https://download.microsoft.com/download/8/4/A/84A35BF1-DAFE-4AE8-82AF-AD2AE20B6B14/directx_Jun2010_redist.exe", "$path\Apps\directx_Jun2010_redist.exe") | Unblock-File
    Write-Host "Downloading Devcon"
    (New-Object System.Net.WebClient).DownloadFile("https://s3.amazonaws.com/parsec-files-ami-setup/Devcon/devcon.exe", "$path\Devcon\devcon.exe") | Unblock-File
    Write-Host "Downloading Parsec"
    (New-Object System.Net.WebClient).DownloadFile("https://builds.parsecgaming.com/package/parsec-windows.exe", "$path\Apps\parsec-windows.exe") | Unblock-File
    Write-Host "Downloading Chrome"
    (New-Object System.Net.WebClient).DownloadFile("https://dl.google.com/tag/s/dl/chrome/install/googlechromestandaloneenterprise64.msi", "$path\Apps\googlechromestandaloneenterprise64.msi") | Unblock-File #TODO: choco install googlechrome -ignore-checksums
}

function install-7zip {
    #7Zip is required to extract the installers
    Write-Host "Downloading and Installing 7Zip"
    (New-Object System.Net.WebClient).DownloadFile("https://www.7-zip.org/a/7z1900-x64.exe" ,"$path\Apps\7zip.exe") | Unblock-File
    Start-Process $path\Apps\7zip.exe -ArgumentList '/S /D="C:\Program Files\7-Zip"' -Wait
}

#install-base-files-silently
function install-windows-features {
    Write-Output "Installing .Net 3.5, Direct Play and DirectX Redist 2010"
    Start-Process -filepath "C:\Windows\System32\msiexec.exe" -ArgumentList "/qn /i '$path\Apps\googlechromestandaloneenterprise64.msi'" -Wait
    Start-Process -FilePath "$path\Apps\directx_jun2010_redist.exe" -ArgumentList "/T:$path\DirectX /Q" -wait
    Start-Process -FilePath "$path\DirectX\DXSETUP.EXE" -ArgumentList '/silent' -wait
    Install-WindowsFeature Direct-Play | Out-Null
    Install-WindowsFeature Net-Framework-Core | Out-Null
    Remove-Item -Path $path\DirectX -force -Recurse 
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
function set-update-policy {
    Write-Output "Disabling Windows Update"
    if((Test-RegistryValue -path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate' -value 'DoNotConnectToWindowsUpdateInternetLocations') -eq $true) {Set-itemproperty -path HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate -Name "DoNotConnectToWindowsUpdateInternetLocations" -Value "1" | Out-Null} else {new-itemproperty -path HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate -Name "DoNotConnectToWindowsUpdateInternetLocations" -Value "1" | Out-Null}
    if((Test-RegistryValue -path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate' -value 'UpdateServiceURLAlternative') -eq $true) {Set-itemproperty -path HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate -Name "UpdateServiceURLAlternative" -Value "http://intentionally.disabled" | Out-Null} else {new-itemproperty -path HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate -Name "UpdateServiceURLAlternative" -Value "http://intentionally.disabled" | Out-Null}
    if((Test-RegistryValue -path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate' -value 'WUServer') -eq $true) {Set-itemproperty -path HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate -Name "WUServer" -Value "http://intentionally.disabled" | Out-Null} else {new-itemproperty -path HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate -Name "WUServer" -Value "http://intentionally.disabled" | Out-Null}
    if((Test-RegistryValue -path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate' -value 'WUSatusServer') -eq $true) {Set-itemproperty -path HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate -Name "WUSatusServer" -Value "http://intentionally.disabled" | Out-Null} else {new-itemproperty -path HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate -Name "WUSatusServer" -Value "http://intentionally.disabled" | Out-Null}
    Set-ItemProperty -Path HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU -Name "AUOptions" -Value 1 | Out-Null
    if((Test-RegistryValue -path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU' -value 'UseWUServer') -eq $true) {Set-itemproperty -path HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU -Name "UseWUServer" -Value 1 | Out-Null} else {new-ItemProperty -Path HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU -Name "UseWUServer" -Value 1 | Out-Null}
}
    
#Sets all applications to force close on shutdown
function force-close-apps 
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
function disable-network-window {
    Write-Output "Disabling New Network Window"
    if((Test-RegistryValue -path HKLM:\SYSTEM\CurrentControlSet\Control\Network -Value NewNetworkWindowOff)-eq $true) {} Else {new-itemproperty -path HKLM:\SYSTEM\CurrentControlSet\Control\Network -name "NewNetworkWindowOff" | Out-Null}
}

#disable logout start menu
function disable-logout {
    Write-Output "Disabling Logout"
    if((Test-RegistryValue -Path HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer -Value StartMenuLogOff )-eq $true) {Set-ItemProperty -Path HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer -Name StartMenuLogOff -Value 1 | Out-Null} Else {New-ItemProperty -Path HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer -Name StartMenuLogOff -Value 1 | Out-Null}
}

#disable lock start menu
function disable-lock {
    Write-Output "Disable Lock"
    if((Test-Path -Path HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System) -eq $true) {} Else {New-Item -Path HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies -Name Software | Out-Null}
    if((Test-RegistryValue -Path HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System -Value DisableLockWorkstation) -eq $true) {Set-ItemProperty -Path HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System -Name DisableLockWorkstation -Value 1 | Out-Null } Else {New-ItemProperty -Path HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System -Name DisableLockWorkstation -Value 1 | Out-Null}
}
    
#Enable Pointer Precision 
function enhance-pointer-precision {
    Write-Output "Enabling Enhanced Pointer Precision"
    Set-Itemproperty -Path 'HKCU:\Control Panel\Mouse' -Name MouseSpeed -Value 1 | Out-Null
}

#enable Mouse Keys
function enable-mousekeys {
    Write-Output "Enabling Mouse Keys"
    set-Itemproperty -Path 'HKCU:\Control Panel\Accessibility\MouseKeys' -Name Flags -Value 63 | Out-Null
}

#set automatic time and timezone
function set-time {
    Write-Output "Setting Time to Automatic"
    Set-ItemProperty -path HKLM:\SYSTEM\CurrentControlSet\Services\W32Time\Parameters -Name Type -Value NTP | Out-Null
    Set-ItemProperty -Path HKLM:\SYSTEM\CurrentControlSet\Services\tzautoupdate -Name Start -Value 00000003 | Out-Null
}

#Disables Server Manager opening on Startup
function disable-server-manager {
    Write-Output "Disable Auto Opening Server Manager"
    Get-ScheduledTask -TaskName ServerManager | Disable-ScheduledTask | Out-Null
}

#Apps that require human intervention
function Install-Parsec
{
    Pre-Parsec
    New-ItemProperty -path HKCU:\Software\Microsoft\Windows\CurrentVersion\Run -Name "Parsec.App.0" -Value "C:\Program Files\Parsec\parsecd.exe" | Out-Null
    Start-Process -FilePath "C:\Program Files\Parsec\parsecd.exe"
}

Function Pre-Parsec 
{
    Write-Host "Installing PreParsec"
    ExtractInstallFiles
    InstallViGEmBus
    CreateFireWallRule
    CreateParsecService
    DownloadParsecServiceManager
    Write-host "Successfully installed Parsec"
}

######PRE PARSEC START
    
function ExtractInstallFiles {
    #Move Parsec Files into correct location
    Write-Host "Moving files to the correct location"

    & 'C:\Program Files\7-Zip\7z.exe' x $path\Apps\parsec-windows.exe -o"$path\Apps\Parsec-Windows" -y | Out-Null
    if((Test-Path -Path 'C:\Program Files\Parsec')-eq $true) {} Else {New-Item -Path 'C:\Program Files\Parsec' -ItemType Directory | Out-Null}
    if((Test-Path -Path "C:\Program Files\Parsec\skel") -eq $true) {} Else {Move-Item -Path $path\Apps\Parsec-Windows\skel -Destination 'C:\Program Files\Parsec' | Out-Null} 
    if((Test-Path -Path "C:\Program Files\Parsec\vigem") -eq $true) {} Else  {Move-Item -Path $path\Apps\Parsec-Windows\vigem -Destination 'C:\Program Files\Parsec' | Out-Null} 
    if((Test-Path -Path "C:\Program Files\Parsec\wscripts") -eq $true) {} Else  {Move-Item -Path $path\Apps\Parsec-Windows\wscripts -Destination 'C:\Program Files\Parsec' | Out-Null} 
    if((Test-Path -Path "C:\Program Files\Parsec\parsecd.exe") -eq $true) {} Else {Move-Item -Path $path\Apps\Parsec-Windows\parsecd.exe -Destination 'C:\Program Files\Parsec' | Out-Null} 
    if((Test-Path -Path "C:\Program Files\Parsec\pservice.exe") -eq $true) {} Else {Move-Item -Path $path\Apps\Parsec-Windows\pservice.exe -Destination 'C:\Program Files\Parsec' | Out-Null} 
}

#Install ViGEmBus for controller support
#DEPENDENCY: parsec installed
Function InstallViGEmBus {
    #Required for Controller Support.
    Write-Host "Installing ViGEmBus - https://github.com/ViGEm/ViGEmBus"
    cmd.exe /c '"C:\Program Files\Parsec\vigem\10\x64\devcon.exe" install "C:\Program Files\Parsec\vigem\10\ViGEmBus.inf" Nefarius\ViGEmBus\Gen1' | Out-Null
}

Function CreateFireWallRule {
    #Creates Parsec Firewall Rule in Windows Firewall
    Write-host "Creating Parsec Firewall Rule"
    New-NetFirewallRule -DisplayName "Parsec" -Direction Inbound -Program "C:\Program Files\Parsec\Parsecd.exe" -Profile Private,Public -Action Allow -Enabled True | Out-Null
}

Function CreateParsecService {
    #Creates Parsec Service
    Write-host "Creating Parsec Service"
    cmd.exe /c 'sc.exe Create "Parsec" binPath= "\"C:\Program Files\Parsec\pservice.exe\"" start= "auto"' | Out-Null
    sc.exe Start 'Parsec' | Out-Null
}

Function DownloadParsecServiceManager {
    [Net.ServicePointManager]::SecurityProtocol = "tls12, tls11, tls"
    (New-Object System.Net.WebClient).DownloadFile("https://github.com/jamesstringerparsec/Parsec-Service-Manager/blob/master/Launcher.exe?raw=true", "$path\ParsecServiceManager.exe") | Unblock-File
}
######PRE PARSEC END

#Checks for Server 2019 and asks user to install Windows Xbox Accessories in order to let their controller work
#USE THIS TO EXTRACT LATER: https://social.technet.microsoft.com/Forums/office/en-US/f5bd7dd6-36f4-4309-8dd5-7d746cb161d2/silent-install-of-xbox-360-controller-drivers?forum=w7itproinstall
Function Server2019Controller {
    if ((gwmi win32_operatingsystem | % caption) -like '*Windows Server 2019*') {
        "Detected Windows Server 2019, downloading Xbox Accessories 1.2 to enable controller support"
        (New-Object System.Net.WebClient).DownloadFile("http://download.microsoft.com/download/6/9/4/69446ACF-E625-4CCF-8F56-58B589934CD3/Xbox360_64Eng.exe", "$path\Drivers\Xbox360_64Eng.exe") | Unblock-File
        Write-Host "In order to use a controller, you need to install Microsoft Xbox Accessories " -ForegroundColor Red
        Start-Process $path\Drivers\Xbox360_64Eng.exe /q
    }
}

#Disable Devices
function disable-devices {
    write-output "Disabling devices not required"
    Start-Process -FilePath "$path\Devcon\devcon.exe" -ArgumentList '/r disable "HDAUDIO\FUNC_01&VEN_10DE&DEV_0083&SUBSYS_10DE11A3*"'
    Get-PnpDevice| where {$_.friendlyname -like "Generic Non-PNP Monitor" -and $_.status -eq "OK"} | Disable-PnpDevice -confirm:$false
    Get-PnpDevice| where {$_.friendlyname -like "Microsoft Basic Display Adapter" -and $_.status -eq "OK"} | Disable-PnpDevice -confirm:$false
    Start-Process -FilePath "$path\Devcon\devcon.exe" -ArgumentList '/r disable "PCI\VEN_1013&DEV_00B8*"'
}

#GPU Detector
Function gpu-detector {
    #Device ID Query 
    $gputype = get-wmiobject -query "select DeviceID from Win32_PNPEntity Where (deviceid Like '%PCI\\VEN_10DE%') and (PNPClass = 'Display' or Name = '3D Video Controller')" | Select-Object DeviceID -ExpandProperty DeviceID
    if ($gputype -eq $null) 
    {
        Write-Output "No GPU Detected, skipping provider specific tasks"
    }
    Else
    {
        if($gputype.substring(13,8) -eq "DEV_13F2") 
        {
            #AWS G3.4xLarge M60
            Write-Output "Tesla M60 Detected"
        }
        ElseIF($gputype.Substring(13,8) -eq "DEV_118A")
        {
            #AWS G2.2xLarge K520
            Write-Output "GRID K520 Detected"
        }
        ElseIF($gputype.Substring(13,8) -eq "DEV_1BB1") 
        {
            #Paperspace P4000
            Write-Output "Quadro P4000 Detected"
        } 
        Elseif($gputype.Substring(13,8) -eq "DEV_1BB0") 
        {
            #Paperspace P5000
            Write-Output "Quadro P5000 Detected"
        }
        Elseif($gputype.substring(13,8) -eq "DEV_15F8") 
        {
            #Tesla P100
            Write-Output "Tesla P100 Detected"
        }
        Elseif($gputype.substring(13,8) -eq "DEV_1BB3") 
        {
            #Tesla P4
            Write-Output "Tesla P4 Detected"
        }
        Elseif($gputype.substring(13,8) -eq "DEV_1EB8") 
        {
            #Tesla T4
            Write-Output "Tesla T4 Detected"
        }
        Elseif($gputype.substring(13,8) -eq "DEV_1430") 
        {
            #Quadro M2000
            Write-Output "Quadro M2000 Detected"
        }
        Else
        {
            write-host "The installed GPU is not currently supported, skipping provider specific tasks"
        }
    }
}

#Audio Drivers
function audio-driver {
    Write-Output "Installing audio driver"
    (New-Object System.Net.WebClient).DownloadFile("http://rzr.to/surround-pc-download", "$path\Apps\razer-surround-driver.exe") | Unblock-File
    Write-Host "Installing Razer Surround - it's the Audio Driver - you DON'T need to sign into Razer Synapse" -ForegroundColor green
    
    #Move extracts Razer Surround Files into correct location
    Write-Host "Moving Razer Surround files to the correct location"
    & 'C:\Program Files\7-Zip\7z.exe' x $path\Apps\razer-surround-driver.exe -o"$path\Apps\razer-surround-driver" -y | Out-Null
    
    #modifys the installer manifest to run without interraction
    $InstallerManifest = $path + '\Apps\razer-surround-driver\$TEMP\RazerSurroundInstaller\InstallerManifest.xml'
    $regex = '(?<=<SilentMode>)[^<]*'
    (Get-Content $InstallerManifest) -replace $regex, 'true' | Set-Content $InstallerManifest -Encoding UTF8
    
    Write-Output "The Audio Driver, Razer Surround is now installing"
    $rzPath = Join-Path $path '\Apps\razer-surround-driver\$TEMP\RazerSurroundInstaller'
    Start-Process -FilePath "RzUpdateManager.exe" -WorkingDirectory $rzPath
    Set-Service -Name audiosrv -StartupType Automatic

    #Shit who knows. Wait for the above update manager to do it's magic and then remove start up for next boot
    Write-Output "120s for Audio Drivers to finalize"
    Start-Sleep -s 120

    #This is to remove autostartup of razer window : MUST ADD
    if (((Get-Item -Path HKLM:\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Run).GetValue("Razer Synapse") -ne $null) -eq $true) 
    {Remove-ItemProperty -path "HKLM:\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Run" -Name "Razer Synapse"
    "Removed Startup Item from Razer Synapse"}
    Else {"Razer Startup Item not present"}
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

function Install-Chocolatey {
    Set-ExecutionPolicy Bypass -Scope Process -Force; [System.Net.ServicePointManager]::SecurityProtocol = [System.Net.ServicePointManager]::SecurityProtocol -bor 3072; iex ((New-Object System.Net.WebClient).DownloadString('https://chocolatey.org/install.ps1'))
    choco feature enable -n allowGlobalConfirmation
}

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
install-ssm
Install-Chocolatey

#download-nvidia
#install-nvidia
#Golden image end

download-resources
install-7zip
install-windows-features
set-update-policy
force-close-apps
disable-network-window
disable-logout
disable-lock
enhance-pointer-precision
enable-mousekeys
set-time
disable-server-manager
Install-Battlenet
Install-Origin
Install-Epicgames
Install-Parsec
Server2019Controller #USE THIS TO EXTRACT LATER: https://social.technet.microsoft.com/Forums/office/en-US/f5bd7dd6-36f4-4309-8dd5-7d746cb161d2/silent-install-of-xbox-360-controller-drivers?forum=w7itproinstall
disable-devices
#gpu-detector
audio-driver
#clean-up
Write-Host "Script ended. It's over. Stop looking at me." -ForegroundColor Green
