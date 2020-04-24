#Useful commands go here
# & "C:\Program Files\NVIDIA Corporation\NVSMI\nvidia-smi.exe" -q #query nvidia driver

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
    (New-Object System.Net.WebClient).DownloadFile("https://us.download.nvidia.com/downloads/cool_stuff/demos/SetupFaceWorks.exe", "$path\SetupFaceWorks.exe") | Unblock-File
    Start-Process -FilePath "$path\SetupFaceWorks.exe" -ArgumentList "/S" -wait
}