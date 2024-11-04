# Check if ran as administrator
$ShouldBypassAdminCheck = Test-Path -Path "./BypassAdmin"
if (!$ShouldBypassAdminCheck -and (-Not ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] 'Administrator'))) {
    Start-Process PowerShell -Verb RunAs "-NoProfile -ExecutionPolicy Bypass -Command `"cd '$pwd'; & '$PSCommandPath';`"";
    exit 0
}
# Set window title
$Host.UI.RawUI.WindowTitle = "CyberPatriot 2024 - Team R-MA"

# List all users and admins
function List-Local {
# Lists all local users
Write-Output "All Local Users:"
Get-LocalUser | Where-Object {
    $_.Enabled -eq $true -and
    $_.Name -notin @("Administrator", "Guest", "DefaultAccount") -and
    $_.SID -notmatch "^S-1-5-18|^S-1-5-19|^S-1-5-20"  # Excludes Local System, Local Service, and Network Service
} | Select-Object Name, Enabled
# Lists all local admins
Write-Output "All Local Administrators:"
Get-LocalGroupMember -Group "Administrators" | Select-Object Name, ObjectClass
}

function UserManagement {
    Clear-Host

    Write-Output @"
       %%%%%%%%%%%%%@                                      
     %%%%%%+--#%%@ %%%   @%%%%%%                           
    %%%%+=#*-::%%%%%  %%%@@@@%%%%%%%%%%%                   
   %%%+=%#-+-:-%%%%%@%%% %%%%  %@@% @@ %%                  
   %*++=+++-:-#%%%%%%@%%%%@@ @%  %%%@@@%%                  
   %++++***=:=%%%%+#%*******#%%%%%%%%@@%%                  
    %=##+.+-%:*%##-*+:::+=::::::=%% %%%                    
     %*=::--:=#*=+**::::::=+::::::+*##%%                   
            @%=#*%-:::::::::#+***##%%%%%%                  
          @%=:=-:::::::::::::*   %%%*#+%%%                 
         @#-:::*:::::::::::::*%   %%%%%#%@                 
         %-::::-#-:::::::::**=%@     @@@                   
         @%--:*%  @%+-::-+#*==***%                          
        %+%%%%%      %#==++%+:::+%                         
       %%%#%%#%%      @%%%=---+#%%%                        
        %%%*%%%%    @%%%%*.*%%%%%%%%                       
         @%%%%%   %%%#-=#::%%%%%%%%%%%                     
                %%%%%+::::::---::-%%%%%%                   
                %%%%%%%=:::::::::#%   %%@                  
               @%+-#*..*%%%#*##%%@    @%%                  
             %%%#:::-*%%%%%%%%%%@     %%@                  
  %%#**%%%%%+*%#:-+:::::-==*%%@      %%@                   
    @%*%%%%*::-=#%%%#+-=+%%%        %%                     
       @   %@%%%%%%%%%%%            %%%%%                  
                  %%%%%%            @%%%%                  
 ____       _  _   __     ____  ____   __   _  _ 
(  _ \ ___ ( \/ ) / _\   (_  _)(  __) / _\ ( \/ )
 )   /(___)/ \/ \/    \    )(   ) _) /    \/ \/ \
(__\_)     \_)(_/\_/\_/   (__) (____)\_/\_/\_)(_/

[1] Add a new user
[2] Remove a user
[3] Add a user as admin
[4] Remove a user as admin
[5] Change all passwords
Q to go back.
"@
}

# Interactive User Menu
function UserMenu {
    UserManagement
    Write-Output ""
    $selection = Read-Host "Please make a selection"
    Write-Output ""
    Write-Output "--------------------------------------------------------"
    Write-Output ""

    switch ($selection) {
        '1' {
            $AddUserName = Read-Host -AsSecureString "Enter a Username"
            $Password = Read-Host -AsSecureString "Enter a Password"
            $FullName = Read-Host -AsSecureString "Enter the Full Name"
            $Desc = Read-Host -AsSecureString "Enter the Description"
            New-LocalUser -Name $AddUserName -Password $Password -FullName $FullName -Description $Desc -Enabled $true
            Write-Output "$AddUserName has been created."
        }
        '2' {
            $RemoveUserName = Read-Host -AsSecureString "Enter the username you would like to remove"
            Remove-LocalUser -Name $RemoveUserName -Confirm
            Write-Output "$RemoveUserName has been removed."
        }
        '3' {
            $AdminUserName = Read-Host -AsSecureString "Enter the username you would like to make admin"
            Add-LocalGroupMember -Group "Administrators" -Member $AdminUserName -Confirm
            Write-Output "$AdminUserName is now an admin."
        }
        '4' {
            $RemoveAdmin = Read-Host -AsSecureString "Enter the username you would like to remove as admin"
            Remove-LocalGroupMember -Group "Administrators" -Member $RemoveAdmin -Confirm
            Write-Output "$RemoveAdmin is no longer admin."
        }
        '5' {
            # Prompt for the new password
            $NewPassword = Read-Host -AsSecureString "Enter New Password for All Users"
            # Change password for all local users
            Get-LocalUser | Where-Object {
            $_.Name -notin @("Administrator", "Guest", "DefaultAccount") -and $_.Enabled -eq $true
            } | ForEach-Object {
            Set-LocalUser -Name $_.Name -Password $NewPassword
            Write-Output "Password changed for all users."
            }
            # Change password for all local administrators
            Get-LocalGroupMember -Group "Administrators" | ForEach-Object {
            Set-LocalUser -Name $_.Name -Password $NewPassword
            Write-Output "Password changed for all admins."
            }
            Write-Output "Password changed for all users and administrators."
        }
        'q' {
            Write-Output 'Going back...'
        }
        default {
            'Invalid selection. Please try again.'
        }
    }

    Write-Output ""
}
function GroupManagement {
    Clear-Host

    Write-Output @"
       %%%%%%%%%%%%%@                                      
     %%%%%%+--#%%@ %%%   @%%%%%%                           
    %%%%+=#*-::%%%%%  %%%@@@@%%%%%%%%%%%                   
   %%%+=%#-+-:-%%%%%@%%% %%%%  %@@% @@ %%                  
   %*++=+++-:-#%%%%%%@%%%%@@ @%  %%%@@@%%                  
   %++++***=:=%%%%+#%*******#%%%%%%%%@@%%                  
    %=##+.+-%:*%##-*+:::+=::::::=%% %%%                    
     %*=::--:=#*=+**::::::=+::::::+*##%%                   
            @%=#*%-:::::::::#+***##%%%%%%                  
          @%=:=-:::::::::::::*   %%%*#+%%%                 
         @#-:::*:::::::::::::*%   %%%%%#%@                 
         %-::::-#-:::::::::**=%@     @@@                   
         @%--:*%  @%+-::-+#*==***%                          
        %+%%%%%      %#==++%+:::+%                         
       %%%#%%#%%      @%%%=---+#%%%                        
        %%%*%%%%    @%%%%*.*%%%%%%%%                       
         @%%%%%   %%%#-=#::%%%%%%%%%%%                     
                %%%%%+::::::---::-%%%%%%                   
                %%%%%%%=:::::::::#%   %%@                  
               @%+-#*..*%%%#*##%%@    @%%                  
             %%%#:::-*%%%%%%%%%%@     %%@                  
  %%#**%%%%%+*%#:-+:::::-==*%%@      %%@                   
    @%*%%%%*::-=#%%%#+-=+%%%        %%                     
       @   %@%%%%%%%%%%%            %%%%%                  
                  %%%%%%            @%%%%                  
 ____       _  _   __     ____  ____   __   _  _ 
(  _ \ ___ ( \/ ) / _\   (_  _)(  __) / _\ ( \/ )
 )   /(___)/ \/ \/    \    )(   ) _) /    \/ \/ \
(__\_)     \_)(_/\_/\_/   (__) (____)\_/\_/\_)(_/

[1] Create a new group
[2] Remove a group
[3] Add a user to a group
[4] Remove a user from a group
[5] List all groups w/ users
Q to go back.
"@
}

# Interactive User Menu
function GroupMenu {
    GroupManagement
    Write-Output ""
    $selection = Read-Host "Please make a selection"
    Write-Output ""
    Write-Output "--------------------------------------------------------"
    Write-Output ""

    switch ($selection) {
        '1' {
            $NewGroupName = Read-Host -AsSecureString "Enter your new group name"
            New-LocalGroup -Name $NewGroupName -Description "Description of the new group" -Confirm
            Write-Output "The group $NewGroupName has been created."
        }
        '2' {
            $RemoveGroupName = Read-Host -AsSecureString "Enter the group name"
            Remove-LocalGroup -Name $RemoveGroupName -Confirm
            Write-Output "The group $RemoveGroupName has been removed."
        }
        '3' {
            $GroupName = Read-Host -AsSecureString "Enter the group name"
            $UserName = Read-Host -AsSecureString "Enter the username"
            Add-LocalGroupMember -Group $GroupName -Member $UserName -Confirm
            Write-Output "$UserName has been added to $GroupName."
        }
        '4' {
            $GroupName2 = Read-Host -AsSecureString "Enter the group name"
            $UserName2 = Read-Host -AsSecureString "Enter the username"
            Remove-LocalGroupMember -Group $GroupName2 -Member $UserName2 -Confirm
            Write-Output "$UserName2 has been removed from $GroupName2."
        }
        '5' {
            # Get all local groups
            $groups = Get-LocalGroup

            # Iterate through each group and display its members
            foreach ($group in $groups) {
                Write-Output "Group: $($group.Name)"
    
                # Get the members of the current group
                $members = Get-LocalGroupMember -Group $group.Name
    
                if ($members) {
                    $members | ForEach-Object {
                        Write-Output "  - Users: $($_.Name) (Type: $($_.ObjectClass))"
                    }
                } else {
                    Write-Output "  - No members found."
                }

                Write-Output ""  # Blank line for better readability
            }
        }
        'q' {
            Write-Output 'Going back...'
        }
        default {
            'Invalid selection. Please try again.'
        }
    }

    Write-Output ""
}
# Password Requirements
function UpdatePasswd {
    # Minimum Password Length
    $minlenamount = Read-Host -AsSecureString "Minimum password length amount (Suggested: 10)"
    net accounts /minpwlen:$minlenamount
    Write-Output "Set minpwlen to $minamount"
    # Minimum Password Age
    $minageamount = Read-Host -AsSecureString "Minimum password age amount (Suggested: 2)"
    net accounts /minpwage:$minageamount
    Write-Output "Set minpwage to $minageamount"
    # Maximum Password Age
    $maxageamount = Read-Host -AsSecureString "Maximum password age amount (Suggested: 90)"
    net accounts /maxpwage:$maxageamount
    Write-Output "Set maxpwage to $maxageamount"
    # Enforce password history
    $uniqueamt = Read-Host -AsSecureString "Enforce password history amount (Suggested: 5)"
    net accounts /uniquepw:$uniqueamt
    Write-Output "Set uniquepw to $uniqueamt"
    # Lockout Threshold
    $lockoutamt = Read-Host -AsSecureString "Secure lockout threshold amount (Suggested: 3)"
    net accounts /lockoutthreshold:$lockoutamt
    Write-Output "Set lockoutthreshold to $lockoutamt"
    # Complexity Requirements
    Set-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Services\Netlogon\Parameters' -Name 'PasswordComplexity' -Value 1
    gpupdate /force
}
# Changes the policies/audits
function ConfigPolicies {
    # Audit Credential Validation [Success]
    AuditPol /set /subcategory:"Credential Validation" /success:enable
    #  Behavior of the elevation prompt for admins in admin approval mode configured to prompt
    Set-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System' -Name 'ConsentPromptBehaviorAdmin' -Value 2
    # Enables SmartScreen on Warn
    Set-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\SmartScreenEnabled' -Name 'SmartScreenEnabled' -Value 'Warn'
    # Remove users from User Rights Assignment
    Write-Output "Check in User Rights Assignment at secpol.msc to make sure there aren't any users in any of them. If there are, remove them."
}

# Turns on Firewall
function Firewall {
    Set-NetFirewallProfile -Profile Domain, Private, Public -Enabled True
    Install-WindowsFeature -Name Windows-Defender-Features -IncludeManagementTools
    Set-Service -Name WinDefend -StartupType Automatic
    Start-Service -Name WinDefend
}

# Disables AutoPlay
function AutoPlay {
    # Disable AutoPlay for all users
    Set-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer' -Name 'NoDriveTypeAutoRun' -Value 255
    # Disable AutoPlay for the current user
    Set-ItemProperty -Path 'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer' -Name 'NoDriveTypeAutoRun' -Value 255
}
# Disable FTP Service
function disFTP {
    Set-Service -Name "FTPSVC" -StartupType Disabled
    Stop-Service -Name "FTPSVC"
}
# Stops unneccessary services
function stopServices {
    Set-Service -Name "W3SVC" -StartupType Disabled
    Stop-Service -Name "W3SVC"
    Get-Process -Name nc, ncat -ErrorAction SilentlyContinue | Stop-Process -Force
}
# Searches for files
function searchFiles {
    Write-Output "Searching for media files..."
    $Extensions = "*.jpg", "*.jpeg", "*.png", "*.tiff", "*.bmp", "*.gif", "*.mp3", "*.wav", "*.ogg", "*.flac", "*.mp4", "*.mov", "*.mkv", "*.txt", "*.docx", "*.doc", "*.xlsx", "*.csv", "*.pptx", "*.psd", "*.pdf", "*.zip", "*.rar", "*.7z", "*.exe", "*.scr", "*.com", "*.msi", "*.bat"
    $SearchPath = "C:\Users"
    Get-ChildItem -Path $SearchPath -Include $Extensions -Recurse -ErrorAction SilentlyContinue -Force
}
# Remove Unnecessary Applications
function removePrograms {
    Write-Output "Removing unnecessary apps..."
    Get-AppxPackage *solitaire* | Remove-AppxPackage
    Get-AppxPackage *xbox* | Remove-AppxPackage
    Get-AppxPackage *3dbuilder* | Remove-AppxPackage
    Get-AppxPackage *onenote* | Remove-AppxPackage
    Write-Output "If this didn't get everything, make sure to check and remove it in Control Panel/Programs."
}
# Disables the guest account
function guestAcc {
    net user guest /active:no
    net user DefaultAccount /active:no
}





# Main Menu
function Show-Menu {
    Clear-Host
    
    Write-Output @"
       %%%%%%%%%%%%%@                                      
     %%%%%%+--#%%@ %%%   @%%%%%%                           
    %%%%+=#*-::%%%%%  %%%@@@@%%%%%%%%%%%                   
   %%%+=%#-+-:-%%%%%@%%% %%%%  %@@% @@ %%                  
   %*++=+++-:-#%%%%%%@%%%%@@ @%  %%%@@@%%                  
   %++++***=:=%%%%+#%*******#%%%%%%%%@@%%                  
    %=##+.+-%:*%##-*+:::+=::::::=%% %%%                    
     %*=::--:=#*=+**::::::=+::::::+*##%%                   
            @%=#*%-:::::::::#+***##%%%%%%                  
          @%=:=-:::::::::::::*   %%%*#+%%%                 
         @#-:::*:::::::::::::*%   %%%%%#%@                 
         %-::::-#-:::::::::**=%@     @@@                   
         @%--:*%  @%+-::-+#*==***%                          
        %+%%%%%      %#==++%+:::+%                         
       %%%#%%#%%      @%%%=---+#%%%                        
        %%%*%%%%    @%%%%*.*%%%%%%%%                       
         @%%%%%   %%%#-=#::%%%%%%%%%%%                     
                %%%%%+::::::---::-%%%%%%                   
                %%%%%%%=:::::::::#%   %%@                  
               @%+-#*..*%%%#*##%%@    @%%                  
             %%%#:::-*%%%%%%%%%%@     %%@                  
  %%#**%%%%%+*%#:-+:::::-==*%%@      %%@                   
    @%*%%%%*::-=#%%%#+-=+%%%        %%                     
       @   %@%%%%%%%%%%%            %%%%%                  
                  %%%%%%            @%%%%                  
 ____       _  _   __     ____  ____   __   _  _ 
(  _ \ ___ ( \/ ) / _\   (_  _)(  __) / _\ ( \/ )
 )   /(___)/ \/ \/    \    )(   ) _) /    \/ \/ \
(__\_)     \_)(_/\_/\_/   (__) (____)\_/\_/\_)(_/

[1] List all Users and Admins
    [1.1] User Management
    [1.2] Group Management
[2] Update Password Requirements
[3] Configure Policies/Audits
[4] Enable Firewall
[5] Disable AutoPlay
[6] Disable FTP service
[7] Disable unneccessary services
[8] Search for files
[9] Remove unneccessary programs
[10] Disable Guest Account
Q to Exit.
"@
}

# Interactive Main Menu
while ($true) {
    Show-Menu
    Write-Output ""
    $selection = Read-Host "Please make a selection"
    Write-Output ""
    Write-Output "--------------------------------------------------------"
    Write-Output ""

    switch ($selection) {
        '1' {
            List-Local
        }
        '1.1' {
            UserMenu
        }
        '1.2' {
            GroupMenu
        }
        '2' {
            UpdatePasswd
        }
        '3' {
            ConfigPolicies
        }
        '4' {
            Firewall
        }
        '5' {
            AutoPlay
        }
        '6' {
            disFTP
        }
        '7' {
            stopServices
        }
        '8' {
            searchFiles
        }
        '9' {
            removePrograms
        }
        '10' {
            guestAcc
        }
        'q' {
            Write-Output 'Exiting...'
            exit
        }
        default {
            'Invalid selection. Please try again.'
        }
    }

    Write-Output ""
    pause
}