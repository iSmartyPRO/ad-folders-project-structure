Function Get-BySID {
    Param(
        [string]$SID
    )
    $SIDValue = New-Object System.Security.Principal.SecurityIdentifier($SID)
    $objUser = $SIDValue.Translate([System.Security.Principal.NTAccount])
    return $objUser.value
}

Function Test-AdminRights {
    $currentPrincipal = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
    return $currentPrincipal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}
Function Test-Module {
    param(
        [string]$Name
    )
    if (Get-Module -ListAvailable -Name $Name) {
        $result = $true
    } else {
        $result = $false
    }
    return $result
}
Function Test-ADOU {
    param([string]$dn)
    if(Get-ADOrganizationalUnit -Filter * | Where-Object {$_.DistinguishedName -eq $dn}){
        $result = $true
    } else {
        $result = $false
    }
    return $result
}

Function Test-ADGroup {
    param([string]$Name)
    if(Get-ADGroup -Filter * | Where-Object {$_.Name -eq $name}){
        $result = $true
    } else {
        $result = $false
    }
    return $result
}


Function New-ProjectStructure {
    param(
        [string]$JsonConfig = "FolderStructure.json"
    )
    if(!(Test-AdminRights)){
        Write-Host "Script require admin rights!" -ForegroundColor Red
        Write-Host "Try this: Start-Process powershell -Verb runas" -ForegroundColor Yellow
        Break;
    }
    if(!(Test-Module -Name "activedirectory")) {
        Write-Host "Active Directory module is missing!" -ForegroundColor Red
        Break;
    }
    $currentUser = $env:username
    $rootDn = (Get-ADDomain -Current LoggedOnUser).DistinguishedName
    $config = Get-Content -Path $JsonConfig | ConvertFrom-Json
    $folders = $config.folders

    Write-Host "Creating OU Structure in Active DIrectory" -ForegroundColor Green
    if(!(Test-ADOU -dn "OU=Accounts,$rootDn")){
        Write-Host "-- Creating: OU=Accounts,$rootDn" -ForegroundColor Magenta
        New-ADOrganizationalUnit -Name "Accounts" -Path $rootDn
    } else {
        Write-Host "-- Already exist: OU=Accounts,$rootDn" -ForegroundColor Yellow
    }
    if(!(Test-ADOU -dn "OU=$($config.project),OU=Accounts,$rootDn")){
        Write-Host "-- Creating: OU=$($config.project),OU=Accounts,$rootDn" -ForegroundColor Magenta
        New-ADOrganizationalUnit -Name $config.project -Path "OU=Accounts,$rootDn"
    } else {
        Write-Host "-- Already exist: OU=$($config.project),OU=Accounts,$rootDn" -ForegroundColor Yellow
    }
    if(!(Test-ADOU -dn "OU=Users,OU=$($config.project),OU=Accounts,$rootDn")){
        Write-Host "-- Creating: OU=Users,OU=$($config.project),OU=Accounts,$rootDn" -ForegroundColor Magenta
        New-ADOrganizationalUnit -Name "Users" -Path "OU=$($config.project),OU=Accounts,$rootDn"
    } else {
        Write-Host "-- Already exist: OU=Users,OU=$($config.project),OU=Accounts,$rootDn" -ForegroundColor Yellow
    }
    if(!(Test-ADOU -dn "OU=Groups,OU=$($config.project),OU=Accounts,$rootDn")){
        Write-Host "-- Creating: OU=Groups,OU=$($config.project),OU=Accounts,$rootDn" -ForegroundColor Magenta
        New-ADOrganizationalUnit -Name "Groups" -Path "Ou=$($config.project),OU=Accounts,$rootDn"
    } else {
        Write-Host "-- Already exist: OU=Groups,OU=$($config.project),OU=Accounts,$rootDn" -ForegroundColor Yellow
    }
    if(!(Test-ADOU -dn "OU=Computers,OU=$($config.project),OU=Accounts,$rootDn")){
        Write-Host "-- Creating: OU=Computers,OU=$($config.project),OU=Accounts,$rootDn" -ForegroundColor Magenta
        New-ADOrganizationalUnit -Name "Computers" -Path "OU=$($config.project),OU=Accounts,$rootDn"
    } else {
        Write-Host "-- Already exist: OU=Computers,OU=$($config.project),OU=Accounts,$rootDn" -ForegroundColor Yellow
    }


    Write-Host "`nCreating Security Groups" -ForegroundColor Green
    if(!(Test-ADGroup -Name "sg_$($config.projectPrefix)_root_full")){
        New-ADGroup -DisplayName "sg_$($config.projectPrefix)_root_full" -Name "sg_$($config.projectPrefix)_root_full" -GroupScope Global -Path "OU=Groups,OU=$($config.project),OU=Accounts,$rootDn" -Description "$($config.descriptionFolder);Full Access"
        Write-Host "-- Group Created: sg_$($config.projectPrefix)_root_full" -ForegroundColor Magenta
    } else {
        Write-Host "-- Already exist: sg_$($config.projectPrefix)_root_full" -ForegroundColor Yellow
    }
    if(!(Test-ADGroup -Name "sg_$($config.projectPrefix)_root_read")){
        New-ADGroup -DisplayName "sg_$($config.projectPrefix)_root_read" -Name "sg_$($config.projectPrefix)_root_read" -GroupScope Global -Path "OU=Groups,OU=$($config.project),OU=Accounts,$rootDn" -Description "$($config.descriptionFolder);Read Only"
        Write-Host "-- Group Created: sg_$($config.projectPrefix)_root_read" -ForegroundColor Magenta
    } else {
        Write-Host "-- Already exist: sg_$($config.projectPrefix)_root_read" -ForegroundColor Yellow
    }
    foreach($f in $folders) {
        if(!(Test-ADGroup -Name "sg_$($config.projectPrefix)_$($f.sgName)_full")){
            New-ADGroup -DisplayName "sg_$($config.projectPrefix)_$($f.sgName)_full" -Name "sg_$($config.projectPrefix)_$($f.sgName)_full" -GroupScope Global -Path "OU=Groups,OU=$($config.project),OU=Accounts,$rootDn" -Description "$($config.descriptionFolder)\$($f.name);Full Access"
            Write-Host "-- Group Created: sg_$($config.projectPrefix)_$($f.sgName)_full" -ForegroundColor Magenta
        } else {
            Write-Host "-- Already exist: sg_$($config.projectPrefix)_$($f.sgName)_full" -ForegroundColor Yellow
        }
        if(!(Test-ADGroup -Name "sg_$($config.projectPrefix)_$($f.sgName)_read")){
            New-ADGroup -DisplayName "sg_$($config.projectPrefix)_$($f.sgName)_read" -Name "sg_$($config.projectPrefix)_$($f.sgName)_read" -GroupScope Global -Path "OU=Groups,OU=$($config.project),OU=Accounts,$rootDn" -Description "$($config.descriptionFolder)\$($f.name);Read Only"
            Write-Host "-- Group Created: sg_$($config.projectPrefix)_$($f.sgName)_read" -ForegroundColor Magenta
        } else {
            Write-Host "-- Already exist: sg_$($config.projectPrefix)_$($f.sgName)_read" -ForegroundColor Yellow
        }
    }

    Write-Host "`nCreating folders" -ForegroundColor Green
    foreach($f in $folders) {
        if(!(Test-Path -Path "$($config.projectFolder)\$($f.name)")) {
            New-Item -Path "$($config.projectFolder)\$($f.name)" -ItemType Directory | Out-Null
            Write-Host "-- Created: $($config.projectFolder)\$($f.name)" -ForegroundColor Magenta
        } else {
            Write-Host "-- Already exist: $($config.projectFolder)\$($f.name)" -ForegroundColor Yellow
        }
    }

    Write-Host "`nDisable inheritanse and apply permissions" -ForegroundColor Green
    foreach($f in $config.folders) {
        if(((Get-Acl -Path "$($config.projectFolder)\$($f.name)").Access | Where-Object {$_.IsInherited -eq $true}).Count -gt 0){
            $acl = Get-Acl -Path "$($config.projectFolder)\$($f.name)"
            $acl.SetAccessRuleProtection($true,$false)
            $ruleCurrentUser = New-Object System.Security.AccessControl.FileSystemAccessRule($currentUser, "FullControl", "Allow");
            $acl.SetAccessRule($ruleCurrentUser);
            $ruleOwner = New-Object System.Security.AccessControl.FileSystemAccessRule((Get-BySID -SID "S-1-3-0"), "FullControl", "ContainerInherit,ObjectInherit","None", "Allow");
            $acl.SetAccessRule($ruleOwner);
            $ruleAdmin = New-Object System.Security.AccessControl.FileSystemAccessRule((Get-BySID -SID "S-1-5-32-544"), "FullControl", "ContainerInherit,ObjectInherit","None", "Allow");
            $acl.SetAccessRule($ruleAdmin);
            $ruleSystem = New-Object System.Security.AccessControl.FileSystemAccessRule((Get-BySID -SID "S-1-5-18"), "FullControl", "ContainerInherit,ObjectInherit","None", "Allow");
            $acl.SetAccessRule($ruleSystem);
            $ruleSgFull = New-Object System.Security.AccessControl.FileSystemAccessRule("sg_$($config.projectPrefix)_$($f.sgName)_full", "Modify", "ContainerInherit,ObjectInherit","None", "Allow");
            $acl.SetAccessRule($ruleSgFull);
            $ruleSgRead = New-Object System.Security.AccessControl.FileSystemAccessRule("sg_$($config.projectPrefix)_$($f.sgName)_read", "ReadAndExecute", "ContainerInherit,ObjectInherit","None", "Allow");
            $acl.SetAccessRule($ruleSgRead);
            $ruleRootFull = New-Object System.Security.AccessControl.FileSystemAccessRule("sg_$($config.projectPrefix)_root_full", "Modify", "ContainerInherit,ObjectInherit","None", "Allow");
            $acl.SetAccessRule($ruleRootFull);
            $ruleRootRead = New-Object System.Security.AccessControl.FileSystemAccessRule("sg_$($config.projectPrefix)_root_read", "ReadAndExecute", "ContainerInherit,ObjectInherit","None", "Allow");
            $acl.SetAccessRule($ruleRootRead);
            $acl | Set-Acl -Path "$($config.projectFolder)\$($f.name)"
            Write-Host "-- Permissions applied for: $($f.name)" -ForegroundColor Magenta
        } else {
            Write-Host "-- Already done (skipped): $($f.name)" -ForegroundColor Yellow
        }
    }

    Write-Host "`nCreating Scans folder" -ForegroundColor Green
    foreach($f in $folders) {
        if($f.scans) {
            if(!(Test-Path -Path "$($config.projectFolder)\$($f.name)\!_Scans")) {
                New-Item -Path "$($config.projectFolder)\$($f.name)\!_Scans" -ItemType Directory | Out-Null
                $acl = Get-Acl -Path "$($config.projectFolder)\$($f.name)\!_Scans"

                $acl.SetAccessRuleProtection($true,$false)
                $ruleCurrentUser = New-Object System.Security.AccessControl.FileSystemAccessRule($currentUser, "FullControl", "Allow");
                $acl.SetAccessRule($ruleCurrentUser);
                $ruleOwner = New-Object System.Security.AccessControl.FileSystemAccessRule((Get-BySID -SID "S-1-3-0"), "FullControl", "ContainerInherit,ObjectInherit","None", "Allow");
                $acl.SetAccessRule($ruleOwner);
                $ruleAdmin = New-Object System.Security.AccessControl.FileSystemAccessRule((Get-BySID -SID "S-1-5-32-544"), "FullControl", "ContainerInherit,ObjectInherit","None", "Allow");
                $acl.SetAccessRule($ruleAdmin);
                $ruleSystem = New-Object System.Security.AccessControl.FileSystemAccessRule((Get-BySID -SID "S-1-5-18"), "FullControl", "ContainerInherit,ObjectInherit","None", "Allow");
                $acl.SetAccessRule($ruleSystem);
                $ruleSgFull = New-Object System.Security.AccessControl.FileSystemAccessRule("sg_$($config.projectPrefix)_$($f.sgName)_full", "Modify", "ContainerInherit,ObjectInherit","None", "Allow");
                $acl.SetAccessRule($ruleSgFull);
                $ruleRootFull = New-Object System.Security.AccessControl.FileSystemAccessRule("sg_$($config.projectPrefix)_root_full", "Modify", "ContainerInherit,ObjectInherit","None", "Allow");
                $acl.SetAccessRule($ruleRootFull);
                $ruleRootRead = New-Object System.Security.AccessControl.FileSystemAccessRule("sg_$($config.projectPrefix)_root_read", "ReadAndExecute", "ContainerInherit,ObjectInherit","None", "Allow");
                $acl.SetAccessRule($ruleRootRead);
                $acl | Set-Acl -Path "$($config.projectFolder)\$($f.name)\!_Scans"
                Write-Host "-- Created: $($config.projectFolder)\$($f.name)\!_Scans" -ForegroundColor Magenta
            } else {
                Write-Host "-- Already exist: $($config.projectFolder)\$($f.name)\!_Scans" -ForegroundColor Yellow
            }
        }
    }
}