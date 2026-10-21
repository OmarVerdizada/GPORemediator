# Standalone GPO procedure. Run in Windows PowerShell 5.1 on the selected writable DC.
# Uses the same mapping writer as the application. No application/API/download required.
& {
    $Action = 'Preview' # Preview is read-only; Apply requires explicit operator confirmation.
    $DomainName = __GR_DOMAIN__
    $DomainController = __GR_DC__
    $GpoId = __GR_GPO__
    $TargetDn = __GR_TARGET__
    $PolicyValue = __GR_VALUE__
    $CustomValue = __GR_CUSTOM__
    $FirstLink = __GR_FIRST__
    $BackupRoot = 'C:\ProgramData\GpoRemediator\Backups' # Local path on this DC.
    $ErrorActionPreference = 'Stop'
    Set-StrictMode -Version Latest
    $map = __GR_MAPPING__ | ConvertFrom-Json

    # Shared, fully visible production implementation. No hidden script imports.
__GR_FUNCTIONS__

    # 1. Validate identity, target and current GPO. Nothing below runs in the UI.
    if($Action -notin @('Preview','Apply')){throw 'Action must be Preview or Apply'}
    foreach($field in @($DomainName,$DomainController,$GpoId,$TargetDn)){
        if([string]::IsNullOrWhiteSpace($field) -or $field -like 'REPLACE_*'){throw 'Fill in Domain, DomainController, GpoId and TargetDn first'}
    }
    $parsedId=[guid]::Empty
    if(![guid]::TryParse($GpoId,[ref]$parsedId)){throw 'GpoId must be a real GPO GUID'}
    Import-Module ActiveDirectory -ErrorAction Stop
    Import-Module GroupPolicy -ErrorAction Stop
    $cfg=@{domain=$DomainName;domainController=$DomainController;backupPath=$BackupRoot}
    $domain=Get-ADDomain -Identity $DomainName -Server $DomainController
    $dc=Get-ADDomainController -Identity $DomainController -Server $DomainController
    if($dc.IsReadOnly -or $dc.Domain -ine $domain.DNSRoot -or $env:COMPUTERNAME -ine ($dc.HostName -split '\.')[0]){
        throw 'Run on the selected writable DC in the selected domain'
    }
    $domainDn=[string]$domain.DistinguishedName
    $s=[pscustomobject]@{gpoId=$GpoId;scopeDn=$TargetDn;setting=$map.id;value=$PolicyValue;customValue=$CustomValue;firstLink=$FirstLink;refresh='None';endpointScopeDn='';verificationUser=''}
    Validate-Selection $s $map
    $null=Assert-VersionSync $GpoId
    $gpo=Get-GPO -Guid $parsedId -Domain $DomainName -Server $DomainController
    $beforeLink=Selected-Link $TargetDn $GpoId
    $preFingerprint=Fingerprint $GpoId $TargetDn
    $linkedScopes=@(All-LinkScopes|Where-Object{Link $_.rawLinks $GpoId $_.dn}|ForEach-Object{$_.dn})
    [pscustomobject]@{Control=$map.id;Domain=$DomainName;DC=$DomainController;GPO=$gpo.DisplayName;GpoId=$GpoId;Target=$TargetDn;Scope=$map.scope;Current=(Mapping-Display $GpoId $map $s);Desired=(Mapping-Display $GpoId $map $s $true);ExistingLinks=($linkedScopes -join '; ');Action=$Action}|Format-List
    Write-Warning 'The GPO change affects every existing link. Read/Apply permissions, WMI, inheritance and winning policy still require review.'
    foreach($warning in @($map.warnings)){Write-Warning $warning}
    if($map.handler -eq 'AdvancedAudit'){
        Write-Warning 'Review control 2.3.2.1: SCENoApplyLegacyAuditPolicy=1 prevents legacy audit policy overriding subcategories. This separate control is not changed.'
        Write-Warning 'The shared audit writer also canonicalizes existing system audit CSV rows without changing their numeric settings. The full backup retains the original file.'
    }
    if($Action -eq 'Preview'){Write-Host 'Read-only preview complete. No backup, GPO write, link change or gpupdate was performed.';return}
    if((Mapping-Matches $GpoId $map $s) -and $beforeLink -and $beforeLink.enabled -and (!$FirstLink -or $beforeLink.order -eq 1)){
        Write-Host 'Selected GPO content and link already match. Endpoint processing is not verified.';return
    }

    # 2. Explicit operator confirmation, exclusive GPO lock, and full backup.
    $confirmation='APPLY '+$map.id+' '+$parsedId.ToString()
    if((Read-Host ('Type exactly: '+$confirmation)) -cne $confirmation){throw 'Cancelled; no changes made'}
    $plan=@{id=[guid]::NewGuid().ToString('N');domain=$DomainName;domainController=$DomainController;selection=$s}
    $directory=Run-Directory $plan
    $null=New-Item -ItemType Directory -Path $directory -Force
    $lock=$null;$writeStarted=$false;$manifest=$null
    try{
        $lock=[IO.File]::Open((Join-Path (Split-Path $directory -Parent) ($parsedId.ToString()+'.lock')),[IO.FileMode]::OpenOrCreate,[IO.FileAccess]::ReadWrite,[IO.FileShare]::None)
        if((Fingerprint $GpoId $TargetDn) -cne $preFingerprint){throw 'GPO or links changed after preview. Start again.'}
        $manifest=[ordered]@{schemaVersion='manual-v1';control=$map.id;domain=$DomainName;domainController=$DomainController;gpoId=$GpoId;targetDn=$TargetDn;beforeLink=$beforeLink;operator=[Security.Principal.WindowsIdentity]::GetCurrent().Name;backupId=$null;directory=$directory;preFingerprint=$preFingerprint;postFingerprint=$null;phase='BACKUP_STARTED'}
        Save-Manifest $manifest $directory
        $backup=Backup-GPO -Guid $parsedId -Path $directory -Domain $DomainName -Server $DomainController -Comment ('Manual CIS '+$map.id)
        if(!$backup -or !$backup.Id){throw 'Backup did not return an ID; refusing to write'}
        $manifest.backupId=$backup.Id.ToString();$manifest.phase='BACKED_UP';Save-Manifest $manifest $directory
        Write-Host ('Backup ID: '+$manifest.backupId+' | Path: '+$directory)
        if((Fingerprint $GpoId $TargetDn) -cne $preFingerprint){throw 'GPO or links changed during backup; no policy write started'}
        $null=Assert-VersionSync $GpoId

        # 3. Same selected-control writer as the tool. Preserve unrelated settings.
        $writeStarted=$true;$manifest.phase='WRITING';Save-Manifest $manifest $directory
        $null=Write-Mapping $plan $map
        $linkParameters=@{Guid=$parsedId;Target=$TargetDn;Domain=$DomainName;Server=$DomainController;LinkEnabled='Yes'}
        if($FirstLink){$linkParameters.Order=1}
        if($null -eq $beforeLink){New-GPLink @linkParameters|Out-Null}else{Set-GPLink @linkParameters|Out-Null}

        # 4. Read back GPO content and link. This does not certify endpoint enforcement.
        $afterLink=Selected-Link $TargetDn $GpoId
        $null=Assert-VersionSync $GpoId
        if(!(Mapping-Matches $GpoId $map $s) -or !$afterLink -or !$afterLink.enabled -or ($FirstLink -and $afterLink.order -ne 1)){
            throw 'GPO content/link read-back did not match. Inspect the retained full backup and manifest.'
        }
        $manifest.postFingerprint=Fingerprint $GpoId $TargetDn;$manifest.phase='GPO_VERIFIED';Save-Manifest $manifest $directory
        [pscustomobject]@{Control=$map.id;GpoId=$GpoId;GpoValue=(Mapping-Display $GpoId $map $s);GpoLink='Enabled';BackupId=$manifest.backupId;Manifest=(Join-Path $directory 'manifest.json');Endpoint='NOT_TESTED';Refresh='NOT_REQUESTED'}|Format-List
        Write-Host 'GPO read-back completed. Run the separate endpoint check after policy processing. Manual results are not application history.'
    }catch{
        $failure=$_
        if($manifest){
            $manifest.phase=if($writeStarted){'REVIEW_REQUIRED'}else{'FAILED_SAFE'}
            try{Save-Manifest $manifest $directory}catch{Write-Warning 'Could not save the failure manifest; retain the printed backup path'}
        }
        Write-Warning ('Stopped. Inspect '+$directory+'. Partial writes are possible after WRITING. A GPO backup does not restore OU links; beforeLink is recorded in the manifest. No automatic restore or gpupdate was attempted.')
        throw $failure
    }finally{if($lock){$lock.Dispose()}}
}
