# Injected only from the compiled-hash-verified local bundle into the DC worker.
function Fgpp-State([string]$Name){
    $found=@(Get-ADFineGrainedPasswordPolicy -Filter {Name -eq $Name} -Server $cfg.domainController -Properties Description,ProtectedFromAccidentalDeletion -ErrorAction Stop)
    if(!$found.Count){return [ordered]@{exists=$false}}
    if($found.Count -ne 1){Fail 'FGPP_AMBIGUOUS' 'Password policy name is ambiguous.'}
    $p=$found[0]
    $subjects=@(Get-ADFineGrainedPasswordPolicySubject -Identity $p.DistinguishedName -Server $cfg.domainController -ErrorAction Stop|ForEach-Object{[string]$_.DistinguishedName}|Sort-Object)
    return [ordered]@{exists=$true;dn=[string]$p.DistinguishedName;guid=[string]$p.ObjectGUID;name=[string]$p.Name;description=[string]$p.Description;protected=[bool]$p.ProtectedFromAccidentalDeletion;precedence=[int]$p.Precedence;passwordHistoryCount=[int]$p.PasswordHistoryCount;minPasswordLength=[int]$p.MinPasswordLength;minPasswordAgeDays=[int]$p.MinPasswordAge.TotalDays;maxPasswordAgeDays=[int]$p.MaxPasswordAge.TotalDays;complexityEnabled=[bool]$p.ComplexityEnabled;reversibleEncryptionEnabled=[bool]$p.ReversibleEncryptionEnabled;lockoutThreshold=[int]$p.LockoutThreshold;lockoutDurationMinutes=[int]$p.LockoutDuration.TotalMinutes;lockoutObservationWindowMinutes=[int]$p.LockoutObservationWindow.TotalMinutes;subjects=$subjects}
}
function Fgpp-Tag($Request){return 'GpoRemediator FGPP:'+(Hash ([string]$Request.scopeDn).ToLowerInvariant())}
function Fgpp-Membership($Before,$Users,$PreviousUsers,[string]$ScopeDn){
    $subjects=[Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)
    foreach($dn in @(Read-Field $Before 'subjects' @())){$null=$subjects.Add([string]$dn)}
    $desired=[Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)
    foreach($user in @($Users)){$null=$desired.Add([string]$user.dn)}
    $added=@($Users|Where-Object{!$subjects.Contains([string]$_.dn)})
    $removed=@($subjects|Where-Object{!$desired.Contains($_)}|Sort-Object|ForEach-Object{
        @{dn=$_;reason=$(if(!$_.EndsWith(','+$ScopeDn,[StringComparison]::OrdinalIgnoreCase)){'OUTSIDE_SELECTED_OU'}else{'DISABLED_OR_NO_LONGER_DISCOVERED'})}
    })
    $old=@{};foreach($user in @($PreviousUsers)){$old[[string]$user.guid]=$user}
    $now=@{};foreach($user in @($Users)){$now[[string]$user.guid]=$user}
    $moved=@();foreach($id in $now.Keys){if($old.ContainsKey($id) -and [string]$old[$id].dn -ine [string]$now[$id].dn){$moved+=@{name=[string]$now[$id].name;guid=$id;beforeDn=[string]$old[$id].dn;afterDn=[string]$now[$id].dn}}}
    $departed=@();foreach($id in $old.Keys){if(!$now.ContainsKey($id)){$departed+=$old[$id]}}
    return @{currentSubjects=$subjects.Count;desiredUsers=$desired.Count;add=$added;remove=$removed;unchanged=($desired.Count-$added.Count);moved=$moved;departed=$departed;baselineAvailable=($old.Count -gt 0)}
}
function Fgpp-Preview($Request,$PreviousUsers=@()){
    $scope=Scope ([string]$Request.scopeDn)
    if($scope.kind -ne 'OU'){Fail 'FGPP_OU_REQUIRED' 'Choose a user OU.'}
    if([string]$Request.name -notmatch '^[A-Za-z][A-Za-z0-9_.-]{2,63}$'){Fail 'FGPP_VALUES_INVALID' 'Invalid policy name.'}
    $users=@(Get-ADUser -SearchBase $scope.dn -SearchScope Subtree -Filter {Enabled -eq $true} -Server $cfg.domainController -Properties Enabled -ResultSetSize 5001 -ErrorAction Stop|Sort-Object DistinguishedName|ForEach-Object{[ordered]@{dn=[string]$_.DistinguishedName;guid=[string]$_.ObjectGUID;name=[string]$_.SamAccountName}})
    if(!$users.Count){Fail 'FGPP_TARGET_EMPTY' 'No enabled users were found in the selected OU.'}
    if($users.Count -gt 5000){Fail 'FGPP_TARGET_LIMIT' 'Select an OU with at most 5000 enabled users.'}
    $before=Fgpp-State ([string]$Request.name)
    if($before.exists -and [string]$before.description -cne (Fgpp-Tag $Request)){Fail 'FGPP_NOT_MANAGED' 'That policy name already exists outside this managed OU workflow. Choose a new name; existing policies are not adopted or overwritten.'}
    return @{scope=$scope;users=$users;before=$before;membership=(Fgpp-Membership $before $users $PreviousUsers ([string]$scope.dn));fingerprint=(Hash (([ordered]@{request=$Request;before=$before;users=$users}|ConvertTo-Json -Depth 20 -Compress)));warnings=@('This policy is assigned DIRECTLY to the reviewed user snapshot. Review the membership additions/removals before Apply. New or moved users are not silently synchronized.','Other direct password policies with a lower precedence number may win. Apply verifies each user resultant policy.','Creating/editing a PSO needs delegated permissions on the Password Settings Container. GPO Link/Edit settings permissions do not grant PSO authority.','This changes domain-user authentication behavior. It does not change a GPO or computer local-account policy.')}
}
function Fgpp-Parameters($Value){
    return @{Precedence=[int]$Value.precedence;PasswordHistoryCount=[int]$Value.passwordHistoryCount;MinPasswordLength=[int]$Value.minPasswordLength;MinPasswordAge=[timespan]::FromDays([int]$Value.minPasswordAgeDays);MaxPasswordAge=[timespan]::FromDays([int]$Value.maxPasswordAgeDays);ComplexityEnabled=[bool]$Value.complexityEnabled;ReversibleEncryptionEnabled=[bool]$Value.reversibleEncryptionEnabled;LockoutThreshold=[int]$Value.lockoutThreshold;LockoutDuration=[timespan]::FromMinutes([int]$Value.lockoutDurationMinutes);LockoutObservationWindow=[timespan]::FromMinutes([int]$Value.lockoutObservationWindowMinutes);Server=[string]$cfg.domainController;ErrorAction='Stop'}
}
function Fgpp-Subjects([string]$Name,[string[]]$Desired){
    $current=@(Get-ADFineGrainedPasswordPolicySubject -Identity $Name -Server $cfg.domainController -ErrorAction Stop|ForEach-Object{[string]$_.DistinguishedName})
    $remove=@($current|Where-Object{$_ -notin $Desired});$add=@($Desired|Where-Object{$_ -notin $current})
    for($i=0;$i -lt $remove.Count;$i+=100){Remove-ADFineGrainedPasswordPolicySubject -Identity $Name -Subjects @($remove|Select-Object -Skip $i -First 100) -Server $cfg.domainController -Confirm:$false -ErrorAction Stop}
    for($i=0;$i -lt $add.Count;$i+=100){Add-ADFineGrainedPasswordPolicySubject -Identity $Name -Subjects @($add|Select-Object -Skip $i -First 100) -Server $cfg.domainController -ErrorAction Stop}
}
function Fgpp-Directory($Plan){
    if([string]$Plan.id -notmatch '^[a-f0-9]{32}$' -or [string]$Plan.domain -ine [string]$cfg.domain -or [string]$Plan.domainController -ine [string]$cfg.domainController){Fail 'PLAN_CONTEXT_CHANGED' 'Password policy plan context changed.'}
    $directory=Join-Path ([IO.Path]::GetFullPath([string]$cfg.backupPath)) ('PasswordPolicies\'+[string]$Plan.id)
    # Validate every ancestor and an existing manifest before reading or writing.
    # A custom PasswordPolicies junction must not redirect a recovery snapshot.
    for($parent=[IO.DirectoryInfo]::new($directory);$null -ne $parent;$parent=$parent.Parent){
        $entry=Get-Item -LiteralPath $parent.FullName -Force -ErrorAction SilentlyContinue
        if($entry -and ($entry.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0){Fail 'BACKUP_PATH_INVALID' 'Password policy backups cannot use junctions or symbolic links.'}
    }
    $manifest=Get-Item -LiteralPath (Join-Path $directory 'manifest.json') -Force -ErrorAction SilentlyContinue
    if($manifest -and ($manifest.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0){Fail 'BACKUP_PATH_INVALID' 'Password policy manifests cannot use file links.'}
    return $directory
}
function Fgpp-SettingsMatch($Current,$Request){
    if(!$Current.exists){return $false}
    foreach($key in @('precedence','passwordHistoryCount','minPasswordLength','minPasswordAgeDays','maxPasswordAgeDays','complexityEnabled','reversibleEncryptionEnabled','lockoutThreshold','lockoutDurationMinutes','lockoutObservationWindowMinutes')){
        if([string]$Current[$key] -cne [string]$Request.$key){return $false}
    }
    return $true
}
function Fgpp-Execute([string]$Action,$Plan){
    $request=$Plan.request;$name=[string]$request.name;$directory=Fgpp-Directory $Plan;$path=Join-Path $directory 'manifest.json'
    if($Action -eq 'verify'){
        if(!(Test-Path -LiteralPath $path)){Fail 'FGPP_NOT_APPLIED' 'No password policy execution manifest exists.'}
        $m=Get-Content -LiteralPath $path -Raw|ConvertFrom-Json
        if([string]$m.plan.id -cne [string]$Plan.id){Fail 'FGPP_MANIFEST_MISMATCH' 'Password policy manifest does not match the selected plan.'}
        if([string]$m.phase -notin @('PUBLISHED','ROLLED_BACK')){return @{state='REVIEW_REQUIRED';message='The operation was interrupted. Inspect its manifest and live password policy before another write.';backupDirectory=$directory}}
        $current=Fgpp-State $name
        if([string]$m.phase -eq 'ROLLED_BACK'){return @{state=$(if((Hash ($current|ConvertTo-Json -Depth 15 -Compress)) -ceq [string]$m.rollbackFingerprint){'ROLLED_BACK'}else{'DRIFT_DETECTED'});policy=$current;message='Checked the post-rollback password policy fingerprint.'}}
        $same=(Hash ($current|ConvertTo-Json -Depth 15 -Compress)) -ceq [string](Read-Field $m 'postFingerprint' '')
        $results=@();foreach($user in @($Plan.preview.users)){
            try{$p=Get-ADUserResultantPasswordPolicy -Identity ([string]$user.guid) -Server $cfg.domainController -ErrorAction Stop;$results+=@{user=[string]$user.name;state=$(if($p -and [string]$p.Name -ieq $name){'VERIFIED'}else{'OVERRIDDEN'});policy=$(if($p){[string]$p.Name}else{'Default domain policy'})}}
            catch{$results+=@{user=[string]$user.name;state='UNAVAILABLE';policy='Unknown'}}
        }
        return @{state=$(if(!$same){'DRIFT_DETECTED'}elseif(@($results|Where-Object state -ne 'VERIFIED').Count){'POLICY_ASSIGNED_REVIEW_REQUIRED'}else{'VERIFIED'});policy=$current;users=$results;message='Resultant policy checked for every reviewed user on the selected DC. Replication to other DCs may still be pending.';backupDirectory=$directory}
    }
    $null=Test-BackupRepository ([string]$cfg.backupPath)
    $null=[IO.Directory]::CreateDirectory($directory)
    $lockPath=Join-Path ([string]$cfg.backupPath) ('fgpp-'+(Hash $name.ToUpperInvariant())+'.lock');$lock=$null;$manifest=$null
    try{$lock=[IO.File]::Open($lockPath,'OpenOrCreate','ReadWrite','None')}catch{Fail 'FGPP_BUSY' 'Another operation is changing this password policy.'}
    try{
        if($Action -eq 'apply'){
            if(Test-Path -LiteralPath $path){Fail 'FGPP_ALREADY_STARTED' 'This plan already has a manifest. Verify before preparing another approved plan.'}
            $fresh=Fgpp-Preview $request
            if([string]$fresh.fingerprint -cne [string]$Plan.preview.fingerprint){Fail 'FGPP_CHANGED' 'OU membership or the password policy changed after Preview. Generate a fresh plan.'}
            $manifest=[ordered]@{plan=$Plan;before=$fresh.before;phase='BACKED_UP';postFingerprint=$null};Save-Manifest $manifest $directory
            $parameters=Fgpp-Parameters $request
            $manifest.phase='WRITING';Save-Manifest $manifest $directory
            if($fresh.before.exists){Set-ADFineGrainedPasswordPolicy -Identity $name @parameters}
            else{New-ADFineGrainedPasswordPolicy -Name $name -Description (Fgpp-Tag $request) -ProtectedFromAccidentalDeletion $false @parameters}
            Fgpp-Subjects $name @($fresh.users|ForEach-Object{[string]$_.dn})
            $current=Fgpp-State $name
            if(!(Fgpp-SettingsMatch $current $request) -or @($current.subjects).Count -ne @($fresh.users).Count -or @($fresh.users|Where-Object{[string]$_.dn -notin $current.subjects}).Count){Fail 'FGPP_PUBLICATION_MISMATCH' 'Live password policy values or subjects do not match the approved snapshot.'}
            $manifest.postFingerprint=Hash ($current|ConvertTo-Json -Depth 15 -Compress);$manifest.phase='PUBLISHED';Save-Manifest $manifest $directory
            return Fgpp-Execute 'verify' $Plan
        }
        if($Action -ne 'rollback'){Fail 'OPERATION_DENIED' 'Unknown password policy action.'}
        if(!(Test-Path -LiteralPath $path)){Fail 'FGPP_NOT_APPLIED' 'No password policy backup manifest exists.'}
        $manifest=Get-Content -LiteralPath $path -Raw|ConvertFrom-Json
        if([string]$manifest.phase -notin @('PUBLISHED','ROLLED_BACK')){Fail 'FGPP_REVIEW_REQUIRED' 'The interrupted execution needs administrator review.'}
        $expected=if([string]$manifest.phase -eq 'ROLLED_BACK'){[string]$manifest.rollbackFingerprint}else{[string]$manifest.postFingerprint}
        $current=Fgpp-State $name
        if(!$expected -or (Hash ($current|ConvertTo-Json -Depth 15 -Compress)) -cne $expected){Fail 'FGPP_CHANGED' 'Password policy changed externally. Automatic rollback is blocked.'}
        $manifest.phase='ROLLING_BACK';Save-Manifest $manifest $directory
        if($manifest.before.exists){$parameters=Fgpp-Parameters $manifest.before;Set-ADFineGrainedPasswordPolicy -Identity $name @parameters;Fgpp-Subjects $name @($manifest.before.subjects)}
        elseif($current.exists){Remove-ADFineGrainedPasswordPolicy -Identity $name -Server $cfg.domainController -Confirm:$false -ErrorAction Stop}
        $manifest|Add-Member -NotePropertyName rollbackFingerprint -NotePropertyValue (Hash ((Fgpp-State $name)|ConvertTo-Json -Depth 15 -Compress)) -Force
        $manifest.phase='ROLLED_BACK';Save-Manifest $manifest $directory
        return @{state='ROLLED_BACK';message='Previous managed password policy settings/subjects restored, or the policy created by this operation removed.';backupDirectory=$directory}
    }catch{
        if($manifest -and [string]$manifest.phase -in @('WRITING','ROLLING_BACK')){$manifest.phase='REVIEW_REQUIRED';Save-Manifest $manifest $directory;return @{state='REVIEW_REQUIRED';message='Password policy mutation was interrupted. Inspect the retained manifest and live PSO before retrying. PSO creation/editing/subject assignment/deletion require separate AD delegation on the Password Settings Container; GPO Link/Edit rights do not grant it.';backupDirectory=$directory}}
        throw
    }finally{if($lock){$lock.Dispose()}}
}
