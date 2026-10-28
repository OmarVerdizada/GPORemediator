$ErrorActionPreference='Stop'
$repo=Split-Path $PSScriptRoot -Parent
Import-Module (Join-Path $PSScriptRoot 'ReleasePackage.psm1') -Force
[xml]$project=Get-Content (Join-Path $repo 'backend/GpoRemediator.csproj') -Raw
$version=[string]($project.Project.PropertyGroup|Where-Object{$_.Version}|Select-Object -First 1).Version
$entries=@();$text=@('.cs','.csproj','.json','.ps1','.psm1','.js','.cjs','.css','.html','.md','.txt','.xml','.py','.yml','.yaml','.csv','.tsv','.sha256','.inf','.mof','.admx','.adml','.reg','.config')
$files=@(Get-ChildItem -LiteralPath $repo -File|Where-Object{$_.Extension -in @('.ps1','.cmd') -or $_.Name -eq 'README.md'})
foreach($folder in @('backend','frontend','scripts','security','release')){
    $files+=@(Get-ChildItem -LiteralPath (Join-Path $repo $folder) -Recurse -File|Where-Object{
        $relative=$_.FullName.Substring($repo.Length+1).Replace('\','/')
        $relative -notmatch '(^|/)(bin|obj|node_modules|__pycache__|\.git)/|\.py[co]$|appsettings\.Local\.json$|^release/package-files\.json$' -and
        ($relative -notmatch '^backend/data/' -or $_.Name -in @('benchmark.json','gpo-production-mappings.json') -or $relative -like 'backend/data/mapping_sources/*')
    })
}
foreach($file in @($files|Sort-Object FullName -Unique)){
    $mode=if($file.Extension.ToLowerInvariant() -in $text){'text-lf'}else{'binary'}
    $entries+=@{path=$file.FullName.Substring($repo.Length+1).Replace('\','/');mode=$mode;sha256=(Get-PackageHash $file.FullName ($mode -eq 'text-lf'))}
}
$manifest=@{product='GPO Remediator';format=1;version=$version;stateSchema='3.1.2';files=$entries}
[IO.File]::WriteAllText((Join-Path $repo 'release/package-files.json'),($manifest|ConvertTo-Json -Depth 8),[Text.UTF8Encoding]::new($false))
Write-Output ('Release manifest: '+$version+' / '+$entries.Count+' verified application components.')
