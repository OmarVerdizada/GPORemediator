param([ValidateRange(1024,65535)][int]$Port = 5080, [switch]$SmokeTest)
$ErrorActionPreference = 'Stop'
$windowsModules = Join-Path $env:SystemRoot 'System32\WindowsPowerShell\v1.0\Modules'
$env:PSModulePath = "$windowsModules;" + (($env:PSModulePath -split ';' | Where-Object { $_ -ine $windowsModules }) -join ';')
Add-Type -AssemblyName PresentationFramework,PresentationCore,WindowsBase
. (Join-Path $PSScriptRoot 'scripts\ServiceControl.ps1')

$projectRoot = $PSScriptRoot
$stateRoot = Join-Path $env:ProgramData 'GpoRemediator'
$work = Join-Path $stateRoot 'State'
$localConfig = Join-Path $stateRoot 'Config\appsettings.Local.json'
$runtimeExe = Join-Path $projectRoot 'runtime\GpoRemediator.exe'
$runtimeMarker = Join-Path $projectRoot 'runtime\production-backend-v4.ready'
$releaseArchive = Join-Path $projectRoot 'release\GpoRemediator-runtime-win-x64.zip'
$releaseHash = $releaseArchive + '.sha256'
New-Item -ItemType Directory -Path $work -Force | Out-Null

function Test-VerifiedReleaseArchive {
    try {
        if (!(Test-Path -LiteralPath $releaseArchive) -or !(Test-Path -LiteralPath $releaseHash)) { return $false }
        $expected=(Get-Content -LiteralPath $releaseHash -Raw -Encoding ASCII).Trim()
        if ($expected -notmatch '^[A-Fa-f0-9]{64}$') { return $false }
        $actual=(Get-FileHash -LiteralPath $releaseArchive -Algorithm SHA256).Hash
        return $actual -ceq $expected.ToUpperInvariant()
    } catch { return $false }
}
$script:releaseReady = Test-VerifiedReleaseArchive

[xml]$layout = @'
<Window xmlns="http://schemas.microsoft.com/winfx/2006/xaml/presentation"
        xmlns:x="http://schemas.microsoft.com/winfx/2006/xaml"
        Title="GPO Remediator — Policy Operations Control Center"
        Width="1280" Height="850" MinWidth="1000" MinHeight="720"
        WindowStartupLocation="CenterScreen" Background="#F4F5FC"
        FontFamily="Segoe UI Variable, Segoe UI" FontSize="13"
        UseLayoutRounding="True" SnapsToDevicePixels="True">
  <Window.Resources>
    <LinearGradientBrush x:Key="NavGradient" StartPoint="0,0" EndPoint="1,1"><GradientStop Color="#2B2851" Offset="0"/><GradientStop Color="#151B32" Offset="1"/></LinearGradientBrush>
    <LinearGradientBrush x:Key="AccentGradient" StartPoint="0,0" EndPoint="1,1"><GradientStop Color="#8475F3" Offset="0"/><GradientStop Color="#5956DB" Offset="1"/></LinearGradientBrush>
    <SolidColorBrush x:Key="Ink" Color="#242941"/>
    <SolidColorBrush x:Key="Muted" Color="#69718B"/>
    <SolidColorBrush x:Key="Line" Color="#E5E7F2"/>
    <SolidColorBrush x:Key="Brand" Color="#7064E7"/>
    <SolidColorBrush x:Key="BrandDark" Color="#5956DB"/>
    <Style TargetType="Button" x:Key="BaseButton">
      <Setter Property="Height" Value="40"/><Setter Property="Padding" Value="16,0"/><Setter Property="Margin" Value="0,0,9,0"/>
      <Setter Property="HorizontalContentAlignment" Value="Center"/><Setter Property="Foreground" Value="#344054"/><Setter Property="Background" Value="#FFFFFF"/><Setter Property="BorderBrush" Value="#D8E0EA"/><Setter Property="BorderThickness" Value="1"/>
      <Setter Property="FontWeight" Value="SemiBold"/><Setter Property="FontSize" Value="12"/><Setter Property="Cursor" Value="Hand"/>
      <Setter Property="Template"><Setter.Value><ControlTemplate TargetType="Button"><Border x:Name="B" Background="{TemplateBinding Background}" BorderBrush="{TemplateBinding BorderBrush}" BorderThickness="{TemplateBinding BorderThickness}" CornerRadius="10"><ContentPresenter Margin="{TemplateBinding Padding}" HorizontalAlignment="{TemplateBinding HorizontalContentAlignment}" VerticalAlignment="Center"/></Border><ControlTemplate.Triggers><Trigger Property="IsMouseOver" Value="True"><Setter TargetName="B" Property="Opacity" Value="0.85"/></Trigger><Trigger Property="IsKeyboardFocused" Value="True"><Setter TargetName="B" Property="BorderBrush" Value="#A99AFF"/><Setter TargetName="B" Property="BorderThickness" Value="2"/></Trigger><Trigger Property="IsPressed" Value="True"><Setter TargetName="B" Property="Opacity" Value="0.86"/></Trigger><Trigger Property="IsEnabled" Value="False"><Setter Property="Opacity" Value="0.38"/><Setter Property="Cursor" Value="Arrow"/></Trigger></ControlTemplate.Triggers></ControlTemplate></Setter.Value></Setter>
    </Style>
    <Style TargetType="Button" x:Key="PrimaryButton" BasedOn="{StaticResource BaseButton}"><Setter Property="Foreground" Value="#FFFFFF"/><Setter Property="Background" Value="{StaticResource AccentGradient}"/><Setter Property="BorderBrush" Value="#7064E7"/><Setter Property="Height" Value="44"/><Setter Property="Padding" Value="20,0"/></Style>
    <Style TargetType="Button" x:Key="DangerButton" BasedOn="{StaticResource BaseButton}"><Setter Property="Foreground" Value="#B4232D"/><Setter Property="BorderBrush" Value="#F2CDD1"/><Setter Property="Background" Value="#FFF8F8"/></Style>
    <Style TargetType="Button" x:Key="SideButton" BasedOn="{StaticResource BaseButton}"><Setter Property="Foreground" Value="#C4C8E2"/><Setter Property="Background" Value="#242943"/><Setter Property="BorderBrush" Value="#3E4668"/><Setter Property="Margin" Value="0,0,0,8"/><Setter Property="HorizontalContentAlignment" Value="Left"/></Style>
    <Style TargetType="ComboBox"><Setter Property="Height" Value="34"/><Setter Property="Padding" Value="8,0"/><Setter Property="VerticalContentAlignment" Value="Center"/><Setter Property="BorderBrush" Value="#D7E0E9"/><Setter Property="Background" Value="#FFFFFF"/></Style>
    <Style TargetType="TextBox" x:Key="FilterBox"><Setter Property="Height" Value="34"/><Setter Property="Padding" Value="10,5"/><Setter Property="BorderBrush" Value="#D7E0E9"/><Setter Property="Background" Value="#FFFFFF"/><Setter Property="VerticalContentAlignment" Value="Center"/></Style>
  </Window.Resources>

  <Grid>
    <Grid.ColumnDefinitions><ColumnDefinition Width="248"/><ColumnDefinition Width="*"/></Grid.ColumnDefinitions>

    <Border Grid.Column="0" Background="{StaticResource NavGradient}">
      <Grid Margin="24,26,24,22">
        <Grid.RowDefinitions><RowDefinition Height="Auto"/><RowDefinition Height="28"/><RowDefinition Height="Auto"/><RowDefinition Height="22"/><RowDefinition Height="Auto"/><RowDefinition Height="*"/><RowDefinition Height="Auto"/></Grid.RowDefinitions>
        <StackPanel>
          <StackPanel Orientation="Horizontal">
            <Border Width="34" Height="34" Background="#7064E7" CornerRadius="9" Margin="0,0,11,0"><TextBlock Text="G" Foreground="White" FontSize="17" FontWeight="Bold" HorizontalAlignment="Center" VerticalAlignment="Center"/></Border>
            <StackPanel VerticalAlignment="Center"><TextBlock Text="GPO REMEDIATOR" Foreground="#F2F8FC" FontSize="15" FontWeight="Bold"/><TextBlock Text="POLICY OPERATIONS CONTROL" Foreground="#A6ADCC" FontSize="10" FontWeight="SemiBold" Margin="0,4,0,0"/></StackPanel>
          </StackPanel>
        </StackPanel>

        <StackPanel Grid.Row="2">
          <TextBlock Text="SERVICE STATUS" Foreground="#959EBF" FontSize="10" FontWeight="Bold" Margin="0,0,0,10"/>
          <Border Background="#242943" BorderBrush="#3E4668" BorderThickness="1" CornerRadius="16" Padding="14">
            <StackPanel>
              <StackPanel Orientation="Horizontal"><Ellipse Name="StatusDot" Width="10" Height="10" Fill="#94A3B8" Margin="0,4,9,0"/><TextBlock Name="Status" Text="Ready" Foreground="#F3F8FC" FontWeight="SemiBold" FontSize="13"/></StackPanel>
              <TextBlock Name="Environment" Text="Automatic" Foreground="#BDC3DF" FontSize="10" Margin="19,6,0,0" TextWrapping="Wrap"/>
              <TextBlock Name="Address" Text="Local service is stopped" Foreground="#A4ADCD" FontSize="10" Margin="19,5,0,0" TextWrapping="Wrap"/>
            </StackPanel>
          </Border>
        </StackPanel>

        <StackPanel Grid.Row="4">
          <TextBlock Text="SESSION" Foreground="#959EBF" FontSize="10" FontWeight="Bold" Margin="0,0,0,10"/>
          <Border Background="#242943" CornerRadius="10" Padding="13"><Grid><Grid.ColumnDefinitions><ColumnDefinition Width="*"/><ColumnDefinition Width="Auto"/></Grid.ColumnDefinitions><StackPanel><TextBlock Name="TopMode" Text="READY" Foreground="#C4B8FF" FontSize="10" FontWeight="Bold"/><TextBlock TextWrapping="Wrap" Text="Loopback · Windows auth" Foreground="#A4ADCD" FontSize="10" Margin="0,4,0,0"/></StackPanel><Border Grid.Column="1" Background="#38365B" CornerRadius="16" Padding="8,4" VerticalAlignment="Center"><TextBlock Text="LOCAL" Foreground="#C4B8FF" FontSize="10" FontWeight="Bold"/></Border></Grid></Border>
        </StackPanel>

        <StackPanel Grid.Row="6">
          <Button Name="Repair" Content="Reinstall verified runtime" Style="{StaticResource SideButton}"/>
          <Button Name="CopyStatus" Content="Copy service summary" Style="{StaticResource SideButton}"/>
          <Button Name="Logs" Content="Open diagnostics folder" Style="{StaticResource SideButton}" Margin="0"/>
          <TextBlock Text="No SDK is required for normal startup or runtime repair." Foreground="#A4ADCD" FontSize="10" TextWrapping="Wrap" Margin="2,10,2,0"/>
        </StackPanel>
      </Grid>
    </Border>

    <Grid Grid.Column="1" Margin="28,26,28,24">
      <Grid.RowDefinitions><RowDefinition Height="Auto"/><RowDefinition Height="18"/><RowDefinition Height="108"/><RowDefinition Height="16"/><RowDefinition Height="Auto"/><RowDefinition Height="16"/><RowDefinition Height="*"/></Grid.RowDefinitions>

      <Grid>
        <Grid.ColumnDefinitions><ColumnDefinition Width="*"/><ColumnDefinition Width="Auto"/></Grid.ColumnDefinitions>
        <StackPanel>
          <TextBlock Text="LOCAL CONTROL CENTER" Foreground="#7064E7" FontSize="10" FontWeight="Bold"/>
          <TextBlock Text="Your policy workspace" Foreground="#242941" FontSize="28" FontWeight="SemiBold" Margin="0,5,0,0"/>
          <TextBlock TextWrapping="Wrap" Text="Start your workspace, check service health, and review diagnostics." Foreground="#718096" FontSize="11" Margin="0,6,0,0"/>
        </StackPanel>
        <Border Grid.Column="1" Background="#EFEDFF" BorderBrush="#DDD7FA" BorderThickness="1" CornerRadius="17" Padding="12,7" VerticalAlignment="Top"><TextBlock Text="LOCAL MANAGEMENT" Foreground="#5956DB" FontSize="10" FontWeight="Bold"/></Border>
      </Grid>

      <Grid Grid.Row="2">
        <Grid.ColumnDefinitions><ColumnDefinition Width="*"/><ColumnDefinition Width="12"/><ColumnDefinition Width="*"/><ColumnDefinition Width="12"/><ColumnDefinition Width="*"/></Grid.ColumnDefinitions>
        <Border Background="White" BorderBrush="{StaticResource Line}" BorderThickness="1" CornerRadius="16" Padding="16">
          <Grid><Grid.RowDefinitions><RowDefinition Height="Auto"/><RowDefinition Height="*"/></Grid.RowDefinitions><Grid><Grid.ColumnDefinitions><ColumnDefinition Width="*"/><ColumnDefinition Width="Auto"/></Grid.ColumnDefinitions><TextBlock Text="RUNTIME" Foreground="#8A98A8" FontSize="10" FontWeight="Bold"/><Ellipse Name="RuntimeDot" Grid.Column="1" Width="8" Height="8" Fill="#94A3B8" Margin="6,2,0,0"/></Grid><StackPanel Grid.Row="1" Margin="0,8,0,0"><TextBlock Name="RuntimeState" Text="Checking" Foreground="{StaticResource Ink}" FontSize="15" FontWeight="SemiBold"/><TextBlock Name="RuntimeDetail" Text="Verifying packaged runtime" Foreground="{StaticResource Muted}" FontSize="10" Margin="0,5,0,0" TextWrapping="Wrap"/></StackPanel></Grid>
        </Border>
        <Border Grid.Column="2" Background="White" BorderBrush="{StaticResource Line}" BorderThickness="1" CornerRadius="16" Padding="16">
          <Grid><Grid.RowDefinitions><RowDefinition Height="Auto"/><RowDefinition Height="*"/></Grid.RowDefinitions><Grid><Grid.ColumnDefinitions><ColumnDefinition Width="*"/><ColumnDefinition Width="Auto"/></Grid.ColumnDefinitions><TextBlock Text="DOMAIN CONFIG" Foreground="#8A98A8" FontSize="10" FontWeight="Bold"/><Ellipse Name="ConfigDot" Grid.Column="1" Width="8" Height="8" Fill="#94A3B8" Margin="6,2,0,0"/></Grid><StackPanel Grid.Row="1" Margin="0,8,0,0"><TextBlock Name="ConfigState" Text="Checking" Foreground="{StaticResource Ink}" FontSize="15" FontWeight="SemiBold"/><TextBlock Name="ConfigDetail" Text="No saved configuration" Foreground="{StaticResource Muted}" FontSize="10" Margin="0,5,0,0" TextWrapping="Wrap"/></StackPanel></Grid>
        </Border>
        <Border Grid.Column="4" Background="White" BorderBrush="{StaticResource Line}" BorderThickness="1" CornerRadius="16" Padding="16">
          <Grid><Grid.RowDefinitions><RowDefinition Height="Auto"/><RowDefinition Height="*"/></Grid.RowDefinitions><Grid><Grid.ColumnDefinitions><ColumnDefinition Width="*"/><ColumnDefinition Width="Auto"/></Grid.ColumnDefinitions><TextBlock Text="EXECUTION" Foreground="#8A98A8" FontSize="10" FontWeight="Bold"/><Ellipse Name="ModeDot" Grid.Column="1" Width="8" Height="8" Fill="#94A3B8" Margin="6,2,0,0"/></Grid><StackPanel Grid.Row="1" Margin="0,8,0,0"><TextBlock Name="ModeState" Text="AUTO" Foreground="{StaticResource Ink}" FontSize="15" FontWeight="SemiBold"/><TextBlock Name="ModeDetail" Text="Service is not running" Foreground="{StaticResource Muted}" FontSize="10" Margin="0,5,0,0" TextWrapping="Wrap"/></StackPanel></Grid>
        </Border>
      </Grid>

      <Border Grid.Row="4" Name="NoticeBorder" Background="#FFFFFF" BorderBrush="{StaticResource Line}" BorderThickness="1" CornerRadius="16" Padding="18,16">
        <Grid>
          <Grid.RowDefinitions><RowDefinition Height="Auto"/><RowDefinition Height="18"/><RowDefinition Height="Auto"/></Grid.RowDefinitions>
          <StackPanel VerticalAlignment="Center"><TextBlock Text="SERVICE CONTROL" Foreground="#8A98A8" FontSize="10" FontWeight="Bold"/><TextBlock Name="Message" Text="Ready to start. The browser workspace opens automatically after the service is healthy." Foreground="#344054" FontSize="12" FontWeight="SemiBold" Margin="0,6,18,0" TextWrapping="Wrap"/><TextBlock TextWrapping="Wrap" Text="AD preflight checks DNS/SRV, Kerberos, LDAP, SYSVOL, WinRM, DC modules and time without policy changes." Foreground="#7B8998" FontSize="10" Margin="0,5,18,0"/></StackPanel>
          <WrapPanel Grid.Row="2" Orientation="Horizontal" VerticalAlignment="Center">
            <Button Name="Preflight" Content="AD preflight" Style="{StaticResource BaseButton}"/>
            <Button Name="Start" Content="Start workspace" Style="{StaticResource PrimaryButton}"/>
            <Button Name="Open" Content="Open browser" Style="{StaticResource BaseButton}"/>
            <Button Name="Restart" Content="Restart" Style="{StaticResource BaseButton}"/>
            <Button Name="Stop" Content="Stop" Style="{StaticResource DangerButton}" Margin="0"/>
          </WrapPanel>
        </Grid>
      </Border>

      <Border Grid.Row="6" Background="#171C31" BorderBrush="#333B59" BorderThickness="1" CornerRadius="16" ClipToBounds="True">
        <Grid>
          <Grid.RowDefinitions><RowDefinition Height="50"/><RowDefinition Height="*"/></Grid.RowDefinitions>
          <Border Grid.Row="0" Background="#232943" Padding="13,8">
          <Grid>
            <Grid.ColumnDefinitions><ColumnDefinition Width="Auto"/><ColumnDefinition Width="12"/><ColumnDefinition Width="170"/><ColumnDefinition Width="10"/><ColumnDefinition Width="*"/><ColumnDefinition Width="10"/><ColumnDefinition Width="Auto"/><ColumnDefinition Width="8"/><ColumnDefinition Width="Auto"/></Grid.ColumnDefinitions>
            <StackPanel Orientation="Horizontal" VerticalAlignment="Center"><Ellipse Width="7" Height="7" Fill="#2DD4BF" Margin="0,0,8,0"/><TextBlock Text="LIVE DIAGNOSTICS" Foreground="#C2CAE6" FontSize="10" FontWeight="Bold" VerticalAlignment="Center"/></StackPanel>
            <ComboBox Grid.Column="2" Name="LogSource" SelectedIndex="0"><ComboBoxItem Content="bootstrap.log"/><ComboBoxItem Content="windows-startup-error.log"/><ComboBoxItem Content="server-error.log"/><ComboBoxItem Content="server.log"/><ComboBoxItem Content="preflight.log"/><ComboBoxItem Content="startup-diagnosis.json"/><ComboBoxItem Content="panel-error.log"/></ComboBox>
            <TextBox Grid.Column="4" Name="LogFilter" Style="{StaticResource FilterBox}" ToolTip="Filter visible log lines"/>
            <Button Grid.Column="6" Name="CopyLog" Content="Copy" Style="{StaticResource BaseButton}" Height="34" Margin="0" Padding="12,0"/>
            <Button Grid.Column="8" Name="ClearFilter" Content="Clear" Style="{StaticResource BaseButton}" Height="34" Margin="0" Padding="12,0"/>
          </Grid>
          </Border>
          <TextBox Grid.Row="1" Name="Log" IsReadOnly="True" TextWrapping="NoWrap" HorizontalScrollBarVisibility="Auto" VerticalScrollBarVisibility="Auto" Background="#171C31" Foreground="#C2CAE6" BorderThickness="0" Padding="16,14" FontFamily="Cascadia Mono, Consolas" FontSize="12"/>
        </Grid>
      </Border>
    </Grid>
  </Grid>
</Window>
'@

$window = [Windows.Markup.XamlReader]::Load((New-Object Xml.XmlNodeReader $layout))
$ui = @{}
foreach ($name in @('TopMode','StatusDot','Status','Address','Environment','RuntimeDot','RuntimeState','RuntimeDetail','ConfigDot','ConfigState','ConfigDetail','ModeDot','ModeState','ModeDetail','Start','Open','Restart','Stop','Preflight','Message','Repair','Logs','Log','LogSource','LogFilter','CopyLog','ClearFilter','NoticeBorder')) { $ui[$name] = $window.FindName($name) }

$script:launcher = $null
$script:actionJob = $null
$script:preflightJob = $null
$script:pendingUntil = [DateTime]::MinValue
$script:lastLog = ''
$script:rawLog = ''
$script:autoOpen = $false
$script:openedForLaunch = $false
$script:runtimeStateCache = $null
$script:runtimeStateChecked = [DateTime]::MinValue

function New-Brush([string]$hex) { New-Object Windows.Media.SolidColorBrush ([Windows.Media.ColorConverter]::ConvertFromString($hex)) }
function Set-Dot([object]$element,[string]$hex) { if ($element) { $element.Fill = New-Brush $hex } }
function Set-ServiceDot([string]$hex) { Set-Dot $ui.StatusDot $hex }

function Get-RuntimeState {
    if ($script:runtimeStateCache -and [DateTime]::UtcNow -lt $script:runtimeStateChecked.AddSeconds(3)) { return $script:runtimeStateCache }
    $manifest = Join-Path $projectRoot 'runtime\runtime-install.json'
    $installed = (Test-Path -LiteralPath $runtimeExe) -and (Test-Path -LiteralPath $runtimeMarker) -and (Test-Path -LiteralPath $manifest)
    if ($installed -and $script:releaseReady) {
        try {
            $m=Get-Content -LiteralPath $manifest -Raw -Encoding UTF8 | ConvertFrom-Json
            $expected=(Get-Content -LiteralPath $releaseHash -Raw -Encoding ASCII).Trim().ToUpperInvariant()
            if ([string]$m.archiveSha256 -ceq $expected) { $state=@{state='Verified';detail='Installed self-contained runtime matches the verified local package';color='#16A34A';ready=$true} }
            else { $state=@{state='Repair required';detail='Runtime was installed from a different package revision';color='#DC2626';ready=$false} }
        } catch { $state=@{state='Repair required';detail='Runtime installation manifest could not be verified';color='#DC2626';ready=$false} }
    } elseif ($script:releaseReady) { $state=@{state='Ready to install';detail='Verified runtime installs automatically on Start';color='#D97706';ready=$false} }
    else { $state=@{state='Package missing';detail='Release archive is unavailable or failed SHA-256 verification';color='#DC2626';ready=$false} }
    $script:runtimeStateCache=$state; $script:runtimeStateChecked=[DateTime]::UtcNow
    return $state
}
function Read-ConfigSummary {
    if (!(Test-Path -LiteralPath $localConfig)) { return @{exists=$false;state='First setup';detail='Domain and writable DC have not been saved';color='#D97706'} }
    try {
        $cfg=Get-Content -LiteralPath $localConfig -Raw -Encoding UTF8 | ConvertFrom-Json
        $domain=[string]$cfg.Windows.Domain; $dc=[string]$cfg.Windows.DomainController
        $ops=@($cfg.Windows.AllowedOperators).Count
        if ([string]::IsNullOrWhiteSpace($domain) -or [string]::IsNullOrWhiteSpace($dc) -or $ops -lt 1) { return @{exists=$true;state='Incomplete';detail='Domain/DC/operator configuration needs attention';color='#DC2626';cfg=$cfg} }
        return @{exists=$true;state=$domain;detail=($dc + ' · ' + $ops + ' operator(s)');color='#16A34A';cfg=$cfg}
    } catch { return @{exists=$true;state='Invalid config';detail='appsettings.Local.json could not be parsed';color='#DC2626'} }
}
function Open-Product {
    $service = Get-RemediatorService
    if (!$service -or $service.ready -eq $false) { return }
    $path = if ($service.openPath) { [string]$service.openPath } else { '/#/dashboard' }
    Start-Process (([string]$service.url).TrimEnd('/') + $path) | Out-Null
}
function Start-Launcher([string]$Mode = 'Auto', [switch]$RepairPackage) {
    if ($script:launcher -and !$script:launcher.HasExited) { return }
    $script:runtimeStateCache=$null; $script:runtimeStateChecked=[DateTime]::MinValue
    $extra = if ($RepairPackage) { ' -Repair' } else { '' }
    $arguments = '-NoLogo -NoProfile -ExecutionPolicy Bypass -File "{0}" -Mode {1} -Port {2} -NoBrowser{3}' -f (Join-Path $projectRoot 'GpoRemediator.ps1'),$Mode,$Port,$extra
    $windowsPowerShell=Join-Path $env:SystemRoot 'System32\WindowsPowerShell\v1.0\powershell.exe'
    $script:launcher = Start-Process $windowsPowerShell -ArgumentList $arguments -WorkingDirectory $projectRoot -WindowStyle Hidden -PassThru
}
function Start-AdPreflight {
    if ($script:preflightJob -or $script:actionJob) { return }
    $summary=Read-ConfigSummary
    if (!$summary.exists -or !$summary.cfg) { $ui.Message.Text='Save the domain and writable DC first, then run AD preflight.'; return }
    $domain=[string]$summary.cfg.Windows.Domain; $dc=[string]$summary.cfg.Windows.DomainController
    $ui.Message.Text = 'AD preflight is validating DNS, SRV discovery, Kerberos, LDAP, SMB/SYSVOL, WinRM and time. No GPO write is performed.'
    $script:preflightJob = Start-Job -ArgumentList $domain,$dc,(Join-Path $work 'preflight.log') -ScriptBlock {
        param($domain,$dc,$log)
        $rows = New-Object Collections.Generic.List[object]
        function Add-Row([string]$name,[bool]$ok,[string]$detail){$rows.Add([pscustomobject]@{Name=$name;Ok=$ok;Detail=$detail})|Out-Null}
        function Test-Tcp([string]$hostName,[int]$port,[int]$timeout=3500){$c=New-Object Net.Sockets.TcpClient;try{$t=$c.ConnectAsync($hostName,$port);if(!$t.Wait($timeout)){return $false};return $c.Connected}catch{return $false}finally{$c.Dispose()}}
        try {
            try { $cs=Get-CimInstance Win32_ComputerSystem -ErrorAction Stop; Add-Row 'DOMAIN JOIN' ([bool]$cs.PartOfDomain) $(if($cs.PartOfDomain){'Joined to '+[string]$cs.Domain}else{'Host is not joined to an AD domain'}) } catch { Add-Row 'DOMAIN JOIN' $false 'Could not read local domain membership' }
            try { $dns=Get-DnsClientServerAddress -AddressFamily IPv4 -ErrorAction Stop | Where-Object {$_.ServerAddresses.Count -gt 0} | Select-Object -First 1; Add-Row 'AD DNS CLIENT' ($null -ne $dns) $(if($dns){$dns.InterfaceAlias+': '+($dns.ServerAddresses -join ', ')}else{'No IPv4 DNS server configured'}) } catch { Add-Row 'AD DNS CLIENT' $false 'Could not read DNS client configuration' }
            try { $ips=@(Resolve-DnsName $dc -ErrorAction Stop | Where-Object {$_.IPAddress} | ForEach-Object {$_.IPAddress} | Sort-Object -Unique); Add-Row 'DC DNS' ($ips.Count -gt 0) ($dc+' -> '+($ips -join ', ')) } catch { Add-Row 'DC DNS' $false ($dc+' could not be resolved') }
            try { $srv=@(Resolve-DnsName -Type SRV ('_ldap._tcp.dc._msdcs.'+$domain) -ErrorAction Stop | Where-Object {$_.NameTarget}); Add-Row 'AD SRV' ($srv.Count -gt 0) $(if($srv){(($srv|ForEach-Object{$_.NameTarget+':'+$_.Port}) -join ', ')}else{'No DC SRV record returned'}) } catch { Add-Row 'AD SRV' $false 'DC locator SRV lookup failed' }
            Add-Row 'KERBEROS / 88' (Test-Tcp $dc 88) ($dc+':88')
            Add-Row 'LDAP / 389' (Test-Tcp $dc 389) ($dc+':389')
            Add-Row 'SMB / 445' (Test-Tcp $dc 445) ($dc+':445')
            Add-Row 'WINRM / 5985' (Test-Tcp $dc 5985) ($dc+':5985')
            try { Test-WSMan $dc -ErrorAction Stop | Out-Null; Add-Row 'WINRM SERVICE' $true 'WSMan endpoint answered' } catch { Add-Row 'WINRM SERVICE' $false $_.Exception.Message }
            try { $sysvol=Test-Path ('\\'+$dc+'\SYSVOL'); Add-Row 'SYSVOL' ([bool]$sysvol) $(if($sysvol){'\\'+$dc+'\SYSVOL is reachable'}else{'SYSVOL share is not reachable'}) } catch { Add-Row 'SYSVOL' $false 'SYSVOL access test failed' }
            try { $identity=[Security.Principal.WindowsIdentity]::GetCurrent().Name; Add-Row 'WINDOWS IDENTITY' ($identity -match '\\') $identity } catch { Add-Row 'WINDOWS IDENTITY' $false 'Identity could not be read' }
            try { $source=(w32tm /query /source 2>$null | Out-String).Trim(); $good=![string]::IsNullOrWhiteSpace($source) -and $source -notmatch 'Free-running System Clock|Local CMOS Clock'; Add-Row 'TIME SOURCE' $good $(if($source){$source}else{'No time source returned'}) } catch { Add-Row 'TIME SOURCE' $false 'Could not query Windows Time service' }
            try {
                $mods=Invoke-Command -ComputerName $dc -Authentication Kerberos -ScriptBlock {
                    [pscustomobject]@{AD=[bool](Get-Module -ListAvailable ActiveDirectory | Select-Object -First 1);GPO=[bool](Get-Module -ListAvailable GroupPolicy | Select-Object -First 1)}
                } -ErrorAction Stop
                Add-Row 'AD MODULE ON DC' ([bool]$mods.AD) $(if($mods.AD){'ActiveDirectory module present'}else{'ActiveDirectory module missing'})
                Add-Row 'GPMC ON DC' ([bool]$mods.GPO) $(if($mods.GPO){'GroupPolicy module present'}else{'GroupPolicy module missing'})
            } catch { Add-Row 'REMOTE MODULE CHECK' $false ('Kerberos PowerShell remoting check failed: '+$_.Exception.Message) }
            $ok=@($rows|Where-Object{$_.Ok}).Count; $total=$rows.Count
            $lines=@(('['+(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')+'] AD preflight for '+$domain+' / '+$dc), '')
            foreach($r in $rows){$lines += ('{0,-22} {1,-5} {2}' -f $r.Name,($(if($r.Ok){'PASS'}else{'FAIL'})),$r.Detail)}
            $lines += ''; $lines += ('Result: '+$ok+'/'+$total+' checks passed. No GPO write was attempted.')
            $lines | Set-Content -LiteralPath $log -Encoding UTF8
            [pscustomobject]@{ok=($ok -eq $total);passed=$ok;total=$total;domain=$domain;dc=$dc}
        } catch {
            ('['+(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')+'] Preflight failed: '+$_.Exception.Message) | Set-Content -LiteralPath $log -Encoding UTF8
            [pscustomobject]@{ok=$false;passed=0;total=1;error=$_.Exception.Message}
        }
    }
}
function Request-ServiceAction([string]$action) {
    if ($script:actionJob) { return }
    $ui.Message.Text = 'Service request is being processed. Active GPO work remains protected by the operation gate.'
    $script:actionJob = Start-Job -ArgumentList $projectRoot,$action -ScriptBlock {
        param($root,$requested)
        try { . (Join-Path $root 'scripts\ServiceControl.ps1'); Invoke-RemediatorServiceAction $requested | Out-Null; @{ok=$true} }
        catch { @{ok=$false;error=$_.Exception.Message} }
    }
    Refresh-Panel
}
function Refresh-Panel {
    $service = Get-RemediatorService
    $launching = $script:launcher -and !$script:launcher.HasExited
    $pending = $script:actionJob -or $script:preflightJob -or [DateTime]::UtcNow -lt $script:pendingUntil
    $runtime = Get-RuntimeState
    $config = Read-ConfigSummary

    $ui.RuntimeState.Text = [string]$runtime.state; $ui.RuntimeDetail.Text=[string]$runtime.detail; Set-Dot $ui.RuntimeDot ([string]$runtime.color)
    $ui.ConfigState.Text = [string]$config.state; $ui.ConfigDetail.Text=[string]$config.detail; Set-Dot $ui.ConfigDot ([string]$config.color)

    $ui.Start.IsEnabled = !$service -and !$launching -and !$pending -and ([bool]$runtime.ready -or $script:releaseReady)
    $ui.Open.IsEnabled = [bool]$service -and $service.ready -ne $false
    $ui.Stop.IsEnabled = [bool]$service -and !$pending
    $configReady = [bool]$config.exists -and $null -ne $config.cfg -and [string]$config.state -notin @('Incomplete','Invalid config','First setup')
    $ui.Restart.IsEnabled = $ui.Stop.IsEnabled -and (!$service -or [string]$service.mode -ne 'Setup' -or $configReady)
    $ui.Preflight.IsEnabled = [bool]$config.exists -and !$pending
    $ui.Repair.IsEnabled = !$service -and !$launching -and !$pending -and $script:releaseReady

    if ($service) {
        $mode = [string]$service.mode
        $ui.Restart.Content = if ($mode -eq 'Setup') { 'Start Windows / AD' } else { 'Restart service' }
        $ui.Environment.Text = if ($mode -eq 'Setup') { 'Configuration staging mode' } else { 'Windows / Active Directory mode' }
        $ui.ModeState.Text = if ($mode -eq 'Setup') { 'SETUP' } else { 'WINDOWS / AD' }
        $ui.ModeDetail.Text = if ($mode -eq 'Setup') { 'Configuration service; Windows / AD promotion available' } else { 'Real AD workflow service' }
        Set-Dot $ui.ModeDot $(if($mode -eq 'Setup'){'#2563EB'}else{'#16A34A'})
        $ui.TopMode.Text = if ($mode -eq 'Setup') { 'SETUP' } else { 'REAL AD' }
        $ui.Address.Text = [string]$service.url
        if ($pending) { $ui.Status.Text = 'Operation in progress'; Set-ServiceDot '#D97706' }
        elseif ($service.ready -eq $false) { $ui.Status.Text = 'Service is preparing'; Set-ServiceDot '#D97706' }
        elseif ($mode -eq 'Setup') {
            $ui.Status.Text = 'Configuration service is ready'; Set-ServiceDot '#2563EB'
            $ui.Message.Text = if ($service.startupIssue) { 'Windows startup diagnosis: ' + [string]$service.startupIssue + ' Open startup-diagnosis.json for the captured local backend failure.' } elseif(!$configReady) { 'Configuration mode is active. Complete Domain, writable DC and operator settings before promotion to Windows / AD.' } else { 'Configuration is ready. Click Start Windows / AD; the launcher performs one controlled Setup-to-Windows handoff.' }
        } else {
            $ui.Status.Text = 'Service is healthy'; Set-ServiceDot '#16A34A'
            $ui.Message.Text = 'Windows / Active Directory mode is running. Use AD preflight for transport diagnostics or open the browser workspace.'
        }
        if ($script:autoOpen -and !$script:openedForLaunch -and $service.ready -ne $false) { $script:openedForLaunch=$true; $script:autoOpen=$false; Open-Product }
    } elseif ($launching) {
        $ui.Restart.Content='Restart service'
        $ui.Status.Text='Starting service'; $ui.Address.Text='Verifying package and starting backend...'; $ui.Environment.Text='Automatic'; $ui.ModeState.Text='STARTING'; $ui.ModeDetail.Text='Launcher is active'; $ui.TopMode.Text='STARTING'; Set-ServiceDot '#D97706'; Set-Dot $ui.ModeDot '#D97706'
    } else {
        $ui.Restart.Content='Restart service'
        $ui.Status.Text = if ($config.exists) { 'Service stopped' } else { 'Initial setup required' }
        $ui.Address.Text = if ($config.exists) { 'Use Start workspace to continue.' } else { 'Start opens the safe configuration service.' }
        $ui.Environment.Text='Automatic'; $ui.ModeState.Text='AUTO'; $ui.ModeDetail.Text='Service is not running'; $ui.TopMode.Text='READY'; Set-ServiceDot '#94A3B8'; Set-Dot $ui.ModeDot '#94A3B8'
    }

    if ($script:launcher -and $script:launcher.HasExited) {
        if ($script:launcher.ExitCode -ne 0 -and !$service) { $ui.Message.Text='Startup did not complete. Open startup-diagnosis.json first, then windows-startup-error.log/server-error.log. AD transport is checked separately by AD preflight; it is not assumed to be the startup cause.'; Set-ServiceDot '#DC2626' }
        $script:launcher=$null; $script:runtimeStateCache=$null; $script:runtimeStateChecked=[DateTime]::MinValue
    }

    if ($script:preflightJob -and $script:preflightJob.State -in @('Completed','Failed','Stopped')) {
        $result=Receive-Job $script:preflightJob -ErrorAction SilentlyContinue
        if ($result) { $ui.Message.Text = if($result.ok){('AD preflight passed: '+$result.passed+'/'+$result.total+' checks.')}else{('AD preflight needs attention: '+$result.passed+'/'+$result.total+' checks passed. Open preflight.log.')} }
        else { $ui.Message.Text='AD preflight did not complete. Open preflight.log and launcher diagnostics.' }
        Remove-Job $script:preflightJob -Force; $script:preflightJob=$null; $script:lastLog=''
    }
    if ($script:actionJob -and $script:actionJob.State -in @('Completed','Failed','Stopped')) {
        $result = Receive-Job $script:actionJob -ErrorAction SilentlyContinue
        if ($result -and $result.ok) { $ui.Message.Text='Service request accepted. Status is refreshing.'; $script:pendingUntil=[DateTime]::UtcNow.AddSeconds(3) }
        else { $ui.Message.Text=if($result.error){[string]$result.error}else{'Service request did not complete. Check diagnostics.'}; $script:pendingUntil=[DateTime]::MinValue }
        Remove-Job $script:actionJob -Force; $script:actionJob=$null
    }

    $selectedLog = if ($ui.LogSource.SelectedItem) { [string]$ui.LogSource.SelectedItem.Content } else { 'bootstrap.log' }
    $logPath = Join-Path $work $selectedLog
    if (Test-Path -LiteralPath $logPath) {
        $script:rawLog=(Get-Content -LiteralPath $logPath -Encoding UTF8 -Tail 240 -ErrorAction SilentlyContinue) -join [Environment]::NewLine
        $filter=[string]$ui.LogFilter.Text
        $content=if([string]::IsNullOrWhiteSpace($filter)){$script:rawLog}else{(($script:rawLog -split '\r?\n')|Where-Object{$_ -match [Regex]::Escape($filter)}) -join [Environment]::NewLine}
        if($content -ne $script:lastLog){$ui.Log.Text=$content;$ui.Log.ScrollToEnd();$script:lastLog=$content}
    } else { $script:rawLog=''; $ui.Log.Text="$selectedLog has no entries yet." }
}

$ui.Start.Add_Click({ try { $script:autoOpen=$true; $script:openedForLaunch=$false; Start-Launcher -Mode 'Auto'; $ui.Message.Text='Starting the verified local package. The browser opens automatically when readiness passes.'; Refresh-Panel } catch { $ui.Message.Text=$_.Exception.Message } })
$ui.Open.Add_Click({ Open-Product })
$window.FindName('CopyStatus').Add_Click({
    try {
        $service=Get-RemediatorService
        $summary=[ordered]@{product='GPO Remediator';capturedAt=[DateTimeOffset]::Now.ToString('o');running=[bool]$service;mode=if($service){[string]$service.mode}else{'Stopped'};url=if($service){[string]$service.url}else{"http://127.0.0.1:$Port"};releaseArchiveVerified=[bool]$script:releaseReady;configurationPresent=(Test-Path -LiteralPath $localConfig);processId=if($service){[int]$service.processId}else{$null}}
        [Windows.Clipboard]::SetText(($summary | ConvertTo-Json))
        $ui.Message.Text='Service summary copied. This summary contains no credentials or configuration contents.'
    } catch { $ui.Message.Text='Could not copy the service summary: '+$_.Exception.Message }
})
$ui.Stop.Add_Click({ Request-ServiceAction 'stop' })
$ui.Restart.Add_Click({ Request-ServiceAction 'restart' })
$ui.Preflight.Add_Click({ Start-AdPreflight; Refresh-Panel })
$ui.Repair.Add_Click({
    $answer=[Windows.MessageBox]::Show('Reinstall the shipped runtime from the verified local release archive? This does not download or compile code and does not require the .NET SDK.','GPO Remediator - Runtime repair',[Windows.MessageBoxButton]::YesNo,[Windows.MessageBoxImage]::Question)
    if($answer -eq [Windows.MessageBoxResult]::Yes){try{$script:autoOpen=$false;Start-Launcher -Mode 'Auto' -RepairPackage;$ui.Message.Text='Verified runtime reinstall started. No SDK/build step is used.';Refresh-Panel}catch{$ui.Message.Text=$_.Exception.Message}}
})
$ui.Logs.Add_Click({ Start-Process explorer.exe -ArgumentList ('"' + $work + '"') })
$ui.LogSource.Add_SelectionChanged({ $script:lastLog=''; Refresh-Panel })
$ui.LogFilter.Add_TextChanged({ $script:lastLog=''; Refresh-Panel })
$ui.CopyLog.Add_Click({ if (![string]::IsNullOrEmpty($ui.Log.Text)) { [Windows.Clipboard]::SetText($ui.Log.Text); $ui.Message.Text='Visible diagnostics copied to clipboard.' } })
$ui.ClearFilter.Add_Click({ $ui.LogFilter.Clear(); $script:lastLog='' })

$timer=New-Object Windows.Threading.DispatcherTimer
$timer.Interval=[TimeSpan]::FromSeconds(1)
$timer.Add_Tick({ try { Refresh-Panel } catch { $ui.Message.Text=$_.Exception.Message } })
$window.Add_Closed({ $timer.Stop(); if($script:actionJob){Remove-Job $script:actionJob -Force -ErrorAction SilentlyContinue}; if($script:preflightJob){Remove-Job $script:preflightJob -Force -ErrorAction SilentlyContinue} })
Refresh-Panel
$timer.Start()
if($SmokeTest){$window.Add_ContentRendered({$window.Close()})}
$window.ShowDialog() | Out-Null
if($SmokeTest){Write-Host 'PASS: control panel rendered and closed normally.'}
