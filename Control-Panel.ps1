param([ValidateRange(1024,65535)][int]$Port = 5080, [switch]$SmokeTest)
$ErrorActionPreference = 'Stop'
$windowsModules = Join-Path $env:SystemRoot 'System32\WindowsPowerShell\v1.0\Modules'
$env:PSModulePath = "$windowsModules;" + (($env:PSModulePath -split ';' | Where-Object { $_ -ine $windowsModules }) -join ';')
Add-Type -AssemblyName PresentationFramework,PresentationCore,WindowsBase
. (Join-Path $PSScriptRoot 'scripts\ServiceControl.ps1')

$projectRoot = $PSScriptRoot
$work = Join-Path $projectRoot 'work'
$localConfig = Join-Path $projectRoot 'backend\appsettings.Local.json'
New-Item -ItemType Directory -Path $work -Force | Out-Null

[xml]$layout = @'
<Window xmlns="http://schemas.microsoft.com/winfx/2006/xaml/presentation"
        xmlns:x="http://schemas.microsoft.com/winfx/2006/xaml"
        Title="GPO Remediator — Local Control Center"
        Width="1080" Height="720" MinWidth="960" MinHeight="650"
        WindowStartupLocation="CenterScreen" Background="#F4F7FB"
        FontFamily="Segoe UI Variable, Segoe UI" FontSize="13">
  <Window.Resources>
    <SolidColorBrush x:Key="Ink" Color="#142033"/>
    <SolidColorBrush x:Key="Muted" Color="#6F7F92"/>
    <SolidColorBrush x:Key="Line" Color="#DFE6EE"/>
    <Style TargetType="Button" x:Key="GhostButton">
      <Setter Property="Height" Value="38"/><Setter Property="Padding" Value="15,0"/><Setter Property="Margin" Value="0,0,8,0"/>
      <Setter Property="Foreground" Value="#344054"/><Setter Property="Background" Value="#FFFFFF"/><Setter Property="BorderBrush" Value="#D6DFE8"/><Setter Property="BorderThickness" Value="1"/><Setter Property="FontWeight" Value="SemiBold"/><Setter Property="Cursor" Value="Hand"/>
      <Setter Property="Template"><Setter.Value><ControlTemplate TargetType="Button"><Border x:Name="B" Background="{TemplateBinding Background}" BorderBrush="{TemplateBinding BorderBrush}" BorderThickness="{TemplateBinding BorderThickness}" CornerRadius="8"><ContentPresenter HorizontalAlignment="Center" VerticalAlignment="Center"/></Border><ControlTemplate.Triggers><Trigger Property="IsMouseOver" Value="True"><Setter TargetName="B" Property="Background" Value="#F7F9FC"/></Trigger><Trigger Property="IsEnabled" Value="False"><Setter Property="Opacity" Value="0.45"/></Trigger></ControlTemplate.Triggers></ControlTemplate></Setter.Value></Setter>
    </Style>
    <Style TargetType="Button" x:Key="PrimaryButton" BasedOn="{StaticResource GhostButton}"><Setter Property="Foreground" Value="#FFFFFF"/><Setter Property="Background" Value="#0B87C9"/><Setter Property="BorderBrush" Value="#0B87C9"/><Setter Property="Height" Value="42"/><Setter Property="Padding" Value="20,0"/></Style>
    <Style TargetType="Button" x:Key="DangerButton" BasedOn="{StaticResource GhostButton}"><Setter Property="Foreground" Value="#B4232D"/><Setter Property="BorderBrush" Value="#F1C8CC"/><Setter Property="Background" Value="#FFF8F8"/></Style>
  </Window.Resources>
  <Grid>
    <Grid.ColumnDefinitions><ColumnDefinition Width="250"/><ColumnDefinition Width="*"/></Grid.ColumnDefinitions>
    <Border Grid.Column="0" Background="#0B1322">
      <Grid Margin="24,28">
        <Grid.RowDefinitions><RowDefinition Height="Auto"/><RowDefinition Height="28"/><RowDefinition Height="Auto"/><RowDefinition Height="*"/><RowDefinition Height="Auto"/></Grid.RowDefinitions>
        <StackPanel>
          <TextBlock Text="GPO REMEDIATOR" Foreground="#EAF8FF" FontSize="18" FontWeight="Bold"/>
          <TextBlock Text="LOCAL POLICY CONTROL" Foreground="#4D6B82" FontSize="9" FontWeight="SemiBold" Margin="0,6,0,0"/>
        </StackPanel>
        <StackPanel Grid.Row="2">
          <TextBlock Text="SERVICE" Foreground="#486178" FontSize="9" FontWeight="Bold" Margin="0,0,0,12"/>
          <Border Background="#101E31" BorderBrush="#1C334B" BorderThickness="1" CornerRadius="10" Padding="13">
            <StackPanel>
              <StackPanel Orientation="Horizontal"><Ellipse Name="StatusDot" Width="9" Height="9" Fill="#94A3B8" Margin="0,3,8,0"/><TextBlock Name="Status" Text="Ready" Foreground="#F2F8FC" FontWeight="SemiBold"/></StackPanel>
              <TextBlock Name="Environment" Text="Automatic" Foreground="#8298AA" FontSize="10" Margin="17,5,0,0" TextWrapping="Wrap"/>
              <TextBlock Name="Address" Text="http://127.0.0.1:5080" Foreground="#5E7B91" FontSize="9" Margin="17,5,0,0" TextWrapping="Wrap"/>
            </StackPanel>
          </Border>
          <TextBlock Text="SESSION" Foreground="#486178" FontSize="9" FontWeight="Bold" Margin="0,24,0,10"/>
          <Border Background="#0E1A2B" CornerRadius="9" Padding="12"><StackPanel><TextBlock Name="TopMode" Text="READY" Foreground="#67E8F9" FontSize="10" FontWeight="Bold"/><TextBlock Text="Localhost only · no TLS certificate" Foreground="#658196" FontSize="9" Margin="0,5,0,0" TextWrapping="Wrap"/></StackPanel></Border>
        </StackPanel>
        <StackPanel Grid.Row="4">
          <Button Name="Repair" Content="Advanced repair" Style="{StaticResource GhostButton}" Background="#101C2D" BorderBrush="#22374E" Foreground="#94A9BA" Margin="0,0,0,8"/>
          <Button Name="Logs" Content="Open diagnostics folder" Style="{StaticResource GhostButton}" Background="#101C2D" BorderBrush="#22374E" Foreground="#94A9BA" Margin="0"/>
        </StackPanel>
      </Grid>
    </Border>
    <Grid Grid.Column="1" Margin="34,28,34,24">
      <Grid.RowDefinitions><RowDefinition Height="Auto"/><RowDefinition Height="18"/><RowDefinition Height="Auto"/><RowDefinition Height="14"/><RowDefinition Height="Auto"/><RowDefinition Height="14"/><RowDefinition Height="*"/></Grid.RowDefinitions>
      <Grid>
        <Grid.ColumnDefinitions><ColumnDefinition Width="*"/><ColumnDefinition Width="Auto"/></Grid.ColumnDefinitions>
        <StackPanel><TextBlock Text="Management agent" Foreground="#0B87C9" FontSize="10" FontWeight="Bold"/><TextBlock Text="Local GPO Remediation Console" Foreground="#142033" FontSize="28" FontWeight="SemiBold" Margin="0,6,0,0"/><TextBlock Text="Start the service, configure Active Directory, and open the browser workspace." Foreground="#738296" FontSize="11" Margin="0,6,0,0"/></StackPanel>
        <Border Grid.Column="1" Background="#E9F8FF" BorderBrush="#C8EAF8" BorderThickness="1" CornerRadius="18" Padding="12,7" VerticalAlignment="Top"><TextBlock Text="LOCAL ONLY" Foreground="#0476A8" FontSize="9" FontWeight="Bold"/></Border>
      </Grid>
      <Grid Grid.Row="2">
        <Grid.ColumnDefinitions><ColumnDefinition Width="*"/><ColumnDefinition Width="12"/><ColumnDefinition Width="*"/><ColumnDefinition Width="12"/><ColumnDefinition Width="*"/></Grid.ColumnDefinitions>
        <Border Background="White" BorderBrush="{StaticResource Line}" BorderThickness="1" CornerRadius="11" Padding="15"><StackPanel><TextBlock Text="RUNTIME" Foreground="#8A98A8" FontSize="9" FontWeight="Bold"/><TextBlock Name="RuntimeState" Text="Checking" Foreground="{StaticResource Ink}" FontWeight="SemiBold" Margin="0,6,0,0"/></StackPanel></Border>
        <Border Grid.Column="2" Background="White" BorderBrush="{StaticResource Line}" BorderThickness="1" CornerRadius="11" Padding="15"><StackPanel><TextBlock Text="CONFIGURATION" Foreground="#8A98A8" FontSize="9" FontWeight="Bold"/><TextBlock Name="ConfigState" Text="Checking" Foreground="{StaticResource Ink}" FontWeight="SemiBold" Margin="0,6,0,0"/></StackPanel></Border>
        <Border Grid.Column="4" Background="White" BorderBrush="{StaticResource Line}" BorderThickness="1" CornerRadius="11" Padding="15"><StackPanel><TextBlock Text="EXECUTION" Foreground="#8A98A8" FontSize="9" FontWeight="Bold"/><TextBlock Name="ModeState" Text="AUTO" Foreground="{StaticResource Ink}" FontWeight="SemiBold" Margin="0,6,0,0"/></StackPanel></Border>
      </Grid>
      <Border Grid.Row="4" Name="NoticeBorder" Background="#FFFFFF" BorderBrush="{StaticResource Line}" BorderThickness="1" CornerRadius="12" Padding="18">
        <Grid><Grid.RowDefinitions><RowDefinition Height="Auto"/><RowDefinition Height="12"/><RowDefinition Height="Auto"/></Grid.RowDefinitions>
          <TextBlock Name="Message" Text="Ready to start. The browser workspace opens automatically when the service is available." Foreground="#536477" FontSize="11" TextWrapping="Wrap"/>
          <StackPanel Grid.Row="2" Orientation="Horizontal">
            <Button Name="Start" Content="Start &amp; open workspace" Style="{StaticResource PrimaryButton}"/>
            <Button Name="Open" Content="Open browser" Style="{StaticResource GhostButton}"/>
            <Button Name="Restart" Content="Restart" Style="{StaticResource GhostButton}"/>
            <Button Name="Stop" Content="Stop service" Style="{StaticResource DangerButton}" Margin="0"/>
          </StackPanel>
        </Grid>
      </Border>
      <Border Grid.Row="6" Background="#0B1322" BorderBrush="#17263A" BorderThickness="1" CornerRadius="12" Padding="0">
        <Grid><Grid.RowDefinitions><RowDefinition Height="42"/><RowDefinition Height="*"/></Grid.RowDefinitions>
          <Grid Margin="15,0"><TextBlock Text="LIVE DIAGNOSTICS" Foreground="#718CA1" FontSize="9" FontWeight="Bold" VerticalAlignment="Center"/><TextBlock Text="bootstrap.log" Foreground="#445E72" FontSize="9" HorizontalAlignment="Right" VerticalAlignment="Center"/></Grid>
          <TextBox Grid.Row="1" Name="Log" IsReadOnly="True" TextWrapping="NoWrap" HorizontalScrollBarVisibility="Auto" VerticalScrollBarVisibility="Auto" Background="#08101C" Foreground="#9CB1C4" BorderThickness="0" Padding="15,13" FontFamily="Cascadia Mono, Consolas" FontSize="10"/>
        </Grid>
      </Border>
    </Grid>
  </Grid>
</Window>
'@

$window = [Windows.Markup.XamlReader]::Load((New-Object Xml.XmlNodeReader $layout))
$ui = @{}
foreach ($name in @('TopMode','StatusDot','Status','Address','Environment','RuntimeState','ConfigState','ModeState','Start','Open','Restart','Stop','Message','Repair','Logs','Log','NoticeBorder')) { $ui[$name] = $window.FindName($name) }

$script:launcher = $null
$script:actionJob = $null
$script:pendingUntil = [DateTime]::MinValue
$script:lastLog = ''
$script:autoOpen = $false
$script:openedForLaunch = $false

function Set-DotColor([string]$hex) { $ui.StatusDot.Fill = New-Object Windows.Media.SolidColorBrush ([Windows.Media.ColorConverter]::ConvertFromString($hex)) }
function Open-Product {
    $service = Get-RemediatorService
    if (!$service -or $service.ready -eq $false) { return }
    $path = if ($service.openPath) { [string]$service.openPath } else { '/#/home' }
    Start-Process (([string]$service.url).TrimEnd('/') + $path) | Out-Null
}
function Start-Launcher([string]$Mode = 'Auto', [switch]$RepairBuild) {
    if ($script:launcher -and !$script:launcher.HasExited) { return }
    $extra = if ($RepairBuild) { ' -Repair' } else { '' }
    $arguments = '-NoLogo -NoProfile -ExecutionPolicy Bypass -File "{0}" -Mode {1} -Port {2} -NoBrowser{3}' -f (Join-Path $projectRoot 'GpoRemediator.ps1'),$Mode,$Port,$extra
    $script:launcher = Start-Process powershell.exe -ArgumentList $arguments -WorkingDirectory $projectRoot -WindowStyle Hidden -PassThru -RedirectStandardOutput (Join-Path $work 'launcher-output.log') -RedirectStandardError (Join-Path $work 'launcher-error.log')
}
function Refresh-Panel {
    $service = Get-RemediatorService
    $launching = $script:launcher -and !$script:launcher.HasExited
    $pending = $script:actionJob -or [DateTime]::UtcNow -lt $script:pendingUntil
    $runtimeReady = (Test-Path -LiteralPath (Join-Path $projectRoot 'runtime\GpoRemediator.exe')) -and (Test-Path -LiteralPath (Join-Path $projectRoot 'runtime\local-http-v2.ready'))
    $configExists = Test-Path -LiteralPath $localConfig

    $ui.RuntimeState.Text = if ($runtimeReady) { 'Local runtime hazırdır' } else { 'İlk dəfə yenilənəcək' }
    $ui.ConfigState.Text = if ($configExists) { 'Saxlanıb' } else { 'İlk sazlama' }

    $ui.Start.IsEnabled = !$service -and !$launching -and !$pending
    $ui.Open.IsEnabled = [bool]$service -and $service.ready -ne $false
    $ui.Stop.IsEnabled = [bool]$service -and !$pending
    $ui.Restart.IsEnabled = $ui.Stop.IsEnabled
    $ui.Repair.IsEnabled = !$service -and !$launching -and !$pending

    if ($service) {
        $mode = [string]$service.mode
        $ui.Environment.Text = if ($mode -eq 'Setup') { 'Setup / local configuration' } else { 'Windows / Active Directory' }
        $ui.ModeState.Text = if ($mode -eq 'Setup') { 'SETUP' } else { 'WINDOWS / AD' }
        $ui.TopMode.Text = if ($mode -eq 'Setup') { 'SETUP' } else { 'REAL AD' }
        $ui.Address.Text = [string]$service.url
        if ($pending) {
            $ui.Status.Text = 'Əməliyyat icra olunur'
            Set-DotColor '#D97706'
        } elseif ($service.ready -eq $false) {
            $ui.Status.Text = 'Xidmət hazırlanır'
            Set-DotColor '#D97706'
        } elseif ($mode -eq 'Setup') {
            $ui.Status.Text = 'Sazlama rejimi hazırdır'
            Set-DotColor '#2563EB'
            $ui.Message.Text = if ($service.startupIssue) { 'Windows / AD rejimi üçün sazlama lazımdır: ' + [string]$service.startupIssue } else { 'İlk sazlamanı brauzerdə tamamlayın. Bu rejim GPO-ya dəyişiklik etmir.' }
        } else {
            $ui.Status.Text = 'Xidmət işləyir'
            Set-DotColor '#16A34A'
            $ui.Message.Text = 'Windows / Active Directory rejimi aktivdir. UI yalnız localhost üzərindən açılır; TLS sertifikatı tələb olunmur.'
        }
        if ($script:autoOpen -and !$script:openedForLaunch -and $service.ready -ne $false) {
            $script:openedForLaunch = $true
            $script:autoOpen = $false
            Open-Product
        }
    } elseif ($launching) {
        $ui.Status.Text = 'Xidmət başladılır'
        $ui.Address.Text = 'Paket yoxlanılır və servis açılır...'
        $ui.Environment.Text = 'Avtomatik'
        $ui.ModeState.Text = 'AUTO'
        $ui.TopMode.Text = 'STARTING'
        Set-DotColor '#D97706'
    } else {
        $ui.Status.Text = if ($configExists) { 'Xidmət dayandırılıb' } else { 'İlk sazlama tələb olunur' }
        $ui.Address.Text = if ($configExists) { 'Başlat və brauzerdə aç düyməsi ilə davam edin.' } else { 'Başlatdıqda təhlükəsiz Setup rejimi avtomatik açılacaq.' }
        $ui.Environment.Text = 'Avtomatik'
        $ui.ModeState.Text = 'AUTO'
        $ui.TopMode.Text = 'READY'
        Set-DotColor '#94A3B8'
    }

    if ($script:launcher -and $script:launcher.HasExited) {
        if ($script:launcher.ExitCode -ne 0 -and !$service) {
            $ui.Message.Text = 'Başlatma tamamlanmadı. Diaqnostika logunda səbəb göstərilir. “Təmir / rebuild” yalnız runtime həqiqətən zədələnibsə istifadə olunmalıdır.'
            Set-DotColor '#DC2626'
        }
        $script:launcher = $null
    }

    $logPath = Join-Path $work 'bootstrap.log'
    if (Test-Path -LiteralPath $logPath) {
        $content = (Get-Content -LiteralPath $logPath -Tail 45 -ErrorAction SilentlyContinue) -join [Environment]::NewLine
        if ($content -ne $script:lastLog) { $ui.Log.Text = $content; $ui.Log.ScrollToEnd(); $script:lastLog = $content }
    } else { $ui.Log.Text = 'Hələ log qeydi yoxdur.' }

    if ($script:actionJob -and $script:actionJob.State -in @('Completed','Failed','Stopped')) {
        $result = Receive-Job $script:actionJob -ErrorAction SilentlyContinue
        if ($result -and $result.ok) { $ui.Message.Text = 'Sorğu qəbul edildi. Xidmətin statusu yenilənir.'; $script:pendingUntil = [DateTime]::UtcNow.AddSeconds(3) }
        else { $ui.Message.Text = if ($result.error) { [string]$result.error } else { 'Sorğu tamamlanmadı. Logları yoxlayın.' }; $script:pendingUntil = [DateTime]::MinValue }
        Remove-Job $script:actionJob -Force
        $script:actionJob = $null
    }
}
function Request-ServiceAction([string]$action) {
    if ($script:actionJob) { return }
    $ui.Message.Text = 'Sorğu göndərilir. Aktiv GPO əməliyyatı varsa xidmət təhlükəsiz şəkildə dayandırılacaq.'
    $script:actionJob = Start-Job -ArgumentList $projectRoot,$action -ScriptBlock {
        param($root,$requested)
        try { . (Join-Path $root 'scripts\ServiceControl.ps1'); Invoke-RemediatorServiceAction $requested | Out-Null; @{ok=$true} }
        catch { @{ok=$false;error=$_.Exception.Message} }
    }
    Refresh-Panel
}

$ui.Start.Add_Click({
    try {
        $script:autoOpen = $true; $script:openedForLaunch = $false
        Start-Launcher -Mode 'Auto'
        $ui.Message.Text = 'Xidmət başladılır. Hazır olduqda brauzer avtomatik açılacaq.'
        Refresh-Panel
    } catch { $ui.Message.Text = $_.Exception.Message }
})
$ui.Open.Add_Click({ Open-Product })
$ui.Stop.Add_Click({ Request-ServiceAction 'stop' })
$ui.Restart.Add_Click({ Request-ServiceAction 'restart' })
$ui.Repair.Add_Click({
    $answer = [Windows.MessageBox]::Show('Bu əməliyyat yalnız paketlənmiş runtime zədələnibsə istifadə olunmalıdır. Lazım gələrsə .NET 8 SDK və NuGet paketləri endiriləcək. Davam edilsin?','GPO Remediator - Təmir',[Windows.MessageBoxButton]::YesNo,[Windows.MessageBoxImage]::Question)
    if ($answer -eq [Windows.MessageBoxResult]::Yes) {
        try { $script:autoOpen = $false; Start-Launcher -Mode 'Build' -RepairBuild; $ui.Message.Text = 'Təmir / rebuild başladıldı. Bu rejim internet bağlantısı tələb edə bilər.'; Refresh-Panel } catch { $ui.Message.Text = $_.Exception.Message }
    }
})
$ui.Logs.Add_Click({ Start-Process explorer.exe -ArgumentList ('"' + $work + '"') })

$timer = New-Object Windows.Threading.DispatcherTimer
$timer.Interval = [TimeSpan]::FromSeconds(1)
$timer.Add_Tick({ try { Refresh-Panel } catch { $ui.Message.Text = $_.Exception.Message } })
$window.Add_Closed({ $timer.Stop(); if ($script:actionJob) { Remove-Job $script:actionJob -Force -ErrorAction SilentlyContinue } })
Refresh-Panel
$timer.Start()
if ($SmokeTest) { $window.Add_ContentRendered({ $window.Close() }) }
$window.ShowDialog() | Out-Null
if ($SmokeTest) { Write-Host 'PASS: control panel rendered and closed normally.' }
