param([ValidateRange(1024,65535)][int]$Port = 5080)
$ErrorActionPreference = 'Stop'
$windowsModules = Join-Path $env:SystemRoot 'System32\WindowsPowerShell\v1.0\Modules'
$env:PSModulePath = "$windowsModules;" + (($env:PSModulePath -split ';' | Where-Object { $_ -ine $windowsModules }) -join ';')
Add-Type -AssemblyName PresentationFramework,PresentationCore,WindowsBase
. (Join-Path $PSScriptRoot 'scripts\ServiceControl.ps1')
$projectRoot = $PSScriptRoot
$work = Join-Path $projectRoot 'work'
New-Item -ItemType Directory -Path $work -Force | Out-Null
[xml]$layout = @'
<Window xmlns="http://schemas.microsoft.com/winfx/2006/xaml/presentation" xmlns:x="http://schemas.microsoft.com/winfx/2006/xaml" Title="GPO Remediator — İdarəetmə" Width="820" Height="680" MinWidth="720" MinHeight="600" WindowStartupLocation="CenterScreen" Background="#F3F6FA" FontFamily="Segoe UI" FontSize="14">
 <Window.Resources>
  <Style TargetType="Button"><Setter Property="Padding" Value="18,11"/><Setter Property="Margin" Value="0,0,10,0"/><Setter Property="Background" Value="White"/><Setter Property="Foreground" Value="#20364B"/><Setter Property="BorderBrush" Value="#CBD5E1"/><Setter Property="Cursor" Value="Hand"/></Style>
 </Window.Resources>
 <Grid Margin="30">
  <Grid.RowDefinitions><RowDefinition Height="Auto"/><RowDefinition Height="Auto"/><RowDefinition Height="Auto"/><RowDefinition Height="*"/><RowDefinition Height="Auto"/></Grid.RowDefinitions>
  <StackPanel Margin="0,0,0,24"><TextBlock Text="GPO REMEDIATOR" Foreground="#087D77" FontSize="12" FontWeight="Bold"/><TextBlock Text="İdarəetmə paneli" FontSize="30" FontWeight="SemiBold" Foreground="#142A3A" Margin="0,6,0,6"/><TextBlock Text="Xidməti başladın, brauzerdə işləyin və buradan dayandırın." Foreground="#52657A"/></StackPanel>
  <Border Grid.Row="1" Background="White" BorderBrush="#DCE5EE" BorderThickness="1" CornerRadius="12" Padding="22" Margin="0,0,0,20">
   <StackPanel>
    <DockPanel><TextBlock Name="Status" Text="Dayandırılıb" FontSize="22" FontWeight="SemiBold" Foreground="#142A3A"/><TextBlock Name="ModeLabel" Text="" HorizontalAlignment="Right" Foreground="#087D77" VerticalAlignment="Center"/></DockPanel>
    <TextBlock Name="Address" Text="Başlamaq üçün rejim seçin." Foreground="#52657A" Margin="0,8,0,18"/>
    <StackPanel Orientation="Horizontal"><TextBlock Text="Rejim" VerticalAlignment="Center" Margin="0,0,14,0"/><ComboBox Name="Mode" Width="275" Padding="10,7" SelectedIndex="0"><ComboBoxItem Content="Demo — təhlükəsiz sınaq" Tag="Demo"/><ComboBoxItem Content="Avtomatik — saxlanmış konfiqurasiya" Tag="Auto"/><ComboBoxItem Content="Windows / Active Directory" Tag="Windows"/></ComboBox><TextBlock Text="Demo AD-də dəyişiklik etmir." Foreground="#52657A" VerticalAlignment="Center" Margin="16,0,0,0"/></StackPanel>
    <WrapPanel Margin="0,20,0,0"><Button Name="Start" Content="▶  Başlat" Background="#087D77" Foreground="White" BorderBrush="#087D77"/><Button Name="Open" Content="Brauzerdə aç" IsEnabled="False"/><Button Name="Restart" Content="Yenidən başlat" IsEnabled="False"/><Button Name="Stop" Content="■  Dayandır" Foreground="#AD3434" IsEnabled="False"/></WrapPanel>
   </StackPanel>
  </Border>
  <TextBlock Grid.Row="2" Name="Message" Text="İlk açılışda hazırlıq bir neçə dəqiqə çəkə bilər. Gedişat aşağıda görünəcək." TextWrapping="Wrap" Foreground="#52657A" Margin="0,0,0,16"/>
  <Grid Grid.Row="3"><Grid.RowDefinitions><RowDefinition Height="Auto"/><RowDefinition Height="*"/></Grid.RowDefinitions><DockPanel Margin="0,0,0,10"><TextBlock Text="Son fəaliyyət" FontWeight="SemiBold" VerticalAlignment="Center"/><Button Name="Logs" Content="Log qovluğu" HorizontalAlignment="Right" Padding="10,5" Margin="0"/></DockPanel><TextBox Grid.Row="1" Name="Log" IsReadOnly="True" TextWrapping="Wrap" VerticalScrollBarVisibility="Auto" Background="#142A3A" Foreground="#D7E6EE" BorderThickness="0" Padding="16" FontFamily="Consolas" FontSize="12"/></Grid>
  <TextBlock Grid.Row="4" Text="Bu pəncərəni bağlamaq xidməti dayandırmır. Dayandır düyməsindən istifadə edin." Foreground="#52657A" TextWrapping="Wrap" Margin="0,18,0,0" FontSize="12"/>
 </Grid>
</Window>
'@
$window = [Windows.Markup.XamlReader]::Load((New-Object Xml.XmlNodeReader $layout))
$ui = @{}
foreach ($name in @('Status','ModeLabel','Address','Mode','Start','Open','Restart','Stop','Message','Logs','Log')) { $ui[$name]=$window.FindName($name) }
if (Test-Path -LiteralPath (Join-Path $projectRoot 'backend\appsettings.Local.json')) { $ui.Mode.SelectedIndex=1 }
$script:launcher = $null
$script:actionJob = $null
$script:actionName = ''
$script:pendingUntil = [DateTime]::MinValue
$script:lastLog = ''
function Refresh-Panel {
    $service = Get-RemediatorService
    $launching = $script:launcher -and !$script:launcher.HasExited
    $pending = $script:actionJob -or [DateTime]::UtcNow -lt $script:pendingUntil
    $ui.Start.IsEnabled = !$service -and !$launching -and !$pending
    $ui.Mode.IsEnabled = $ui.Start.IsEnabled
    $ui.Open.IsEnabled = [bool]$service -and $service.ready -ne $false
    $ui.Stop.IsEnabled = [bool]$service -and !$pending
    $ui.Restart.IsEnabled = $ui.Stop.IsEnabled
    if ($service) {
        $ui.Status.Text = if ($pending) { 'Əməliyyat icra olunur…' } elseif ($service.ready -eq $false) { 'Bağlantı yoxlanılır…' } else { 'Xidmət işləyir' }
        $ui.ModeLabel.Text = if ($service.mode -eq 'Demo') { 'DEMO' } else { 'WINDOWS' }
        $ui.Address.Text = [string]$service.url
        if ($service.startupIssue) {
            $ui.Status.Text = 'Sazlama tələb olunur'
            $ui.ModeLabel.Text = 'YERLİ SAZLAMA'
            $ui.Message.Text = 'Windows / AD hazır deyil. “Brauzerdə aç” ilə sazlamaları tamamlayın. Səbəb: ' + [string]$service.startupIssue
        }
    } elseif ($launching) { $ui.Status.Text='Hazırlanır…'; $ui.Address.Text='Build və xidmətin açılması gözlənilir.'; $ui.ModeLabel.Text='' }
    else { $ui.Status.Text='Dayandırılıb'; $ui.Address.Text='Başlat düyməsi ilə yenidən aça bilərsiniz.'; $ui.ModeLabel.Text='' }
    if ($script:launcher -and $script:launcher.HasExited -and $script:launcher.ExitCode -ne 0) {
        $ui.Message.Text='Başlatma alınmadı. Aşağıdakı logu yoxlayın və yenidən cəhd edin.'
        $script:launcher=$null
    }
    $logPath=Join-Path $work 'bootstrap.log'
    if (Test-Path -LiteralPath $logPath) {
        $content=(Get-Content -LiteralPath $logPath -Tail 35 -ErrorAction SilentlyContinue) -join [Environment]::NewLine
        if ($content -ne $script:lastLog) { $ui.Log.Text=$content; $ui.Log.ScrollToEnd(); $script:lastLog=$content }
    }
    if ($script:actionJob -and $script:actionJob.State -in @('Completed','Failed','Stopped')) {
        $result=Receive-Job $script:actionJob -ErrorAction SilentlyContinue
        if ($result -and $result.ok) { $ui.Message.Text='Sorğu qəbul edildi. Xidmətin statusu yenilənir.'; $script:pendingUntil=[DateTime]::UtcNow.AddSeconds(3) }
        else { $ui.Message.Text=if ($result.error) { [string]$result.error } else { 'Sorğu tamamlanmadı. Logları yoxlayın.' }; $script:pendingUntil=[DateTime]::MinValue }
        Remove-Job $script:actionJob -Force
        $script:actionJob=$null
    }
}
function Request-ServiceAction([string]$action) {
    if ($script:actionJob) { return }
    $ui.Message.Text='Sorğu göndərilir. Aktiv GPO əməliyyatı varsa xidmət dayandırılmayacaq.'
    $script:actionJob=Start-Job -ArgumentList $projectRoot,$action -ScriptBlock {
        param($root,$requested)
        try { . (Join-Path $root 'scripts\ServiceControl.ps1'); Invoke-RemediatorServiceAction $requested | Out-Null; @{ok=$true} }
        catch { @{ok=$false;error=$_.Exception.Message} }
    }
    Refresh-Panel
}
$ui.Start.Add_Click({
    try {
        $mode=[string]$ui.Mode.SelectedItem.Tag
        $arguments='-NoLogo -NoProfile -ExecutionPolicy Bypass -File "{0}" -Mode {1} -Port {2} -NoBrowser' -f (Join-Path $projectRoot 'GpoRemediator.ps1'),$mode,$Port
        $script:launcher=Start-Process powershell.exe -ArgumentList $arguments -WorkingDirectory $projectRoot -WindowStyle Hidden -PassThru -RedirectStandardOutput (Join-Path $work 'launcher-output.log') -RedirectStandardError (Join-Path $work 'launcher-error.log')
        $ui.Message.Text='Tətbiq hazırlanır. Hazır olduqda “Brauzerdə aç” düyməsini basın.'
        Refresh-Panel
    } catch { $ui.Message.Text=$_.Exception.Message }
})
$ui.Open.Add_Click({ $service=Get-RemediatorService; if ($service) { $path=if ($service.openPath) { [string]$service.openPath } else { '/#/home' }; Start-Process (([string]$service.url).TrimEnd('/')+$path) } })
$ui.Stop.Add_Click({ Request-ServiceAction 'stop' })
$ui.Restart.Add_Click({ Request-ServiceAction 'restart' })
$ui.Logs.Add_Click({ Start-Process explorer.exe -ArgumentList ('"'+$work+'"') })
$timer=New-Object Windows.Threading.DispatcherTimer
$timer.Interval=[TimeSpan]::FromSeconds(1)
$timer.Add_Tick({ try { Refresh-Panel } catch { $ui.Message.Text=$_.Exception.Message } })
$window.Add_Closed({ $timer.Stop(); if ($script:actionJob) { Remove-Job $script:actionJob -Force -ErrorAction SilentlyContinue } })
Refresh-Panel
$timer.Start()
$window.ShowDialog() | Out-Null
