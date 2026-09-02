[CmdletBinding()]param()
Set-StrictMode -Version Latest
$ErrorActionPreference='Stop'
. (Join-Path $PSScriptRoot 'ExternalTransferOfficialComponentAnchor.ps1')
function Assert-AnchorTest([bool]$Condition,[string]$Message){if(-not $Condition){throw "official anchor self-test failed: $Message"}}
function Get-TestHash([byte[]]$Bytes){$s=[Security.Cryptography.SHA256]::Create();try{([BitConverter]::ToString($s.ComputeHash($Bytes))).Replace('-','')}finally{$s.Dispose()}}
$root=Join-Path (Join-Path ([IO.Path]::GetFullPath((Join-Path $PSScriptRoot '..'))) 'target') ('official-anchor-selftest-'+[Guid]::NewGuid().ToString('N'))
[IO.Directory]::CreateDirectory($root)|Out-Null
try {
  $payloads=@([Text.Encoding]::UTF8.GetBytes('cli-fixture'),[Text.Encoding]::UTF8.GetBytes('daemon-fixture'),[Text.Encoding]::UTF8.GetBytes('helper-fixture'))
  $names=@('serctl_cli.exe','serctl_daemon.exe','serctl-xfer');$platforms=@('windows-x86_64','windows-x86_64','linux-x86_64')
  $paths=@();for($i=0;$i -lt 3;$i++){$p=Join-Path $root $names[$i];[IO.File]::WriteAllBytes($p,$payloads[$i]);$paths+=$p}
  $record=[pscustomobject][ordered]@{schema_version=1;record_contract='serctl-verified-downloaded-set-record-v1';release_tag='v1.0.0-beta';commit='1'*40;tag_object='2'*40;repository='example/serctl';synthetic_fixture=$true;components=@()}
  for($i=0;$i -lt 3;$i++){$record.components += [pscustomobject][ordered]@{platform=$platforms[$i];name=$names[$i];binary_size=[long]$payloads[$i].Length;sha256=Get-TestHash $payloads[$i];version=('synthetic-'+$names[$i])}}
  $recordPath=Join-Path $root 'downloaded-set.json';[IO.File]::WriteAllText($recordPath,(($record|ConvertTo-Json -Compress -Depth 8)+"`n"),[Text.UTF8Encoding]::new($false))
  function Invoke-Fixture($Record=$recordPath,$Components=$paths,$Output=(Join-Path $root ([Guid]::NewGuid().ToString('N')+'.anchor'))){
    $streams=@([IO.File]::Open($Record,'Open','Read','Read'))+@($Components|%{[IO.File]::Open($_,'Open','Read','ReadWrite')})+@([IO.File]::Open($Output,'CreateNew','ReadWrite','Read'))
    try{New-ExternalTransferOfficialComponentAnchorInternal $streams[0].SafeFileHandle $streams[1].SafeFileHandle $streams[2].SafeFileHandle $streams[3].SafeFileHandle $streams[4].SafeFileHandle;return $Output}finally{$streams|% Dispose}
  }
  $output=Invoke-Fixture;$anchor=[IO.File]::ReadAllText($output)|ConvertFrom-Json
  Assert-AnchorTest ($anchor.anchor_contract -ceq 'serctl-official-component-anchor-v1' -and -not $anchor.sealable -and $anchor.synthetic_fixture) 'synthetic anchor identity changed'
  $reuseRejected=$false;$rs0=[IO.File]::Open($recordPath,'Open','Read','Read');$cs0=@($paths|%{[IO.File]::Open($_,'Open','Read','Read')});$oo0=[IO.File]::Open($output,'Open','ReadWrite','Read');try{try{New-ExternalTransferOfficialComponentAnchorInternal $rs0.SafeFileHandle $cs0[0].SafeFileHandle $cs0[1].SafeFileHandle $cs0[2].SafeFileHandle $oo0.SafeFileHandle}catch{$reuseRejected=$true}}finally{$rs0.Dispose();$cs0|% Dispose;$oo0.Dispose()};Assert-AnchorTest $reuseRejected 'nonempty/reused output handle accepted'
  $dupRejected=$false;$s=[IO.File]::Open($recordPath,'Open','Read','Read');$o=[IO.File]::Open((Join-Path $root 'dup.anchor'),'CreateNew','ReadWrite','Read');try{try{New-ExternalTransferOfficialComponentAnchorInternal $s.SafeFileHandle $s.SafeFileHandle $s.SafeFileHandle $s.SafeFileHandle $o.SafeFileHandle}catch{$dupRejected=$true}}finally{$s.Dispose();$o.Dispose()};Assert-AnchorTest $dupRejected 'duplicate purpose handle accepted'
  $bad=$record.PSObject.Copy();$bad|Add-Member unknown_field 1;$badPath=Join-Path $root 'bad.json';[IO.File]::WriteAllText($badPath,(($bad|ConvertTo-Json -Compress -Depth 8)+"`n"));$rejected=$false;try{Invoke-Fixture $badPath|Out-Null}catch{$rejected=$true};Assert-AnchorTest $rejected 'unknown record field accepted'
  $hashBad=($record|ConvertTo-Json -Depth 8|ConvertFrom-Json);$hashBad.components[0].sha256='F'*64;$hashBadPath=Join-Path $root 'hash-bad.json';[IO.File]::WriteAllText($hashBadPath,(($hashBad|ConvertTo-Json -Compress -Depth 8)+"`n"));$hashRejected=$false;try{Invoke-Fixture $hashBadPath|Out-Null}catch{$hashRejected=$true};Assert-AnchorTest $hashRejected 'component hash substitution accepted'
  $replaceStream=[IO.File]::Open($paths[0],'Open','Read','ReadWrite,Delete');$replacement=Join-Path $root 'replacement';[IO.File]::Move($paths[0],$replacement);[IO.File]::WriteAllBytes($paths[0],[Text.Encoding]::UTF8.GetBytes('changed'));$toctouOut=Join-Path $root 'toctou.anchor';$rs=[IO.File]::Open($recordPath,'Open','Read','Read');$d=[IO.File]::Open($paths[1],'Open','Read','Read');$h=[IO.File]::Open($paths[2],'Open','Read','Read');$oo=[IO.File]::Open($toctouOut,'CreateNew','ReadWrite','Read');try{New-ExternalTransferOfficialComponentAnchorInternal $rs.SafeFileHandle $replaceStream.SafeFileHandle $d.SafeFileHandle $h.SafeFileHandle $oo.SafeFileHandle}finally{$rs.Dispose();$replaceStream.Dispose();$d.Dispose();$h.Dispose();$oo.Dispose()};Assert-AnchorTest (Test-Path $toctouOut) 'open-handle TOCTOU pin failed'
} finally {if(Test-Path $root){Remove-Item -LiteralPath $root -Recurse -Force}}
Write-Host 'Official component anchor self-test passed (synthetic fixture; unsealable).'
