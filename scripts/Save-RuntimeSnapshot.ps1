param([string]$RailwayCli = 'railway', [string]$SshKey, [string]$OutputPath)
$ErrorActionPreference = 'Stop'
if (Test-Path -LiteralPath $OutputPath) { throw 'Refusing to overwrite runtime snapshot' }
$snapshot = @{}
foreach ($service in @('BiniTech-Auth','BiniTech-PDV')) {
  $config = & $RailwayCli ssh config --service $service --environment production --identity-file $SshKey --dry-run
  if ($LASTEXITCODE -ne 0) { throw 'Cannot resolve SSH service' }
  $sshUser = (($config | Select-String '^\s+User\s+(\S+)').Matches.Groups | Select-Object -Last 1).Value
  if ([string]::IsNullOrWhiteSpace($sshUser)) { throw 'Missing service instance' }
  $names = if ($service -eq 'BiniTech-Auth') { @('JWT_SECRET','SECURITY_PEPPER','AUTH_MONGODB_URI','AUTH_MONGODB_DATABASE','AUTH_REDIS_URL') } else { @('ADMIN_USERNAME','ADMIN_PASSWORD') }
  foreach ($name in $names) {
    $secret = ssh -T -o BatchMode=yes -o ConnectTimeout=10 -o StrictHostKeyChecking=accept-new -o UserKnownHostsFile=C:/Users/Niico/pdv/.auth-work/migration/known_hosts -i $SshKey "$sshUser@ssh.railway.com" printenv $name
    if ($LASTEXITCODE -ne 0 -or [string]::IsNullOrWhiteSpace($secret)) { throw "Runtime variable unavailable: $service/$name" }
    $snapshot["$service/$name"] = ($secret -join "`n").TrimEnd()
  }
}
# Generated backup artifact, encrypted using Windows DPAPI for the current user.
$encrypted = ($snapshot | ConvertTo-Json -Compress | ConvertTo-SecureString -AsPlainText -Force) | ConvertFrom-SecureString
[IO.File]::WriteAllText($OutputPath, $encrypted)
Write-Output 'Runtime rollback/smoke-test snapshot encrypted with Windows DPAPI; no secrets printed.'
