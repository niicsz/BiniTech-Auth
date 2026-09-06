param(
  [ValidateSet('Prepare','Audit','Copy','Verify','Cleanup')][string]$Mode = 'Audit',
  [switch]$WritersStopped,
  [switch]$CutoverVerified,
  [string]$RailwayCli = 'railway',
  [string]$DatabaseService = 'MongoDB',
  [string]$ProxyEndpoint = 'altaria.proxy.rlwy.net:17362'
)
$ErrorActionPreference = 'Stop'
$migrationProject = '0fb63aa2-ccbd-4dcb-a451-6324960b0b22'
function Read-Variables([string]$service) {
  $raw = & $RailwayCli variables --service $service --environment production --project $migrationProject --json
  if ($LASTEXITCODE -ne 0) { throw "Cannot read variables for $service" }
  return $raw | ConvertFrom-Json
}
function Set-Secret([string]$service, [string]$name, [string]$value) {
  if ([string]::IsNullOrWhiteSpace($value)) { throw "Empty variable: $name" }
  $result = $value | & $RailwayCli variable set $name --stdin --service $service --environment production --project $migrationProject --skip-deploys
  if ($LASTEXITCODE -ne 0) { throw "Cannot configure $service/$name" }
  Write-Output "Configured $service/$name (value hidden; no deployment triggered)"
}
function New-MigrationSecret {
  return [Convert]::ToHexString([Security.Cryptography.RandomNumberGenerator]::GetBytes(48))
}
$migrationSourceVars = Read-Variables 'BiniTech-PDV'
$migrationTargetVars = Read-Variables $DatabaseService
$migrationAuthVars = Read-Variables 'BiniTech-Auth'
$env:MIGRATION_SOURCE_URI = $migrationSourceVars.MONGODB_URI
$env:MIGRATION_TARGET_URI = 'mongodb://' + [uri]::EscapeDataString($migrationTargetVars.MONGOUSER) + ':' +
  [uri]::EscapeDataString($migrationTargetVars.MONGOPASSWORD) + '@' + $ProxyEndpoint + '/?authSource=admin'
try {
  if ($Mode -eq 'Prepare') {
    $migrationPepper = $migrationAuthVars.SECURITY_PEPPER
    if ([string]::IsNullOrWhiteSpace($migrationPepper) -or $migrationPepper.StartsWith('${{')) {
      throw 'Resolved original pepper is unavailable; do not change password hashes or deploy.'
    }
    $migrationDbPassword = if ($migrationAuthVars.AUTH_DB_PASSWORD) { $migrationAuthVars.AUTH_DB_PASSWORD } else { New-MigrationSecret }
    $migrationServiceKey = if ($migrationAuthVars.AUTH_SERVICE_KEY) { $migrationAuthVars.AUTH_SERVICE_KEY } else { New-MigrationSecret }
    $migrationSigningKey = if ($migrationAuthVars.AUTH_DB_PASSWORD) { $migrationAuthVars.JWT_SECRET } else { New-MigrationSecret }
    # Save generated values before provisioning, allowing safe retries after interruption.
    Set-Secret 'BiniTech-Auth' 'AUTH_DB_PASSWORD' $migrationDbPassword
    Set-Secret 'BiniTech-Auth' 'AUTH_SERVICE_KEY' $migrationServiceKey
    Set-Secret 'BiniTech-Auth' 'JWT_SECRET' $migrationSigningKey
    Set-Secret 'BiniTech-Auth' 'SECURITY_PEPPER' $migrationPepper
    $env:MIGRATION_APP_PASSWORD = $migrationDbPassword
    mongosh --nodb --quiet --eval 'const c = new Mongo(process.env.MIGRATION_TARGET_URI); const d = c.getDB("binitech_auth"); if (!d.getUser("binitech_auth_app")) { d.createUser({user:"binitech_auth_app",pwd:process.env.MIGRATION_APP_PASSWORD,roles:[{role:"readWrite",db:"binitech_auth"}]}); } else { d.updateUser("binitech_auth_app",{pwd:process.env.MIGRATION_APP_PASSWORD,roles:[{role:"readWrite",db:"binitech_auth"}]}); } print("Dedicated database user configured");'
    if ($LASTEXITCODE -ne 0) { throw 'Cannot configure dedicated database user' }
    $migrationInternalUri = 'mongodb://binitech_auth_app:' + $migrationDbPassword + '@' + $migrationTargetVars.MONGOHOST + ':' +
      $migrationTargetVars.MONGOPORT + '/binitech_auth?authSource=binitech_auth'
    Set-Secret 'BiniTech-Auth' 'AUTH_MONGODB_URI' $migrationInternalUri
    Set-Secret 'BiniTech-Auth' 'AUTH_MONGODB_DATABASE' 'binitech_auth'
    Set-Secret 'BiniTech-Auth' 'AUTH_APPLICATION_ID' 'pdv'
    Set-Secret 'BiniTech-PDV' 'AUTH_SERVICE_KEY' '${{BiniTech-Auth.AUTH_SERVICE_KEY}}'
    $env:MIGRATION_MODE = 'audit'
  } else {
    $env:MIGRATION_MODE = $Mode.ToLowerInvariant()
  }
  $env:MIGRATION_WRITERS_STOPPED = if ($WritersStopped) { 'YES' } else { 'NO' }
  $env:MIGRATION_CUTOVER_VERIFIED = if ($CutoverVerified) { 'YES' } else { 'NO' }
  mongosh --nodb --quiet --file (Join-Path $PSScriptRoot 'migrate-pdv-identities.js')
  if ($LASTEXITCODE -ne 0) { throw 'Migration verification failed. Production must not be switched.' }
} finally {
  'MIGRATION_SOURCE_URI','MIGRATION_TARGET_URI','MIGRATION_APP_PASSWORD','MIGRATION_MODE',
    'MIGRATION_WRITERS_STOPPED','MIGRATION_CUTOVER_VERIFIED' | ForEach-Object { Remove-Item -LiteralPath "Env:$_" -ErrorAction SilentlyContinue }
}
