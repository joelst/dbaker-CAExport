#requires -Modules Microsoft.Graph.Identity.SignIns, Microsoft.Graph.Authentication
<#
.SYNOPSIS
    Export Conditional Access Policies with Recommendations.

.DESCRIPTION
    This script exports Conditional Access (CA) policies from Azure AD to an HTML file.
    It includes recommendations and checks for each policy to enhance security.

.PARAMETER PolicyID
  (Optional) A specific Conditional Access policy Id (GUID). When supplied the export/report is limited
  to this single policy. When omitted all policies are processed.

.PARAMETER Html
  Switch. Generate the interactive HTML report (default if no other export switch is specified).

.PARAMETER Json
  Switch. Generate a JSON file containing the enriched policy objects (including duplicate markers).

.PARAMETER Csv
  Switch. Generate a flattened CSV export of the policy objects suitable for spreadsheet review.

.PARAMETER CsvPivot
  Switch. Generate a pivot‑friendly CSV (wide format) for ad‑hoc aggregation in Excel / BI tools.

.PARAMETER NoRecommendations
  Switch. Skip generation of the recommendations analysis and omit the Recommendations tab from the HTML output. Useful for faster exports when only raw policy data is required.

.PARAMETER CsvColumns
  Optional string array specifying a custom subset / order of columns for the Csv export. When omitted
  the default full set is used.

.OUTPUTS
  Files written to the working directory. Filenames are timestamped and prefixed with CAExport_<TenantName>_.

.EXAMPLE
  PS> .\Export-CAPolicyWithRecs.ps1
  Exports all Conditional Access policies and produces an HTML report (default output).

.EXAMPLE
  PS> .\Export-CAPolicyWithRecs.ps1 -PolicyID 11111111-2222-3333-4444-555555555555 -Json
  Exports only the specified policy and produces a JSON file with enriched data.

.EXAMPLE
  PS> .\Export-CAPolicyWithRecs.ps1 -Csv -CsvColumns Name,Status,'Require MFA','Block'
  Produces a CSV limited to the selected columns in the specified order.

.EXAMPLE
  PS> .\Export-CAPolicyWithRecs.ps1 -Html -Json -Csv -CsvPivot
  Produces all supported output formats in a single invocation.

.EXAMPLE
  PS> .\Export-CAPolicyWithRecs.ps1 -NoRecommendations -Csv
  Exports policies (CSV + default HTML/JSON if no other switches) while skipping recommendation analysis for faster runtime.

.EXAMPLE
  PS> .\Export-CAPolicyWithRecs.ps1 -PolicyID (Get-Clipboard) -Html
  Uses a policy Id copied to the clipboard and generates only the HTML report.

.EXAMPLE
.\Export-CAPolicyWithRecs.ps1

This example runs the script and exports all Conditional Access policies with recommendations.

.NOTES
    Author:  Douglas Baker
             @dougsbaker
  Version: 3.1.1

Output report uses open source components for HTML formatting
- bootstrap - MIT License - https://getbootstrap.com/docs/4.0/about/license/
- fontawesome - CC BY 4.0 License - https://fontawesome.com/license/free

############################################################################
This sample script is not supported under any standard support program or service.
This sample script is provided AS IS without warranty of any kind.
This work is licensed under a Creative Commons Attribution 4.0 International License
https://creativecommons.org/licenses/by-nc-sa/4.0/
############################################################################

#>

[CmdletBinding()]
# Suppress PSAvoidLongLines for unavoidable embedded HTML/URLs
[Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSAvoidLongLines', '')]
param (
  [Parameter()]
  [ValidatePattern('^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$')]
  [String]$PolicyID,
  [switch]$Html,
  [switch]$NoBrowser,
  [string]$OutputPath,
  [switch]$Json,
  [switch]$Csv,
  [switch]$CsvPivot,
  [switch]$NoRecommendations,
  [string[]]$CsvColumns
)
<#
  Reconstructed: helper functions, Graph connection, data retrieval, enrichment, CAExport build, duplicate detection, pivot prep.
#>

<#
.SYNOPSIS
  Write an informational message to the information stream.
.DESCRIPTION
  Wrapper around Write-Information so that callers can use -InformationAction / -InformationPreference
  and optionally suppress or capture messages. Replaces earlier Write-Host usage for lint compliance.
.PARAMETER Message
  The text to emit.
#>
function Write-Info {
  [CmdletBinding()]
  param([Parameter(Mandatory)][string]$Message)
  Write-Information -MessageData "[INFO] $Message" -InformationAction Continue
}

<#
.SYNOPSIS
  Write a warning message.
.DESCRIPTION
  Thin wrapper kept for symmetry with Write-Info.
.EXAMPLE
  Write-Warn 'Policy collection returned zero results.'
  Emits a formatted warning to the warning stream.
#>
function Write-Warn {
  [CmdletBinding()]
  param([Parameter(Mandatory)][string]$Message)
  Write-Warning $Message
}

<#
.SYNOPSIS
  Establish a Microsoft Graph connection if one does not already exist.
.DESCRIPTION
  Checks for an existing MgGraph context and, if missing, connects with the required scopes
  (Policy.Read.All, Directory.Read.All, RoleManagement.Read.All).
.NOTES
  Replaces Ensure-GraphConnection (deprecated) to satisfy approved verb list (Connect-*).
.EXAMPLE
  Connect-GraphContext
  Ensures the current session is connected with required scopes; returns immediately if already connected.
#>
function Connect-GraphContext {
  [CmdletBinding()]
  param()
  $ctx = $null
  try { $ctx = Get-MgContext -ErrorAction Stop } catch { Write-Verbose 'No existing Graph context found (Get-MgContext failed).' }
  $requiredScopes = 'Policy.Read.All', 'Directory.Read.All', 'RoleManagement.Read.All'
  $needsConnect = $false
  if (-not $ctx -or -not $ctx.Account) { $needsConnect = $true }
  else {
    $granted = @($ctx.Scopes)
    foreach ($r in $requiredScopes) {
      if ($granted -notcontains $r) { $needsConnect = $true; break }
    }
  }
  if ($needsConnect) {
    Write-Info 'Connecting to Microsoft Graph (Policy.Read.All, Directory.Read.All, RoleManagement.Read.All)'
    Connect-MgGraph -Scopes $requiredScopes | Out-Null
  }
}

<#
.SYNOPSIS
  Safely invoke a script block, returning $null on failure.
.DESCRIPTION
  Executes the provided script block with error trapping. Exceptions are suppressed (logged to Verbose)
  and $null is returned so that callers can continue a best-effort enrichment pattern.
.PARAMETER ScriptBlock
  The code to execute.
.EXAMPLE
  Invoke-SafeGet { Get-MgUser -UserId $id -Property Id,DisplayName }
#>
function Invoke-SafeGet {
  [CmdletBinding()]
  param([Parameter(Mandatory)][ScriptBlock]$ScriptBlock)
  try { & $ScriptBlock } catch { Write-Verbose ('Invoke-SafeGet suppressed error: {0}' -f $_.Exception.Message); return $null }
}

<#
.SYNOPSIS
  Convert a list of IDs to their friendly names when present in a lookup map.
.DESCRIPTION
  For each element in List, if the Map contains that key the mapped value is output; otherwise the original value.
  Null / empty input yields an empty array.
.PARAMETER List
  Collection of IDs or values.
.PARAMETER Map
  Hashtable keyed by ID with friendly values.
.EXAMPLE
  Convert-IdListToNames -List $policy.conditions.users.includeUsers -Map $UserMap
#>
function Convert-IdListToName {
  [CmdletBinding()]
  param([string[]]$List, [hashtable]$Map)
  if (-not $List) { return @() }
  return $List | ForEach-Object { if ($Map.ContainsKey($_)) { $Map[$_] } else { $_ } }
}

<#
.SYNOPSIS
  Test whether a string is a GUID.
.DESCRIPTION
  Wraps [guid]::TryParse for readability and reuse.
  Filters out sentinel tokens (e.g. 'All') earlier in the pipeline.
.EXAMPLE
  Test-IsGuid 'd2719d52-3f4e-4f7c-9d0d-4f5c2a8ab123'
  Returns True.
.EXAMPLE
  Test-IsGuid 'All'
  Returns False.
#>
function Test-IsGuid {
  [CmdletBinding()]
  param([string]$Value)
  if (-not $Value) { return $false }
  return [bool]([guid]::TryParse($Value, [ref]([guid]::Empty)))
}

# Unified resolver: given a list of IDs (users/groups/roles/apps), return friendly names when available.
function Resolve-EntityNameList {
  [CmdletBinding()]
  param(
    [string[]]$Ids,
    [hashtable]$UserMap,
    [hashtable]$GroupMap,
    [hashtable]$RoleMap,
    [hashtable]$AppMap
  )
  if (-not $Ids) { return @() }
  return $Ids | ForEach-Object {
    $id = $_
    if ([string]::IsNullOrWhiteSpace($id)) { return $id }
    if ($UserMap -and $UserMap.ContainsKey($id)) { return $UserMap[$id] }
    if ($GroupMap -and $GroupMap.ContainsKey($id)) { return $GroupMap[$id] }
    if ($RoleMap -and $RoleMap.ContainsKey($id)) { return $RoleMap[$id] }
    if ($AppMap -and $AppMap.ContainsKey($id)) { return $AppMap[$id] }
    return $id
  }
}

# Replace GUIDs in arbitrary free‑text with friendly names (users, groups, roles, apps) when resolvable.
function Resolve-EntityGuidsInText {
  [CmdletBinding()]
  param(
    [string]$Text,
    [hashtable]$UserMap,
    [hashtable]$GroupMap,
    [hashtable]$RoleMap,
    [hashtable]$AppMap
  )
  # Touch parameters to satisfy static analyzers; they are also used within the regex scriptblock below
  $null = $UserMap; $null = $GroupMap; $null = $RoleMap; $null = $AppMap
  if ([string]::IsNullOrWhiteSpace($Text)) { return $Text }
  # Standard GUID pattern
  $pattern = '[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}'
  return ([regex]::Replace($Text, $pattern, {
        param($m)
        $g = $m.Value
        if ($UserMap -and $UserMap.ContainsKey($g)) { return $UserMap[$g] }
        if ($GroupMap -and $GroupMap.ContainsKey($g)) { return $GroupMap[$g] }
        if ($RoleMap -and $RoleMap.ContainsKey($g)) { return $RoleMap[$g] }
        if ($AppMap -and $AppMap.ContainsKey($g)) { return $AppMap[$g] }
        return $g
      }))
}

# Backward compatibility aliases (deprecated names). Retained temporarily so external callers
# referencing prior function names do not break. Marked for removal in a future major version.
Set-Alias -Name Ensure-GraphConnection -Value Connect-GraphContext -ErrorAction SilentlyContinue
Set-Alias -Name Safe-Get -Value Invoke-SafeGet -ErrorAction SilentlyContinue
Set-Alias -Name Translate-List -Value Convert-IdListToName -ErrorAction SilentlyContinue

Connect-GraphContext

# Script metadata / version stamp (bump when feature changes)
$Script:CAExportVersion = '3.1.1'

if ($OutputPath) {
  try {
    if (-not (Test-Path -LiteralPath $OutputPath)) { New-Item -ItemType Directory -Path $OutputPath -Force | Out-Null }
    $ExportLocation = (Resolve-Path -LiteralPath $OutputPath).Path
    Write-Info "Using custom output path: $ExportLocation"
  }
  catch {
    Write-Warn ("Failed to set custom OutputPath '{0}': {1}" -f $OutputPath, $_.Exception.Message)
  }
}

# If no -OutputPath was supplied or resolution failed, default to current working directory
if (-not $ExportLocation) {
  $ExportLocation = (Get-Location).Path
  Write-Info "No OutputPath specified – defaulting to current directory: $ExportLocation"
}

# ---------------- Retrieve Tenant & Policies ----------------
Write-Info 'Retrieving tenant information'
$TenantName = (Get-MgOrganization -ErrorAction SilentlyContinue | Select-Object -First 1 -ExpandProperty DisplayName)
if (-not $TenantName) { $TenantName = 'UnknownTenant' }
$Date = (Get-Date).ToString('u')

Write-Info 'Retrieving Conditional Access policies'
try {
  $allPolicies = @()
  $uri = 'https://graph.microsoft.com/beta/identity/conditionalAccess/policies?$top=100'
  do {
    $resp = Invoke-MgGraphRequest -Method GET -Uri $uri -OutputType PSObject
    if ($resp.value) { $allPolicies += $resp.value }
    $uri = $resp.'@odata.nextLink'
  } while ($uri)
}
catch {
  Write-Warn ('Failed to retrieve policies: {0}' -f $_.Exception.Message)
  $allPolicies = @()
}

if ($PolicyID) { $CAPolicy = $allPolicies | Where-Object { $_.id -eq $PolicyID } } else { $CAPolicy = $allPolicies }
if (-not $CAPolicy) { Write-Warn 'No policies retrieved.'; $CAPolicy = @() }

# Raw snapshot & index
$RawPolicyObjects = $CAPolicy | ForEach-Object { $_ }  # shallow clone
$RawPolicyIndex = @{}
foreach ($rp in $RawPolicyObjects) { if ($rp.id) { $RawPolicyIndex[$rp.id] = $rp } }

# ---------------- Collect IDs for enrichment ----------------
$userIds = [System.Collections.Generic.HashSet[string]]::new()
$groupIds = [System.Collections.Generic.HashSet[string]]::new()
$roleIds = [System.Collections.Generic.HashSet[string]]::new()
$appIds = [System.Collections.Generic.HashSet[string]]::new()
$locIds = [System.Collections.Generic.HashSet[string]]::new()
$touIds = [System.Collections.Generic.HashSet[string]]::new()

foreach ($p in $CAPolicy) {
  $c = $p.conditions
  if ($c.users) {
    foreach ($i in @($c.users.includeUsers)) { if ($i -and $i -notin @('All', 'None', 'GuestsOrExternalUsers')) { [void]$userIds.Add($i) } }
    foreach ($i in @($c.users.excludeUsers)) { if ($i) { [void]$userIds.Add($i) } }
    foreach ($i in @($c.users.includeGroups)) { if ($i) { [void]$groupIds.Add($i) } }
    foreach ($i in @($c.users.excludeGroups)) { if ($i) { [void]$groupIds.Add($i) } }
    foreach ($i in @($c.users.includeRoles)) { if ($i) { [void]$roleIds.Add($i) } }
    foreach ($i in @($c.users.excludeRoles)) { if ($i) { [void]$roleIds.Add($i) } }
  }
  if ($c.applications) {
    foreach ($i in @($c.applications.includeApplications)) { if ($i -and (Test-IsGuid $i)) { [void]$appIds.Add($i) } }
    foreach ($i in @($c.applications.excludeApplications)) { if ($i -and (Test-IsGuid $i)) { [void]$appIds.Add($i) } }
  }
  if ($c.locations) {
    foreach ($i in @($c.locations.includeLocations)) { if ($i -and (Test-IsGuid $i)) { [void]$locIds.Add($i) } }
    foreach ($i in @($c.locations.excludeLocations)) { if ($i -and (Test-IsGuid $i)) { [void]$locIds.Add($i) } }
  }
  if ($p.grantControls) {
    foreach ($i in @($p.grantControls.termsOfUse)) { if ($i -and (Test-IsGuid $i)) { [void]$touIds.Add($i) } }
  }
}

# ---------------- Build lookup maps (best-effort) ----------------
$UserMap = @{}; $GroupMap = @{}; $RoleMap = @{}; $AppMap = @{}; $LocMap = @{}; $TouMap = @{}

foreach ($id in $userIds) { $obj = Invoke-SafeGet { Get-MgUser -UserId $id -Property Id, DisplayName } ; if ($obj) { $UserMap[$id] = $obj.DisplayName } }
foreach ($id in $groupIds) { $obj = Invoke-SafeGet { Get-MgGroup -GroupId $id -Property Id, DisplayName } ; if ($obj) { $GroupMap[$id] = $obj.DisplayName } }
<#
  Role Resolution Improvement:
  CA policy includeRoles/excludeRoles can contain either:
    - Active directoryRole object IDs (Get-MgDirectoryRole returns these)
    - roleTemplateId GUIDs (directoryRole.roleTemplateId OR roleDefinition.templateId)
    - Unified roleDefinition IDs (roleManagement/directory/roleDefinitions)
  Previous implementation only attempted Get-MgDirectoryRole per ID which fails for
  templateId / roleDefinition IDs when the role is not currently activated.
  New approach:
    1. Bulk fetch active directoryRoles (captures id + roleTemplateId)
    2. Bulk fetch roleDefinitions (captures id + templateId)
    3. Build a composite lookup map so ANY of the above identifiers resolve.
    4. Fallback: per-id Get-MgDirectoryRole (in case of transient activation) if still unknown.
    5. Log unresolved role IDs (they will remain as raw IDs in output).
*#>

$roleLookup = @{}
$dirRoles = Invoke-SafeGet { Get-MgDirectoryRole -All }
if ($dirRoles) {
  foreach ($r in $dirRoles) {
    if ($r.id -and -not $roleLookup.ContainsKey($r.id)) { $roleLookup[$r.id] = $r.displayName }
    if ($r.roleTemplateId -and -not $roleLookup.ContainsKey($r.roleTemplateId)) { $roleLookup[$r.roleTemplateId] = $r.displayName }
  }
}

# Retrieve role definitions (unified) via beta endpoint (paged)
$roleDefs = @()
$roleDefUri = 'https://graph.microsoft.com/beta/roleManagement/directory/roleDefinitions?$top=200'
while ($roleDefUri) {
  $resp = Invoke-SafeGet { Invoke-MgGraphRequest -Method GET -Uri $roleDefUri -OutputType PSObject }
  if ($resp.value) { $roleDefs += $resp.value }
  $roleDefUri = $resp.'@odata.nextLink'
}
foreach ($rd in $roleDefs) {
  if ($rd.id -and -not $roleLookup.ContainsKey($rd.id)) { $roleLookup[$rd.id] = $rd.displayName }
  if ($rd.templateId -and -not $roleLookup.ContainsKey($rd.templateId)) { $roleLookup[$rd.templateId] = $rd.displayName }
}

foreach ($id in $roleIds) {
  if ($roleLookup.ContainsKey($id)) {
    $RoleMap[$id] = $roleLookup[$id]
  }
  else {
    # Fallback attempt (in case role just became active)
    $obj = Invoke-SafeGet { Get-MgDirectoryRole -DirectoryRoleId $id -Property Id, DisplayName }
    if ($obj) { $RoleMap[$id] = $obj.DisplayName } else { Write-Warn "Unresolved role id: $id" }
  }
}
# Applications (service principals)
foreach ($id in $appIds) {
  if (Test-IsGuid $id) {
    $obj = Invoke-SafeGet { Get-MgServicePrincipal -ServicePrincipalId $id -Property Id, DisplayName, AppId }
    if ($obj) { $AppMap[$id] = $obj.DisplayName }
  }
}
foreach ($id in $locIds) {
  if (Test-IsGuid $id) {
    $obj = Invoke-SafeGet { Invoke-MgGraphRequest -Method GET -Uri "https://graph.microsoft.com/beta/identity/conditionalAccess/namedLocations/$id" }
    if ($obj) { $LocMap[$id] = $obj.displayName }
  }
}
foreach ($id in $touIds) {
  if (Test-IsGuid $id) {
    $obj = Invoke-SafeGet { Invoke-MgGraphRequest -Method GET -Uri "https://graph.microsoft.com/beta/agreements/$id" }
    if ($obj) { $TouMap[$id] = $obj.displayName }
  }
}

# (Deprecated: Translate-List now provided via alias to Convert-IdListToNames)

# ---------------- Construct CAExport ----------------
$CAExport = @()
foreach ($Policy in $CAPolicy) {
  $DateModified = if ($Policy.modifiedDateTime) { $Policy.modifiedDateTime } else { $Policy.createdDateTime }
  $InclPlat = $Policy.conditions.platforms.includePlatforms
  $ExclPlat = $Policy.conditions.platforms.excludePlatforms
  $InclDev = $Policy.conditions.devices.includeDevices
  $ExclDev = $Policy.conditions.devices.excludeDevices
  $devFilters = $Policy.conditions.devices.deviceFilter.rule
  $authenticationFlowsString = ( $Policy.conditions.additionalProperties.authenticationFlows.values -join ', ' )
  $InclLocation = $Policy.conditions.locations.includeLocations | ForEach-Object { if ($_ -and (Test-IsGuid $_) -and $LocMap.ContainsKey($_)) { $LocMap[$_] } else { $_ } }
  $ExclLocation = $Policy.conditions.locations.excludeLocations | ForEach-Object { if ($_ -and (Test-IsGuid $_) -and $LocMap.ContainsKey($_)) { $LocMap[$_] } else { $_ } }
  $IncludeUG = @()
  $IncludeUG += (Convert-IdListToName $Policy.conditions.users.includeUsers $UserMap)
  $IncludeUG += (Convert-IdListToName $Policy.conditions.users.includeGroups $GroupMap)
  $IncludeUG += (Convert-IdListToName $Policy.conditions.users.includeRoles $RoleMap)
  if ($Policy.conditions.users.includeGuestsOrExternalUsers.guestOrExternalUserTypes) { $IncludeUG += $Policy.conditions.users.includeGuestsOrExternalUsers.guestOrExternalUserTypes }
  $ExcludeUG = @()
  $ExcludeUG += (Convert-IdListToName $Policy.conditions.users.excludeUsers $UserMap)
  $ExcludeUG += (Convert-IdListToName $Policy.conditions.users.excludeGroups $GroupMap)
  $ExcludeUG += (Convert-IdListToName $Policy.conditions.users.excludeRoles $RoleMap)
  if ($Policy.conditions.users.excludeGuestsOrExternalUsers.guestOrExternalUserTypes) { $ExcludeUG += $Policy.conditions.users.excludeGuestsOrExternalUsers.guestOrExternalUserTypes }

  $rawOriginal = if ($RawPolicyIndex.ContainsKey($Policy.id)) { $RawPolicyIndex[$Policy.id] } else { $null }

  $CAExport += [pscustomobject]@{
    Name                            = $Policy.displayName
    PolicyId                        = $Policy.id
    Status                          = $Policy.state
    DateModified                    = $DateModified
    Users                           = ''
    UsersInclude                    = ($IncludeUG -join ", `r`n")
    UsersExclude                    = ($ExcludeUG -join ", `r`n")
    UsersIncludeIds                 = if ($rawOriginal) { ($rawOriginal.conditions.users.includeUsers -join ", `r`n") } else { $null }
    UsersExcludeIds                 = if ($rawOriginal) { ($rawOriginal.conditions.users.excludeUsers -join ", `r`n") } else { $null }
    RolesIncludeIds                 = if ($rawOriginal) { ($rawOriginal.conditions.users.includeRoles -join ", `r`n") } else { $null }
    RolesExcludeIds                 = if ($rawOriginal) { ($rawOriginal.conditions.users.excludeRoles -join ", `r`n") } else { $null }
    'Cloud apps or actions'         = ''
    ApplicationsIncluded            = ($Policy.conditions.applications.includeApplications -join ", `r`n")
    ApplicationsExcluded            = ($Policy.conditions.applications.excludeApplications -join ", `r`n")
    ApplicationsIncludedIds         = if ($rawOriginal) { ($rawOriginal.conditions.applications.includeApplications -join ", `r`n") } else { $null }
    ApplicationsExcludedIds         = if ($rawOriginal) { ($rawOriginal.conditions.applications.excludeApplications -join ", `r`n") } else { $null }
    userActions                     = ($Policy.conditions.applications.includeUserActions -join ", `r`n")
    AuthContext                     = ($Policy.conditions.applications.includeAuthenticationContextClassReferences -join ", `r`n")
    Conditions                      = ''
    UserRisk                        = ($Policy.conditions.userRiskLevels -join ", `r`n")
    SignInRisk                      = ($Policy.conditions.signInRiskLevels -join ", `r`n")
    PlatformsInclude                = ($InclPlat -join ", `r`n")
    PlatformsExclude                = ($ExclPlat -join ", `r`n")
    LocationsIncluded               = ($InclLocation -join ", `r`n")
    LocationsExcluded               = ($ExclLocation -join ", `r`n")
    LocationsIncludedIds            = if ($rawOriginal) { ($rawOriginal.conditions.locations.includeLocations -join ", `r`n") } else { $null }
    LocationsExcludedIds            = if ($rawOriginal) { ($rawOriginal.conditions.locations.excludeLocations -join ", `r`n") } else { $null }
    ClientApps                      = ($Policy.conditions.clientAppTypes -join ", `r`n")
    DevicesIncluded                 = ($InclDev -join ", `r`n")
    DevicesExcluded                 = ($ExclDev -join ", `r`n")
    DeviceFilters                   = ($devFilters -join ", `r`n")
    AuthenticationFlows             = $authenticationFlowsString
    'Grant Controls'                = ''
    Block                           = if ($Policy.grantControls.builtInControls -contains 'Block') { 'True' } else { '' }
    'Require MFA'                   = if ($Policy.grantControls.builtInControls -contains 'Mfa') { 'True' } else { '' }
    'Authentication Strength MFA'   = $Policy.grantControls.authenticationStrength.displayName
    CompliantDevice                 = if ($Policy.grantControls.builtInControls -contains 'CompliantDevice') { 'True' } else { '' }
    DomainJoinedDevice              = if ($Policy.grantControls.builtInControls -contains 'DomainJoinedDevice') { 'True' } else { '' }
    CompliantApplication            = if ($Policy.grantControls.builtInControls -contains 'CompliantApplication') { 'True' } else { '' }
    ApprovedApplication             = if ($Policy.grantControls.builtInControls -contains 'ApprovedApplication') { 'True' } else { '' }
    PasswordChange                  = if ($Policy.grantControls.builtInControls -contains 'PasswordChange') { 'True' } else { '' }
    TermsOfUse                      = ((Convert-IdListToName $Policy.grantControls.termsOfUse $TouMap) -join ", `r`n")
    TermsOfUseIds                   = if ($rawOriginal) { ($rawOriginal.grantControls.termsOfUse -join ", `r`n") } else { $null }
    CustomControls                  = ($Policy.grantControls.customAuthenticationFactors -join ", `r`n")
    GrantOperator                   = $Policy.grantControls.operator
    'Session Controls'              = ''
    ApplicationEnforcedRestrictions = $Policy.sessionControls.applicationEnforcedRestrictions.isEnabled
    CloudAppSecurity                = $Policy.sessionControls.cloudAppSecurity.isEnabled
    SignInFrequency                 = if ($Policy.sessionControls.signInFrequency.value -and $Policy.sessionControls.signInFrequency.type) { "$( $Policy.sessionControls.signInFrequency.value ) $( $Policy.sessionControls.signInFrequency.type )" }
    PersistentBrowser               = $Policy.sessionControls.persistentBrowser.mode
    ContinuousAccessEvaluation      = $Policy.sessionControls.continuousAccessEvaluation.mode
    ResilientDefaults               = $Policy.sessionControls.disableResilienceDefaults
    secureSignInSession             = $Policy.sessionControls.additionalProperties.secureSignInSession.values
    CreatedDateTime                 = $Policy.createdDateTime
    Description                     = $Policy.description
    RawJson                         = ''
    IsDuplicate                     = $false
    DuplicateMatches                = ''
    ContentHash                     = ''
  }
}

# Duplicate detection (content-based). Compute normalized JSON hash per policy and mark duplicates.
if ($CAExport.Count -gt 1) {
  $hashGroups = @{}
  foreach ($p in $CAExport) {
    # Build a normalized object (exclude date/time / id / description fields to reduce false positives)
    $norm = $p | Select-Object * -ExcludeProperty PolicyId, DateModified, CreatedDateTime, Description, DuplicateMatches, IsDuplicate, RawJson, ContentHash
    $normJson = ($norm | ConvertTo-Json -Depth 8)
    $bytes = [Text.Encoding]::UTF8.GetBytes($normJson)
    $sha = [System.Security.Cryptography.SHA256]::Create()
    $hash = ([BitConverter]::ToString($sha.ComputeHash($bytes))).Replace('-', '')
    $p.ContentHash = $hash
    if (-not $hashGroups.ContainsKey($hash)) { $hashGroups[$hash] = @() }
    $hashGroups[$hash] += $p
  }
  foreach ($kv in $hashGroups.GetEnumerator()) {
    if ($kv.Value.Count -gt 1) {
      foreach ($p in $kv.Value) {
        $p.IsDuplicate = $true
        $p.DuplicateMatches = ($kv.Value | Where-Object { $_.Name -ne $p.Name } | ForEach-Object { $_.Name }) -join ', '
      }
    }
  }
}

# Map external switch parameters to internal export control flags for backward compatibility / clarity
if ($PSBoundParameters.ContainsKey('Html')) { $HTMLExport = [bool]$Html }
if ($PSBoundParameters.ContainsKey('Json')) { $JsonExport = [bool]$Json }
if ($PSBoundParameters.ContainsKey('Csv')) { $CsvExport = [bool]$Csv }
if ($PSBoundParameters.ContainsKey('CsvPivot')) { $CsvPivotExport = [bool]$CsvPivot }
# Default behavior: if no explicit export switches supplied, emit HTML + JSON + CSV (pivot remains opt-in)
if (-not ($HTMLExport -or $JsonExport -or $CsvExport -or $CsvPivotExport)) { $HTMLExport = $true; $JsonExport = $true; $CsvExport = $true }
$LinkURL = 'https://entra.microsoft.com/#view/Microsoft_AAD_ConditionalAccess/PolicyBlade/PolicyMenuBlade/~/Policies/policyId/'
$baseName = "CAExport_${TenantName}_$(Get-Date -Format 'yyyyMMdd_HHmmss')"
$FileName = "$baseName.html"
$JsonFileName = "$baseName.json"
$CsvFileName = "$baseName.csv"
$CsvPivotFileName = "$baseName-pivot.csv"
$HtmlParts = @()
if (-not $NoRecommendations) {
  Write-Info 'Analyzing: getting recommendations'
  if (-not ([System.Management.Automation.PSTypeName]'Recommendation').Type) {
    class Recommendation {
      [string]$Control
      [string]$Name
      [string]$PassText
      [string]$FailRecommendation
      [string]$Importance
      [hashtable]$Links
      [bool]$Status
      [bool]$SwapStatus
      [string]$Note
      [string[]]$Excluded
      Recommendation([string]$Control, [string]$Name, [string]$PassText, [string]$FailRecommendation, [string]$Importance, [hashtable]$Links, [bool]$Status, [bool]$SwapStatus) {
        $this.Control = $Control
        $this.Name = $Name
        $this.PassText = $PassText
        $this.FailRecommendation = $FailRecommendation
        $this.Importance = $Importance
        $this.Links = $Links
        $this.Status = $Status
        $this.SwapStatus = $SwapStatus
        $this.Note = ''
        $this.Excluded = @()
      }
    }
  }

  $recommendations = @(
    [Recommendation]::new(
      'CA-00',
      'Legacy Authentication',
      'Legacy Authentication is blocked or minimized, targeting Legacy Authentication protocols.',
      'Review and update policies to restrict or block Legacy Authentication protocols to ensure security.',
      'Legacy Authentication protocols are outdated and less secure. It is recommended to block or minimize their usage to enhance the security of your environment.',
      @{'Legacy Authentication Overview' = 'https://learn.microsoft.com/en-us/entra/identity/conditional-access/policy-block-legacy-authentication' },
      $false,
      $true
    ),
    [Recommendation]::new(
      'CA-01',
      'MFA Policy targets All users Group and All Cloud Apps',
      'There is at least one policy that targets all users and cloud apps.',
      'Review and update MFA policies to ensure they target all users and cloud apps, including any necessary exclusions.',
      'Multi-factor Authentication (MFA) should apply to all users and cloud apps as a baseline for security. Policies should include the necessary exclusions if required but should primarily target all users and apps for maximum security.',
      @{'The Challenge with Targeted Architecture' = 'https://learn.microsoft.com/en-us/azure/architecture/guide/security/conditional-access-architecture#:~:text=The%20challenge%20with%20the,that%20number%20isn%27t%20supported.' },
      $false,
      $true
    ),
    [Recommendation]::new(
      'CA-02',
      'Mobile Device Policy requires MDM or MAM',
      'There is at least one policy that requires MDM or MAM for mobile devices.',
      'Consider adding policies to check for device management, either through MDM or MAM, to ensure secure mobile access.',
      'Mobile Device Management (MDM) or Mobile Application Management (MAM) should be enforced to ensure that mobile devices accessing organizational data are properly managed and secure. Policies should include requirements for MDM or MAM to increase security for mobile devices.',
      @{'MAM Overview'                             = 'https://learn.microsoft.com/en-us/mem/intune/apps/app-management#mobile-application-management-mam-basics'
        'Protect Data on personally owned devices' = 'https://smbtothecloud.com/protecting-company-data-on-personally-owned-devices/'
      },
      $false,
      $true
    ),
    [Recommendation]::new(
      'CA-03',
      'Require Hybrid Join or Intune Compliance on Windows or Mac',
      'There is at least one policy that requires Hybrid Join or Intune Compliance for Windows or Mac devices.',
      'Consider adding policies to ensure that Windows or Mac devices are either Hybrid Joined or compliant with Intune to enhance security.',
      'Hybrid Join or Intune Compliance should be enforced to ensure that Windows or Mac devices accessing organizational data are properly managed and secure. Policies should include requirements for Hybrid Join or Intune Compliance to increase security for these devices.',
      @{
        'Hybrid Join Overview'       = 'https://learn.microsoft.com/en-us/azure/active-directory/devices/hybrid-azuread-join-plan'
        'Intune Compliance Overview' = 'https://learn.microsoft.com/en-us/mem/intune/protect/compliance-policy-create-windows'
      },
      $false,
      $true
    ),
    [Recommendation]::new(
      'CA-04',
      'Require MFA for Admins',
      'There is at least one policy that requires Multi-Factor Authentication (MFA) for administrators.',
      'Consider adding policies to ensure that administrators are required to use Multi-Factor Authentication (MFA) to enhance security.',
      'Multi-Factor Authentication (MFA) should be enforced for administrators to ensure that access to critical systems and data is secure. Policies should include requirements for MFA to increase security for administrative accounts. Policies should target the folowing roles Global Administrator, Security Administrator, SharePoint Administrator, Exchange Administrator, Conditional Access Administrator, Helpdesk Administrator, Billing Administrator, User Administrator, Authentication Administrator, Application Administrator, Cloud Application Administrator, Password Administrator, Privileged Authentication Administrator, Privileged Role Administrator',
      @{
        'MFA Overview'   = 'https://learn.microsoft.com/en-us/azure/active-directory/authentication/concept-mfa-howitworks'
        'MFA for Admins' = 'https://learn.microsoft.com/en-us/entra/identity/conditional-access/policy-old-require-mfa-admin'
      },
      $false,
      $true
    ),
    [Recommendation]::new(
      'CA-05',
      'Require Phish-Resistant MFA for Admins',
      'There is at least one policy that requires phish-resistant Multi-Factor Authentication (MFA) for administrators.',
      'Consider adding policies to ensure that administrators are required to use phish-resistant Multi-Factor Authentication (MFA) to enhance security.',
      'Phish-resistant Multi-Factor Authentication (MFA) should be enforced for administrators to ensure that access to critical systems and data is secure. Policies should include requirements for phish-resistant MFA to increase security for administrative accounts. Policies should target the following roles: Global Administrator, Security Administrator, SharePoint Administrator, Exchange Administrator, Conditional Access Administrator, Helpdesk Administrator, Billing Administrator, User Administrator, Authentication Administrator, Application Administrator, Cloud Application Administrator, Password Administrator, Privileged Authentication Administrator, Privileged Role Administrator.',
      @{
        'MSFT Authentication Strengths'  = 'https://learn.microsoft.com/en-us/entra/identity/authentication/concept-authentication-strengths'
        'Phish-Resistant MFA for Admins' = 'https://learn.microsoft.com/en-us/entra/identity/conditional-access/policy-admin-phish-resistant-mfa'
      },
      $false,
      $true
    ),
    [Recommendation]::new(
      'CA-06',
      'Policy Excludes Same Entities It Includes',
      'There is at least one policy that excludes the same entities it includes, resulting in no effective condition being checked.',
      'Review and update policies to ensure that they do not exclude the same entities they include, as this results in no effective condition being checked.',
      'Policies should be configured to include and exclude distinct sets of entities to ensure that conditions are effectively checked. This helps in maintaining the integrity and effectiveness of the policy.',
      @{
        'Policy Configuration Best Practices' = 'https://learn.microsoft.com/en-us/azure/active-directory/conditional-access/best-practices'
      },
      $true,
      $false
    )
    [Recommendation]::new(
      'CA-07',
      'No Users Targeted in Policy',
      'There is at least one policy that does not target any users.',
      'Review and update policies to ensure that they target specific users, groups, or roles to be effective.',
      'Policies should be configured to target specific users, groups, or roles to ensure that they are applied correctly and provide the intended security controls.',
      @{
        'Policy Configuration Best Practices' = 'https://learn.microsoft.com/en-us/azure/active-directory/conditional-access/best-practices'
      },
      $true,
      $false
    )
    [Recommendation]::new(
      'CA-08',
      'Direct User Assignment',
      'There are no direct user assignments in the policy.',
      'Review and update policies to avoid direct user assignments and instead use exclusion groups to manage user access more efficiently.',
      'Direct user assignments in policies are not ideal for maintaining flexibility and scalability. Exclusion groups should be used instead to manage policies efficiently without manually adding users to each policy.',
      @{},
      $true,
      $false
    )
    [Recommendation]::new(
      'CA-09',
      'Implement Risk-Based Policy',
      'There is at least 1 policy that addresses risk-based conditional access.',
      'Consider implementing risk-based conditional access policies to enhance security by dynamically applying access controls based on the risk level of the sign-in or user.',
      'Risk-based policies help in dynamically assessing the risk level of sign-ins and users, and applying appropriate access controls to mitigate potential threats. This ensures that high-risk activities are subject to stricter controls, thereby enhancing the overall security posture.',
      @{
        'Risk-Based Conditional Access Overview'  = 'https://learn.microsoft.com/en-us/entra/id-protection/howto-identity-protection-configure-risk-policies'
        'Require MFA for Risky Sign-in'           = 'https://learn.microsoft.com/en-us/entra/identity/conditional-access/policy-risk-based-sign-in#enable-with-conditional-access-policy'
        'Require Passsword Change for Risky USer' = 'https://learn.microsoft.com/en-us/entra/identity/conditional-access/policy-risk-based-user#enable-with-conditional-access-policy'
      },
      $false,
      $true
    )
    [Recommendation]::new(
      'CA-10',
      'Block Device Code Flow',
      'There is at least 1 policy that blocks device code flow.',
      'Consider implementing a policy to block device code flow to enhance security by preventing unauthorized access through device code authentication.',
      'Blocking device code flow helps in preventing unauthorized access through device code authentication, which can be exploited by attackers. Implementing this policy ensures that only secure authentication methods are used.',
      @{
        'Block Device Code Flow Overview' = 'https://learn.microsoft.com/en-us/entra/identity/conditional-access/concept-authentication-flows#device-code-flow'
      },
      $false,
      $true
    )
    [Recommendation]::new(
      'CA-11',
      'Require MFA to Enroll a Device in Intune',
      'There is at least 1 policy that requires Multi-Factor Authentication (MFA) to enroll a device in Intune.',
      'Consider implementing a policy to require Multi-Factor Authentication (MFA) for enrolling devices in Intune to enhance security.',
      "Requiring MFA for device enrollment in Intune ensures that only authorized users can enroll devices, thereby enhancing the security of your organization's mobile device management.",
      @{
        'MFA for Intune Enrollment Overview' = 'https://learn.microsoft.com/en-us/mem/intune/enrollment/multi-factor-authentication'
      },
      $false,
      $true
    )
    [Recommendation]::new(
      'CA-12',
      'Block Unknown/Unsupported Devices',
      'There is no policy that blocks unknown or unsupported devices.',
      "Consider implementing a policy to block unknown or unsupported devices to enhance security by preventing unauthorized access from devices that do not meet your organization's security standards.",
      "Blocking unknown or unsupported devices helps in preventing unauthorized access from devices that may not comply with your organization's security policies. Implementing this policy ensures that only secure and compliant devices can access organizational resources.",
      @{
        'Block Unknown/Unsupported Devices Overview' = 'https://learn.microsoft.com/en-us/entra/identity/conditional-access/policy-all-users-device-unknown-unsupported'
      },
      $false,
      $true
    )
  )

  function Test-PolicyStatus {
    param (
      [ref]$Recommendation,
      $PolicyCheck,
      $StatusCheck
    )

    if (&$StatusCheck $PolicyCheck) {
      $Recommendation.Value.Status = $Recommendation.Value.SwapStatus
    }

    if ($Recommendation.Value.Status -and $PolicyCheck.state -eq 'enabled') {
      $Status1 = 'policy-item success'
      $Status2 = 'status-icon-large success'
      $Status3 = '✔'
    }
    else {
      $Status1 = 'policy-item warning'
      $Status2 = 'status-icon-large warning'
      $Status3 = '⚠'
    }

    $CheckExcUG = $PolicyCheck.Conditions.Users.ExcludeUsers + $PolicyCheck.Conditions.Users.ExcludeGroups + $PolicyCheck.Conditions.Users.ExcludeRoles + $PolicyCheck.conditions.users.ExcludeGuestsOrExternalUsers.GuestOrExternalUserTypes -replace ',', ', '
    $CheckIncUG = $PolicyCheck.Conditions.Users.IncludeUsers + $PolicyCheck.Conditions.Users.IncludeGroups + $PolicyCheck.Conditions.Users.IncludeRoles + $PolicyCheck.conditions.users.IncludeGuestsOrExternalUsers.GuestOrExternalUserTypes -replace ',', ', '
    $CheckIncCond = $PolicyCheck.Conditions.Locations.includelocations + $PolicyCheck.Conditions.Platforms.IncludePlatforms
    $CheckExcCond = $PolicyCheck.Conditions.Locations.Excludelocations + $PolicyCheck.Conditions.Platforms.ExcludePlatforms
    $CheckGrant = $PolicyCheck.GrantControls.BuiltInControls + $PolicyCheck.GrantControls.AuthenticationStrength.DisplayName + $PolicyCheck.GrantControls.CustomAuthenticationFactors + $PolicyCheck.GrantControls.TermsOfUse
    $checkSession = ''

    if ($PolicyCheck.SessionControls.ApplicationEnforcedRestrictions.IsEnabled) {
      $checkSession += "    ApplicationEnforcedRestrictions: $($PolicyCheck.SessionControls.ApplicationEnforcedRestrictions.IsEnabled)`n"
    }
    if ($PolicyCheck.SessionControls.CloudAppSecurity.IsEnabled) {
      $checkSession += "    CloudAppSecurity: $($PolicyCheck.SessionControls.CloudAppSecurity.IsEnabled)`n"
    }
    if ($PolicyCheck.SessionControls.SignInFrequency.Value -and $PolicyCheck.SessionControls.SignInFrequency.Type) {
      $checkSession += "    SignInFrequency: $($PolicyCheck.SessionControls.SignInFrequency.Value) $($PolicyCheck.SessionControls.SignInFrequency.Type)`n"
    }
    if ($PolicyCheck.SessionControls.PersistentBrowser.Mode) {
      $checkSession += "    PersistentBrowser: $($PolicyCheck.SessionControls.PersistentBrowser.Mode)`n"
    }
    if ($PolicyCheck.SessionControls.ContinuousAccessEvaluation.Mode) {
      $checkSession += "    ContinuousAccessEvaluation: $($PolicyCheck.SessionControls.ContinuousAccessEvaluation.Mode)`n"
    }
    if ($PolicyCheck.SessionControls.DisableResilienceDefaults) {
      $checkSession += "    ResiliantDefaults: $($PolicyCheck.SessionControls.DisableResilienceDefaults)`n"
    }
    if ($PolicyCheck.SessionControls.AdditionalProperties.secureSignInSession.Values) {
      $checkSession += "    secureSignInSession: $($PolicyCheck.SessionControls.AdditionalProperties.secureSignInSession.Values)`n"
    }

    if (&$StatusCheck $PolicyCheck) {
      $Recommendation.Value.Note += "
    <div class='policy'>
        <div class='$($Status1)'>
            <div class='policy-header'>
                <strong>$($PolicyCheck.DisplayName) <a href='$($LinkURL)$($PolicyCheck.Id)' target='_blank'><span class='icon-ext'></span></a></strong>
                <div class='recommendation-status'>Status: $($PolicyCheck.state)</div>
                <div class='$($Status2)'>$Status3</div>
            </div>
            <div class='policy-content'>
                <div class='policy-include'>
                    <div class='label-container'>
                        <span class='include-label'>Include</span>
                    </div>
                    <div class='include-content'>
                        <b>Users:</b> $($CheckIncUG -join ', ')
                        <br>
                        <b>Application/Actions:</b> $($PolicyCheck.Conditions.Applications.IncludeApplications -join ', ') $($PolicyCheck.Conditions.Applications.IncludeUserActions -join ', ')
                        <br>
                        <b>Conditions:</b> $($CheckIncCond -join ', ')
                    </div>
                </div>
                <div class='policy-exclude'>
                    <div class='label-container'>
                        <span class='exclude-label'>Exclude</span>
                    </div>
                    <div class='exclude-content'>
                        <b> Users:</b> $($CheckExcUG -join ', ')
                        <br>
                        <b>Applications:</b> $($PolicyCheck.Conditions.Applications.ExcludeApplications -join ', ')
                        <br>
                        <b>Conditions:</b> $($CheckExcCond -join ', ')
                    </div>
                </div>
                 <div class='policy-grant'>
                    <div class='label-container'>
                        <span class='grant-label'>Access</span>
                    </div>
                    <div class='grant-content'>
                        <b> Grant:</b> $($CheckGrant  -join ', ') :$($PolicyCheck.GrantControls.Operator)
                        <br>
                        <b> Session:</b> $($CheckSession  -join ', ')
                    </div>
                </div>
            </div>
        </div>
    </div>"
    }
  }


  $CheckFunctions = @{
    'CA-00' = {
      param($PolicyCheck)
      $PolicyCheck.GrantControls.BuiltInControls -contains 'Block' -and
      $PolicyCheck.Conditions.ClientAppTypes -contains 'exchangeActiveSync' -and
      $PolicyCheck.Conditions.ClientAppTypes -contains 'other'
    }
    'CA-01' = {
      param($PolicyCheck)
      $PolicyCheck.GrantControls.BuiltInControls -contains 'Mfa' -and
      $PolicyCheck.Conditions.Users.IncludeUsers -eq 'all' -and
      $PolicyCheck.Conditions.Applications.IncludeApplications -eq 'all'
    }
    'CA-02' = {
      param($PolicyCheck)
      ($PolicyCheck.Conditions.Platforms.IncludePlatforms -contains 'android' -or
      $PolicyCheck.Conditions.Platforms.IncludePlatforms -contains 'iOS' -or
      $PolicyCheck.Conditions.Platforms.IncludePlatforms -contains 'windowsPhone') -and
      ($PolicyCheck.GrantControls.BuiltInControls -contains 'approvedApplication' -or
      $PolicyCheck.GrantControls.BuiltInControls -contains 'compliantApplication' -or
      $PolicyCheck.GrantControls.BuiltInControls -contains 'compliantDevice')
    }
    'CA-03' = {
      param($PolicyCheck)
      ($PolicyCheck.Conditions.Platforms.IncludePlatforms -contains 'windows' -or
      $PolicyCheck.Conditions.Platforms.IncludePlatforms -contains 'macOS') -and
      ($PolicyCheck.GrantControls.BuiltInControls -contains 'compliantDevice' -or
      $PolicyCheck.GrantControls.BuiltInControls -contains 'domainJoinedDevice')
    }

    'CA-04' = {
      param($PolicyCheck)
      ($PolicyCheck.Conditions.Users.IncludeRoles -contains 'Privileged Role Administrator' -or
      $PolicyCheck.Conditions.Users.IncludeRoles -contains 'Global Administrator' -or
      $PolicyCheck.Conditions.Users.IncludeRoles -contains 'Privileged Authentication Administrator' -or
      $PolicyCheck.Conditions.Users.IncludeRoles -contains 'Security Administrator' -or
      $PolicyCheck.Conditions.Users.IncludeRoles -contains 'SharePoint Administrator' -or
      $PolicyCheck.Conditions.Users.IncludeRoles -contains 'Exchange Administrator' -or
      $PolicyCheck.Conditions.Users.IncludeRoles -contains 'Conditional Access Administrator' -or
      $PolicyCheck.Conditions.Users.IncludeRoles -contains 'Helpdesk Administrator' -or
      $PolicyCheck.Conditions.Users.IncludeRoles -contains 'Billing Administrator' -or
      $PolicyCheck.Conditions.Users.IncludeRoles -contains 'User Administrator' -or
      $PolicyCheck.Conditions.Users.IncludeRoles -contains 'Authentication Administrator' -or
      $PolicyCheck.Conditions.Users.IncludeRoles -contains 'Application Administrator' -or
      $PolicyCheck.Conditions.Users.IncludeRoles -contains 'Cloud Application Administrator' -or
      $PolicyCheck.Conditions.Users.IncludeRoles -contains 'Password Administrator') -and
      ($PolicyCheck.GrantControls.BuiltInControls -contains 'Mfa' -or
      $PolicyCheck.GrantControls.AuthenticationStrength.DisplayName -contains 'Phishing-resistant MFA' -or
      $PolicyCheck.GrantControls.AuthenticationStrength.DisplayName -contains 'Passwordless MFA' -or
      $PolicyCheck.GrantControls.AuthenticationStrength.DisplayName -contains 'Multifactor authentication')
    }
    'CA-05' = {
      param($PolicyCheck)
      ($PolicyCheck.Conditions.Users.IncludeRoles -contains 'Privileged Role Administrator' -or
      $PolicyCheck.Conditions.Users.IncludeRoles -contains 'Global Administrator' -or
      $PolicyCheck.Conditions.Users.IncludeRoles -contains 'Privileged Authentication Administrator' -or
      $PolicyCheck.Conditions.Users.IncludeRoles -contains 'Security Administrator' -or
      $PolicyCheck.Conditions.Users.IncludeRoles -contains 'SharePoint Administrator' -or
      $PolicyCheck.Conditions.Users.IncludeRoles -contains 'Exchange Administrator' -or
      $PolicyCheck.Conditions.Users.IncludeRoles -contains 'Conditional Access Administrator' -or
      $PolicyCheck.Conditions.Users.IncludeRoles -contains 'Helpdesk Administrator' -or
      $PolicyCheck.Conditions.Users.IncludeRoles -contains 'Billing Administrator' -or
      $PolicyCheck.Conditions.Users.IncludeRoles -contains 'User Administrator' -or
      $PolicyCheck.Conditions.Users.IncludeRoles -contains 'Authentication Administrator' -or
      $PolicyCheck.Conditions.Users.IncludeRoles -contains 'Application Administrator' -or
      $PolicyCheck.Conditions.Users.IncludeRoles -contains 'Cloud Application Administrator' -or
      $PolicyCheck.Conditions.Users.IncludeRoles -contains 'Password Administrator') -and
      ($PolicyCheck.GrantControls.AuthenticationStrength.DisplayName -contains 'Phishing-resistant MFA')
    }
    'CA-06' = {
      param($PolicyCheck)
      ($null -ne $PolicyCheck.Conditions.Users.IncludeUsers -and $null -ne $PolicyCheck.Conditions.Users.ExcludeUsers -and
      ($PolicyCheck.Conditions.Users.IncludeUsers | ForEach-Object { $PolicyCheck.Conditions.Users.ExcludeUsers -contains $_ })) -or
      ($null -ne $PolicyCheck.Conditions.Users.IncludeGroups -and $null -ne $PolicyCheck.Conditions.Users.ExcludeGroups -and
      ($PolicyCheck.Conditions.Users.IncludeGroups | ForEach-Object { $PolicyCheck.Conditions.Users.ExcludeGroups -contains $_ })) -or
      ($null -ne $PolicyCheck.Conditions.Users.IncludeRoles -and $null -ne $PolicyCheck.Conditions.Users.ExcludeRoles -and
      ($PolicyCheck.Conditions.Users.IncludeRoles | ForEach-Object { $PolicyCheck.Conditions.Users.ExcludeRoles -contains $_ })) -or
      ($null -ne $PolicyCheck.Conditions.Platforms.IncludePlatforms -and $null -ne $PolicyCheck.Conditions.Platforms.ExcludePlatforms -and
      ($PolicyCheck.Conditions.Platforms.IncludePlatforms | ForEach-Object { $PolicyCheck.Conditions.Platforms.ExcludePlatforms -contains $_ })) -or
      ($null -ne $PolicyCheck.Conditions.Locations.IncludeLocations -and $null -ne $PolicyCheck.Conditions.Locations.ExcludeLocations -and
      ($PolicyCheck.Conditions.Locations.IncludeLocations | ForEach-Object { $PolicyCheck.Conditions.Locations.ExcludeLocations -contains $_ })) -or
      ($null -ne $PolicyCheck.Conditions.Applications.IncludeApplications -and $null -ne $PolicyCheck.Conditions.Applications.ExcludeApplications -and
      ($PolicyCheck.Conditions.Applications.IncludeApplications | ForEach-Object { $PolicyCheck.Conditions.Applications.ExcludeApplications -contains $_ }))
    }
    'CA-07' = {
      param($PolicyCheck)
      (($null -eq $PolicyCheck.Conditions.Users.IncludeUsers) -or $PolicyCheck.Conditions.Users.IncludeUsers.Count -eq 0 -or $PolicyCheck.Conditions.Users.IncludeUsers -eq 'None') -and
      (($null -eq $PolicyCheck.Conditions.Users.IncludeGroups) -or $PolicyCheck.Conditions.Users.IncludeGroups.Count -eq 0 -or
      ($PolicyCheck.Conditions.Users.IncludeGroups | ForEach-Object { $_ -match '\((\d+)\)' -and [int]$matches[1] -eq 0 })) -and
      (($null -eq $PolicyCheck.Conditions.Users.IncludeRoles) -or $PolicyCheck.Conditions.Users.IncludeRoles.Count -eq 0) -and
      ($null -eq $PolicyCheck.conditions.users.IncludeGuestsOrExternalUsers.GuestOrExternalUserTypes)
    }
    'CA-08' = {
      param($PolicyCheck)
      $PolicyCheck.Conditions.Users.IncludeUsers -ne 'None' -and
      $null -ne $PolicyCheck.Conditions.Users.IncludeUsers -and
      $PolicyCheck.Conditions.Users.IncludeUsers -ne 'All' -and
      $PolicyCheck.Conditions.Users.IncludeUsers -ne 'GuestsOrExternalUsers'
    }
    'CA-09' = {
      param($PolicyCheck)
      ($null -ne $PolicyCheck.Conditions.SignInRiskLevels) -or
      ($null -ne $PolicyCheck.Conditions.UserRiskLevels)
    }
    'CA-10' = {
      param($PolicyCheck)
      $PolicyCheck.Conditions.AdditionalProperties.authenticationFlows.Values -split ',' -contains 'deviceCodeFlow' -and
      $PolicyCheck.grantcontrols.BuiltInControls -contains 'Block'
    }
    'CA-11' = {
      param($PolicyCheck)
      ($PolicyCheck.Conditions.Applications.IncludeUserActions -contains 'urn:user:registerdevice') -and
      ($PolicyCheck.GrantControls.BuiltInControls -contains 'Mfa')
    }
    'CA-12' = {
      param($PolicyCheck)
      ($PolicyCheck.GrantControls.BuiltInControls -contains 'Block') -and
      ($PolicyCheck.Conditions.Platforms.IncludePlatforms -contains 'all') -and
      ($PolicyCheck.Conditions.Platforms.ExcludePlatforms.Count -gt 0)
    }
  }


  foreach ($policy in $CAPolicy) {
    foreach ($recommendation in $recommendations) {
      Test-PolicyStatus -Recommendation ([ref]$recommendation) -PolicyCheck $policy -StatusCheck $CheckFunctions[$recommendation.Control]
    }
  }
}

## (Removed obsolete Set Row Order block)

# ---------------- Build Pivot Dataset (wide) ----------------
# The pivot format rotates policy-centric data so that each policy becomes a column and each attribute a row.
# This allows quick scanning in Excel / BI of where controls/conditions differ across policies.
# Implementation notes:
#  - Use a stable ordered list of pivot fields ($pivotFields)
#  - Each row object has a 'CA Item' property (row label) plus one property per policy (policy display name)
#  - Boolean-like values preserved (✔ for True style fields) while multi-line fields condensed to single line for readability

$pivot = @()
$pivotFields = @(
  'Status', 'DateModified', 'CreatedDateTime', 'Description', 'DuplicateMatches',
  'UsersInclude', 'UsersExclude', 'RolesIncludeIds', 'RolesExcludeIds',
  'ApplicationsIncluded', 'ApplicationsExcluded', 'userActions', 'AuthContext',
  'UserRisk', 'SignInRisk', 'PlatformsInclude', 'PlatformsExclude', 'ClientApps',
  'LocationsIncluded', 'LocationsExcluded', 'DevicesIncluded', 'DevicesExcluded', 'DeviceFilters', 'AuthenticationFlows',
  'Block', 'Require MFA', 'Authentication Strength MFA', 'CompliantDevice', 'DomainJoinedDevice', 'CompliantApplication', 'ApprovedApplication', 'PasswordChange', 'TermsOfUse', 'CustomControls', 'GrantOperator',
  'ApplicationEnforcedRestrictions', 'CloudAppSecurity', 'SignInFrequency', 'PersistentBrowser', 'ContinuousAccessEvaluation', 'ResilientDefaults', 'secureSignInSession'
)

if ($CAExport.Count -gt 0) {
  foreach ($field in $pivotFields) {
    $row = [ordered]@{ 'CA Item' = $field }
    foreach ($pol in $CAExport) {
      $val = $null
      if ($pol.PSObject.Properties.Match($field)) { $val = $pol.$field }
      # Normalize multiline -> semi-colon separated single line for sheet friendliness
      if ($val -is [string]) { $val = ($val -split "`r?`n") -join '; ' }
      $row[$pol.Name] = $val
    }
    $pivot += [pscustomobject]$row
  }
}
function Get-RecommendationsHtmlFragment {
  param (
    [Parameter(Mandatory = $true)]
    [object[]]$Recommendations
  )
  # Redesigned compact recommendation cards using <details> for collapsible body.
  $htmlFragment = @'
<div class='recommendations' id='ca-security-checks' style=''>
'@
  foreach ($rec in $Recommendations) {
    # Replace any GUIDs in the note with friendly names (users/groups/roles/apps) without altering punctuation
    $rec.Note = Resolve-EntityGuidsInText -Text $rec.Note -UserMap $UserMap -GroupMap $GroupMap -RoleMap $RoleMap -AppMap $AppMap
    $links = ''
    foreach ($key in $rec.Links.Keys) { $links += "<a class='rec-link' href='$($rec.Links[$key])' target='_blank' rel='noopener'>$key<span class='icon-ext'></span></a>" }
    if ($rec.Status) {
      $RecStatus = 'pass'
      $RecStatusNote = [System.Web.HttpUtility]::HtmlEncode($rec.PassText)
      $Icon = '✔'
      $StateLabel = 'Pass'
      $detailOpen = ''
    }
    else {
      $RecStatus = 'fail'
      $RecStatusNote = [System.Web.HttpUtility]::HtmlEncode($rec.FailRecommendation)
      $Icon = '⚠'
      $StateLabel = 'Attention'
      $detailOpen = ' open'
    }
    $encName = [System.Web.HttpUtility]::HtmlEncode($rec.Name)
    $encCtrl = [System.Web.HttpUtility]::HtmlEncode($rec.Control)
    $importance = [System.Web.HttpUtility]::HtmlEncode($rec.Importance)
    # Policy note may already contain curated safe markup (e.g., <div class='policy'> blocks).
    # Keep it raw except strip any script/style blocks defensively.
    $rawNote = $rec.Note -replace '(?i)<script[^>]*>.*?</script>', '' -replace '(?i)<style[^>]*>.*?</style>', ''
    $encNote = $rawNote
    $htmlFragment += @"
<details class='recommendation-card $RecStatus'$detailOpen>
  <summary><span class='rec-status-icon' aria-label='$StateLabel'>$Icon</span><span class='rec-code'>$encCtrl</span><span class='rec-title'>$encName</span></summary>
  <div class='rec-body'>
    <div class='rec-importance'>$importance</div>
    <div class='rec-status-text'>$RecStatusNote</div>
    <div class='rec-links'>$links</div>
  <div class='rec-matched-policies'>$encNote</div>
  </div>
</details>
"@
  }
  $htmlFragment += "<div class='timestamp-note'>Report generated: $([System.Web.HttpUtility]::HtmlEncode((Get-Date).ToString('u')))</div></div>"
  return $htmlFragment
}

if ($HTMLExport) {
  if (-not $NoRecommendations) {
    $SecurityCheck = (Get-RecommendationsHtmlFragment -Recommendations $recommendations) -replace "id='ca-security-checks' style=''", "id='panel-recommendations' role='tabpanel' aria-labelledby='tab-recommendations' aria-hidden='true' style='display:none;'"
  }
  else {
    $SecurityCheck = ''
  }
  $recTabs = if ($NoRecommendations) {
    "<span id='tab-summary' class='btn-toggle' role='tab' aria-selected='false' tabindex='-1' aria-controls='panel-summary'>Summary</span><span id='tab-policies' class='btn-toggle active' role='tab' aria-selected='true' tabindex='0' aria-controls='panel-policies'>Policy Details</span>"
  }
  else {
    "<span id='tab-summary' class='btn-toggle' role='tab' aria-selected='false' tabindex='-1' aria-controls='panel-summary'>Summary</span><span id='tab-policies' class='btn-toggle active' role='tab' aria-selected='true' tabindex='0' aria-controls='panel-policies'>Policy Details</span><span id='tab-recommendations' class='btn-toggle' role='tab' aria-selected='false' tabindex='-1' aria-controls='panel-recommendations'>Recommendations</span>"
  }
  $OmissionBannerHtml = if ($NoRecommendations) { "<div class='no-recs-banner' role='note'>Recommendations omitted (-NoRecommendations)</div>" } else { '' }
  Write-Info 'Saving to File: HTML'
  # Self-contained CSS (removed external dependencies)
  $style = @'
  /* General Styles */
  html, body { font-family: Arial, sans-serif; margin:0; padding:0; }
  .title { font-size: 1.5em; font-weight: bold; }
  /* Navigation */
  .navbar-custom { position:fixed; top:0; left:0; right:0; display:flex; align-items:center; justify-content:space-between; background:#005494; color:#fff; padding:14px 20px; box-shadow:0 2px 4px rgba(0,0,0,.25); z-index:999; font-size:14px; }
  .no-recs-banner { margin:70px 18px 10px 18px; background:#fff4cc; border:1px solid #e0c766; padding:10px 14px; border-radius:5px; font-size:0.75rem; color:#5a4700; box-shadow:0 1px 2px rgba(0,0,0,.05); }
  /* Offset main tab panels so content isn't hidden under fixed navbar */
  /* Panel offsets: recommendations needs more vertical offset due to heading density; others can be tighter */
  #panel-recommendations { padding-top:70px; margin-top:0; scroll-margin-top:80px; }
  #panel-summary, #panel-policies { padding-top:48px; margin-top:0; scroll-margin-top:60px; }
  /* Fine-tune summary since its internal section already has top margin */
  #panel-summary .summary-wrapper { margin-top:10px !important; }
  .nav-left, .nav-center, .nav-right { display:flex; align-items:center; }
  .nav-center { flex:1; justify-content:center; font-weight:600; }
  .nav-left .brand { font-weight:700; margin-left:8px; }
  .nav-right { gap:12px; font-size:12px; }
  .icon-server { font-size:18px; line-height:1; }
  .view-toggle-group .btn-toggle { color:#fff; background:#0d6efd33; border:1px solid rgba(255,255,255,0.4); padding:4px 10px; margin-right:6px; border-radius:4px; cursor:pointer; font-size:0.85rem; user-select:none; }
  .view-toggle-group .btn-toggle.active { background:#ffffff; color:#005494; font-weight:600; box-shadow:0 0 0 2px #ffffff55; }
  .view-toggle-group .btn-toggle:focus { outline:none; }
  .search-box { position:relative; margin-left:12px; }
  .search-box input { padding:4px 26px 4px 8px; border-radius:4px; border:1px solid #fff; background:#ffffff; color:#003553; font-size:0.8rem; min-width:190px; }
  .search-box input:focus { outline:2px solid #91d2ff; }
  .search-box .search-clear { position:absolute; right:6px; top:50%; transform:translateY(-50%); cursor:pointer; color:#005494; font-weight:bold; display:none; }
  .search-box.has-value .search-clear { display:inline; }
  /* Table */
  table { border-collapse: collapse; margin-bottom:30px; margin-top:55px; font-size:0.9em; min-width:400px; width:100%; table-layout:auto; }
  thead tr { background:linear-gradient(90deg,#005494,#0a79c5); color:#ffffff; text-align:center; }
  th, td { padding:8px 12px; border:1px solid #d2d2d2; vertical-align:top; text-align:center; }
  /* Dynamic width adjustments: allow natural content sizing, but keep some guidance */
  th.name-col, td.name-col { min-width:180px; }
  th.bool-col, td.bool-col { width:46px; min-width:46px; }
  /* Legacy fixed width (optional) */
  .fixed-layout th, .fixed-layout td { min-width:200px; }
  tbody tr:nth-of-type(even) { background-color:#f3f3f3; }
  tbody tr:last-of-type { border-bottom:2px solid #005494; }
  tr:hover { background-color:#d8d8d8 !important; }
  .selected:not(th) { background-color:#eaf7ff !important; }
  /* Improved header readability + distinct sticky first column header */
  th { background-color:transparent; color:#ffffff; font-weight:600; font-size:0.92rem; letter-spacing:.3px; border-bottom:3px solid #00416d; }
  th.sticky-name { background:#004d7f; box-shadow:4px 0 6px -4px rgba(0,0,0,.35); }
  .colselected { outline:3px solid #59c7fb; background:#e3f6ff !important; }
  .sticky-name { position:sticky; inset-inline-start:0; background:#005494; color:#fff; z-index:5; font-weight:700; text-align:left; box-shadow:4px 0 6px -4px rgba(0,0,0,.35); }
  .sticky-name.colselected { outline:none; }
  /* Sticky header (below navbar ~55px high) */
  .sticky-header thead th { position:sticky; top:55px; z-index:6; }
  .sticky-header thead th.sticky-name { z-index:7; }
  .sticky-name a { color:#fff; }
  tbody tr:nth-of-type(even) .sticky-name { background:#547c9b; }
  tbody tr:nth-of-type(5), tbody tr:nth-of-type(8), tbody tr:nth-of-type(13), tbody tr:nth-of-type(25), tbody tr:nth-of-type(37) { background-color:#005494 !important; }
  .tooltip-container { position:relative; display:inline-block; }
  .tooltip-text { visibility:hidden; width:200px; background:#000; color:#fff; text-align:center; border-radius:6px; padding:5px 0; position:absolute; z-index:1; top:115%; left:50%; margin-left:-100px; opacity:0; transition:opacity .3s; }
  .tooltip-container:hover .tooltip-text { visibility:visible; opacity:1; }
  /* Recommendations - compact cards */
  #ca-security-checks { padding:20px 18px 40px 18px; background:#f5f7fa; border:1px solid #d0d7de; border-radius:6px; margin-top:55px; }
  details.recommendation-card { border:1px solid #d8dee4; border-left:5px solid #888; border-radius:4px; padding:4px 10px 6px 10px; margin:0 0 8px 0; background:#ffffff; box-shadow:0 1px 2px rgba(0,0,0,.04); }
  details.recommendation-card[open] { box-shadow:0 2px 4px rgba(0,0,0,.07); }
  details.recommendation-card.pass { border-left-color:#218739; }
  details.recommendation-card.fail { border-left-color:#d37d00; }
  details.recommendation-card summary { list-style:none; cursor:pointer; display:flex; align-items:center; gap:8px; font-weight:600; font-size:0.82rem; }
  details.recommendation-card summary::-webkit-details-marker { display:none; }
  .rec-status-icon { font-size:0.85rem; width:18px; text-align:center; }
  details.recommendation-card.pass .rec-status-icon { color:#218739; }
  details.recommendation-card.fail .rec-status-icon { color:#d37d00; }
  .rec-code { font-family:ui-monospace,SFMono-Regular,Menlo,Monaco,Consolas,'Liberation Mono','Courier New',monospace; background:#eef2f5; padding:2px 5px; border-radius:3px; font-size:0.68rem; color:#303b44; }
  details.recommendation-card.fail .rec-code { background:#ffe8cc; }
  .rec-title { flex:1; }
  .rec-body { margin:6px 2px 2px 2px; font-size:0.72rem; line-height:1.25; }
  .rec-importance { color:#334; margin-bottom:4px; }
  .rec-status-text { margin:4px 0 4px 0; font-weight:500; }
  .rec-links { margin:4px 0 4px 0; display:flex; flex-wrap:wrap; gap:6px; }
  .rec-link { font-size:0.66rem; background:#e6f2fb; padding:3px 6px; border-radius:3px; text-decoration:none; color:#005494; border:1px solid #c6e0f2; }
  .rec-link:hover { background:#d2e8f8; }
  .rec-matched-policies .policy-item { font-size:0.66rem; }
  .rec-matched-policies .policy-header { font-size:0.65rem; }
  .policy { margin-top:10px; }
  .policy-item { border:2px solid; padding:10px; border-radius:5px; margin-bottom:10px; }
  .policy-item.success { border-color:green; background:#e6ffe6; }
  .policy-item.warning { border-color:orange; background:#fff8e6; }
  .policy-item.error { border-color:red; background:#ffe6e6; }
  .policy-content { display:flex; flex-direction:column; padding-left:20px; margin-top:5px; }
  .policy-include, .policy-exclude, .policy-grant { display:flex; align-items:flex-start; margin-top:5px; }
  .label-container { display:flex; align-items:center; margin-right:10px; }
  .include-label, .exclude-label, .grant-label { writing-mode:vertical-rl; transform:rotate(180deg); border-left:3px solid darkgrey; color:darkgray; }
  .status-icon-large { position:absolute; top:0; right:0; font-size:2em; }
  .status-icon-large.success { color:green; }
  .status-icon-large.warning { color:orange; }
  .status-icon-large.error { color:red; }
  .icon-ext { font-size:0.75em; margin-left:4px; color:#000; }
  .selected td { background:#eaf7ff; }
  #back-to-top { position:fixed; right:18px; bottom:18px; background:#005494; color:#fff; border:none; padding:10px 14px; border-radius:50%; font-size:16px; cursor:pointer; box-shadow:0 2px 6px rgba(0,0,0,.3); display:none; z-index:998; }
  #back-to-top:hover { background:#0073c7; }
  .timestamp-note { font-size:0.7rem; color:#555; margin:6px 0 14px 0; }
  /* Value match highlighting */
  td.value-match, th.value-match { box-shadow:inset 0 0 0 3px #ffcc33; background:#fff6cc !important; position:relative; }
  td.value-match:after, th.value-match:after { content:''; position:absolute; inset:0; pointer-events:none; box-shadow:0 0 0 2px #ffb400, 0 0 4px 2px rgba(255,153,0,.45); border-radius:2px; }
  /* Raw JSON details */
  details.raw-json { max-width:400px; }
  /* Summary table styling (separate class so not counted as a policy data table) */
  /* Compact summary table styling */
  .summary-wrapper { max-width:760px; margin:0 0 25px 0; }
  table.summary-table { border-collapse:separate; border-spacing:0; width:100%; font-size:0.72rem; line-height:1.05; margin-bottom:18px; box-shadow:0 0 0 1px #d0d7de; }
  table.summary-table th, table.summary-table td { border:0; padding:3px 6px; background:#fff; white-space:nowrap; }
  table.summary-table thead th { position:sticky; top:0; background:#0d3855; color:#fff; font-weight:600; font-size:0.70rem; letter-spacing:.5px; text-transform:uppercase; }
  /* Striped rows for summary table */
  table.summary-table tbody tr:nth-child(odd)  { background:#ffffff; }
  table.summary-table tbody tr:nth-child(even) { background:#f1f5f8; }
  table.summary-table tbody tr:hover { background:#e2edf3; }
  table.summary-table tbody td:first-child { font-weight:500; }
  table.summary-table td:nth-child(2), table.summary-table td:nth-child(3) { text-align:right; }
  /* Create a subtle column separation */
  table.summary-table td + td, table.summary-table th + th { border-left:1px solid #e2e8ec; }
  /* Allow wrapping on longer metric labels */
  table.summary-table td:first-child { white-space:normal; }
  @media (min-width:900px){
    /* Present metrics in two side-by-side columns (two tables) if desired later; placeholder for responsive enhancements */
  }
  details.raw-json summary { cursor:pointer; font-weight:600; color:#005494; }
  details.raw-json pre { max-height:300px; overflow:auto; background:#0f1f2a; color:#d7f1ff; padding:8px; border-radius:4px; font-size:0.7rem; }
  .json-toggle-bar { display:flex; gap:6px; margin-bottom:6px; }
  .json-toggle-bar button { background:#194e73; color:#fff; border:1px solid #0d3956; padding:3px 8px; font-size:0.65rem; cursor:pointer; border-radius:4px; }
  .json-toggle-bar button.active { background:#ffcc33; color:#003553; font-weight:600; }
  /* Duplicate row highlight */
  tr.dup-row { background:repeating-linear-gradient(45deg,#fff3e0,#fff3e0 12px,#ffe0b2 12px,#ffe0b2 24px); }
  tr.dup-row td { border-top:2px solid #ffb347; border-bottom:2px solid #ffb347; }
  .id-col-hidden { display:none !important; }
  .id-col-toggle { background:#ffffff; color:#005494; border:1px solid rgba(255,255,255,0.4); padding:4px 10px; font-size:0.7rem; border-radius:4px; cursor:pointer; margin-left:6px; }
  .id-col-toggle.active { background:#ffcc33; color:#002640; font-weight:600; }
  /* Boolean / placeholder & status styling */
  .bool-yes { color:#1f7a33; font-weight:600; }
  .bool-no { color:#c4c4c4; font-weight:400; }
  .placeholder { color:#b9b9b9; font-style:italic; }
  th.bool-col, td.bool-col { min-width:46px; width:46px; padding:6px 4px; font-size:0.65rem; }
  td.bool-col span { display:inline-block; min-width:16px; }
  .status-badge { display:inline-block; padding:2px 6px; border-radius:10px; font-size:0.62rem; font-weight:600; letter-spacing:.3px; }
  .status-enabled { background:#daf5d9; color:#1f7a33; border:1px solid #b2e3b0; }
  .status-disabled { background:#f2dede; color:#b94a48; border:1px solid #e0b4b3; }
  .status-report { background:#fff4cc; color:#8c6d00; border:1px solid #f2dd8f; }
  td:has(details.raw-json) { min-width:240px; }
  /* Legend & utility bars */
  .legend-bar { margin:55px 0 12px 0; background:#ffffff; border:1px solid #d8dee4; border-left:4px solid #005494; padding:8px 12px; border-radius:4px; font-size:0.68rem; display:flex; flex-wrap:wrap; gap:10px; align-items:center; }
  .layout-toggle { background:#ffffff; color:#005494; border:1px solid #c3d1dc; padding:4px 8px; font-size:0.65rem; border-radius:4px; cursor:pointer; }
  .layout-toggle.active { background:#005494; color:#fff; }
  .legend-title { font-weight:700; margin-right:4px; }
  .legend-item { display:flex; align-items:center; gap:4px; }
  .legend-swatch { display:inline-flex; align-items:center; justify-content:center; min-width:18px; height:18px; font-size:0.65rem; border-radius:4px; border:1px solid #c9d1d9; background:#f3f4f6; color:#333; }
  .legend-swatch.enabled { background:#daf5d9; border-color:#b2e3b0; }
  .legend-swatch.report { background:#fff4cc; border-color:#f2dd8f; }
  .legend-swatch.disabled { background:#f2dede; border-color:#e0b4b3; }
  .legend-swatch.pass { background:#d9f2e3; border-color:#b4e2c4; color:#1f7a33; }
  .legend-swatch.fail { background:#ffe8cc; border-color:#f2c08f; color:#8c5a00; }
  .legend-divider { width:1px; height:18px; background:#d0d7de; }
  .util-button { background:#e6eef4; border:1px solid #c3d1dc; padding:4px 8px; font-size:0.65rem; border-radius:4px; cursor:pointer; color:#003553; }
  .util-button.active { background:#005494; color:#fff; border-color:#00416d; }
  .util-button:focus { outline:2px solid #91d2ff; }
  .rec-filter-group { display:flex; gap:4px; }
  .bool-mode-toggle { margin-left:auto; }
  /* Description clamp */
  .desc-cell { max-width:280px; position:relative; }
  .desc-text { display:-webkit-box; -webkit-line-clamp:3; -webkit-box-orient:vertical; overflow:hidden; text-overflow:ellipsis; white-space:normal; }
  .desc-cell.expanded .desc-text { -webkit-line-clamp:unset; max-height:none; }
  .desc-expand { position:absolute; bottom:2px; right:4px; background:#ffffffcc; border:1px solid #c3d1dc; font-size:0.55rem; padding:2px 4px; cursor:pointer; border-radius:3px; }
  .desc-expand:hover { background:#f1f5f8; }
  @media (max-width:1200px){ th,td{min-width:180px;font-size:0.8em;} .search-box input{min-width:150px;} th.bool-col, td.bool-col { min-width:40px; } }
  @media (max-width:1200px){ th,td{min-width:180px;font-size:0.8em;} .search-box input{min-width:150px;} }
  @media (max-width:800px){ th,td{min-width:140px;font-size:0.7em;} .view-toggle-group{display:flex;flex-wrap:wrap;} .search-box{margin-top:6px;} }
'@

  # Add visually hidden utility class and live region container for accessibility announcements
  # The live region enables non-visual users to receive feedback for actions (e.g., JSON copied, filter changes)
  $style = $style + '\n  .visually-hidden { position:absolute !important; width:1px !important; height:1px !important; padding:0 !important; margin:-1px !important; overflow:hidden !important; clip:rect(0 0 0 0) !important; white-space:nowrap !important; border:0 !important; }'
  $htmlDoc = "<!DOCTYPE html><html><head><meta charset='utf-8'><meta name='viewport' content='width=device-width, initial-scale=1'><style>$style</style><title>CA Export v$CAExportVersion - $TenantName</title></head><body><nav class='navbar-custom'><div class='nav-left'><div class='icon-server' aria-hidden='true'>🖥️</div><div class='brand'>CA Export v$CAExportVersion</div><div class='view-toggle-group' role='tablist' aria-label='Report view' style='margin-left:20px;'>$recTabs<button id='toggle-id-cols' class='id-col-toggle' aria-pressed='false' title='Show/hide raw ID columns'>Show ID Columns</button></div><div class='search-box'><input id='policy-search' type='text' placeholder='Search policies...' aria-label='Search policies'/><span class='search-clear' id='policy-search-clear' title='Clear' role='button' aria-label='Clear search'>&times;</span></div></div><div class='nav-center'><strong>$TenantName</strong></div><div class='nav-right'><strong>$Date</strong></div></nav>$OmissionBannerHtml<div id='live-region' class='visually-hidden' aria-live='polite' aria-atomic='true'></div><button id='back-to-top' aria-label='Back to top' title='Back to top'>↑</button>"

  # $SecurityCheck already set above based on -NoRecommendations; no duplicate call here

  Write-Info 'Launching: Web Browser'
  # Ensure export path ends with separator
  if ($ExportLocation -and $ExportLocation[-1] -notin @('\', '/')) { $ExportLocation = $ExportLocation + [IO.Path]::DirectorySeparatorChar }
  $Launch = Join-Path -Path $ExportLocation -ChildPath $FileName
  # We'll build the summary fragment first, then add the real summary panel (no placeholder/replacement needed)

  # ----- Summary Table -----
  $policyTotal = $CAPolicy.Count
  $enabledCount = ($CAPolicy | Where-Object { $_.State -eq 'enabled' }).Count
  $reportOnly = ($CAPolicy | Where-Object { $_.State -eq 'enabledForReportingButNotEnforced' }).Count
  $disabledCount = ($CAPolicy | Where-Object { $_.State -eq 'disabled' }).Count
  $duplicates = ($CAExport | Where-Object { $_.IsDuplicate }).Count
  $withMfa = ($CAExport | Where-Object { $_.'Require MFA' -eq 'True' -or $_.'Authentication Strength MFA' }).Count
  $withStrength = ($CAExport | Where-Object { $null -ne $_.'Authentication Strength MFA' -and $_.'Authentication Strength MFA' -ne '' }).Count
  $withBlock = ($CAExport | Where-Object { $_.Block -eq 'True' }).Count
  $riskPolicies = ($CAPolicy | Where-Object { $_.Conditions.SignInRiskLevels -or $_.Conditions.UserRiskLevels }).Count
  $devicePolicies = ($CAPolicy | Where-Object { $_.Conditions.Devices.IncludeDevices -or $_.Conditions.Devices.ExcludeDevices -or $_.GrantControls.BuiltInControls -contains 'compliantDevice' -or $_.GrantControls.BuiltInControls -contains 'domainJoinedDevice' }).Count
  $termsPolicies = ($CAPolicy | Where-Object { $_.GrantControls.TermsOfUse }).Count
  $phishResistant = ($CAExport | Where-Object { $_.'Authentication Strength MFA' -match 'Phishing-resistant' }).Count
  $avgModifiedDays = 0
  $now = Get-Date
  $dateVals = @()
  foreach ( $p in $CAExport ) {
    if ( $p.DateModified ) {
      $d = [datetime] $p.DateModified
      $dateVals += ( ( $now - $d ).TotalDays )
    }
  }
  if ( $dateVals.Count -gt 0 ) {
    $avgModifiedDays = [math]::Round( ( $dateVals | Measure-Object -Average | Select-Object -ExpandProperty Average ), 1 )
  }

  $summaryTable = @()
  $summaryTable += '<div class="summary-section summary-wrapper" style="margin:55px 0 10px 0;">'
  $summaryTable += '<h2 style="margin:0 0 6px 0;font-size:1rem;color:#003553;letter-spacing:.5px;">Policy Summary</h2>'
  $summaryTable += '<table class="summary-table">'
  $summaryTable += '<thead><tr><th>Metric</th><th>Value</th><th>Percent</th></tr></thead><tbody>'
  function Add-SummaryRow {
    param(
      [string]$Name,
      $Value,
      [double]$TotalRef
    )
    $pct = ''
    $numericVal = 0.0
    $canParse = $false
    if ($null -ne $Value) {
      if (
        $Value -is [int] -or $Value -is [long] -or $Value -is [double] -or $Value -is [decimal]) {
        $numericVal = [double]$Value; $canParse = $true
      }
      elseif ($Value -isnot [string]) {
        try { $numericVal = [double]$Value; $canParse = $true } catch { Write-Verbose 'Add-SummaryRow: numeric conversion failed.' }
      }
      elseif ([double]::TryParse([string]$Value, [ref]$numericVal)) {
        $canParse = $true
      }
    }
    if ($canParse -and $TotalRef -gt 0) {
      try { $pct = ('{0:P1}' -f ($numericVal / $TotalRef)) } catch { $pct = '' }
    }
    $encName = [System.Web.HttpUtility]::HtmlEncode($Name)
    $displayValue = if ($Value -is [string]) { [System.Web.HttpUtility]::HtmlEncode($Value) } else { $Value }
    return "<tr><td>$encName</td><td>$displayValue</td><td>$pct</td></tr>"
  }
  # Non-numeric row (percent intentionally blank)
  $summaryTable += (Add-SummaryRow -Name 'Total Policies' -Value $policyTotal -TotalRef '')
  $summaryTable += (Add-SummaryRow -Name 'Enabled' -Value $enabledCount -TotalRef $policyTotal)
  $summaryTable += (Add-SummaryRow -Name 'Report-only' -Value $reportOnly -TotalRef $policyTotal)
  $summaryTable += (Add-SummaryRow -Name 'Disabled' -Value $disabledCount -TotalRef $policyTotal)
  $summaryTable += (Add-SummaryRow -Name 'Duplicate (content) Matches' -Value $duplicates -TotalRef $policyTotal)
  $summaryTable += (Add-SummaryRow -Name 'Policies Requiring MFA (any)' -Value $withMfa -TotalRef $policyTotal)
  $summaryTable += (Add-SummaryRow -Name 'Policies With Auth Strength' -Value $withStrength -TotalRef $policyTotal)
  $summaryTable += (Add-SummaryRow -Name 'Phishing-resistant Strength' -Value $phishResistant -TotalRef $policyTotal)
  $summaryTable += (Add-SummaryRow -Name 'Policies With Block Control' -Value $withBlock -TotalRef $policyTotal)
  $summaryTable += (Add-SummaryRow -Name 'Risk-Based Policies' -Value $riskPolicies -TotalRef $policyTotal)
  $summaryTable += (Add-SummaryRow -Name 'Device Condition / Control Policies' -Value $devicePolicies -TotalRef $policyTotal)
  $summaryTable += (Add-SummaryRow -Name 'Terms of Use Policies' -Value $termsPolicies -TotalRef $policyTotal)
  $summaryTable += ("<tr><td>Average Age Since Modified (days)</td><td>$avgModifiedDays</td><td></td></tr>")
  $summaryTable += '</tbody></table>'
  $summaryTable += '</div>'
  # Prepare summary HTML fragment and assign stable id for later detection
  $SummaryHtmlFragment = ($summaryTable -join "`n") -replace '<div class="summary-section"', '<div class="summary-section" id="summary-root"'
  # Add populated summary panel, then open policies panel
  $HtmlParts += "<div class='policy-summary' id='panel-summary' role='tabpanel' aria-labelledby='tab-summary' aria-hidden='true' style='display:none;'>$SummaryHtmlFragment</div>"
  $HtmlParts += "<div class='policy-export' id='panel-policies' role='tabpanel' aria-labelledby='tab-policies' aria-hidden='false'>"
  # Legend / utilities bar
  $legendHtml = @'
  <div class='legend-bar' id='legend-bar'>
    <span class='legend-title'>Legend:</span>
    <span class='legend-item'><span class='legend-swatch'>—</span> Empty / None</span>
    <span class='legend-item'><span class='legend-swatch enabled'>EN</span> Enabled</span>
    <span class='legend-item'><span class='legend-swatch report'>RP</span> Report-only</span>
    <span class='legend-item'><span class='legend-swatch disabled'>DIS</span> Disabled</span>
    <span class='legend-item'><span class='legend-swatch pass'>✔</span> Rec Pass</span>
    <span class='legend-item'><span class='legend-swatch fail'>⚠</span> Rec Attention</span>
    <span class='legend-item'><span class='legend-swatch'>✔</span> Boolean True</span>
    <span class='legend-item'><span class='legend-swatch'>—</span> Boolean False</span>
    <span class='legend-divider' aria-hidden='true'></span>
  <button type='button' id='bool-mode-toggle' class='util-button bool-mode-toggle' data-mode='icon' aria-pressed='false' title='Toggle boolean display mode'>Boolean: Icons</button>
  <button type='button' id='layout-mode-toggle' class='layout-toggle' data-mode='dynamic' aria-pressed='false' title='Toggle fixed/dynamic column widths'>Layout: Dynamic</button>
  </div>
'@
  $HtmlParts += $legendHtml
  # Define columns (reuse CSV default ordering for consistency, but can trim for HTML readability)
  $htmlColumns = @(
    'Name', 'Status', 'DateModified', 'CreatedDateTime', 'Description', 'DuplicateMatches',
    'UsersInclude', 'UsersExclude', 'UsersIncludeIds', 'UsersExcludeIds', 'RolesIncludeIds', 'RolesExcludeIds',
    'ApplicationsIncluded', 'ApplicationsExcluded', 'ApplicationsIncludedIds', 'ApplicationsExcludedIds',
    'userActions', 'AuthContext', 'UserRisk', 'SignInRisk', 'PlatformsInclude', 'PlatformsExclude',
    'LocationsIncluded', 'LocationsExcluded', 'LocationsIncludedIds', 'LocationsExcludedIds', 'ClientApps',
    'DevicesIncluded', 'DevicesExcluded', 'DeviceFilters', 'AuthenticationFlows', 'Block', 'Require MFA', 'Authentication Strength MFA',
    'CompliantDevice', 'DomainJoinedDevice', 'CompliantApplication', 'ApprovedApplication', 'PasswordChange', 'TermsOfUse', 'TermsOfUseIds', 'CustomControls', 'GrantOperator',
    'ApplicationEnforcedRestrictions', 'CloudAppSecurity', 'SignInFrequency', 'PersistentBrowser', 'ContinuousAccessEvaluation', 'ResilientDefaults', 'secureSignInSession', 'RawJson'
  )
  # Build table rows per policy
  $table = @()
  $table += '<table class="sticky-header">'
  # Specify boolean columns for icon rendering
  $boolColumns = @('Block', 'Require MFA', 'CompliantDevice', 'DomainJoinedDevice', 'CompliantApplication', 'ApprovedApplication', 'PasswordChange', 'ApplicationEnforcedRestrictions', 'CloudAppSecurity', 'ResilientDefaults')
  $header = '<thead><tr>' + ($htmlColumns | ForEach-Object {
      if ($_ -eq 'Name') { '<th id="th-name" class="sticky-name name-col">Name</th>' }
      elseif ($_ -eq 'Status') { '<th>Status</th>' }
      elseif ($boolColumns -contains $_) { "<th class='bool-col'>$_</th>" }
      else { "<th>$_</th>" }
    }) -join '' + '</tr></thead>'
  $table += $header
  $table += '<tbody>'
  foreach ($p in $CAExport) {
    $rowTds = @()
    $colIndex = 0
    foreach ($col in $htmlColumns) {
      $colIndex++
      $raw = $null
      if ($p.PSObject.Properties.Match($col)) { $raw = $p.$col }
      if ($col -eq 'RawJson') {
        $jsonMut = $p | Select-Object * -ExcludeProperty RawJson | ConvertTo-Json -Depth 6
        $safeMut = [System.Web.HttpUtility]::HtmlEncode($jsonMut)
        $jsonOrig = ''
        if ($RawPolicyIndex -and $p.PolicyId -and $RawPolicyIndex.ContainsKey($p.PolicyId)) {
          $jsonOrig = $RawPolicyIndex[$p.PolicyId] | ConvertTo-Json -Depth 6
        }
        $safeOrig = [System.Web.HttpUtility]::HtmlEncode($jsonOrig)
        $disableOrig = if ($safeOrig) { '' } else { ' disabled title="No original snapshot"' }
        # Include copy button; aria-live announcements handled by global JS using #live-region
        # Buttons: Mutated vs Original toggle pre elements (data-mode attr). Copy button copies currently displayed JSON.
        $rowTds += "<td><details class='raw-json'><summary>View</summary><div class='json-toggle-bar'><button type='button' class='json-btn active' data-mode='mut' aria-pressed='true'>Mutated</button><button type='button' class='json-btn' data-mode='orig' aria-pressed='false'$disableOrig>Original</button><button type='button' class='json-copy util-button' data-copy='mut' title='Copy displayed JSON' aria-label='Copy JSON'>Copy</button></div><pre class='json-block' data-mode='mut'>$safeMut</pre><pre class='json-block' data-mode='orig' style='display:none;'>$safeOrig</pre></details></td>"
      }
      elseif ($col -eq 'Name' -and $p.PolicyId) {
        $plink = "$LinkURL$($p.PolicyId)"
        $safe = [System.Web.HttpUtility]::HtmlEncode([string]$raw)
        $rowTds += "<td class='sticky-name name-col'><a href='$plink' target='_blank'>$safe<span class='icon-ext'></span></a></td>"
      }
      elseif ($col -eq 'Status') {
        $statusVal = [string]$raw
        switch -Regex ($statusVal) {
          '^enabled$' { $badge = "<span class='status-badge status-enabled' title='Enabled'>ENABLED</span>"; break }
          'enabledForReportingButNotEnforced' { $badge = "<span class='status-badge status-report' title='Report-only'>REPORT</span>"; break }
          '^disabled$' { $badge = "<span class='status-badge status-disabled' title='Disabled'>DISABLED</span>"; break }
          default { $badge = ([System.Web.HttpUtility]::HtmlEncode($statusVal)) }
        }
        $rowTds += "<td>$badge</td>"
      }
      elseif ($col -eq 'Description') {
        if ($null -eq $raw -or [string]::IsNullOrWhiteSpace([string]$raw)) {
          $rowTds += "<td class='desc-cell'><span class='placeholder' aria-label='None'>—</span></td>"
        }
        else {
          $safe = [System.Web.HttpUtility]::HtmlEncode([string]$raw)
          $descId = 'desc-' + [guid]::NewGuid().ToString('N')
          $rowTds += "<td class='desc-cell'><div class='desc-text' id='$descId'>$safe</div><button type='button' class='desc-expand' aria-label='Expand description' aria-expanded='false' aria-controls='$descId'>More</button></td>"
        }
      }
      elseif ($boolColumns -contains $col) {
        if ($raw -eq 'True' -or $raw -eq $true) { $rowTds += "<td class='bool-col'><span class='bool-yes' aria-label='True'>✔</span></td>" }
        else { $rowTds += "<td class='bool-col'><span class='bool-no' aria-label='False'>—</span></td>" }
      }
      else {
        if ($null -eq $raw -or [string]::IsNullOrWhiteSpace([string]$raw)) { $rowTds += "<td><span class='placeholder' aria-label='None'>—</span></td>" }
        else {
          $safe = [System.Web.HttpUtility]::HtmlEncode([string]$raw)
          $rowTds += "<td>$safe</td>"
        }
      }
    }
    $dupClass = if ($p.IsDuplicate) { ' class="dup-row"' } else { '' }
    $table += "<tr$dupClass>" + ($rowTds -join '') + '</tr>'
  }
  $table += '</tbody></table>'
  # (Summary panel already populated above)
  # Append policies table (inside policies panel) exactly once, then close policies panel
  $HtmlParts += ($table -join "`n")
  $HtmlParts += '</div>'  # close policy-export / panel-policies
  # Append recommendations panel as a sibling (was previously nested causing it to be hidden and table omitted)
  $HtmlParts += $SecurityCheck

  $fallbackToggle = @'
<script>
// Enhanced vanilla JS interactions (3-tab aware, accessible)
document.addEventListener('DOMContentLoaded', function(){
  var tabs = Array.prototype.slice.call(document.querySelectorAll('.view-toggle-group [role=tab]'));
  var hasRecommendations = !!document.getElementById('tab-recommendations');
  var panels = {
    'tab-summary': document.getElementById('panel-summary'),
    'tab-policies': document.getElementById('panel-policies')
  };
  if(hasRecommendations){ panels['tab-recommendations'] = document.getElementById('panel-recommendations'); }
  // Explicit panel element references for later logic (table lookup, etc.)
  var policies = panels['tab-policies'];
  var summary  = panels['tab-summary'];
  var recs     = hasRecommendations ? panels['tab-recommendations'] : null;
  var searchInput = document.getElementById('policy-search');
  var searchClear = document.getElementById('policy-search-clear');
  var backToTop = document.getElementById('back-to-top');
  var idToggle = document.getElementById('toggle-id-cols');
  var recToggle = document.getElementById('toggle-recs');
  var boolModeToggle = document.getElementById('bool-mode-toggle');
  var layoutModeToggle = document.getElementById('layout-mode-toggle');

  function activate(tabId){ // Persist and switch between main report panels (Summary / Policy Details / Recommendations)
    if(!panels[tabId]){ if(window.console) console.warn('Activate called for unknown tabId', tabId); }
    tabs.forEach(function(t){
      var on = (t.id === tabId);
      t.classList.toggle('active', on);
      t.setAttribute('aria-selected', on ? 'true' : 'false');
      t.tabIndex = on ? 0 : -1;
      var panel = panels[t.id];
      if(panel){
        panel.style.display = on ? 'block' : 'none';
        panel.setAttribute('aria-hidden', on ? 'false':'true');
      }
    });
    if(window.console){ console.log('Tab activated:', tabId, 'summary visible?', summary && summary.style.display, 'policies visible?', policies && policies.style.display); }
    if(searchInput){
      var isPolicies = (tabId === 'tab-policies');
      searchInput.disabled = !isPolicies;
      searchInput.title = isPolicies ? 'Search policies' : 'Search only available in Policy Details view';
    }
  var hash = '#policies';
  if(hasRecommendations && tabId === 'tab-recommendations') hash = '#recommendations';
    if(tabId === 'tab-summary') hash = '#summary';
  try { history.replaceState(null, '', hash); } catch(e){}
  try { localStorage.setItem('caexport.activeTab', tabId); } catch(e){}
    window.scrollTo({top:0});
  }

  // Click handling
  tabs.forEach(function(t){ t.addEventListener('click', function(){ activate(t.id); }); });

  // Keyboard navigation (Left/Right/Home/End)
  function tabKeyHandler(e){
    var key = e.key;
    var currentIndex = tabs.indexOf(document.activeElement);
    if(currentIndex === -1) return;
    if(key === 'ArrowRight'){ e.preventDefault(); var next = (currentIndex+1) % tabs.length; tabs[next].focus(); activate(tabs[next].id); }
    else if(key === 'ArrowLeft'){ e.preventDefault(); var prev = (currentIndex-1+tabs.length) % tabs.length; tabs[prev].focus(); activate(tabs[prev].id); }
    else if(key === 'Home'){ e.preventDefault(); tabs[0].focus(); activate(tabs[0].id); }
    else if(key === 'End'){ e.preventDefault(); tabs[tabs.length-1].focus(); activate(tabs[tabs.length-1].id); }
  }
  tabs.forEach(function(t){ t.addEventListener('keydown', tabKeyHandler); });

  // Hash routing
  var storedTab = null; try { storedTab = localStorage.getItem('caexport.activeTab'); } catch(e){}
  if(window.location.hash){
    var h = window.location.hash.toLowerCase();
    if(hasRecommendations && h.includes('recommend')) activate('tab-recommendations');
    else if(h.includes('summary')) activate('tab-summary');
    else activate('tab-policies');
  } else if(storedTab && panels[storedTab]) { activate(storedTab); } else { activate('tab-policies'); }

  // Table interactions (guarded)
  var table = policies ? policies.querySelector('table') : null;
  if(table){
    // Helper: clear all value-match highlights
    function clearValueMatches(){
      var prev = table.querySelectorAll('.value-match');
      for(var i=0;i<prev.length;i++){ prev[i].classList.remove('value-match'); }
    }
    // Current tracked match value
    var activeMatchValue = null;
    table.addEventListener('click', function(e){
      var cell = e.target.closest('td,th');
      // JSON toggle buttons
      var jsonBtn = e.target.closest('button.json-btn');
      if(jsonBtn){
        var td = jsonBtn.closest('td');
        var btns = td.querySelectorAll('button.json-btn');
        for(var i=0;i<btns.length;i++){ btns[i].classList.remove('active'); btns[i].setAttribute('aria-pressed','false'); }
        jsonBtn.classList.add('active'); jsonBtn.setAttribute('aria-pressed','true');
        var mode = jsonBtn.getAttribute('data-mode');
        var blocks = td.querySelectorAll('pre.json-block');
        for(var b=0;b<blocks.length;b++){ blocks[b].style.display = (blocks[b].getAttribute('data-mode') === mode) ? 'block' : 'none'; }
        // Update copy button data attribute to reflect current mode
        var copyBtn = td.querySelector('button.json-copy');
        if(copyBtn){ copyBtn.setAttribute('data-copy', mode); }
        return; // don't fall through to row select logic for the toggle click
      }
      // JSON copy button
      var jsonCopy = e.target.closest('button.json-copy');
      if(jsonCopy){
        var td = jsonCopy.closest('td');
        var mode = jsonCopy.getAttribute('data-copy') || 'mut';
        var block = td.querySelector("pre.json-block[data-mode='"+mode+"']");
        if(block){
          var text = block.textContent || '';
          navigator.clipboard.writeText(text).then(function(){
            var lr = document.getElementById('live-region');
            if(lr){ lr.textContent = 'JSON copied to clipboard ('+mode+').'; }
            jsonCopy.textContent = 'Copied';
            setTimeout(function(){ jsonCopy.textContent='Copy'; }, 1500);
          }).catch(function(){
            var lr = document.getElementById('live-region');
            if(lr){ lr.textContent = 'Copy failed'; }
          });
        }
        return;
      }
      var tr = e.target.closest('tr');
      if(tr && tr.parentElement.tagName !== 'THEAD'){
        tr.classList.toggle('selected');
      }
      if(!cell) return;
      var raw = (cell.textContent||'').trim();
      // If empty cell: clear highlights and reset
      if(raw.length===0){ clearValueMatches(); activeMatchValue=null; return; }
      // If clicking same value again -> toggle off
      if(activeMatchValue !== null && raw === activeMatchValue){ clearValueMatches(); activeMatchValue=null; return; }
      // Apply new highlight set
      clearValueMatches();
      activeMatchValue = raw;
      var cells = table.querySelectorAll('td,th');
      for(var i=0;i<cells.length;i++){
        var txt = (cells[i].textContent||'').trim();
        if(txt === raw && raw.length>0){ cells[i].classList.add('value-match'); }
      }
    });
    var headers = table.querySelectorAll('thead th');
    for(var h=0; h<headers.length; h++){
      (function(th, idx){
        th.addEventListener('click', function(){
          var active = !th.classList.contains('colselected');
            // Clear existing
          for(var k=0;k<headers.length;k++){ headers[k].classList.remove('colselected'); }
          var rows = table.querySelectorAll('tr');
          for(var r=0;r<rows.length;r++){
            var cells = rows[r].children;
            for(var c=0;c<cells.length;c++){
              cells[c].classList.remove('colselected');
            }
          }
          if(active){
            th.classList.add('colselected');
            for(var r2=0;r2<rows.length;r2++){
              var c2 = rows[r2].children[idx];
              if(c2){ c2.classList.add('colselected'); }
            }
          }
        });
      })(headers[h], h);
    }
  }
  // Raw ID column names
  var rawIdCols = ['UsersIncludeIds','UsersExcludeIds','RolesIncludeIds','RolesExcludeIds','ApplicationsIncludedIds','ApplicationsExcludedIds','LocationsIncludedIds','LocationsExcludedIds','TermsOfUseIds'];
  function setIdColumns(show){
    if(!table) return;
    var headers = table.querySelectorAll('thead th');
    headers.forEach(function(th, idx){
      var label = th.textContent.trim();
      if(rawIdCols.indexOf(label) > -1){
        var rows = table.querySelectorAll('tbody tr');
        if(show){ th.classList.remove('id-col-hidden'); } else { th.classList.add('id-col-hidden'); }
        rows.forEach(function(r){ var c=r.children[idx]; if(c){ if(show){ c.classList.remove('id-col-hidden'); } else { c.classList.add('id-col-hidden'); } } });
      }
    });
  }
  // Restore ID column visibility
  var showIdsPref = false; try { showIdsPref = localStorage.getItem('caexport.showIds')==='true'; } catch(e){}
  setIdColumns(showIdsPref);
  if(showIdsPref && idToggle){ idToggle.classList.add('active'); idToggle.textContent='Hide ID Columns'; idToggle.setAttribute('aria-pressed','true'); }
  if(idToggle){
    idToggle.addEventListener('click', function(){
      var active = idToggle.classList.toggle('active');
      idToggle.textContent = active ? 'Hide ID Columns' : 'Show ID Columns';
      idToggle.setAttribute('aria-pressed', active ? 'true' : 'false');
      setIdColumns(active);
      try { localStorage.setItem('caexport.showIds', active?'true':'false'); } catch(e){}
    });
  }

  // Recommendation expand/collapse (simple show/hide of recommendation cards)
  if(recToggle){
    recToggle.addEventListener('click', function(){
      var recPanel = document.getElementById('panel-recommendations');
      if(!recPanel) return;
      var items = recPanel.querySelectorAll('.recommendation');
      var collapsing = recToggle.getAttribute('data-collapsed') !== 'true';
      items.forEach(function(el){ el.style.display = collapsing ? 'none' : ''; });
      recToggle.setAttribute('data-collapsed', collapsing ? 'true' : 'false');
      recToggle.textContent = collapsing ? 'Show Recs' : 'Hide Recs';
      recToggle.classList.toggle('active', !collapsing);
    });
  }

  // Recommendation pass/fail filter buttons injected dynamically (with persistence)
  // Stored key: caexport.recFilter -> 'all' | 'fail' | 'pass'
  (function(){
    var recPanel = document.getElementById('panel-recommendations');
    if(!recPanel) return;
    if(!recPanel.querySelector('.rec-filter-group')){
      var bar = document.createElement('div');
      bar.className='rec-filter-group';
      bar.setAttribute('role','group');
      bar.style.margin='0 0 10px 0';
      var buttons=[
        {id:'rec-filter-all', label:'All', filter:'all'},
        {id:'rec-filter-fail', label:'Attention', filter:'fail'},
        {id:'rec-filter-pass', label:'Pass', filter:'pass'}
      ];
      var storedRecFilter = null; try { storedRecFilter = localStorage.getItem('caexport.recFilter'); } catch(e){}
      buttons.forEach(function(cfg,idx){
        var b=document.createElement('button');
        var makeActive = storedRecFilter ? (storedRecFilter===cfg.filter) : (idx===0);
        b.type='button'; b.textContent=cfg.label; b.className='util-button'+(makeActive?' active':'');
        b.dataset.filter=cfg.filter; b.id=cfg.id; b.addEventListener('click', function(){
          var allBtns=bar.querySelectorAll('button'); allBtns.forEach(function(bb){bb.classList.remove('active');});
          b.classList.add('active');
          var cards = recPanel.querySelectorAll('details.recommendation-card');
          cards.forEach(function(card){
            if(cfg.filter==='all'){ card.style.display=''; }
            else {
              var isPass = card.classList.contains('pass');
              var show = (cfg.filter==='pass' && isPass) || (cfg.filter==='fail' && !isPass);
              card.style.display = show ? '' : 'none';
            }
          });
          try { localStorage.setItem('caexport.recFilter', cfg.filter); } catch(e){}
        });
        bar.appendChild(b);
      });
      if(storedRecFilter && storedRecFilter!=='all'){
        var trigger = bar.querySelector('button[data-filter="'+storedRecFilter+'"]');
        if(trigger){ trigger.click(); }
      }
      recPanel.insertBefore(bar, recPanel.firstChild);
    }
  })();

  // Boolean icon/text toggle with persistence
  // Stored key: caexport.boolMode -> 'icon' (default) or 'text'
  if(boolModeToggle && table){
    var storedBoolMode = null; try { storedBoolMode = localStorage.getItem('caexport.boolMode'); } catch(e){}
    function applyBoolMode(mode){
      var toIcons = (mode === 'icon');
      boolModeToggle.setAttribute('data-mode', mode);
      boolModeToggle.textContent = 'Boolean: ' + (toIcons ? 'Icons' : 'Text');
      var boolCols = ['Block','Require MFA','CompliantDevice','DomainJoinedDevice','CompliantApplication','ApprovedApplication','PasswordChange','ApplicationEnforcedRestrictions','CloudAppSecurity','ResilientDefaults'];
      var headerCells = table.querySelectorAll('thead th');
      var indexes=[]; headerCells.forEach(function(h,i){ if(boolCols.indexOf(h.textContent.trim())>-1){ indexes.push(i); }});
      var rows = table.querySelectorAll('tbody tr');
      rows.forEach(function(r){ indexes.forEach(function(idx){ var cell=r.children[idx]; if(!cell)return; var span=cell.querySelector('span.bool-yes, span.bool-no'); if(!span)return; span.textContent = span.classList.contains('bool-yes') ? (toIcons?'✔':'True') : (toIcons?'—':'False'); }); });
    }
    applyBoolMode(storedBoolMode && ['icon','text'].indexOf(storedBoolMode)>-1 ? storedBoolMode : 'icon');
    boolModeToggle.addEventListener('click', function(){
      var current = boolModeToggle.getAttribute('data-mode');
      var next = current === 'icon' ? 'text' : 'icon';
      applyBoolMode(next);
      try { localStorage.setItem('caexport.boolMode', next); } catch(e){}
    });
  }

  // Layout mode toggle (dynamic vs fixed widths) with persistence
  if(layoutModeToggle && policies){
    var storedLayout = null; try { storedLayout = localStorage.getItem('caexport.layoutMode'); } catch(e){}
    function applyLayout(mode){
      // mode: 'dynamic' or 'fixed'
      if(mode==='fixed'){
        policies.classList.add('fixed-layout');
        layoutModeToggle.textContent='Layout: Fixed';
        layoutModeToggle.classList.add('active');
        layoutModeToggle.setAttribute('data-mode','fixed');
        layoutModeToggle.setAttribute('aria-pressed','true');
      } else {
        policies.classList.remove('fixed-layout');
        layoutModeToggle.textContent='Layout: Dynamic';
        layoutModeToggle.classList.remove('active');
        layoutModeToggle.setAttribute('data-mode','dynamic');
        layoutModeToggle.setAttribute('aria-pressed','false');
      }
    }
    applyLayout(storedLayout && ['dynamic','fixed'].indexOf(storedLayout)>-1 ? storedLayout : 'dynamic');
    layoutModeToggle.addEventListener('click', function(){
      var current = layoutModeToggle.getAttribute('data-mode');
      var next = current==='dynamic' ? 'fixed' : 'dynamic';
      applyLayout(next);
      try { localStorage.setItem('caexport.layoutMode', next); } catch(e){}
      var lr=document.getElementById('live-region'); if(lr){ lr.textContent='Layout set to '+ (next==='fixed'?'fixed widths':'dynamic widths'); }
    });
  }

  // Description expand/collapse (aria-expanded + aria-controls for accessibility)
  if(table){
    table.addEventListener('click', function(e){
      var btn = e.target.closest('.desc-expand');
      if(!btn) return;
      var cell = btn.closest('.desc-cell');
      var expanded = cell.classList.toggle('expanded');
      btn.textContent = expanded ? 'Less' : 'More';
  btn.setAttribute('aria-label', expanded ? 'Collapse description' : 'Expand description');
  btn.setAttribute('aria-expanded', expanded ? 'true' : 'false');
    });
  }

  // Policy search filter
  function filterPolicies(){
    if(!table) return; // nothing to do
    var q = (searchInput.value || '').toLowerCase();
    if(searchInput.parentElement){
      if(q.length>0){ searchInput.parentElement.classList.add('has-value'); }
      else { searchInput.parentElement.classList.remove('has-value'); }
    }
    var rows = table.querySelectorAll('tbody tr');
    for(var i=0;i<rows.length;i++){
      var row = rows[i];
      // Do not hide header-like separator rows (if any) based on background color markers
      if(q.length===0){ row.style.display=''; continue; }
      var cells = row.children;
      var match = false;
      for(var c=0;c<cells.length;c++){
        if(cells[c].textContent && cells[c].textContent.toLowerCase().indexOf(q) > -1){ match = true; break; }
      }
      row.style.display = match ? '' : 'none';
    }
  }
  if(searchInput){
    searchInput.addEventListener('input', filterPolicies);
    searchInput.addEventListener('keydown', function(e){ if(e.key==='Escape'){ searchInput.value=''; filterPolicies(); searchInput.blur(); } });
  }
  if(searchClear){
    searchClear.addEventListener('click', function(){ searchInput.value=''; filterPolicies(); searchInput.focus(); });
  }

  // Back to top visibility
  function updateBackToTop(){
    if(!backToTop) return;
    if(window.scrollY > 300){ backToTop.style.display='block'; } else { backToTop.style.display='none'; }
  }
  window.addEventListener('scroll', updateBackToTop);
  if(backToTop){
    backToTop.addEventListener('click', function(){ window.scrollTo({top:0, behavior:'smooth'}); });
  }
  updateBackToTop();

  // Ensure search state matches initial view (handled in activate but safeguard)
  if(searchInput && searchInput.disabled && window.location.hash.toLowerCase().indexOf('policies')>-1){ searchInput.disabled=false; }
});
</script>
'@
  $fullPage = $htmlDoc + $HtmlParts + $fallbackToggle + '</body></html>'
  $fullPage | Out-File $Launch -Encoding UTF8
  if (-not $NoBrowser) { Start-Process $Launch }
}
if ($JsonExport) {
  Write-Info 'Saving to File: JSON (enriched policies) & RAW JSON'
  $LaunchJson = Join-Path -Path $ExportLocation -ChildPath $JsonFileName
  try {
    $CAExport | ConvertTo-Json -Depth 12 | Out-File $LaunchJson
    Write-Info "JSON (enriched) saved: $LaunchJson"
  }
  catch { Write-Warn "Failed to save enriched JSON: $_" }
  if ($RawPolicyObjects) {
    $rawFile = Join-Path -Path $ExportLocation -ChildPath "${baseName}_raw.json"
    try { $RawPolicyObjects | ConvertTo-Json -Depth 12 | Out-File $rawFile; Write-Info "Raw JSON saved: $rawFile" } catch { Write-Warn "Failed to save raw JSON: $_" }
  }
}
if ($CsvExport) {
  Write-Info 'Saving to File: CSV (one row per policy)'
  $LaunchCsv = Join-Path -Path $ExportLocation -ChildPath $CsvFileName
  $defaultColumns = @(
    'Name', 'PolicyId', 'Status', 'DateModified', 'CreatedDateTime', 'Description', 'DuplicateMatches',
    'UsersInclude', 'UsersExclude', 'UsersIncludeIds', 'UsersExcludeIds', 'RolesIncludeIds', 'RolesExcludeIds',
    'ApplicationsIncluded', 'ApplicationsExcluded', 'ApplicationsIncludedIds', 'ApplicationsExcludedIds',
    'userActions', 'AuthContext', 'UserRisk', 'SignInRisk', 'PlatformsInclude', 'PlatformsExclude',
    'LocationsIncluded', 'LocationsExcluded', 'LocationsIncludedIds', 'LocationsExcludedIds', 'ClientApps',
    'DevicesIncluded', 'DevicesExcluded', 'DeviceFilters', 'AuthenticationFlows', 'Block', 'Require MFA', 'Authentication Strength MFA',
    'CompliantDevice', 'DomainJoinedDevice', 'CompliantApplication', 'ApprovedApplication', 'PasswordChange', 'TermsOfUse', 'TermsOfUseIds', 'CustomControls', 'GrantOperator',
    'ApplicationEnforcedRestrictions', 'CloudAppSecurity', 'SignInFrequency', 'PersistentBrowser', 'ContinuousAccessEvaluation', 'ResilientDefaults', 'secureSignInSession'
  )
  $chosenColumns = if ($CsvColumns) { $CsvColumns } else { $defaultColumns }
  $available = if ($CAExport.Count -gt 0) { $CAExport[0].PSObject.Properties.Name } else { @() }
  $missingCols = @(); $finalCols = @()
  foreach ($c in $chosenColumns) { if ($available -contains $c) { $finalCols += $c } else { $missingCols += $c } }
  if ($missingCols) { Write-Warn "Ignoring unknown CSV columns: $($missingCols -join ', ')" }
  $exportSet = if ($finalCols) { $CAExport | Select-Object -Property $finalCols } else { $null }
  if (-not $exportSet) { Write-Warn 'No CAExport data found; exporting raw policies.'; $CAPolicy | Select-Object * | Export-Csv -NoTypeInformation -Path $LaunchCsv }
  else { $exportSet | Export-Csv -NoTypeInformation -Path $LaunchCsv }
  Write-Info "CSV saved: $LaunchCsv"
}
if ($CsvPivotExport) {
  Write-Info 'Saving to File: Pivot CSV'
  $LaunchCsvPivot = Join-Path -Path $ExportLocation -ChildPath $CsvPivotFileName
  $pivotToExport = $pivot
  if (-not $pivotToExport -or $pivotToExport.Count -eq 0) { Write-Warn 'Pivot empty; skipping pivot CSV.' }
  else {
    try {
      $pivotToExport | Export-Csv -NoTypeInformation -Path $LaunchCsvPivot
      Write-Info "Pivot CSV saved: $LaunchCsvPivot"
    }
    catch {
      Write-Warn "Failed to write pivot CSV: $($_.Exception.Message)"
    }
  }
}