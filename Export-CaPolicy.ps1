#Conditional Access Export Utility

<#
	.SYNOPSIS
		Conditional Access Export Utility
	.DESCRIPTION
       Exports CA Policy to HTML Format for auditing/historical purposes.

	.PARAMETER TenantID
		Optional. The Azure AD tenant ID to connect to. If not specified, connects to the default tenant.

	.PARAMETER PolicyID
		Optional. A specific Conditional Access policy ID (GUID) to export. If not specified, all policies are exported.

	.PARAMETER Csv
		Switch. Generate a CSV file in pivot format (wide format) for analysis in Excel or BI tools.

	.NOTES
		Douglas Baker
		@dougsbaker

    CONTRIBUTORS
		Andres Bohren
    @andresbohren

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
# Suppress long line warnings for embedded HTML
[Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSAvoidLongLines', '')]
[Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSAlignAssignmentStatement', '')]
[Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseConsistentIndentation', '')]
param (
  [Parameter()]
  [String]$TenantID,
  [Parameter()]
  [String]$PolicyID,
  [switch]$Csv
)

# Reference parameters to satisfy analyzer usage checks
$null = $TenantID

function Write-Info { param([string]$Message) Write-Information -MessageData $Message -InformationAction Continue }
function Write-Warn { param([string]$Message) Write-Warning $Message }
function Write-Err { param([string]$Message) Write-Error -Message $Message }

function Test-ModuleInstalled {
  param([string[]]$ModuleNames)
  $missing = @(); foreach ($m in $ModuleNames) { if (-not (Get-Module -ListAvailable -Name $m)) { $missing += $m } }; return $missing
}

function Initialize-GraphModule {
  <#
.SYNOPSIS
  Ensure required PowerShell modules are installed and loadable for the current user.
.DESCRIPTION
  Verifies presence of Microsoft Graph modules used by this script and installs them to CurrentUser scope when missing.
  Attempts to trust PSGallery and install the NuGet provider when necessary. Imports modules after install.
.PARAMETER RequiredModules
  The list of module names to validate/install. Defaults to Microsoft Graph modules used by this script.
.EXAMPLE
  Ensure-GraphModules
#>
  [CmdletBinding()]
  param(
    [string[]]$RequiredModules = @(
      'Microsoft.Graph',
      'Microsoft.Graph.Authentication',
      'Microsoft.Graph.Identity.DirectoryManagement',
      'Microsoft.Graph.Identity.SignIns'
    )
  )

  try {
    # Prefer TLS 1.2 for gallery operations (safe no-op on newer PowerShell)
    [System.Net.ServicePointManager]::SecurityProtocol = [System.Net.SecurityProtocolType]::Tls12
  }
  catch {
    Write-Verbose 'Failed to set SecurityProtocol to TLS 1.2; proceeding with defaults.'
  }

  # Ensure NuGet provider exists (for Install-Module)
  try {
    $nuget = Get-PackageProvider -Name NuGet -ErrorAction SilentlyContinue
    if (-not $nuget) {
      Write-Info 'Installing NuGet package provider (CurrentUser)'
      Install-PackageProvider -Name NuGet -Scope CurrentUser -Force -MinimumVersion '2.8.5.201' -ErrorAction Stop | Out-Null
    }
  }
  catch {
    Write-Warn ('Failed to install NuGet provider: {0}' -f $_.Exception.Message)
  }

  # Ensure PSGallery is available and trusted
  try {
    $repo = Get-PSRepository -Name 'PSGallery' -ErrorAction Stop
    if ($repo.InstallationPolicy -ne 'Trusted') {
      try { Set-PSRepository -Name 'PSGallery' -InstallationPolicy Trusted -ErrorAction Stop } catch { Write-Warn 'Could not set PSGallery as Trusted. You may be prompted during install.' }
    }
  }
  catch {
    Write-Warn 'PowerShell Gallery (PSGallery) not found. Module installation may fail until the repository is available.'
  }

  foreach ($m in $RequiredModules) {
    $installed = Get-Module -ListAvailable -Name $m
    if (-not $installed) {
      Write-Info ('Installing module: {0} (CurrentUser)' -f $m)
      try {
        Install-Module -Name $m -Scope CurrentUser -AllowClobber -Force -ErrorAction Stop
      }
      catch {
        Write-Warn ("Failed to install module '{0}': {1}" -f $m, $_.Exception.Message)
      }
    }
    # Import (best-effort)
    #try {
      #Import-Module -Name $m -Force -ErrorAction Stop
    #}
    #catch {
      #Write-Warn ("Failed to import module '{0}': {1}" -f $m, $_.Exception.Message)
    #}
  }
}

function Test-GraphConnected { try { Get-MgOrganization -ErrorAction Stop | Out-Null; return $true } catch { return $false } }
function Get-CurrentGraphScope { try { (Get-MgContext).Scopes } catch { @() } }
function Connect-GraphContext {
  param([string[]]$RequiredScopes = @('Policy.Read.All', 'Directory.Read.All', 'Application.Read.All', 'Agreement.Read.All'))
  Initialize-GraphModule
  $connected = Test-GraphConnected
  $current = Get-CurrentGraphScope
  $still = @(); foreach ($s in $RequiredScopes) { if ($current -notcontains $s) { $still += $s } }
  if (-not $connected -or $still) {
    Write-Info 'Connecting to Microsoft Graph...'
    try {
      if ($TenantID) {
        Connect-MgGraph -Scopes $RequiredScopes -TenantId $TenantID -ErrorAction Stop | Out-Null
      }
      else {
        Connect-MgGraph -Scopes $RequiredScopes -ErrorAction Stop | Out-Null
      }
    }
    catch { Write-Err "Unable to connect to Microsoft Graph: $_"; throw }
  }
  if (-not (Test-GraphConnected)) { Write-Err 'Failed to connect to Microsoft Graph.'; exit 1 }
  $current = Get-CurrentGraphScope
  if ($still) { Write-Warn "Connected but missing scopes: $($still -join ', ')" }
  Write-Info "Connected scopes: $($current -join ', ')"
}

$ExportLocation = $PSScriptRoot; if (!$ExportLocation) { $ExportLocation = $PWD }
$HTMLExport = $true
$CsvExport = $Csv

Connect-GraphContext

$TenantData = Get-MgOrganization
$TenantName = $TenantData.DisplayName
$date = Get-Date
Write-Info "Connected: $TenantName tenant"

# Generate timestamped filename
$baseName = "CAExport_${TenantName}_$(Get-Date -Format 'yyyyMMdd_HHmmss')"
$FileName = "$baseName.html"
$CsvFileName = "$baseName-pivot.csv"


#Collect CA Policy
Write-Info 'Exporting: CA Policy'
if ($PolicyID) {
  $CAPolicy = Get-MgIdentityConditionalAccessPolicy -ConditionalAccessPolicyId $PolicyID
}
else {
  $CAPolicy = Get-MgIdentityConditionalAccessPolicy -All
}

$TenantData = Get-MgOrganization
$TenantName = $TenantData.DisplayName
$date = Get-Date


Write-Info "Extracting: Names from Guid's"
#Swap User Guid With Names
#Get Name
$ADUsers = $CAPolicy.Conditions.Users.IncludeUsers
$ADUsers += $CAPolicy.Conditions.Users.IncludeGroups
$ADUsers += $CAPolicy.Conditions.Users.IncludeRoles
$ADUsers += $CAPolicy.Conditions.Users.ExcludeUsers
$ADUsers += $CAPolicy.Conditions.Users.ExcludeGroups
$ADUsers += $CAPolicy.Conditions.Users.ExcludeRoles



# Filter the $AdUsers array to include only valid GUIDs
$ADsearch = $AdUsers | Where-Object {
  ([Guid]::TryParse($_, [ref] [Guid]::Empty))
}

#users Hashtable
$mgobjects = if ($ADsearch -and $ADsearch.Count -gt 0) { Get-MgDirectoryObjectById -Ids $ADsearch } else { @() }
$mgObjectsLookup = @{}
if ($mgobjects) { $mgobjects | ForEach-Object { $mgObjectsLookup[$_.Id] = $_.AdditionalProperties.displayName } }

# Applications lookup - collect all application IDs from policies
$AppIds = @()
foreach ($policy in $CAPolicy) {
  if ($policy.Conditions -and $policy.Conditions.Applications) {
    $AppIds += $policy.Conditions.Applications.IncludeApplications
    $AppIds += $policy.Conditions.Applications.ExcludeApplications
  }
}
$AppIds = $AppIds | Where-Object { $_ -and ([Guid]::TryParse($_, [ref][Guid]::Empty)) } | Sort-Object -Unique

# Populate applications hashtable
$MGAppsLookup = @{}
foreach ($AppId in $AppIds) {
  try {
    $app = Get-MgServicePrincipal -ServicePrincipalId $AppId -Property Id, DisplayName, AppId -ErrorAction SilentlyContinue
    if ($app) {
      $MGAppsLookup[$AppId] = $app.DisplayName
    }
  }
  catch {
    # Service principal not found or access denied - skip
    Write-Verbose "Could not retrieve service principal for ID '$AppId': $_"
  }
}

#"<div class='tooltip-container'>" + $obj.DisplayName +"<span class='tooltip-text'>App Id:"+ $obj.AppId +"</span></div>"

foreach ($policy in $CAPolicy) {
  if (-not $policy.Conditions -or -not $policy.Conditions.Applications) { continue }

  for ($i = 0; $i -lt $policy.Conditions.Applications.ExcludeApplications.Count; $i++) {
    $AppId = $policy.Conditions.Applications.ExcludeApplications[$i]
    if ($MGAppsLookup.ContainsKey($AppId)) {
      $policy.Conditions.Applications.ExcludeApplications[$i] = $MGAppsLookup[$AppId]
    }
  }

  for ($i = 0; $i -lt $policy.Conditions.Applications.IncludeApplications.Count; $i++) {
    $AppId = $policy.Conditions.Applications.IncludeApplications[$i]
    if ($MGAppsLookup.ContainsKey($AppId)) {
      $policy.Conditions.Applications.IncludeApplications[$i] = $MGAppsLookup[$AppId]
    }
  }
}


#Swap Location with Names
$mgLoc = Get-MgIdentityConditionalAccessNamedLocation
$MGLocLookup = @{}
foreach ($obj in $mgLoc) {
  $MGLocLookup[$obj.Id] = $obj.DisplayName
}
foreach ($policy in $CAPolicy) {
  if (-not $policy.Conditions -or -not $policy.Conditions.Locations) { continue }
  for ($i = 0; $i -lt $policy.Conditions.Locations.IncludeLocations.Count; $i++) {
    $LocId = $policy.Conditions.Locations.IncludeLocations[$i]
    if ($MGLocLookup.ContainsKey($LocId)) {
      $policy.Conditions.Locations.IncludeLocations[$i] = $MGLocLookup[$LocId]
    }
  }
  for ($i = 0; $i -lt $policy.Conditions.Locations.ExcludeLocations.Count; $i++) {
    $LocId = $policy.Conditions.Locations.ExcludeLocations[$i]
    if ($MGLocLookup.ContainsKey($LocId)) {
      $policy.Conditions.Locations.ExcludeLocations[$i] = $MGLocLookup[$LocId]
    }
  }
}


#Switch TOU Id for Name
$mgTou = Get-MgAgreement
$MGTouLookup = @{}
foreach ($obj in $mgTou) {
  $MGTouLookup[$obj.Id] = $obj.DisplayName
}
foreach ($policy in $CAPolicy) {
  if (-not $policy.GrantControls -or -not $policy.GrantControls.TermsOfUse) { continue }

  for ($i = 0; $i -lt $policy.GrantControls.TermsOfUse.Count; $i++) {
    $TouId = $policy.GrantControls.TermsOfUse[$i]
    if ($MGTouLookup.ContainsKey($TouId)) {
      $policy.GrantControls.TermsOfUse[$i] = $MGTouLookup[$TouId]
    }
  }
}

#swap Admin Roles
$mgRole = Get-MgDirectoryRoleTemplate
$mgRoleLookup = @{}
foreach ($obj in $mgRole) {
  $mgRoleLookup[$obj.Id] = $obj.DisplayName
}
foreach ($policy in $caPolicy) {
  if (-not $policy.Conditions -or -not $policy.Conditions.Users) { continue }
  if ($policy.Conditions.Users.IncludeRoles) {

    for ($i = 0; $i -lt $policy.Conditions.Users.IncludeRoles.Count; $i++) {
      $RoleId = $policy.Conditions.Users.IncludeRoles[$i]
      if ($mgRoleLookup.ContainsKey($RoleId)) {
        $policy.Conditions.Users.IncludeRoles[$i] = $mgRoleLookup[$RoleId]
      }
    }
  }
  if ($policy.Conditions.Users.ExcludeRoles) {

    for ($i = 0; $i -lt $policy.Conditions.Users.ExcludeRoles.Count; $i++) {
      $RoleId = $policy.Conditions.Users.ExcludeRoles[$i]
      if ($mgRoleLookup.ContainsKey($RoleId)) {
        $policy.Conditions.Users.ExcludeRoles[$i] = $mgRoleLookup[$RoleId]
      }
    }
  }
}

# exit
$CAExport = @()

$AdUsers = @()
$Apps = @()
#Extract Values
Write-Info 'Extracting: CA Policy Data'
foreach ( $Policy in $CAPolicy) {

  $IncludeUG = $null
  $IncludeUG = $Policy.Conditions.Users.IncludeUsers
  $IncludeUG += $Policy.Conditions.Users.IncludeGroups
  $IncludeUG += $Policy.Conditions.Users.IncludeRoles
  $DateCreated = $null
  $DateCreated = $Policy.CreatedDateTime
  $DateModified = $null
  $DateModified = $Policy.ModifiedDateTime

  $ExcludeUG = $null
  $ExcludeUG = $Policy.Conditions.Users.ExcludeUsers
  $ExcludeUG += $Policy.Conditions.Users.ExcludeGroups
  $ExcludeUG += $Policy.Conditions.Users.ExcludeRoles


  $Apps += $Policy.Conditions.Applications.IncludeApplications
  $Apps += $Policy.Conditions.Applications.ExcludeApplications
  $InclLocation = $Null
  $ExclLocation = $Null
  $InclLocation = $Policy.Conditions.Locations.includelocations
  $ExclLocation = $Policy.Conditions.Locations.Excludelocations
  $InclPlat = $Null
  $ExclPlat = $Null
  $InclPlat = $Policy.Conditions.Platforms.IncludePlatforms
  $ExclPlat = $Policy.Conditions.Platforms.ExcludePlatforms
  $InclDev = $null
  $ExclDev = $null
  $InclDev = $Policy.Conditions.Devices.IncludeDevices
  $ExclDev = $Policy.Conditions.Devices.ExcludeDevices
  $devFilters = $null
  $devFilters = $Policy.Conditions.Devices.DeviceFilter.Rule

  $CAExport += [PSCustomObject][ordered]@{
    Name = $Policy.DisplayName
    Status = $Policy.State
    Created = $DateCreated
    Modified = $DateModified
    'Included Users' = ($IncludeUG -join ", `r`n")
    'Excluded Users' = ($ExcludeUG -join ", `r`n")
    'Cloud apps or actions' = ''
    'Included Applications' = ($Policy.Conditions.Applications.IncludeApplications -join ", `r`n")
    'Excluded Applications' = ($Policy.Conditions.Applications.ExcludeApplications -join ", `r`n")
    'User Actions' = ($Policy.Conditions.Applications.IncludeUserActions -join ", `r`n")
    'Auth Context' = ($Policy.Conditions.Applications.IncludeAuthenticationContextClassReferences -join ", `r`n")
    Conditions = ''
    'User Risk' = ($Policy.Conditions.UserRiskLevels -join ", `r`n")
    'Sign In Risk' = ($Policy.Conditions.SignInRiskLevels -join ", `r`n")
    # Platforms = $Policy.Conditions.Platforms;
    'Included Platforms ' = ($InclPlat -join ", `r`n")
    'Excluded Platforms ' = ($ExclPlat -join ", `r`n")
    # Locations = $Policy.Conditions.Locations;
    'Included Locations' = ($InclLocation -join ", `r`n")
    'Excluded Locations' = ($ExclLocation -join ", `r`n")
    'Client Apps' = ($Policy.Conditions.ClientAppTypes -join ", `r`n")
    # Devices = $Policy.Conditions.Devices;
    'Included Devices' = ($InclDev -join ", `r`n")
    'Excluded Devices' = ($ExclDev -join ", `r`n")
    'Device Filters' = ($devFilters -join ", `r`n")
    'Access Controls' = ''
    'Grant Controls' = ''
    # Grant = ($Policy.GrantControls.BuiltInControls -join ", `r`n");
    Block = if ($Policy.GrantControls.BuiltInControls -contains 'Block') { 'True' } else { '' }
    'Require MFA' = if ($Policy.GrantControls.BuiltInControls -contains 'Mfa') { 'True' } else { '' }
    'Authentication Strength MFA' = $Policy.GrantControls.AuthenticationStrength.DisplayName
    'Compliant Device' = if ($Policy.GrantControls.BuiltInControls -contains 'CompliantDevice') { 'True' } else { '' }
    'Domain Joined Device' = if ($Policy.GrantControls.BuiltInControls -contains 'DomainJoinedDevice') { 'True' } else { '' }
    'Compliant Application' = if ($Policy.GrantControls.BuiltInControls -contains 'CompliantApplication') { 'True' } else { '' }
    'Approved Application' = if ($Policy.GrantControls.BuiltInControls -contains 'ApprovedApplication') { 'True' } else { '' }
    'Password Change' = if ($Policy.GrantControls.BuiltInControls -contains 'PasswordChange') { 'True' } else { '' }
    'Terms Of Use' = ($Policy.GrantControls.TermsOfUse -join ", `r`n")
    'Custom Controls' = ($Policy.GrantControls.CustomAuthenticationFactors -join ", `r`n")
    GrantOperator = $Policy.GrantControls.Operator
    # Session = $Policy.SessionControls
    'Session Controls' = ''
    'Application Enforced Restrictions' = $Policy.SessionControls.ApplicationEnforcedRestrictions.IsEnabled
    'Cloud App Security' = $Policy.SessionControls.CloudAppSecurity.IsEnabled
    'Sign In Frequency' = "$($Policy.SessionControls.SignInFrequency.Value) $($Policy.SessionControls.SignInFrequency.Type)"
    'Persistent Browser' = $Policy.SessionControls.PersistentBrowser.Mode
    'Continuous Access Evaluation' = $Policy.SessionControls.ContinuousAccessEvaluation.Mode
    'Resilient Defaults' = $policy.SessionControls.DisableResilienceDefaults
    'Secure Sign In Session' = $policy.SessionControls.AdditionalProperties.secureSignInSession.Values
  }
}

#Export Setup
Write-Info 'Pivoting: CA to Export Format'
$pivot = @()
# Header row
$rowItem = [PSCustomObject]@{}
$rowItem | Add-Member -Type NoteProperty -Name 'CA Item' -Value 'row1'
$pcount = 1
foreach ($ca in $CAExport) {
  $rowItem | Add-Member -Type NoteProperty -Name "Policy $pcount" -Value 'row1'
  $pcount += 1
}
$pivot += $rowItem

# Determine properties from the first policy object
$properties = @()
if ($CAExport -and $CAExport.Count -gt 0) {
  $properties = ($CAExport | Select-Object -First 1 | Get-Member -MemberType NoteProperty).Name
}

# Add property rows
foreach ($prop in $properties) {
  $rowItem = [PSCustomObject]@{}
  $rowItem | Add-Member -Type NoteProperty -Name 'CA Item' -Value $prop
  $pcount = 1
  foreach ($ca in $CAExport) {
    $value = $null
    try { $value = $ca.$prop } catch { $value = $null }
    $rowItem | Add-Member -Type NoteProperty -Name "Policy $pcount" -Value $value
    $pcount += 1
  }
  $pivot += $rowItem
}


#Set Row Order
$sort = 'Name', 'Status', 'Created', 'Modified', 'Included Users', 'Excluded Users', 'Cloud apps or actions', 'Included Applications', 'Excluded Applications', 'User Actions', 'Auth Context', 'Conditions', 'User Risk', 'Sign In Risk', 'Included Platforms ', 'Excluded Platforms ', 'Client Apps', 'Included Locations', 'Excluded Locations', 'Devices', 'Included Devices', 'Excluded Devices', 'Device Filters', 'Access Controls', 'Grant Controls', 'Block', 'Require MFA', 'Authentication Strength MFA', 'Compliant Device', 'Domain Joined Device', 'Compliant Application', 'Approved Application', 'Password Change', 'Terms Of Use', 'Custom Controls', 'GrantOperator', 'Session Controls', 'Application Enforced Restrictions', 'Cloud App Security', 'Sign In Frequency', 'Persistent Browser', 'Continuous Access Evaluation', 'Resilient Defaults', 'Secure Sign In Session'


if ($HTMLExport) {
  Write-Info 'Saving to File: HTML'
  $jquery = '  <script src="https://ajax.googleapis.com/ajax/libs/jquery/3.5.1/jquery.min.js"></script>
    <script>
    $(document).ready(function(){
        $("tr").click(function(){
            if(!$(this).hasClass("selected")){
                $(this).addClass("selected");
            } else {
                $(this).removeClass("selected");
            }
        });

        $("th").click(function(){
            // Get the index of the clicked column
            var colIndex = $(this).index();
            // Select the corresponding col element and add or remove the class
            $("colgroup col").eq(colIndex).toggleClass("colselected");
        });
    });
    </script>'
  $htmlContent = "<html><head><base href='https://docs.microsoft.com/' target='_blank'>
    <meta charset='utf-8'>
        <meta name='viewport' content='width=device-width, initial-scale=1, shrink-to-fit=no'>

                  <link rel='stylesheet' href='https://cdnjs.cloudflare.com/ajax/libs/font-awesome/5.11.2/css/all.min.css' crossorigin='anonymous'>
                  <link rel='stylesheet' href='https://stackpath.bootstrapcdn.com/bootstrap/4.3.1/css/bootstrap.min.css' integrity='sha384-ggOyR0iXCbMQv3Xipma34MD+dH/1fQ784/j6cY/iJTQUOhcWr7x9JvoRxT2MZw1T' crossorigin='anonymous'>
                  <script src='https://code.jquery.com/jquery-3.3.1.slim.min.js' integrity='sha384-q8i/X+965DzO0rT7abK41JStQIAqVgRVzpbzo5smXKp4YfRvH+8abtTE1Pi6jizo' crossorigin='anonymous'></script>
                  <script src='https://cdnjs.cloudflare.com/ajax/libs/popper.js/1.14.7/umd/popper.min.js' integrity='sha384-UO2eT0CpHqdSJQ6hJty5KVphtPhzWj9WO1clHTMGa3JDZwrnQq4sF86dIHNDz0W1' crossorigin='anonymous'></script>
                  <script src='https://stackpath.bootstrapcdn.com/bootstrap/4.3.1/js/bootstrap.min.js' integrity='sha384-JjSmVgyd0p3pXB1rRibZUAYoIIy6OrQ6VrjIEaFf/nJGzIxFDsf4x0xIM+B07jRM' crossorigin='anonymous'></script>
                  <script src='https://cdnjs.cloudflare.com/ajax/libs/font-awesome/5.11.2/js/all.js'></script>
                $jquery<style>
                .title {
                    font-size: 1.5em;
                    font-weight: bold;
                    font-family: Arial, sans-serif;
                    top: 0;
                    right: 0;
                    left: 0;
                }

                table {
                    border-collapse: collapse;
                    margin-bottom: 30px;
                    margin-top: 55px;
                    font-size: 0.9em;
                    font-family: Arial, sans-serif;
                    min-width: 400px;

                }
                  thead tr {
                      background-color: #009879;
                      color: #ffffff;
                      text-align: center;
                 }
                  th, td {
                      min-width: 250px;
                      padding: 12px 15px;
                      border: 1px solid lightgray;
                      vertical-align: top;
                      text-align: center;
                 }

                  td {
                      vertical-align: top;
                 }
                  tbody tr {
                     /* border-bottom: 1px solid #dddddd;*/
                 }
                  tbody tr:nth-of-type(even) {
                      background-color: #f3f3f3;
                 }

                  tbody tr:last-of-type {
                      border-bottom: 2px solid #009879;
                 }
                 tr:hover {
                    background-color: #d8d8d8!important;
                }

              .selected:not(th){
                  background-color:#eaf7ff!important;

                  }
                  th{
                     background-color:white ;
                  }
                  .colselected {

                      width: 10%; border: 5px solid #59c7fb;

                }
                table tr th:first-child,table tr td:first-child {
                      position: sticky;
                      inset-inline-start: 0;
                      background-color: #005494;
                      border: 0px;
                      Color: #fff;
                      font-weight: bolder;
                      text-align: center;
                 }
                 tbody tr:nth-of-type(even) td:first-child  {
                      background-color: #547c9b;
                 }
                  tbody tr:nth-of-type(5),
                  tbody tr:nth-of-type(8),
                  tbody tr:nth-of-type(13),
                  tbody tr:nth-of-type(24),
                  tbody tr:nth-of-type(36) {
                  background-color: #005494!important;
                  }
                 .navbar-custom {
                    background-color: #005494;
                    color: white;
                    padding-bottom: 10px;

                }
                /* Modify brand and text color */

                .navbar-custom .navbar-brand,
                .navbar-custom .navbar-text {
                    color: white;
                    padding-top: 70px;
                    padding-bottom: 10px;
                }
                       /* Tooltip container */
        .tooltip-container {
            position: relative;
            display: inline-block;
        }

        /* Tooltip text */
        .tooltip-text {
            visibility: hidden;
            width: 200px;
            background-color: black;
            color: #fff;
            text-align: center;
            border-radius: 6px;
            padding: 5px 0;
            position: absolute;
            z-index: 1;
            top: 115%; /* Position the tooltip below the text */
            left: 50%;
            margin-left: -100px;
            opacity: 0;
            transition: opacity 0.3s;
        }

        .tooltip-container:hover .tooltip-text {
            visibility: visible;
            opacity: 1;
        }
                </style></head><body> <nav class='navbar  fixed-top navbar-custom p-3 border-bottom'>
                <div class='container-fluid'>
                    <div class='col-sm' style='text-align:left'>
                        <div class='row'><div><i class='fa fa-server' aria-hidden='true'></i></div><div class='ml-3'><strong>CA Export</strong></div></div>
                    </div>
                    <div class='col-sm' style='text-align:center'>
                        <strong>$TenantName</strong>
                    </div>
                    <div class='col-sm' style='text-align:right'>
                    <strong>$Date</strong>
                    </div>
                </div>
            </nav> "


  Write-Info 'Launching: Web Browser'
  $Launch = Join-Path -Path $ExportLocation -ChildPath $FileName
  $table = $pivot | Where-Object { $_.'CA Item' -ne 'row1' } | Sort-Object { $sort.IndexOf($_.'CA Item') } | ConvertTo-Html -Fragment
  $htmlContent = $htmlContent + $table
  Add-Type -AssemblyName System.Web
  [System.Web.HttpUtility]::HtmlDecode($htmlContent) | Out-File $Launch
  Start-Process $Launch
}

if ($CsvExport) {
  Write-Info 'Saving to File: CSV (Pivot)'
  $LaunchCsv = Join-Path -Path $ExportLocation -ChildPath $CsvFileName
  $csvData = $pivot | Where-Object { $_.'CA Item' -ne 'row1' } | Sort-Object { $sort.IndexOf($_.'CA Item') }
  $csvData | Export-Csv -Path $LaunchCsv -NoTypeInformation -Encoding UTF8
  Write-Info "CSV exported to: $LaunchCsv"
}