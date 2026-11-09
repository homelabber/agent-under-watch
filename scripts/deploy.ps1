[CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = 'High')]
param(
    [string] $ResourceGroup,
    [string] $WorkspaceName,
    [ValidateSet('Workbook', 'Watchlists', 'Rules', 'OptionalTelemetry', 'OptionalRules')]
    [string] $Component = 'Workbook',
    [string[]] $RuleKey = @(),
    [string] $WatchlistDirectory,
    [switch] $EnableRules,
    [switch] $AcknowledgeTenantValidation,
    [switch] $ValidateOnly
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$root = Split-Path $PSScriptRoot -Parent
if (-not $WatchlistDirectory) { $WatchlistDirectory = Join-Path $root 'watchlists' }
$catalog = @(Get-Content -LiteralPath (Join-Path $root 'catalog\rules.json') -Raw | ConvertFrom-Json)
$contracts = [ordered]@{
    AIAgentInventory = @('SearchKey', 'AgentId', 'AgentName', 'ServicePrincipalObjectId', 'AppId', 'OwnerUPN', 'Criticality', 'Enabled')
    AIAgentApprovedMakers = @('SearchKey', 'ActorUPN', 'EnvironmentId', 'Enabled')
    AIAgentRuntimeInventory = @('SearchKey', 'RuntimeKey', 'AgentId', 'DeviceId', 'ProcessFileName', 'ProcessFolderPath', 'Enabled')
    AIAgentAllowedDestinations = @('SearchKey', 'AgentId', 'DestinationHost', 'Enabled')
}

function Assert-Watchlists {
    $active = @{}
    foreach ($alias in $contracts.Keys) {
        $file = Join-Path $WatchlistDirectory "$alias.csv"
        if (-not (Test-Path -LiteralPath $file -PathType Leaf)) { throw "Missing watchlist: $file" }
        $rows = @(Import-Csv -LiteralPath $file)
        if ($rows.Count -eq 0) { throw "$alias must contain at least the disabled seed row." }
        $columns = @($rows[0].PSObject.Properties.Name)
        foreach ($column in $contracts[$alias]) {
            if ($column -notin $columns) { throw "Missing column $column in $alias" }
        }
        foreach ($row in $rows) {
            if ($row.Enabled -notin @('true', 'false')) { throw "$alias.Enabled must be true or false." }
        }
        $active[$alias] = @($rows | Where-Object { $_.Enabled -eq 'true' })
        foreach ($row in $active[$alias]) {
            foreach ($property in $row.PSObject.Properties) {
                if ($property.Value -is [string] -and $property.Value -cne $property.Value.Trim()) { throw "$alias.$($property.Name) has surrounding whitespace." }
            }
            if ([string]::IsNullOrWhiteSpace($row.SearchKey)) { throw "$alias has an empty SearchKey." }
            switch ($alias) {
                'AIAgentInventory' {
                    if (-not $row.AgentId -or $row.SearchKey -ine $row.AgentId) { throw 'Inventory SearchKey must equal AgentId.' }
                    foreach ($field in @('ServicePrincipalObjectId', 'AppId')) {
                        if ($row.$field -and $row.$field -notmatch '^[0-9a-fA-F]{8}(-[0-9a-fA-F]{4}){3}-[0-9a-fA-F]{12}$') { throw "Invalid inventory $field GUID." }
                    }
                }
                'AIAgentApprovedMakers' {
                    if (-not $row.ActorUPN -or $row.SearchKey -ine $row.ActorUPN -or -not $row.EnvironmentId) { throw 'Maker SearchKey must equal ActorUPN and EnvironmentId is required.' }
                }
                'AIAgentRuntimeInventory' {
                    if (-not $row.RuntimeKey -or $row.SearchKey -ine $row.RuntimeKey -or -not $row.AgentId -or -not $row.DeviceId -or -not $row.ProcessFileName -or -not $row.ProcessFolderPath) { throw 'Runtime mapping requires key, agent, device, process name and full process folder path.' }
                    if ($row.ProcessFileName -match '[\\/*?]' -or $row.ProcessFolderPath -match '[*?]') { throw 'Runtime process mappings must be exact, without wildcards.' }
                }
                'AIAgentAllowedDestinations' {
                    if (-not $row.AgentId -or $row.SearchKey -ine $row.AgentId -or $row.DestinationHost -notmatch '^[a-zA-Z0-9](?:[a-zA-Z0-9.\-]*[a-zA-Z0-9])?$') { throw 'Destination rows require AgentId and an exact hostname without scheme, path, port or wildcard.' }
                }
            }
        }
    }
    $duplicates = @($active.AIAgentInventory | Group-Object { $_.AgentId.ToLowerInvariant() } | Where-Object Count -gt 1)
    if ($duplicates.Count) { throw 'Duplicate enabled AgentId inventory mappings.' }
    foreach ($field in @('ServicePrincipalObjectId', 'AppId')) {
        $duplicates = @($active.AIAgentInventory | Where-Object { $_.$field } | Group-Object { $_.$field.ToLowerInvariant() } | Where-Object Count -gt 1)
        if ($duplicates.Count) { throw "Ambiguous enabled $field mappings; v1 requires one agent per identity." }
    }
    foreach ($runtime in $active.AIAgentRuntimeInventory) {
        if ($runtime.AgentId -notin @($active.AIAgentInventory.AgentId)) { throw 'Runtime AgentId is not enabled in inventory.' }
    }
    foreach ($destination in $active.AIAgentAllowedDestinations) {
        if ($destination.AgentId -notin @($active.AIAgentInventory.AgentId)) { throw 'Destination AgentId is not enabled in inventory.' }
    }
    $runtimeDuplicates = @($active.AIAgentRuntimeInventory | Group-Object { "$($_.DeviceId)|$($_.ProcessFolderPath.ToLowerInvariant())|$($_.ProcessFileName.ToLowerInvariant())" } | Where-Object Count -gt 1)
    if ($runtimeDuplicates.Count) { throw 'Ambiguous enabled runtime process mappings.' }
    return $active
}

$watchlists = Assert-Watchlists
Get-ChildItem -LiteralPath (Join-Path $root 'arm') -Filter '*.json' -Recurse | ForEach-Object {
    $null = Get-Content -LiteralPath $_.FullName -Raw | ConvertFrom-Json
}
foreach ($rule in $catalog) {
    $path = Join-Path $root "arm\rules\$($rule.key).json"
    if (-not (Test-Path -LiteralPath $path -PathType Leaf)) { throw "Missing built rule: $($rule.key). Run python -B tools\build_content.py." }
}
if ($RuleKey.Count) {
    $unknown = @($RuleKey | Where-Object { $_ -notin @($catalog.key) })
    if ($unknown.Count) { throw "Unknown rule keys: $($unknown -join ', ')" }
}
if ($EnableRules -and $Component -notin @('Rules', 'OptionalRules')) { throw 'EnableRules only applies to rule components.' }
if ($EnableRules -and -not $AcknowledgeTenantValidation) { throw 'Enabling rules requires AcknowledgeTenantValidation after tenant query and false-positive review.' }
if ($ValidateOnly) {
    Write-Output "Offline validation passed: $($catalog.Count) rules, ARM JSON, and four watchlist contracts. No Azure connection or KQL execution performed."
    return
}
if ($WhatIfPreference) {
    $null = $PSCmdlet.ShouldProcess("$ResourceGroup / $WorkspaceName", "Deploy $Component; rules enabled=$($EnableRules.IsPresent)")
    return
}
if (-not $ResourceGroup -or -not $WorkspaceName) { throw 'ResourceGroup and WorkspaceName are required for deployment.' }
if (-not (Get-Command az -ErrorAction SilentlyContinue)) { throw 'Azure CLI is required. No tools are installed automatically.' }

function Invoke-Azure([string[]] $Arguments) {
    $output = & az @Arguments --only-show-errors
    if ($LASTEXITCODE -ne 0) { throw "Azure CLI failed: $($Arguments[0..([Math]::Min(2, $Arguments.Count - 1))] -join ' ')" }
    return $output
}

$workspace = (Invoke-Azure @('monitor', 'log-analytics', 'workspace', 'show', '--resource-group', $ResourceGroup, '--workspace-name', $WorkspaceName, '--output', 'json')) | ConvertFrom-Json
$selected = @($catalog | Where-Object { ($Component -eq 'Rules' -and -not $_.optional) -or ($Component -eq 'OptionalRules' -and $_.optional) })
if ($RuleKey.Count) { $selected = @($selected | Where-Object { $_.key -in $RuleKey }) }
if ($Component -in @('Rules', 'OptionalRules')) {
    if (-not $selected.Count) { throw 'No rules match the selected component and keys.' }
    $knownAgentRules = @($selected | Where-Object { $_.key -ne 'rapid-unapproved-publish' })
    if ($knownAgentRules.Count -and -not $watchlists.AIAgentInventory.Count) { throw 'Configure at least one enabled real agent before deploying inventory-scoped rules. The rapid-unapproved-publish rule also supports unregistered agents.' }
    foreach ($table in @($selected.requiredTables | Sort-Object -Unique)) {
        if ($table -notmatch '^[A-Za-z][A-Za-z0-9_]*$') { throw "Invalid table identifier $table" }
        $null = Invoke-Azure @('monitor', 'log-analytics', 'query', '--workspace', $workspace.customerId, '--analytics-query', "$table | take 0", '--output', 'json')
    }
    foreach ($alias in @($selected.requiredWatchlists | Sort-Object -Unique)) {
        $null = Invoke-Azure @('monitor', 'log-analytics', 'query', '--workspace', $workspace.customerId, '--analytics-query', "_GetWatchlist('$alias') | take 0", '--output', 'json')
    }
    foreach ($rule in $selected) {
        $query = Get-Content -LiteralPath (Join-Path $root $rule.queryFile) -Raw
        $validationQuery = $query.TrimEnd().TrimEnd(';') + "`n| take 0"
        $null = Invoke-Azure @('monitor', 'log-analytics', 'query', '--workspace', $workspace.customerId, '--analytics-query', $validationQuery, '--output', 'json')
    }
}

function Deploy-Template([string] $Name, [string] $TemplatePath, [string[]] $TemplateParameters) {
    if ($PSCmdlet.ShouldProcess("$ResourceGroup / $WorkspaceName", "Deploy $Name")) {
        $arguments = @('deployment', 'group', 'create', '--resource-group', $ResourceGroup, '--name', "ai-agent-$Name", '--template-file', (Join-Path $root $TemplatePath), '--parameters') + $TemplateParameters + @('--output', 'none')
        $null = Invoke-Azure $arguments
        Write-Output "Deployed $Name."
    }
}

switch ($Component) {
    'Workbook' { Deploy-Template 'workbook' 'arm\workbook.json' @("workspaceName=$WorkspaceName", "location=$($workspace.location)") }
    'Watchlists' {
        foreach ($alias in $contracts.Keys) {
            $csv = Get-Content -LiteralPath (Join-Path $WatchlistDirectory "$alias.csv") -Raw
            Deploy-Template $alias 'arm\watchlist.json' @("workspaceName=$WorkspaceName", "alias=$alias", "rawContent=$csv")
        }
    }
    'OptionalTelemetry' { Deploy-Template 'optional-telemetry' 'arm\optional-telemetry.json' @("workspaceName=$WorkspaceName", "location=$($workspace.location)") }
    default {
        foreach ($rule in $selected) {
            Deploy-Template $rule.key "arm\rules\$($rule.key).json" @("workspaceName=$WorkspaceName", "enableRule=$($EnableRules.IsPresent.ToString().ToLowerInvariant())")
        }
    }
}
