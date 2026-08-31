<#
.SYNOPSIS
  Create an auto-labeling sensitivity policy via Microsoft Graph (beta) using interactive Connect-MgGraph.

.DESCRIPTION
  Connects with delegated interactive auth (Connect-MgGraph), finds a sensitivity label and a built-in sensitive information type
  and creates an auto-labeling policy that applies the label when the SIT is detected.

.NOTES
  - Requires Microsoft.Graph module (Install-Module Microsoft.Graph).
  - Uses beta endpoint: /beta/informationProtection/policy/labels/autoLabeling
  - Delegated scope required: Policy.ReadWrite.InformationProtection (admin consent may be required)
  - Test in a non-production tenant first.
#>

param(
  [Parameter(Mandatory=$true)]
  [string]$LabelNameFragment,

  [Parameter(Mandatory=$true)]
  [string]$SensitiveTypeNameFragment,

  [Parameter(Mandatory=$true)]
  [string]$PolicyDisplayName,

  [int]$Priority = 1,

  [string[]]$Scopes = @("Policy.ReadWrite.InformationProtection")
)

function Ensure-GraphConnection {
  param([string[]]$ScopesToRequest)

  # Connect to Microsoft Graph interactively; will pop up a sign-in window
  Write-Host "Connecting to Microsoft Graph..."
  Connect-MgGraph -Scopes $ScopesToRequest -ErrorAction Stop
  Write-Host "Connected as:" (Get-MgContext).Account
}

function Invoke-Graph {
  param(
    [Parameter(Mandatory=$true)][string]$Method,
    [Parameter(Mandatory=$true)][string]$Url,
    [object]$Body = $null
  )

  # Prefer Invoke-MgGraphRequest when available (uses the current Graph session)
  if (Get-Command Invoke-MgGraphRequest -ErrorAction SilentlyContinue) {
    if ($Body) {
      return Invoke-MgGraphRequest -Method $Method -Uri $Url -Body ($Body | ConvertTo-Json -Depth 10) -ContentType "application/json"
    } else {
      return Invoke-MgGraphRequest -Method $Method -Uri $Url
    }
  }

  # Else acquire an access token via Get-MsalToken (Microsoft.Graph.Authentication) if available
  if (Get-Command Get-MsalToken -ErrorAction SilentlyContinue) {
    Write-Host "Using Get-MsalToken to acquire access token for Invoke-RestMethod..."
    # Use the same scopes used in Connect-MgGraph; pass them again
    $scopes = if ($Scopes -and $Scopes.Count -gt 0) { $Scopes } else { @("Policy.ReadWrite.InformationProtection") }
    $msal = Get-MsalToken -Scopes $scopes -ErrorAction Stop
    $token = $msal.AccessToken
  } else {
    # Last resort: use the stored token on Get-MgContext if it has an AccessToken property
    $ctx = Get-MgContext
    if ($ctx -and $ctx.AuthContext -and $ctx.AuthContext.Account -and $ctx.AccessToken) {
      $token = $ctx.AccessToken
    } else {
      throw "No Invoke-MgGraphRequest and no supported token acquisition cmdlet (Get-MsalToken). Install/Import Microsoft.Graph.Authentication module or use Invoke-MgGraphRequest."
    }
  }

  $headers = @{
    Authorization = "Bearer $token"
    "Content-Type" = "application/json"
  }

  if ($Body) {
    $json = $Body | ConvertTo-Json -Depth 10
    return Invoke-RestMethod -Method $Method -Uri $Url -Headers $headers -Body $json
  } else {
    return Invoke-RestMethod -Method $Method -Uri $Url -Headers $headers
  }
}

function Find-Label {
  param([string]$Fragment)
  Write-Host "Fetching sensitivity labels (beta)..."
  $resp = Invoke-Graph -Method GET -Url "https://graph.microsoft.com/beta/informationProtection/labels"
  # response has .value
  $labels = $resp.value
  if (-not $labels) { throw "No labels returned. Ensure you have appropriate permissions and labels exist." }

  $match = $labels | Where-Object {
    ($_.displayName -and ($_.displayName -like "*$Fragment*")) -or
    ($_.name -and ($_.name -like "*$Fragment*"))
  } | Select-Object -First 1

  return $match
}

function Find-SensitiveType {
  param([string]$Fragment)
  Write-Host "Fetching built-in sensitive information types (dataClassification/sensitiveTypes)..."
  $resp = Invoke-Graph -Method GET -Url "https://graph.microsoft.com/beta/dataClassification/sensitiveTypes"
  $types = $resp.value
  if (-not $types) { throw "No sensitive types returned. Ensure you have appropriate permissions." }

  $match = $types | Where-Object {
    $_.name -and ($_.name -like "*$Fragment*")
  } | Select-Object -First 1

  return $match
}

function Create-AutoLabelPolicy {
  param($DisplayName, $LabelId, $SensitiveTypeId, $Priority, $ScopesArray)

  $payload = @{
    displayName = $DisplayName
    description = "Auto-label policy: apply label when sensitive info type $SensitiveTypeId is detected"
    isEnabled = $true
    priority = $Priority
    conditions = @{
      matchesAny = @(
        @{
          type = "sensitiveInformation"
          sensitiveTypeIds = @($SensitiveTypeId)
          minCount = 1
        }
      )
    }
    actions = @(
      @{
        type = "applyLabel"
        labelId = $LabelId
      }
    )
    scopes = $ScopesArray
  }

  Write-Host "Posting auto-labeling policy to Graph beta endpoint..."
  $result = Invoke-Graph -Method POST -Url "https://graph.microsoft.com/beta/informationProtection/policy/labels/autoLabeling" -Body $payload
  return $result
}

# --------------------------
# Main flow
# --------------------------
try {
  Ensure-GraphConnection -ScopesToRequest $Scopes

  $label = Find-Label -Fragment $LabelNameFragment
  if (-not $label) {
    Write-Error "No label matched '$LabelNameFragment'. Available labels (sample):"
    $sample = Invoke-Graph -Method GET -Url "https://graph.microsoft.com/beta/informationProtection/labels"
    $sample.value | Select-Object id, displayName | Format-Table -AutoSize
    exit 1
  }
  Write-Host "Using label: $($label.displayName) (id: $($label.id))"

  $sit = Find-SensitiveType -Fragment $SensitiveTypeNameFragment
  if (-not $sit) {
    Write-Error "No sensitive type matched '$SensitiveTypeNameFragment'. Available types (sample):"
    $sample2 = Invoke-Graph -Method GET -Url "https://graph.microsoft.com/beta/dataClassification/sensitiveTypes"
    $sample2.value | Select-Object id, name | Format-Table -AutoSize
    exit 1
  }
  Write-Host "Using sensitive type: $($sit.name) (id: $($sit.id))"

  # Scope mapping - use these values in the Graph payload
  $scopes = @("exchangeLocationAll","sharePointLocationAll","oneDriveLocationAll")

  $policyResult = Create-AutoLabelPolicy -DisplayName $PolicyDisplayName -LabelId $label.id -SensitiveTypeId $sit.id -Priority $Priority -ScopesArray $scopes

  Write-Host "Policy creation result:"
  $policyResult | ConvertTo-Json -Depth 6 | Write-Host

  Write-Host "Completed. Verify the policy in the Microsoft Purview / Compliance Center UI."
} catch {
  Write-Error "ERROR: $_"
  throw
}
