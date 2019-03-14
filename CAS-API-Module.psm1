###########################################
###########1998-2019 VMware, INC###########
###########Nikolay Nikolov      ###########
###########Free to use and modify##########
###########################################


#####Initialization############
######             ############

######Script Parameters#######
<#
Param(
    [Parameter(Mandatory=$true)][ValidateNotNullOrEmpty()][string]$ConfigOperation
)

add-type @"
     using System.Net;
     using System.Security.Cryptography.X509Certificates;

     public class IgnoreSSLPolicy : ICertificatePolicy {
         public IgnoreSSLPolicy() {}
         public bool CheckValidationResult(
             ServicePoint sPoint, X509Certificate cert,
             WebRequest wRequest, int certProb) {
             return true;
         }
     }
"@
[System.Net.ServicePointManager]::CertificatePolicy = new-object IgnoreSSLPolicy
#>

Set-StrictMode -Version Latest

######Initial vRA Parameters
$CASURI = "https://api.mgmt.cloud.vmware.com"
$accept = "application/json"
$contentType = "application/json"

$reqHeaders = @{}
$reqHeaders.add("Accept", $accept)
$reqHeaders.add("Content-Type", $contentType)

###########  Functions ###########
###########            ###########

function New-CASAPIClient
{
    [cmdletbinding()]
    param (
        [Parameter(Mandatory=$true)][ValidateNotNullOrEmpty()][string]$refreshToken="",
        [ValidateNotNullOrEmpty()][string]$organization="DEFAULT"
    )
    $body = @{}
    $body.add("refreshToken", $refreshToken)
    $token = ""
    $orgExists = $false

    $tempUri = $CASURI +  "/iaas/login"
    try 
    {
        $token = Invoke-RestMethod -Uri $tempUri -Headers $reqHeaders -Body (ConvertTo-Json $body) -Method Post 
    }
    catch [Exception]
    {
        Write-Host "There was an error while attempting to log in with the specified refreshToken."
        return $_.Exception.Message
    }

    if ($env:PSCASAPITOKEN)
    {
        $tokenValues = $env:PSCASAPITOKEN.split(";")
        foreach($tokenValue in $tokenValues)
        {
            $orgValue = $tokenValue.split("\")[0]
            $tokenToReplace = $tokenValue.split("\")[1]
            if ($orgValue -eq $organization)
            {
                Write-Host "An authentication token for the same organization already exists. Do you want to replace it?"
                while ($true)
                {
                    $replace = Read-Host -Prompt ("Y/N")
                    if ($replace -eq "Y")
                    {
                        try 
                        {
                            $env:PSCASAPITOKEN = $env:PSCASAPITOKEN.Replace($tokenToReplace, $token.token)
                            Write-Host "Successfully added the token to the token list."
                            $orgExists = $true
                            break
                        }
                        catch [EXCEPTION]
                        {
                            Write-Host "Cannot update the environment variable PSCASAPITOKEN."
                            return $_.Exception.Message 
                        }
                        
                    }
                    if($replace -eq "N")
                    {
                        Write-Host "Not updating the token for organization $organization."
                        break
                    }
                }
            }
        }
        if($orgExists -eq $false)
        {
            try
            {
                $env:PSCASAPITOKEN = $env:PSCASAPITOKEN + ";" + "$organization\" + $token.token
                Write-Host "Successfully added the token to the token list."    
            }
            catch [EXCEPTION]
            {
                Write-Host "Cannot update the environment variable PSCASAPITOKEN."
                return $_.Exception.Message 
            }
            
        }
    }else
    {
        try
        {
            $env:PSCASAPITOKEN = "$organization\" + $token.token
            Write-Host "Successfully added the token to the token list."    
        }
        catch [EXCEPTION]
        {
            Write-Host "Cannot update the environment variable PSCASAPITOKEN."
            return $_.Exception.Message 
        }
    }   
    Write-Host "Do you want to make this organization the active one?"
    while ($true)
    {
        $isActive = Read-Host -Prompt ("Y/N")
        if ($isActive -eq "Y")
        {
            Set-CASAPIActiveOrganization -organization $organization
            break
        }
        if($isActive -eq "N")
        {
            Write-Host "Staying with the currently active organization. If you want to change it later, use Set-CASAPIActiveOrganization."
            break
        }
    }
}
function Set-CASAPIActiveOrganization
{
    param (
        [Parameter(Mandatory=$true)][ValidateNotNullOrEmpty()][string]$organization
    )

    $orgExists = $false

    if (!$env:PSCASAPITOKEN)
    {
        Write-Host "Please, create a token first by using New-CASAPIClient."
        return 1
    }
    if ($env:PSCASAPITOKEN)
    {
        $tokens = $env:PSCASAPITOKEN.split(";")
        foreach($token in $tokens)
        {
            $orgValue = $token.split("\")[0]
            if ($orgValue -eq $organization)
            {
                try 
                {
                    $env:PSCASAPIACTIVEORG = $organization
                    $orgExists = $true
                    Write-Host "Successfully set the organization named $organization as an active one."
                    return 0
                }
                catch [EXCEPTION]{
                    Write-Host "Cannot update the environment variable PSCASAPIACTIVEORG."
                    return $_.Exception.Message 
                }
            }
        }
    } 
    if($orgExists -eq $false)
    {
        Write-Host "No organization named $organization found."
        return 0
    }
}
function Invoke-CASAPI
{
    param(
        [string]$organization,
        [Parameter(Mandatory=$true)][ValidateNotNullOrEmpty()][uri]$apiURI="",
        [hashtable]$reqBody=@{},
        [Parameter(Mandatory=$true)][ValidateNotNullOrEmpty()][hashtable]$reqHeaders=@{},
        [string]$method="GET"
    )

    $tokenList = @()
    $token = ""

    if(!$apiURI.IsAbsoluteUri)
    {
        Write-Host "Please, specify a valid API URI."
        return 1
    }

    if ($reqHeaders.ContainsKey('Authorization'))
    {
        $reqHeaders.Remove('Authorization')
    }

    if ($organization -eq $env:PSCASAPIACTIVEORG -or $organization -eq "")
    {
        if($organization -eq "") {$organization = $env:PSCASAPIACTIVEORG} #set the $organization variable to the currently active one in case it's empty
        
        $envPSCASAPITOKEN = $env:PSCASAPITOKEN
        if ($envPSCASAPITOKEN)
        {
            $tokenList = $envPSCASAPITOKEN.split(";")
        }
        foreach($tokenValue in $tokenList)
        {
            if($organization -eq $tokenValue.split("\")[0])
            {
                $token = $tokenValue.Substring($tokenValue.IndexOf('\')+1, $tokenValue.Length - $tokenValue.IndexOf('\') -1)
            }
        }
        if($token.Length -eq 0)
        {
            Write-Host "No organization with this name found" -ForegroundColor Red
            return 1 
        }
    } else
    {
        Write-Host "The chosen organization ($organization) is not the active one. Do you want to use it?"
        while ($true)
        {
            $useCurrent = Read-Host -Prompt ("Y/N")
            if ($useCurrent -eq "Y")
            {
                break
            }
            if($useCurrent -eq "N")
            {
                Write-Host "Please, use the Set-CASAPIActiveOrganization cmdlet to set an active organization. Aborting..."
                return 1
            }
        }
    }
    $reqHeaders.Add('Authorization', "Bearer $token")
  
    $result=$null

    if($method -eq "GET")
    {
        $result = try {Invoke-RestMethod -Uri $apiURI.OriginalString -Headers $reqHeaders -Method $method } catch {$_.Exception.Response}
    }else
    {
        $result = try {Invoke-RestMethod -Uri $apiURI.OriginalString -Headers $reqHeaders -Body (ConvertTo-JSON $reqBody) -Method $method -TimeoutSec 0 } catch {$_.Exception.Response}
    }
    $statusCode = ""
    if($result -ne $null)
    {
        if ($result.PSobject.Properties.name -match "StatusCode"){$statusCode = $result.StatusCode}
    }
    if ($statusCode -eq "Unauthorized")
    {
        Write-Host "ERROR: Current token is invalid. Please, regenerate the token for the current organization ($organization)." -ForegroundColor Red
        return 1
    }
    return $result
}

function Get-CASDeployments
{
    param(
        [string][ValidateNotNullOrEmpty()][Parameter(ParameterSetName="Id")]$DeploymentIds,
        [string][ValidateNotNullOrEmpty()][Parameter(ParameterSetName="Name")]$Name,
        [string][ValidateNotNullOrEmpty()][Parameter(ParameterSetName="Project")]$Projects,
        [string][ValidateNotNullOrEmpty()][Parameter(ParameterSetName="Search")]$Search,
        [string][ValidateNotNullOrEmpty()][Parameter(ParameterSetName="Templates")]$Templates,
        [string]$ExpandLastRequest = "false",
        [string]$ExpandMetadata = "false",
        [string]$ExpandProject = "false",
        [string]$ExpandResources = "false",
        [string]$Sort,
        [string][ValidateNotNullOrEmpty()][Parameter(ParameterSetName="GetAll")]$GetAll = "true"
    )
    $urlParams = "ExpandLastRequest=$expandLastRequest&ExpandMetadata=$expandMetadata&ExpandProject=$expandProject&ExpandResources=$expandResources"
    if($sort)
    {
        $urlParams = $urlParams + "&sort=$Sort"
    }
    
        switch ($PsCmdlet.ParameterSetName)
        {
            "Id" {$urlParams = $urlParams + "&ids=$DeploymentIds"}
            "Name" {$urlParams = $urlParams + "&name=$Name"}
            "Project" {$urlParams = $urlParams + "&projects=$Projects"}
            "Search" {$urlParams = $urlParams + "&search=$Search"}
            "Templates" {$urlParams = $urlParams + "&templates=$Templates"}
            "GetAll" {$urlParams = $urlparams}
        }
        $result = Invoke-CASAPI -apiUri "$CASURI/deployment/api/deployments?$urlParams" -reqHeaders $reqHeaders

    return $result
}

function Get-CASDeployment
{
    param(
        [Parameter(Mandatory=$true)][ValidateNotNullOrEmpty()][string]$DeploymentId,
        [string]$ExpandLastRequest = "false",
        [string]$ExpandMetadata = "false",
        [string]$ExpandProject = "false",
        [string]$ExpandResources = "false"
    )
    $urlParams = "expandLastRequest=$ExpandLastRequest&expandMetadata=$ExpandMetadata&expandProject=$ExpandProject&expandResources=$ExpandResources"
    $result = Invoke-CASAPI -apiUri "$CASURI/deployment/api/deployments/$DeploymentId`?$urlParams" -reqHeaders $reqHeaders # added a ` to escape the question mark (?)

    return $result
}

function Get-CASDeploymentAction
{
    param(
        [string][Parameter(Mandatory=$true)][ValidateNotNullOrEmpty()]$DeploymentId,
        [string][ValidateNotNullOrEmpty()]$ActionId
    )

    $result = Invoke-CASAPI -apiUri "$CASURI/deployment/api/deployments/$DeploymentId/actions/$ActionId" -reqHeaders $reqHeaders

    return $result
}

function Get-CASDeploymentResources
{
    param(

        [string][Parameter(Mandatory=$true)][ValidateNotNullOrEmpty()]$DeploymentId,
        [string]$ExpandMetadata = "false",
        [string]$Sort
    )
    $urlParams = "expandMetadata=$expandMetadata"
    if($Sort)
    {
        $urlParams = $urlParams + "&sort=$sort"
    }
    $result = Invoke-CASAPI -apiUri "$CASURI/deployment/api/deployments/$DeploymentId/resources?$urlParams" -reqHeaders $reqHeaders

    return $result
}

function Get-CASDeploymentResource
{
    param(
        [string][Parameter(Mandatory=$true)][ValidateNotNullOrEmpty()]$DeploymentId,
        [string][Parameter(Mandatory=$true)][ValidateNotNullOrEmpty()]$ResourceId,
        [string]$ExpandMetadata = "false"
    )
    $urlParams = "expandMetadata=$expandMetadata"
    $result = Invoke-CASAPI -apiUri "$CASURI/deployment/api/deployments/$DeploymentId/resources/$ResourceId`?$urlParams" -reqHeaders $reqHeaders

    return $result
}

function Get-CASResourceActions
{
    param(
        [string][Parameter(Mandatory=$true)][ValidateNotNullOrEmpty()]$DeploymentId,
        [string][Parameter(Mandatory=$true)][ValidateNotNullOrEmpty()]$ResourceId
    )
    $result = Invoke-CASAPI -apiUri "$CASURI/deployment/api/deployments/$DeploymentId/resources/$ResourceId/actions" -reqHeaders $reqHeaders

    return $result
}

function Get-CASResourceAction
{
    param(
        [string][Parameter(Mandatory=$true)][ValidateNotNullOrEmpty()]$DeploymentId,
        [string][Parameter(Mandatory=$true)][ValidateNotNullOrEmpty()]$ResourceId,
        [string][Parameter(Mandatory=$true)][ValidateNotNullOrEmpty()]$ActionId
    )
    $result = Invoke-CASAPI -apiUri "$CASURI/deployment/api/deployments/$DeploymentId/resources/$ResourceId/actions/$ActionId" -reqHeaders $reqHeaders

    return $result
}

function Test-CASDeploymentExists
{
    param(
        [string][Parameter(Mandatory=$true)][ValidateNotNullOrEmpty()]$DeploymentName
    )
    $result = Invoke-CASAPI -apiUri "$CASURI/deployment/api/deployments/names/$DeploymentName" -reqHeaders $reqHeaders
    if($result -eq "")
    {
        return $true
    } else 
    {
        return $false
    }
}

function Send-CASDeploymentAction
{
    param(
        [string][Parameter(Mandatory=$true)][ValidateNotNullOrEmpty()]$RequestId,
        [string][Parameter(Mandatory=$true)][ValidateNotNullOrEmpty()][ValidateSet("cancel", "pause", "resume")]$Action
    )
    $result = Invoke-CASAPI -apiUri "$CASURI/deployment/api/requests/$RequestId`?action=$Action" -reqHeaders $reqHeaders -reqBody @{} -method "POST"

    return $result
}

function Remove-CASDeployment
{
    param(
        [string][Parameter(Mandatory=$true)][ValidateNotNullOrEmpty()]$DeploymentId
    )
    $result = Invoke-CASAPI -apiUri "$CASURI/deployment/api/deployments/$DeploymentId" -reqHeaders $reqHeaders -reqBody @{} -method "DELETE"

    return $result
}


function Update-CASDeployment
{
    param(
        [string][Parameter(Mandatory=$true)][ValidateNotNullOrEmpty()]$DeploymentId,
        [string][Parameter(Mandatory=$true)][ValidateNotNullOrEmpty()]$BlueprintId,
        [string]$Description,
        [hashtable][Parameter(Mandatory=$true)][ValidateNotNullOrEmpty()]$Inputs,
        [string][Parameter(Mandatory=$true)][ValidateNotNullOrEmpty()]$Name
    )
    $reqBody = @{}
    $reqBody.Add("blueprintId", $BlueprintId)
    $reqBody.Add("description", $Description)
    $reqBody.Add("inputs", $Inputs)
    $reqBody.Add("name", $Name)
    
    $result = Invoke-CASAPI -apiUri "$CASURI/deployment/api/deployments/$DeploymentId" -reqHeaders $reqHeaders -reqBody $reqBody -method "PATCH"
    
    return $result
}

function New-CASDeploymentResourceAction
{
    param(
        [string][Parameter(Mandatory=$true)][ValidateNotNullOrEmpty()]$DeploymentId,
        [string][Parameter(Mandatory=$true)][ValidateNotNullOrEmpty()]$ActionId,
        [string]$Reason,
        [hashtable]$Inputs = @{}
    )
    $reqBody = @{}
    $reqBody.Add("actionId", $ActionId)
    $reqBody.Add("inputs", $Inputs)
    $reqBody.Add("reason", $Reason)
    
    $result = Invoke-CASAPI -apiUri "$CASURI/deployment/api/deployments/$DeploymentId/requests" -reqHeaders $reqHeaders -reqBody $reqBody -method "POST"
    
    return $result
}

function Remove-CASDeploymentResource
{
    param(
        [string][Parameter(Mandatory=$true)][ValidateNotNullOrEmpty()]$DeploymentId,
        [string][Parameter(Mandatory=$true)][ValidateNotNullOrEmpty()]$ResourceId
    )

    $result = Invoke-CASAPI -apiUri "$CASURI/deployment/api/deployments/$DeploymentId/resources/$ResourceId" -reqHeaders $reqHeaders -reqBody @{} -method "DELETE"
    
    return $result
}

function New-CASResourceAction
{
    param(
        [string][Parameter(Mandatory=$true)][ValidateNotNullOrEmpty()]$DeploymentId,
        [string][Parameter(Mandatory=$true)][ValidateNotNullOrEmpty()]$ResourceId,
        [string][Parameter(Mandatory=$true)][ValidateNotNullOrEmpty()]$ActionId,
        [string]$Reason,
        [hashtable][Parameter(Mandatory=$true)][ValidateNotNullOrEmpty()]$Inputs
    )
    $reqBody = @{}
    $reqBody.Add("actionId", $ActionId)
    $reqBody.Add("inputs", $Inputs)
    $reqBody.Add("reason", $Reason)
    
    $result = Invoke-CASAPI -apiUri "$CASURI/deployment/api/deployments/$DeploymentId/resources/$ResourceId/requests" -reqHeaders $reqHeaders -reqBody $reqBody -method "POST"
    
    return $result
}

#Blueprint Service
function Get-CASBlueprints
{
    param(
        [string]$Expand="true",
        [string]$Released="false",
        [string]$orderBy="updatedAt DESC",
        [string]$Versioned="false",
        [string]$Fields,
        [string]$Name,
        [string]$Projects,
        [string]$Search,
        [string]$Tags
    )
    $urlParams = "expand=$Expand&orderBy=`'$orderBy`'&released=$Released&versioned=$Versioned"
    if($Fields) { $urlParams = $urlParams + "&fields=$Fields" }
    if($Name) {$urlParams = $urlParams + "&name=$Name"}
    if($Projects){$urlParams = $urlParams + "&projects=$Projects"}
    if($Search){$urlParams = $urlParams + "&search=$Search"}
    if($Tags){$urlParams = $Tags + "&tags=$Tags"}
 
    $result = Invoke-CASAPI -apiUri "$CASURI/blueprint/api/blueprints?$urlParams" -reqHeaders $reqHeaders

    return $result
}

function Get-CASBlueprint
{
    param(
        [string][Parameter(Mandatory=$true)][ValidateNotNullOrEmpty()]$BlueprintId
    )

    $result = Invoke-CASAPI -apiUri "$CASURI/blueprint/api/blueprints/$BlueprintId" -reqHeaders $reqHeaders

    return $result
}

function Get-CASBlueprintSchema
{
    param(
        [string][Parameter(Mandatory=$true)][ValidateNotNullOrEmpty()]$BlueprintId
    )    
 
    $result = Invoke-CASAPI -apiUri "$CASURI/blueprint/api/blueprints/$BlueprintId/inputs-schema" -reqHeaders $reqHeaders

    return $result
}

function Get-CASBlueprintVersions
{
    param(
        [string][Parameter(Mandatory=$true)][ValidateNotNullOrEmpty()]$BlueprintId,
        [string]$Expand="true",
        [string]$Fields,
        [string]$orderBy = "updatedAt DESC",
        [string][ValidateSet("VERSIONED", "RELEASED")]$Status
    )    
 
    $urlParams = "expand=$Expand&OrderBy=`'$orderBy`'"
    if($Fields) { $urlParams = $urlParams + "&fields=$Fields" }
    if($Status) { $urlParams = $urlParams + "&status=$Status" }

    $result = Invoke-CASAPI -apiUri "$CASURI/blueprint/api/blueprints/$BlueprintId/versions?$urlParams" -reqHeaders $reqHeaders

    return $result
}

function Get-CASBlueprintVersion
{
    param(
        [string][Parameter(Mandatory=$true)][ValidateNotNullOrEmpty()]$BlueprintId,
        [string][Parameter(Mandatory=$true)][ValidateNotNullOrEmpty()]$Version
    )    
 
    $result = Invoke-CASAPI -apiUri "$CASURI/blueprint/api/blueprints/$BlueprintId/versions/$Version" -reqHeaders $reqHeaders

    return $result
}

function Get-CASBlueprintEvents
{
    param(
        [string][Parameter(Mandatory=$true)][ValidateNotNullOrEmpty()]$DeploymentId,
        [string]$orderBy = "createdAt DESC",
        [string]$RequestId
    )    
 
    $urlParams = "orderBy=`'$orderBy`'"
    if($RequestId) { $urlParams = $urlParams + "&requestId=$RequestId" }

    $result = Invoke-CASAPI -apiUri "$CASURI/blueprint/api/blueprint-deployments/$DeploymentID/events?$urlParams" -reqHeaders $reqHeaders

    return $result
}

function Get-CASBlueprintRequests
{
    param(
        [string]$DeploymentId,
        [string]$Expand="true",
        [string]$IncludePlan="false",
        [string]$Fields,
        [string]$orderBy = "updatedAt DESC"
    )    
 
    $urlParams = "deploymentId=$DeploymentId&orderBy=`'$orderBy`'&expand=$Expand&IncludePlan=$IncludePlan"
    if($Fields) { $urlParams = $urlParams + "&fields=$Fields" }
    if($DeploymentId) { $urlParams = $urlParams + "&deploymentID=$DeploymentId" }
    $result = Invoke-CASAPI -apiUri "$CASURI/blueprint/api/blueprint-requests?$urlParams" -reqHeaders $reqHeaders

    return $result
}

function Get-CASBlueprintRequest
{
    param(
        [string][Parameter(Mandatory=$true)][ValidateNotNullOrEmpty()]$RequestId
    )    
 
    $result = Invoke-CASAPI -apiUri "$CASURI/blueprint/api/blueprint-requests/$RequestId" -reqHeaders $reqHeaders

    return $result
}

function Get-CASBlueprintRequestPlan
{
    param(
        [string][Parameter(Mandatory=$true)][ValidateNotNullOrEmpty()]$RequestId,
        [string]$Expand="false"
    )    
    $urlParams = "expand=$Expand"
    $result = Invoke-CASAPI -apiUri "$CASURI/blueprint/api/blueprint-requests/$RequestId/plan?$urlParams" -reqHeaders $reqHeaders

    return $result
}

function Get-CASBlueprintRequestResourcePlan
{
    param(
        [string][Parameter(Mandatory=$true)][ValidateNotNullOrEmpty()]$RequestId,
        [string]$Expand="false"
    )    
    $urlParams = "expand=$Expand"
    $result = Invoke-CASAPI -apiUri "$CASURI/blueprint/api/blueprint-requests/$RequestId/resources-plan?$urlParams" -reqHeaders $reqHeaders

    return $result
}

function Get-CASBlueprintProviderResources
{
    param(
        [string]$Expand="false",
        [string]$Name,
        [string]$OrderBy="name ASC",
        [string]$ProviderId,
        [string]$Search
        
    )    
    $urlParams = "expand=$Expand&orderBy=`'$OrderBy`'"
    if($Name) { $urlParams = $urlParams + "&name=$Name" }
    if($ProviderId) { $urlParams = $urlParams + "&providerId=$ProviderId" }
    if($Search) { $urlParams = $urlParams + "&search=$Search" }
    
    $result = Invoke-CASAPI -apiUri "$CASURI/blueprint/api/provider-resources?$urlParams" -reqHeaders $reqHeaders

    return $result
}

function Get-CASBlueprintProviderResource
{
    param(
        [string][Parameter(Mandatory=$true)][ValidateNotNullOrEmpty()]$ResourceTypeId
    )    
  
    $result = Invoke-CASAPI -apiUri "$CASURI/blueprint/api/provider-resources/$ResourceTypeId" -reqHeaders $reqHeaders

    return $result
}

function  New-CASBlueprint
{
    param(
        [string][Parameter(Mandatory=$true)][ValidateNotNullOrEmpty()]$Name,
        [string]$Description,
        [string][Parameter(Mandatory=$true)][ValidateNotNullOrEmpty()]$ProjectId,
        [string][Parameter(Mandatory=$true)][ValidateNotNullOrEmpty()]$Content,
        [string]$Tags
    )
    $blueprintBody = @{}
    $blueprintBody.Add("name", $Name)
    $blueprintBody.Add("description", $Description)
    $blueprintBody.Add("projectId", "$ProjectId")
    $blueprintBody.Add("content", $Content)
    $tagsArray = $Tags.split(",")
    $blueprintBody.Add("tags", $tagsArray)

    $result = Invoke-CASAPI -apiUri "$CASURI/blueprint/api/blueprints" -reqHeaders $reqHeaders -reqBody $blueprintBody -method "POST"
    
    return $result
}

function Update-CASBlueprint
{
    param(
        [string][Parameter(Mandatory=$true)][ValidateNotNullOrEmpty()]$BlueprintId,
        [string][Parameter(Mandatory=$true)][ValidateNotNullOrEmpty()]$Name,
        [string]$Description,
        [string][Parameter(Mandatory=$true)][ValidateNotNullOrEmpty()]$ProjectId,
        [string][Parameter(Mandatory=$true)][ValidateNotNullOrEmpty()]$Content,
        [string]$Tags
    )
    $blueprintBody = @{}
    $blueprintBody.Add("name", $Name)
    $blueprintBody.Add("description", $Description)
    $blueprintBody.Add("projectId", "$ProjectId")
    $blueprintBody.Add("content", $Content)

    $tagsArray = $Tags.split(",")
    $blueprintBody.Add("tags", $tagsArray)

    $result = Invoke-CASAPI -apiUri "$CASURI/blueprint/api/blueprints/$BlueprintId" -reqHeaders $reqHeaders -reqBody $blueprintBody -method "PUT"
    
    return $result
}

function Remove-CASBlueprint
{
    param(
        [string][Parameter(Mandatory=$true)][ValidateNotNullOrEmpty()]$BlueprintId
    )

    $result = Invoke-CASAPI -apiUri "$CASURI/blueprint/api/blueprints/$BlueprintId" -reqHeaders $reqHeaders -reqBody @{} -method "DELETE"

    return $result
}

function New-CASBlueprintVersion
{
    param(
        [string][Parameter(Mandatory=$true)][ValidateNotNullOrEmpty()]$BlueprintId,
        [string][Parameter(Mandatory=$true)][ValidateNotNullOrEmpty()]$Version,
        [string]$ChangeLog,
        [string]$Description
    )
    
    $versionBody = @{}
    $versionBody.Add("version", $Version)
    $versionBody.Add("changelog", $ChangeLog)
    $versionBody.Add("description","$Description")

    $result = Invoke-CASAPI -apiUri "$CASURI/blueprint/api/blueprints/$BlueprintId/versions" -reqHeaders $reqHeaders -reqBody $versionBody -method "POST"

    return $result
}

function New-CASBlueprintVersionRelease
{
    param(
        [string][Parameter(Mandatory=$true)][ValidateNotNullOrEmpty()]$BlueprintId,
        [string][Parameter(Mandatory=$true)][ValidateNotNullOrEmpty()]$Version
    )

    $result = Invoke-CASAPI -apiUri "$CASURI/blueprint/api/blueprints/$BlueprintId/versions/$Version/action/release" -reqHeaders $reqHeaders -reqBody @{} -method "POST"

    return $result
}

function Restore-CASBlueprintVersion
{
    param(
        [string][Parameter(Mandatory=$true)][ValidateNotNullOrEmpty()]$BlueprintId,
        [string][Parameter(Mandatory=$true)][ValidateNotNullOrEmpty()]$Version
    )

    $result = Invoke-CASAPI -apiUri "$CASURI/blueprint/api/blueprints/$BlueprintId/versions/$Version/action/restore" -reqHeaders $reqHeaders -reqBody @{} -method "POST"

    return $result
}

function Remove-CASBlueprintVersionRelease
{
    param(
        [string][Parameter(Mandatory=$true)][ValidateNotNullOrEmpty()]$BlueprintId,
        [string][Parameter(Mandatory=$true)][ValidateNotNullOrEmpty()]$Version
    )

    $result = Invoke-CASAPI -apiUri "$CASURI/blueprint/api/blueprints/$BlueprintId/versions/$Version/action/unrelease" -reqHeaders $reqHeaders -reqBody @{} -method "POST"

    return $result
}

function New-CASBlueprintRequest
{
    param(
        [string][Parameter(Mandatory=$true)][ValidateNotNullOrEmpty()]$BlueprintId,
        [string][Parameter(Mandatory=$true)][ValidateNotNullOrEmpty()]$Version,
        [string]$Content, #CHeck use
        [string]$DeploymentID, #check use
        [string]$DeploymentName, 
        [bool]$Destroy=$true, #check use
        [bool]$Plan=$true,
        [string][Parameter(Mandatory=$true)][ValidateNotNullOrEmpty()]$ProjectId,
        [string]$Reason,
        [string]$Tags
    )

    $blueprintBody = @{}
    $blueprintBody.Add("blueprintId", $BlueprintId)
    $blueprintBody.Add("version", $Version)
    $blueprintBody.Add("content", $Content)
    $blueprintBody.Add("deploymentId", $DeploymentID)
    $blueprintBody.Add("deploymentName", $DeploymentName)
    $blueprintBody.Add("destroy", $Destroy)
    $blueprintBody.Add("plan", $Plan)
    $blueprintBody.Add("projectId", $ProjectId)
    $blueprintBody.Add("reason", $Reason)

    $tagsArray = $Tags.split(",")
    $blueprintBody.Add("tags", $tagsArray)

    $result = Invoke-CASAPI -apiUri "$CASURI/blueprint/api/blueprint-requests" -reqHeaders $reqHeaders -reqBody $blueprintBody -method "POST"

    return $result
}
