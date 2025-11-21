<#
AgentClient.ps1
Usage examples:
  # download remote file
  .\AgentClient.ps1 -BaseUrl "http://hostname:5000" -Token "secret" -Command GetFile -RemotePath "folder/file.txt" -Out "C:\temp\file.txt"

  # upload local file
  .\AgentClient.ps1 -BaseUrl "http://hostname:5000" -Token "secret" -Command PutFile -LocalPath "C:\temp\file.txt" -RemotePath "folder/file.txt"

  # delete remote file
  .\AgentClient.ps1 -BaseUrl "http://hostname:5000" -Token "secret" -Command RemoveFile -RemotePath "folder/file.txt"

  # list processes
  .\AgentClient.ps1 -BaseUrl "http://hostname:5000" -Token "secret" -Command GetProcesses

  # get net info
  .\AgentClient.ps1 -BaseUrl "http://hostname:5000" -Token "secret" -Command GetNet
#>

param(
    [Parameter(Mandatory=$true)][string]$BaseUrl,
    [Parameter(Mandatory=$true)][string]$Token,
    [Parameter(Mandatory=$true)][ValidateSet("GetFile","PutFile","RemoveFile","GetProcesses","GetNet")] [string]$Command,
    [string]$LocalPath,
    [string]$RemotePath,
    [string]$Out
)

function Get-AuthHeader {
    param([string]$token)
    return @{ Authorization = "Bearer $token" }
}

function Invoke-AgentGetFile {
    param($baseUrl, $token, $remotePath, $outFile)
    if (-not $remotePath) { throw "RemotePath is required for GetFile" }
    if (-not $outFile) { $outFile = Split-Path -Leaf $remotePath }

    $uri = "$baseUrl/file?path=$([uri]::EscapeDataString($remotePath))"
    $headers = Get-AuthHeader -token $token

    Write-Verbose "Downloading $uri -> $outFile"
    Invoke-WebRequest -Uri $uri -Headers $headers -OutFile $outFile -UseBasicParsing -ErrorAction Stop
    Write-Output "Saved $outFile"
}

function Invoke-AgentPutFile {
    param($baseUrl, $token, $localPath, $remotePath)
    if (-not $localPath) { throw "LocalPath is required for PutFile" }
    if (-not (Test-Path $localPath)) { throw "Local file not found: $localPath" }
    if (-not $remotePath) { throw "RemotePath is required for PutFile" }

    $uri = "$baseUrl/file?path=$([uri]::EscapeDataString($remotePath))"
    $headers = Get-AuthHeader -token $token

    Write-Verbose "Uploading $localPath -> $uri"
    # Use -InFile for streaming upload (no buffering)
    $response = Invoke-RestMethod -Uri $uri -Method Post -Headers $headers -InFile $localPath -ContentType "application/octet-stream" -ErrorAction Stop
    Write-Output $response
}

function Invoke-AgentRemoveFile {
    param($baseUrl, $token, $remotePath)
    if (-not $remotePath) { throw "RemotePath is required for RemoveFile" }

    $uri = "$baseUrl/file?path=$([uri]::EscapeDataString($remotePath))"
    $headers = Get-AuthHeader -token $token

    Write-Verbose "Deleting $uri"
    $response = Invoke-RestMethod -Uri $uri -Method Delete -Headers $headers -ErrorAction Stop
    Write-Output $response
}

function Invoke-AgentGetProcesses {
    param($baseUrl, $token)
    $uri = "$baseUrl/processes"
    $headers = Get-AuthHeader -token $token

    Write-Verbose "Getting processes from $uri"
    $response = Invoke-RestMethod -Uri $uri -Method Get -Headers $headers -ErrorAction Stop
    # Pretty output as table if array of objects
    if ($response -is [System.Collections.IEnumerable]) {
        $response | Sort-Object id | Format-Table -AutoSize
    } else {
        Write-Output $response
    }
}

function Invoke-AgentGetNet {
    param($baseUrl, $token)
    $uri = "$baseUrl/net"
    $headers = Get-AuthHeader -token $token

    Write-Verbose "Getting net info from $uri"
    $response = Invoke-RestMethod -Uri $uri -Method Get -Headers $headers -ErrorAction Stop
    # Print a compact summary
    if ($response.tcpConnections) {
        $response.tcpConnections | Select-Object local, remote, state, pid | Format-Table -AutoSize
    }
    if ($response.udpListeners) {
        "`nUDP listeners:"
        $response.udpListeners | ForEach-Object { Write-Output "  $_" }
    }
}

try {
    switch ($Command) {
        "GetFile"      { Invoke-AgentGetFile -baseUrl $BaseUrl -token $Token -remotePath $RemotePath -outFile $Out }
        "PutFile"      { Invoke-AgentPutFile -baseUrl $BaseUrl -token $Token -localPath $LocalPath -remotePath $RemotePath }
        "RemoveFile"   { Invoke-AgentRemoveFile -baseUrl $BaseUrl -token $Token -remotePath $RemotePath }
        "GetProcesses" { Invoke-AgentGetProcesses -baseUrl $BaseUrl -token $Token }
        "GetNet"       { Invoke-AgentGetNet -baseUrl $BaseUrl -token $Token }
        default { throw "Unknown command $Command" }
    }
} catch {
    Write-Error $_.Exception.Message
    exit 1
}