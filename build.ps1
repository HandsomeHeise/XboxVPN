[CmdletBinding()]
param(
    [string]$OutputDirectory
)

$ErrorActionPreference = 'Stop'
if (!$OutputDirectory) {
    $OutputDirectory = Join-Path $PSScriptRoot 'Build'
}
$msbuild = Join-Path $env:WINDIR 'Microsoft.NET/Framework/v4.0.30319/MSBuild.exe'
if (!(Test-Path -LiteralPath $msbuild -PathType Leaf)) {
    throw 'MSBuild 4.0 is required to build with the Xbox 360 SDK.'
}

$sdkArguments = @()
if ($env:XEDK) {
    $sdkPath = [IO.Path]::GetFullPath($env:XEDK).TrimEnd('\', '/').Replace('\', '/') + '/'
    if (!(Test-Path -LiteralPath (Join-Path $sdkPath 'bin/win32/imagexex.exe') -PathType Leaf)) {
        throw "The XEDK environment variable does not point to an Xbox 360 SDK installation ($sdkPath)."
    }
    $sdkArguments = @("/p:XDKInstallDir=$sdkPath")
}

# A trailing forward slash survives quoting in Windows PowerShell.
$output = [IO.Path]::GetFullPath($OutputDirectory).TrimEnd('\', '/').Replace('\', '/') + '/'
$xexPath = Join-Path $output 'XboxVPN.xex'
if (Test-Path -LiteralPath $xexPath -PathType Leaf) {
    Remove-Item -LiteralPath $xexPath
}

try {
    & $msbuild (Join-Path $PSScriptRoot 'XboxVPN.vcxproj') /t:Rebuild /p:Configuration=Release '/p:Platform=Xbox 360' `
        "/p:OutDir=$output" "/p:IntDir=${output}Intermediate/" @sdkArguments /nologo
    if ($LASTEXITCODE -ne 0) {
        throw "Xbox 360 SDK build failed (MSBuild exit code $LASTEXITCODE)."
    }

    $bytes = [IO.File]::ReadAllBytes($xexPath)
    function Read-XexUInt32([long]$offset) {
        if ($offset -lt 0 -or $offset + 4 -gt $bytes.Length) {
            throw 'The XboxVPN XEX has an invalid header offset.'
        }
        return ([uint64]$bytes[$offset] -shl 24) -bor ([uint64]$bytes[$offset + 1] -shl 16) -bor `
            ([uint64]$bytes[$offset + 2] -shl 8) -bor $bytes[$offset + 3]
    }

    if ((Read-XexUInt32 0) -ne 0x58455832 -or (Read-XexUInt32 4) -ne 0xA) {
        throw 'Expected a resident XEX2 system DLL with module flags 0xA.'
    }

    $securityOffset = Read-XexUInt32 16
    $loadAddress = Read-XexUInt32 ($securityOffset + 0x110)
    $imageSize = Read-XexUInt32 ($securityOffset + 4)
    $imageEnd = $loadAddress + $imageSize
    if ($loadAddress -ne 0x814F0000L -or !$imageSize -or $imageEnd -gt 0x815B0000L) {
        throw ('Resident XEX exceeds its address range (base={0:X8}, size={1:X8}).' -f $loadAddress, $imageSize)
    }

    $importOffset = 0
    $headerCount = Read-XexUInt32 20
    for ($i = 0; $i -lt $headerCount; ++$i) {
        $entry = 24 + 8 * $i
        if ((Read-XexUInt32 $entry) -eq 0x103FF) {
            $importOffset = Read-XexUInt32 ($entry + 4)
            break
        }
    }
    if (!$importOffset) {
        throw 'The XboxVPN XEX has no import descriptor.'
    }
    $nameLength = Read-XexUInt32 ($importOffset + 4)
    $nameStart = $importOffset + 12
    if (!$nameLength -or $nameStart + $nameLength -gt $bytes.Length) {
        throw 'The XboxVPN XEX has an invalid import name table.'
    }
    $importNames = [Text.Encoding]::ASCII.GetString($bytes, $nameStart, $nameLength).Split([char]0) |
        Where-Object { $_ } | Sort-Object -Unique
    if ($importNames.Count -ne 2 -or $importNames -notcontains 'xboxkrnl.exe' -or $importNames -notcontains 'xam.xex') {
        throw ('Unexpected XboxVPN import libraries ({0}).' -f ($importNames -join ', '))
    }

    Write-Host ('Verified resident XboxVPN XEX {0:X8}-{1:X8} ({2})' -f $loadAddress, $imageEnd, $xexPath)
} catch {
    if (Test-Path -LiteralPath $xexPath -PathType Leaf) {
        Remove-Item -LiteralPath $xexPath
    }
    throw
}
