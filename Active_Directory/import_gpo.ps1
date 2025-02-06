#!ps
#maxlength=100000
#timeout=90000

import-module grouppolicy
$gponame = "Remote_Management_Policy"
$site    = "***"
$downloadpath = "c:\users\public\"
$downloadfile = $downloadpath + $gponame + ".zip"

if (Test-path $downloadfile) { 
	Remove-item $downloadfile 
}

iwr -Uri "$site$gponame.zip" -OutFile $downloadfile

if ( (Test-path $downloadfile) -eq $false) { 
	curl -o $downloadfile "$site/$gponame.zip"
}


$guid = gci $downloadpath | ? { $_.name -match "{.*}" }

if ($guid -ne $null -and $guid -ne "") { 
#	Remove-item $guid.fullname -recurse
}

Add-Type -AssemblyName System.IO.Compression.FileSystem
function Unzip
{
    param([string]$zipfile, [string]$outpath)

    [System.IO.Compression.ZipFile]::ExtractToDirectory($zipfile, $outpath)
}

unzip $downloadfile $downloadpath

$global:currentdomain = Get-WmiObject -Namespace root\cimv2 -Class Win32_ComputerSystem | Select -ExpandProperty Domain
$prefix = $currentdomain.split(".")[0]
$suffix = $currentdomain.split(".")[1]

New-GPO -Name $gponame | New-GPLink -Target "dc=$prefix,dc=$suffix" -LinkEnabled Yes 
import-gpo -BackupGpoName $gponame -TargetName $gponame -path $downloadpath -CreateIfNeeded