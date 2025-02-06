#!PS
net start spooler
$printers = ` #old printer IP on the left, new IP on the right
"
1.1.1.1 2.2.2.2
3.3.3.3 4.4.4.4
"

$printerlist = @()
$printers = $printers.Split([Environment]::NewLine).where({$_ -ne ''})
foreach ($line in $printers) {
    $IPv4regex = [Regex]::new("\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}")
    $matches = $IPv4regex.matches($line)
    $oldip = $matches.value[0]
    $newip = $matches.value[1]
    $printerlist += @(
            @{ OldPrinterIP = $oldip ; NewPrinterIP = $newip }
        ) | % { New-Object object | Add-Member -NotePropertyMembers $_ -PassThru }
}

function Fix-PrinterIP {
    param(
    $list,
    [switch]$change
    )

    foreach ($item in $list) {
        $newip = $item.NewPrinterIP
        $oldip = $item.OldPrinterIP

        if ($newip -eq $null -or $oldip -eq $null) { Write-host $item could not be processed ; continue }

        $matchingprinters = (Get-Printer | ? { $_.PortName -match $oldip -and $_.PortName -notmatch 'WSD'})
        foreach ($printer in $matchingprinters) {
        
            if ($printer.name -match "[\[\]]|[\(\)]") {
                $newname = $printer.name -replace("[\[\]]|[\(\)]",'')
                Rename-Printer -name $printer.name -NewName $newname
                $printer = (Get-printer $newname)
            }

            if ($Printer.Name -ne $null) {
                $Printer | % { Write-host "Printer `($($_.Name)`) | OLD IP -> $($_.PortName)" -NoNewline } 

                switch ($change) {
                    $true {         

                        if ([Boolean](get-printerport -name $newip -ErrorAction SilentlyContinue) -eq $false) {
                            Add-PrinterPort -Name $newip -PrinterHostAddress $newip -ErrorAction Continue
                            }
                    
                        Set-printer -name $Printer.Name -Portname $newip
                    
                        $newprinter = (Get-Printer | ? { $_.PortName -eq $newip})

                        if ([Boolean]$newprinter -eq $true) {
                            $newprinter | % { Write-host " | NEW IP -> $($_.PortName)" } 
                            #Remove-PrinterPort -Name $oldip
                            }


                        if (Get-Printer | ? { $_.PortName -match $oldip -and $newprinter.Name -eq $_.Name}) {
                            Write-host Failed to update printer $Printer.Name#, attempting change via registry.
                            }
                    }
                }
            }
        } 
    }
}

Write-host -----[Before] -NoNewline
Get-printer | select Name,PortName,DriverName | ft -AutoSize
Write-host .___________[Changes]____________.`n
Fix-PrinterIP -list $printerlist -change
Write-host `n\________________________________/`n`n
Write-host -----[After] -NoNewline
Get-printer | select Name,PortName,DriverName | ft -AutoSize
net stop spooler
net start spooler

        


#$regbackup = "c:\regbak_debloat_$(get-date -format 'yyyyMMdd').reg"
#if (!(test-path $regbackup)) { cmd /c "regedit /e $regbackup" }
                        
#$registrykey = gci "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Print\Printers\" | ? { ($_.Name).split('\')[-1] -eq $printer.Name }
#$keypath = $registrykey.name.replace('HKEY_LOCAL_MACHINE','HKLM:')
#if (test-path $keypath -eq $false) {
#    $keypath = $keypath.replace(
#}
#New-ItemProperty -path $registrykey -Name 'Port' -value $newip -whatif

###Run the following to send a print job after completing the above steps, will blow up the printer with test prints...
# Invoke-CimMethod -MethodName printtestpage -InputObject (Get-CimInstance win32_printer -Filter "name LIKE '$Printername'")
# Get-PrintJob -PrinterName $Printername | Format-Table | Out-String|% {Write-Host -foreground Green $_}

                       
                    
