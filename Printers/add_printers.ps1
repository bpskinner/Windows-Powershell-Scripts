$loggedin = ([string]((gwmi win32_computersystem | select username).username)).Split('\')

function create_port () {
    $global:printername = read-host `nPlease name the new printer
    $global:printerIP = read-host Please enter its IP address
    $global:port = $($printername + "_$printerIP")
    if (Get-PrinterPort -name $port -ErrorAction ignore) { remove-printerport -Name $port } 
    }

function choose_list () {
    try { for ($i = 0; $i -le ($list.count); $x = $list[$i++] ) {
        if ($x -ne $null -and $i -ne 0) { Write-host "$i. $x" } } } catch { Write-host Failed to enumerate list. It is most likely empty.`n -ForegroundColor darkred; run }
    try { $choice = [int](Read-host "`nSelect") } catch { Write-host Invalid entry`, try again...`n -ForegroundColor Red; run }
    if ($list[$choice -1] -eq $null -or $choice -eq 0) { Write-host Invalid selection`, try again...`n -ForegroundColor Red; run } else { return $list[$choice -1] }
    }

function add_printer () {
    Write-host `nCurrently added printers: -ForegroundColor Red
    (Get-printer | ft Name, PortName, DriverName) 
    create_port
    Write-host `nSelect a driver from the following: -ForegroundColor Red
    $list = [array](Get-Printerdriver | ? {$_ -notmatch 'microsoft' -and $_ -notmatch 'remote desktop' -and $_ -notmatch 'PDF'}).name
    $global:driver = (choose_list)
    Write-host 'Adding printer ' -NoNewline; write-host $printername -ForegroundColor red -NoNewline; write-host ' with port name ' -NoNewline; write-host $port -ForegroundColor red -NoNewline; write-host ' ...'
    Add-Printerport -name $port -PrinterHostAddress $printerIP 
    Add-Printer -DriverName $driver -name $printername -PortName $port
    write-host Done!`n -ForegroundColor cyan -backgroundcolor black
    } 

function remove_printer () {
    Write-host `nSelect a printer to remove: -ForegroundColor Red
    $list = [array](Get-Printer).name
    $global:printer = (choose_list)
    write-host Removing printer -nonewline; write-host " $printer " -ForegroundColor Red -NoNewline; write-host ...
    Remove-Printer -name $printer
    write-host Done!`n -ForegroundColor cyan -backgroundcolor black
    }

function set_default () {
    cmd /c 'control printers'
    }

function run () { 
    write-host "`n1. Add Printer `n2. Remove Printer `n3. Set Default Printer [Not working yet] `n4. Exit and Delete .bat script `n5. Restart spooler service" -ForegroundColor Red -BackgroundColor black
    try { $choice = [int](read-host Select) } catch {write-host `nInvalid entry!`n -ForegroundColor red; run }
    if ($choice -eq 1) { add_printer }
    if ($choice -eq 2) { remove_printer }
    if ($choice -eq 3) { set_default } 
    if ($choice -eq 4) { remove-item "C:\users\public\desktop\add_printers.bat" -force; exit }
    if ($choice -eq 5) { restart-service spooler }
    run
    }

run