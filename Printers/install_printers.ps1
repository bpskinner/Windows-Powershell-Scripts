write-host Installing print drivers...; sleep 3
$driver_path =  "C:\users\public\setup_files\printers\"
mkdir c:\users\public\setup_files\printers\
try {
Invoke-WebRequest "http://downloads.amsinet.com/printers.zip" -OutFile $driver_path
Expand-Archive -Path ("$driver_path" + "printers.zip") -DestinationPath "$driver_path"
Remove-Item "$driver_path\printers.zip" -force
$alldrivers = (gci $driver_path -Attributes Directory).name
$alldrivers
$driver_names = 'Brother Mono Universal Printer (PCL)', 'Lexmark Universal v2 XL', 'HP Universal Printing PCL 6', "TOSHIBA Universal Printer 2", "RICOH PCL6 V4 UniversalDriver V4.10","KONICA MINOLTA Universal V4 PCL"
foreach ($driver in $alldrivers) { pnputil.exe -i -a $($driver_path + $driver + '\*.inf') }
foreach ($drivername in $driver_names) { Add-PrinterDriver -name $drivername -verbose -ErrorAction SilentlyContinue }
} 
finally {
Remove-Item $driver_path -Force -Recurse -verbose
}