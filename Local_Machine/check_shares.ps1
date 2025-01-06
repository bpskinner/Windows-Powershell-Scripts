#!ps
#maxlength=100000
#timeout=90000
Get-SmbShare | ? { $_.ShareType -eq 'FileSystemDirectory' } | Get-SmbShareAccess | ? { $_.accountname -eq 'Everyone' -and $_.AccessRight -eq 'Full' }