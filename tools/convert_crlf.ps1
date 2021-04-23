Get-ChildItem -File -Filter cloudhsm.* | ForEach-Object {((Get-Content $_.FullName -Raw) -replace "`r","") | Set-Content $_.FullName -NoNewline}
