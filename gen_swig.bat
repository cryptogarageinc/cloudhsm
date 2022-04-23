swig -go -c++ -cgo -intgosize 32 -o cloudhsm.cxx swig.i

powershell -NoProfile -ExecutionPolicy Unrestricted .\tools\convert_crlf.ps1

go run golang.org/x/tools/cmd/goimports@v0.1.10 -w .

pause
