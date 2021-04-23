swig -go -c++ -cgo -intgosize 32 -o cloudhsm.cxx swig.i

powershell -NoProfile -ExecutionPolicy Unrestricted .\tools\convert_crlf.ps1

pause
