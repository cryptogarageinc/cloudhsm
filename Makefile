.PHONY: all
all: format

update:
	go mod download
	go mod tidy

format:
	go run golang.org/x/tools/cmd/goimports@v0.1.10 -w .
	go mod tidy

vet:
	LD_LIBRARY_PATH="./build/Release" go vet .

build:
	mkdir build
	cd build && cmake .. -DENABLE_SHARED=on -DCMAKE_BUILD_TYPE=Release -DTARGET_RPATH="/usr/local/lib" && make

gen-swig:
	./gen_swig.sh
	make format
