.PHONY: all
all: format

update:
	go mod download
	go mod tidy

format:
	go run golang.org/x/tools/cmd/goimports@v0.1.12 -w .
	go mod tidy

vet:
	go vet ./...

gen-swig: gen-swig-exec format

gen-swig-exec:
	./gen_swig.sh
