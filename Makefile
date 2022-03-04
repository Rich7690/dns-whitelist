default: build

build:
	go build -o dns-whitelist ./main.go
download:
	curl -sSfL https://raw.githubusercontent.com/golangci/golangci-lint/master/install.sh | sh -s v1.42.0
lint:
	./bin/golangci-lint run --fix