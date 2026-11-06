.PHONY: check fmt-check vet lint test build-all build

check: fmt-check vet lint test build-all

fmt-check:
	@test -z "$$(gofmt -l .)" || (gofmt -l .; exit 1)

vet:
	go vet ./...

lint:
	golangci-lint run ./...

test:
	go test ./...

build:
	CGO_ENABLED=0 go build -o firedrill ./cmd/firedrill

build-all:
	CGO_ENABLED=0 GOOS=darwin GOARCH=arm64 go build -o /dev/null ./cmd/firedrill
	CGO_ENABLED=0 GOOS=darwin GOARCH=amd64 go build -o /dev/null ./cmd/firedrill
	CGO_ENABLED=0 GOOS=linux GOARCH=arm64 go build -o /dev/null ./cmd/firedrill
	CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -o /dev/null ./cmd/firedrill
	CGO_ENABLED=0 GOOS=windows GOARCH=arm64 go build -o /dev/null ./cmd/firedrill
	CGO_ENABLED=0 GOOS=windows GOARCH=amd64 go build -o /dev/null ./cmd/firedrill
