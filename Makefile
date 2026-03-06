.PHONY: build test lint security clean

BINARY=iam-advisor

build:
	go build -o $(BINARY) .

test:
	go test -race ./...

vet:
	go vet ./...

lint:
	golangci-lint run ./...

security: govulncheck gosec staticcheck trivy

govulncheck:
	@which govulncheck > /dev/null || go install golang.org/x/vuln/cmd/govulncheck@latest
	govulncheck ./...

gosec:
	@which gosec > /dev/null || go install github.com/securego/gosec/v2/cmd/gosec@latest
	gosec ./...

staticcheck:
	@which staticcheck > /dev/null || go install honnef.co/go/tools/cmd/staticcheck@latest
	staticcheck ./...

trivy:
	@which trivy > /dev/null || (echo "Install trivy: https://aquasecurity.github.io/trivy/latest/getting-started/installation/" && exit 1)
	trivy fs --severity CRITICAL,HIGH .

clean:
	rm -f $(BINARY) *.sarif coverage.out
