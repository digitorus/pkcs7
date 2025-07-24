all: vet test

test:
	GODEBUG=x509sha1=1 go test -covermode=count -coverprofile=coverage.out .

showcoverage: test
	go tool cover -html=coverage.out

vet:
	go vet .

staticcheck:
	$(shell go env GOPATH)/bin/staticcheck .

gettools:
	go install honnef.co/go/tools/cmd/staticcheck@latest
