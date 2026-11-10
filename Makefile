.PHONY: build test race bench clean

BINARY := bin/packetveil

build:
	@mkdir -p bin
	CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o $(BINARY) ./cmd/packetveil

test:
	go test -v ./pkg/...

race:
	go test -v -race ./pkg/...

bench:
	go test -run=^$$ -bench=. -benchmem ./pkg/...

clean:
	rm -rf bin/
