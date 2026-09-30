.PHONY: build test run clean deps

BINARY := soteria
CMD := ./cmd/soteria

build:
	go build -o $(BINARY) $(CMD)

test:
	go test ./...

run: build
	sudo ./$(BINARY) -config config/config.json

clean:
	rm -f $(BINARY)

deps:
	go mod tidy
