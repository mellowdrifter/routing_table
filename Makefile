.PHONY: all test fuzz clean bench

all: test

test: fuzz
	go test -v ./...

fuzz:
	go test -fuzz=FuzzIPv4Rib -fuzztime 20s .
	go test -fuzz=FuzzIPv6Rib -fuzztime 20s .

bench:
	go test -bench=. ./...

clean:
	go clean
	rm -rf testdata/fuzz
