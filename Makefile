# netreach — every gate in one place. `make check` is what CI runs.
GO        ?= go
GOFLAGS   ?= -p=3
BIN       := bin/netreach
CORE_PKGS := ./interval/...,./hspace/...,./model/...,./engine/...,./sim/...,./report/...
COVER_MIN ?= 85

export GOFLAGS

.PHONY: all build test race cover fmt fmt-check vet lint check demo verify bench fuzz clean

all: check

build:
	$(GO) build -o $(BIN) ./cmd/netreach

test:
	$(GO) test ./...

race:
	$(GO) test -race ./...

## cover: whole-suite coverage of the core packages, gated at COVER_MIN percent.
cover:
	$(GO) test -coverpkg=$(CORE_PKGS) -coverprofile=coverage.out ./... > /dev/null
	@scripts/coverage-gate.sh coverage.out $(COVER_MIN)

fmt:
	gofmt -w .

fmt-check:
	@out="$$(gofmt -l .)"; if [ -n "$$out" ]; then echo "gofmt needed:"; echo "$$out"; exit 1; fi

vet:
	$(GO) vet ./...

lint:
	golangci-lint run ./...

## check: format + vet + lint (zero warnings) + race-enabled tests + coverage gate.
check: fmt-check vet lint race cover
	@echo "make check: all gates passed"

## verify: hand-derived ground truth for every fixture topology.
verify: build
	$(BIN) verify -dir testdata/topologies

demo: build
	@scripts/demo.sh $(BIN)

bench: build
	$(BIN) bench
	$(GO) test -run '^$$' -bench . -benchtime 20x ./hspace/

## fuzz: short native-fuzzing run of the interval algebra.
fuzz:
	$(GO) test -run '^$$' -fuzz FuzzSetAlgebra -fuzztime 30s ./interval/

clean:
	rm -rf bin coverage.out
