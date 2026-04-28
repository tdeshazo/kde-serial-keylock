BINDIR ?= bin
GO ?= go

.PHONY: all build keylock settimer test vet lint check clean

all: build

build: keylock settimer

keylock: | $(BINDIR)
	$(GO) build -o $(BINDIR)/keylock ./cmd/keylock

settimer: | $(BINDIR)
	$(GO) build -o $(BINDIR)/settimer ./cmd/settimer

test:
	$(GO) test ./...

vet:
	$(GO) vet ./...

lint: vet

check: test vet build

$(BINDIR):
	mkdir -p $(BINDIR)

clean:
	rm -f $(BINDIR)/keylock $(BINDIR)/settimer
