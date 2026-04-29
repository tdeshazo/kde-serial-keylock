BINDIR ?= bin
GO ?= go

.PHONY: all build keylock settimer screentime-coordinator screentime-agent screentime test vet lint check clean

all: build

build: keylock settimer screentime-coordinator screentime-agent screentime

keylock: | $(BINDIR)
	$(GO) build -o $(BINDIR)/keylock ./cmd/keylock

settimer: | $(BINDIR)
	$(GO) build -o $(BINDIR)/settimer ./cmd/settimer

screentime-coordinator: | $(BINDIR)
	$(GO) build -o $(BINDIR)/screentime-coordinator ./cmd/screentime-coordinator

screentime-agent: | $(BINDIR)
	$(GO) build -o $(BINDIR)/screentime-agent ./cmd/screentime-agent

screentime: | $(BINDIR)
	$(GO) build -o $(BINDIR)/screentime ./cmd/screentime

test:
	$(GO) test ./...

vet:
	$(GO) vet ./...

lint: vet

check: test vet build

$(BINDIR):
	mkdir -p $(BINDIR)

clean:
	rm -f $(BINDIR)/keylock $(BINDIR)/settimer $(BINDIR)/screentime-coordinator $(BINDIR)/screentime-agent $(BINDIR)/screentime
