SHELL=/bin/bash -o pipefail
GO ?= go

NAME := rekor-falco
OUTPUT := lib$(NAME).so

ifeq ($(DEBUG), 1)
    GODEBUGFLAGS= GODEBUG=cgocheck=2
else
    GODEBUGFLAGS= GODEBUG=cgocheck=0
endif

all: $(OUTPUT)

clean:
	@rm -rf /tmp/lima/rekor-falco
	@rm -f *.so *.h

$(OUTPUT): *.go
	@$(GODEBUGFLAGS) $(GO) build -buildmode=c-shared -o $(OUTPUT)

lima: clean
	mkdir -pv /tmp/lima/rekor-falco
	cp -r . /tmp/lima/rekor-falco
	limactl start --tty=false lima.yaml
	limactl shell lima -- cd /tmp/lima/rekor-falco && make all
	limactl shell lima -- falco -r /tmp/lima/rekor-falco/example-rule.yaml -c /tmp/lima/rekor-falco/falco.yaml &> /tmp/lima/falco.log &
	limactl shell lima -- tail -f /tmp/lima/falco.log
