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
	@rm -f *.so *.h

$(OUTPUT): *.go
	@$(GODEBUGFLAGS) $(GO) build -buildmode=c-shared -o $(OUTPUT)
