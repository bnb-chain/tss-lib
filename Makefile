PACKAGES = $(shell go list ./... | grep -v '/vendor/')

all: protob test

########################################
### Protocol Buffers

protob:
	@echo "--> Building Protocol Buffers"
	for protocol in keygen signing regroup; do \
		protoc --go_out=. ./protob/ecdsa-$$protocol.proto ; \
	done

build: protob

########################################
### Testing

test_unit:
	@echo "--> Running Unit Tests"
	go test -race $(PACKAGES)

test:
	make test_unit

########################################
### Pre Commit

pre_commit: test

########################################

# To avoid unintended conflicts with file names, always add to .PHONY
# # unless there is a reason not to.
# # https://www.gnu.org/software/make/manual/html_node/Phony-Targets.html
.PHONY: protob build test test_unit
