PACKAGES = $(shell go list ./... | grep -v '/vendor/')

all: test

########################################
### Testing

test:
	make test_unit

test_unit:
	go test -race $(PACKAGES)

########################################
### Pre Commit

pre_commit: test_unit

########################################

# To avoid unintended conflicts with file names, always add to .PHONY
# # unless there is a reason not to.
# # https://www.gnu.org/software/make/manual/html_node/Phony-Targets.html
.PHONY: test test_unit
