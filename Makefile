SERVER_OUT := "bin/server"
CLIENT_OUT := "bin/client"
PKG := "github.com/netclave/identity-provider"
SERVER_PKG_BUILD := "${PKG}/server"
CLIENT_PKG_BUILD := "${PKG}/client"
PKG_LIST := $(shell go list ${PKG}/... | grep -v /vendor/)

.PHONY: all server client

all: server client

dep: ## Get the dependencies
	@go get -v -d ./...

server: dep ## Build the binary file for server
	@go build -i -v -o $(SERVER_OUT) $(SERVER_PKG_BUILD)

client: dep ## Build the binary file for client
	@go build -i -v -o $(CLIENT_OUT) $(CLIENT_PKG_BUILD)

clean: ## Remove previous builds
	@rm $(SERVER_OUT) $(CLIENT_OUT)

help: ## Display this help screen
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | sort | awk 'BEGIN {FS = ":.*?## "}; {printf "\033[36m%-30s\033[0m %s\n", $$1, $$2}'
