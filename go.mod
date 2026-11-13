module vaultmcp

go 1.24.7

require github.com/modelcontextprotocol/go-sdk v1.2.0

require (
	github.com/google/jsonschema-go v0.3.0 // indirect
	github.com/yosida95/uritemplate/v3 v3.0.2 // indirect
	golang.org/x/oauth2 v0.30.0 // indirect
)

replace golang.org/x/oauth2 => github.com/golang/oauth2 v0.30.0

replace golang.org/x/tools => github.com/golang/tools v0.34.0
