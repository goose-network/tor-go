module github.com/goose-network/tor-go

go 1.26.0

require golang.org/x/crypto v0.57.0

require (
	github.com/goose-network/goose-plugin-api v0.0.0
	golang.org/x/sys v0.48.0 // indirect
)

replace github.com/goose-network/goose-plugin-api => ../goose-plugin-api
