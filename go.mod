module github.com/goose-network/tor-go

go 1.26.0

require golang.org/x/crypto v0.57.0

require (
	github.com/goose-network/goose-plugin-api v0.0.0-20261026123131-fb552d7d52b0
	golang.org/x/sys v0.48.0 // indirect
)

// Dev-time local checkout of the api contract (dropped before release; the
// module resolves the published pin instead).
