// Command tor-go is a standalone Tor client. It loads a directory (consensus
// + microdescriptors) from files given on the command line, connects to a
// guard, and serves a SOCKS5 proxy applications connect to.
//
// Usage:
//
//	tor-go -consensus consensus.txt -microdescriptors microdescs.txt \
//	   [-socks 127.0.0.1:1080] [-pathlen 3] [-upstream 127.0.0.1:7890]
//
// To bootstrap a real directory over the network (through the upstream proxy),
// use -fetch-dir instead of -consensus/-microdescriptors:
//
//	tor-go -fetch-dir -upstream 127.0.0.1:7890 -socks 127.0.0.1:1080
//
// -upstream is the address of a SOCKS5 proxy that tor-go dials through to
// reach relays and directory authorities (e.g. a local Clash/V2Ray instance at
// 127.0.0.1:7890). Empty means dial relays directly.
//
// For testing without a real directory, -mock-dir loads a built-in mock
// directory (used by the e2e test harness).
package main

import (
	"context"
	"flag"
	"log"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/goose-network/tor-go/internal/directory"
	"github.com/goose-network/tor-go/internal/torclient"
)

func main() {
	consensusPath := flag.String("consensus", "", "path to a (micro)consensus file")
	microdescPath := flag.String("microdescriptors", "", "path to a microdescriptors file")
	socksAddr := flag.String("socks", "127.0.0.1:1080", "SOCKS5 listen address (applications connect here)")
	pathLen := flag.Int("pathlen", 3, "circuit path length")
	mockDir := flag.Bool("mock-dir", false, "use a built-in mock directory (for testing)")
	upstream := flag.String("upstream", "", "SOCKS5 upstream proxy to reach relays (e.g. 127.0.0.1:7890)")
	fetchDir := flag.Bool("fetch-dir", false, "bootstrap a real directory over the network (requires -upstream or direct outbound)")
	flag.Parse()

	var routers map[string]*directory.Router
	var err error
	switch {
	case *fetchDir:
		log.Printf("tor-go: fetching real directory via upstream %q ...", *upstream)
		fctx, fcancel := context.WithTimeout(context.Background(), 5*time.Minute)
		routers, err = directory.Fetch(fctx, directory.FetchOptions{
			UpstreamProxy: *upstream,
			Timeout:       5 * time.Minute,
			MaxMicrodescs: 0,
		})
		fcancel()
		if err != nil {
			log.Fatalf("tor-go: fetch directory: %v", err)
		}
	case *mockDir:
		routers = directory.MockDirectory()
	default:
		if *consensusPath == "" || *microdescPath == "" {
			log.Fatal("tor-go: must supply -consensus and -microdescriptors, or -mock-dir, or -fetch-dir")
		}
		routers, err = loadDirectory(*consensusPath, *microdescPath)
		if err != nil {
			log.Fatalf("tor-go: load directory: %v", err)
		}
	}
	log.Printf("tor-go: loaded %d relays", len(routers))

	cfg := &torclient.Config{
		SocksAddr:     *socksAddr,
		PathLen:       *pathLen,
		Directory:     routers,
		UpstreamProxy: *upstream,
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	cli, err := torclient.New(ctx, cfg)
	if err != nil {
		log.Fatalf("tor-go: init: %v", err)
	}

	// Handle SIGINT/SIGTERM.
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
	go func() {
		<-sigCh
		log.Println("tor-go: shutting down")
		cancel()
	}()

	if err := cli.Serve(ctx); err != nil && err != context.Canceled {
		log.Fatalf("tor-go: serve: %v", err)
	}
}

// loadDirectory reads the consensus and microdescriptor files and parses them.
func loadDirectory(consensusPath, microdescPath string) (map[string]*directory.Router, error) {
	consensus, err := os.ReadFile(consensusPath)
	if err != nil {
		return nil, err
	}
	routers, err := directory.ParseConsensus(consensus)
	if err != nil {
		return nil, err
	}
	microdescs, err := os.ReadFile(microdescPath)
	if err != nil {
		return nil, err
	}
	if err := directory.ParseMicrodescriptors(microdescs, routers); err != nil {
		return nil, err
	}
	return routers, nil
}
