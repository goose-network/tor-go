package circuit

import "net"

// netParseIP wraps net.ParseIP so the main circuit file does not need to
// import net directly (kept separate for clarity of the protocol file).
func netParseIP(s string) net.IP { return net.ParseIP(s) }
