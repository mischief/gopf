package pf

import "time"

// TableStats holds per-table counters retrieved via DIOCRGETTSTATS.
// Packet and byte counters sum every match type (block, match, pass, xpass).
type TableStats struct {
	Name       string
	Anchor     string
	Addresses  uint64
	Match      uint64
	NoMatch    uint64
	PacketsIn  uint64
	PacketsOut uint64
	BytesIn    uint64
	BytesOut   uint64
	Cleared    time.Time
}
