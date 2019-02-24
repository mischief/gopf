package pf

import (
	"bytes"
	"fmt"
	"net"
	"strings"
)

// Action describes what to do with a matched packet.
type Action int

const (
	Block Action = PF_BLOCK
	Pass         = PF_PASS
)

// Direction determines whether the rule matches packets going in, out, or in both directions.
type Direction int

func (d Direction) String() string {
	switch d {
	case InOut:
		return ""
	case In:
		return "in"
	case Out:
		return "out"
	}

	panic("unknown direction")
}

const (
	InOut Direction = iota
	In
	Out
)

type Target struct {
	Addr Addr
	Port uint16
}

func (t Target) String() string {
	r := t.Addr.String()

	if t.Port != 0 {
		r += fmt.Sprintf(" port %d", t.Port)
	}

	return r
}

type Addr interface {
	String() string
	noimpl()
}

// AddrDynIf is an Addr
type AddrDynIf struct {
	Interface string
}

func (a AddrDynIf) String() string {
	return a.Interface
}

func (AddrDynIf) noimpl() {
}

// AddrIPMask is an Addr composed of an IP and a CIDR netmask.
type AddrIPMask struct {
	net.IPNet
}

var (
	IPv4All = net.IP{0xff, 0xff, 0xff, 0xff}
	IPv6All = net.IP{0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff}

	IPAny = AddrIPMask{net.IPNet{net.IPv6zero, net.IPMask(net.IPv6zero)}}
)

func (a AddrIPMask) String() string {
	if a.IP.IsUnspecified() {
		return "any"
	}

	r := a.IPNet.String()
	if (len(a.Mask) == net.IPv4len && bytes.Compare(a.Mask, IPv4All) == 0) ||
		(len(a.Mask) == net.IPv6len && bytes.Compare(a.Mask, IPv6All) == 0) {
		r = strings.Split(r, "/")[0]
	}

	return r
}

func (AddrIPMask) noimpl() {
}

type Rdr struct {
	Addr
}

// Rule corresponds to a pf rule.
type Rule struct {
	Nr        uint32
	Action    Action
	Direction Direction
	Log       bool
	Quick     bool
	Interface string
	Tag       string

	Src Target
	Dst Target
	Rdr *Target
}

func (r Rule) String() string {
	s := fmt.Sprintf("@%d %s", r.Nr, r.Action)

	if r.Direction != InOut {
		s += " " + r.Direction.String()
	}

	if r.Log {
		s += " log"
	}

	if r.Quick {
		s += " quick"
	}

	if r.Interface != "" {
		s += " on " + r.Interface
	}

	s += fmt.Sprintf(" from %s to %s", r.Src, r.Dst)

	if r.Rdr != nil {
		s += fmt.Sprintf(" rdr-to %s", r.Rdr)
	}

	if r.Tag != "" {
		s += " tag " + r.Tag
	}

	return s
}

// Anchors hold collections of rules.
type Anchor interface {
	Rules() ([]Rule, error)
	Insert(r *Rule) error
	DeleteIndex(nr int) error
}

// QueueStats holds stats from a queue.
type QueueStats struct {
	TransmitBytes   uint64
	TransmitPackets uint64
	DroppedBytes    uint64
	DroppedPackets  uint64
}

// Queue is a snapshot of a pf queue.
type Queue struct {
	Name   string
	Parent string
	IfName string
	Stats  QueueStats
}

// IfStats provides information about the pf loginterface.
type IfStats struct {
	Name string
	IPv4 IPStats
	IPv6 IPStats
}

type IPStats struct {
	BytesIn           uint64
	BytesOut          uint64
	PacketsInPassed   uint64
	PacketsInBlocked  uint64
	PacketsOutPassed  uint64
	PacketsOutBlocked uint64
}

// Stats gives statistical information about the firewall.
type Stats interface {
	// Enabled returns true if the firewall is enabled, otherwise false.
	Enabled() bool

	StateCount() int
	StateSearches() int
	StateInserts() int
	StateRemovals() int

	// IfStats returns statistics from the pf loginterface.
	// If the loginterface is unset, IfStats returns nil.
	IfStats() *IfStats
}

// Pf is a handle to the firewall loaded in the kernel.
type Pf interface {
	Stats() (Stats, error)
	Anchors() ([]string, error)
	Anchor(anchor string) (Anchor, error)
	Queues() ([]Queue, error)
	Close() error
}
