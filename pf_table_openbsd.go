package pf

// #include <sys/ioctl.h>
// #include <sys/socket.h>
// #include <net/if.h>
// #include <net/pfvar.h>
import "C"

import (
	"time"
	"unsafe"
)

const (
	DIOCRGETTABLES = C.DIOCRGETTABLES
	DIOCRGETTSTATS = C.DIOCRGETTSTATS
)

// Tables returns per-table counters for every table in every anchor.
func (p *OpenPf) Tables() ([]TableStats, error) {
	io := &C.struct_pfioc_table{}
	io.pfrio_esize = C.int(unsafe.Sizeof(C.struct_pfr_tstats{}))

	// A nil buffer asks the kernel for the table count only.
	if err := ioctl(p.fd.Fd(), DIOCRGETTSTATS, unsafe.Pointer(io)); err != nil {
		return nil, err
	}

	n := int(io.pfrio_size)
	if n == 0 {
		return nil, nil
	}

	// Slack absorbs tables added between the sizing call and this one.
	buf := make([]C.struct_pfr_tstats, n+16)
	io.pfrio_buffer = unsafe.Pointer(&buf[0])
	io.pfrio_size = C.int(len(buf))

	if err := ioctl(p.fd.Fd(), DIOCRGETTSTATS, unsafe.Pointer(io)); err != nil {
		return nil, err
	}

	n = int(io.pfrio_size)
	if n > len(buf) {
		n = len(buf)
	}

	tables := make([]TableStats, 0, n)

	for i := 0; i < n; i++ {
		ts := &buf[i]

		t := TableStats{
			Name:      C.GoString(&ts.pfrts_t.pfrt_name[0]),
			Anchor:    C.GoString(&ts.pfrts_t.pfrt_anchor[0]),
			Addresses: uint64(ts.pfrts_cnt),
			Match:     uint64(ts.pfrts_match),
			NoMatch:   uint64(ts.pfrts_nomatch),
			Cleared:   time.Unix(int64(ts.pfrts_tzero), 0),
		}

		for op := 0; op < C.PFR_OP_TABLE_MAX; op++ {
			t.PacketsIn += uint64(ts.pfrts_packets[C.PFR_DIR_IN][op])
			t.PacketsOut += uint64(ts.pfrts_packets[C.PFR_DIR_OUT][op])
			t.BytesIn += uint64(ts.pfrts_bytes[C.PFR_DIR_IN][op])
			t.BytesOut += uint64(ts.pfrts_bytes[C.PFR_DIR_OUT][op])
		}

		tables = append(tables, t)
	}

	return tables, nil
}
