package pf

/*
#include <sys/types.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <sys/fcntl.h>
#include <net/if.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <net/pfvar.h>
#include <net/hfsc.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int
unmask(struct pf_addr_wrap *a)
{
	int i = 31, j = 0, b = 0;
	u_int32_t tmp;
	struct pf_addr *m;

	m = &a->v.a.mask;

	while (j < 4 && m->addr32[j] == 0xffffffff) {
		b += 32;
		j++;
	}

	if (j < 4) {
		tmp = ntohl(m->addr32[j]);
		for (i = 31; tmp & (1 << i); --i)
			b++;
	}

	return b;
}

char*
pfaddr(struct pf_addr_wrap *a, int af){
	int bits;
	char addr[INET6_ADDRSTRLEN];
	char *s = malloc(INET6_ADDRSTRLEN*2+2);
	memset(s, 0, INET6_ADDRSTRLEN*2+2);
	switch(a->type){
	case PF_ADDR_ADDRMASK:
		addr[0] = 0;
		inet_ntop(af, &a->v.a.addr, addr, INET6_ADDRSTRLEN);
		if(addr[0] == 0){
			switch(af){
			default:
				strlcpy(addr, "0", 2);
			case AF_INET:
				strlcpy(addr, "0.0.0.0", 8);
				break;
			case AF_INET6:
				strlcpy(addr, "::", 3);
				break;
			}
		}
		bits = unmask(a);
		snprintf(s, INET6_ADDRSTRLEN*2+2, "%s/%d", addr, bits);
		break;
	case PF_ADDR_DYNIFTL:
		snprintf(s, INET6_ADDRSTRLEN, "(%s)", a->v.ifname);
		break;
	}

	return s;
}

void
pfsetaddr(struct pf_addr_wrap *a, int af, char *addr, char *mask)
{
	memset(&a->v.a, 0, sizeof(a->v.a));

	switch(af){
	case AF_INET:
		if(inet_pton(af, addr, &a->v.a.addr.v4.s_addr) != 1)
			return;
		if(inet_pton(af, mask, &a->v.a.mask.v4.s_addr) != 1)
			return;
		break;
	case AF_INET6:
		if(inet_pton(af, addr, &a->v.a.addr.v6.s6_addr) != 1)
			return;
		if(inet_pton(af, mask, &a->v.a.mask.v6.s6_addr) != 1)
			return;
		break;
	}
}

char*
pfgetifname(struct pf_addr_wrap *a)
{
	return a->v.ifname;
}

void
pfsetifname(struct pf_addr_wrap *a, char *ifname){
	memset(&a->v.a.addr, 0x0, sizeof(a->v.a.addr));
	memset(&a->v.a.mask, 0xff, sizeof(a->v.a.mask));
	strlcpy(a->v.ifname, ifname, sizeof(a->v.ifname));
}

uint16_t
cntohs(uint16_t v){
	return ntohs(v);
}

uint16_t
chtons(uint16_t v){
	return htons(v);
}

*/
import "C"
import (
	"fmt"
	"net"
	"os"
	"syscall"
	"unsafe"
)

const (
	PF_RESERVED_ANCHOR = C.PF_RESERVED_ANCHOR

	PF_TRANS_RULESET = C.PF_TRANS_RULESET

	/* ioctls */
	DIOCADDRULE     = C.DIOCADDRULE
	DIOCGETRULES    = C.DIOCGETRULES
	DIOCGETRULE     = C.DIOCGETRULE
	DIOCGETSTATUS   = C.DIOCGETSTATUS
	DIOCGETRULESETS = C.DIOCGETRULESETS
	DIOCGETRULESET  = C.DIOCGETRULESET
	DIOCXBEGIN      = C.DIOCXBEGIN
	DIOCXCOMMIT     = C.DIOCXCOMMIT
	DIOCCHANGERULE  = C.DIOCCHANGERULE
	DIOCGETQUEUES   = C.DIOCGETQUEUES
	DIOCGETQUEUE    = C.DIOCGETQUEUE
	DIOCGETQSTATS   = C.DIOCGETQSTATS

	/* DIOCCHANGERULE actions */
	PF_CHANGE_ADD_TAIL   = C.PF_CHANGE_ADD_TAIL
	PF_CHANGE_REMOVE     = C.PF_CHANGE_REMOVE
	PF_CHANGE_GET_TICKET = C.PF_CHANGE_GET_TICKET

	/* rule direction */
	PF_INOUT = C.PF_INOUT
	PF_IN    = C.PF_IN
	PF_OUT   = C.PF_OUT
	PF_FWD   = C.PF_FWD

	/* rule actions */
	PF_PASS  = C.PF_PASS
	PF_BLOCK = C.PF_DROP
	PF_MATCH = C.PF_MATCH
	PF_RDR   = C.PF_RDR

	/* address types */
	PF_ADDR_ADDRMASK = C.PF_ADDR_ADDRMASK
	PF_ADDR_DYNIFTL  = C.PF_ADDR_DYNIFTL
	PF_ADDR_NONE     = C.PF_ADDR_NONE

	/* keep state types */
	PF_STATE_NORMAL = C.PF_STATE_NORMAL

	/* port operations */
	PF_OP_EQ = C.PF_OP_EQ
)

var (
	/* action labels */
	actiontypes = []string{
		"pass", "block", "scrub",
		"no scrub", "nat", "no nat", "binat", "no binat", "rdr", "no rdr",
		"", "", "match",
	}

	dirtypes = []string{
		"",
		"in",
		"out",
	}
)

func ioctl(fd, op, arg uintptr) error {
	_, _, ep := syscall.Syscall(syscall.SYS_IOCTL, fd, op, arg)
	if ep != 0 {
		return syscall.Errno(ep)
	}
	return nil
}

func ntohs(v uint16) uint16 {
	return uint16(C.cntohs(C.uint16_t(v)))
}

func addrwrapstr(w *C.struct_pf_addr_wrap, af int) string {
	c := C.pfaddr(w, C.int(af))
	defer C.free(unsafe.Pointer(c))
	s := C.GoString(c)
	return s
}

func goaddrtopfaddr(ad Addr, w *C.struct_pf_addr_wrap) {
	switch addr := ad.(type) {
	case AddrIPMask:
		w._type = PF_ADDR_ADDRMASK
		af := syscall.AF_INET
		def := net.IPv4zero
		if addr.IP.To4() == nil {
			af = syscall.AF_INET6
			def = net.IPv6zero
		}

		a := addr.IP
		if len(a) == 0 {
			a = def
		}

		m := net.IP(addr.Mask)
		if len(m) == 0 {
			m = def
		}

		as := C.CString(a.String())
		defer C.free(unsafe.Pointer(as))

		ms := C.CString(m.String())
		defer C.free(unsafe.Pointer(ms))

		// TODO: check error
		C.pfsetaddr(w, C.int(af), as, ms)
	case AddrDynIf:
		w._type = PF_ADDR_DYNIFTL
		ifname := C.CString(addr.Interface)
		defer C.free(unsafe.Pointer(ifname))
		C.pfsetifname(w, ifname)
	default:
		panic("bad addr type")
	}
}

func pfaddrtogoaddr(w *C.struct_pf_addr_wrap, a Addr) {
	if w._type == PF_ADDR_DYNIFTL {
		//		a.DynIf = true
		//		a.Name = C.GoString(C.pfgetifname(w))
	}

	if w._type == PF_ADDR_ADDRMASK {
	}
}

type OpenRule struct {
	r C.struct_pf_rule
}

func (r *OpenRule) Nr() uint {
	return uint(r.r.nr)
}

func (r OpenRule) IfName() string {
	return C.GoString(&r.r.ifname[0])
}

func (r OpenRule) string() string {
	action := actiontypes[r.r.action]

	rs := action

	if r.r.direction > 0 {
		rs += " " + dirtypes[r.r.direction]
	}

	if r.r.log != 0 {
		rs += " log"
	}

	if r.r.quick != 0 {
		rs += " quick"
	}

	in := r.IfName()

	if in != "" {
		rs += " on "
		if r.r.ifnot != 0 {
			rs += "! "
		}
		rs += in
	}

	return rs
}

type OpenPf struct {
	fd *os.File
}

func OpenFD(fd uintptr) Pf {
	return &OpenPf{fd: os.NewFile(fd, "pf")}
}

func Open() (Pf, error) {
	pf := new(OpenPf)

	fd, err := os.OpenFile("/dev/pf", os.O_RDWR, 0)
	if err != nil {
		return nil, err
	}

	pf.fd = fd

	return pf, nil
}

func (p *OpenPf) Close() error {
	return p.fd.Close()
}

type OpenStats struct {
	s C.struct_pf_status
}

func (s *OpenStats) Enabled() bool {
	return s.s.running != 0
}

func (s *OpenStats) StateCount() int {
	return int(s.s.states)
}

func (s *OpenStats) StateSearches() int {
	return int(s.s.fcounters[0])
}

func (s *OpenStats) StateInserts() int {
	return int(s.s.fcounters[1])
}

func (s *OpenStats) StateRemovals() int {
	return int(s.s.fcounters[2])
}

func (s *OpenStats) IfStats() *IfStats {
	ifname := C.GoString(&s.s.ifname[0])

	if len(ifname) == 0 {
		return nil
	}

	ifstats := &IfStats{
		Name: ifname,
		IPv4: IPStats{
			BytesIn:           uint64(s.s.bcounters[0][0]),
			BytesOut:          uint64(s.s.bcounters[0][1]),
			PacketsInPassed:   uint64(s.s.pcounters[0][0][PF_PASS]),
			PacketsInBlocked:  uint64(s.s.pcounters[0][0][PF_BLOCK]),
			PacketsOutPassed:  uint64(s.s.pcounters[0][1][PF_PASS]),
			PacketsOutBlocked: uint64(s.s.pcounters[0][1][PF_BLOCK]),
		},
		IPv6: IPStats{
			BytesIn:           uint64(s.s.bcounters[1][0]),
			BytesOut:          uint64(s.s.bcounters[1][1]),
			PacketsInPassed:   uint64(s.s.pcounters[1][0][PF_PASS]),
			PacketsInBlocked:  uint64(s.s.pcounters[1][0][PF_BLOCK]),
			PacketsOutPassed:  uint64(s.s.pcounters[1][1][PF_PASS]),
			PacketsOutBlocked: uint64(s.s.pcounters[1][1][PF_BLOCK]),
		},
	}

	return ifstats
}

func (p *OpenPf) Stats() (Stats, error) {
	stats := C.struct_pf_status{}

	err := ioctl(p.fd.Fd(), DIOCGETSTATUS, uintptr(unsafe.Pointer(&stats)))
	if err != nil {
		return nil, err
	}

	return &OpenStats{s: stats}, nil
}

func (p *OpenPf) Anchors() ([]string, error) {
	pr := &C.struct_pfioc_ruleset{}

	err := ioctl(p.fd.Fd(), DIOCGETRULESETS, uintptr(unsafe.Pointer(pr)))
	if err != nil {
		return nil, err
	}

	anchors := make([]string, 0)

	n := int(pr.nr)

	for i := 0; i < n; i++ {
		pr.nr = C.u_int32_t(i)

		err := ioctl(p.fd.Fd(), DIOCGETRULESET, uintptr(unsafe.Pointer(pr)))
		if err != nil {
			return nil, err
		}

		anchor := ""

		if pr.path[0] != '\x00' {
			anchor += C.GoString(&pr.path[0]) + "/"
		}

		name := C.GoString(&pr.name[0])

		if name == PF_RESERVED_ANCHOR {
			continue
		}

		anchor += name

		anchors = append(anchors, anchor)
	}

	return anchors, nil
}

func (p *OpenPf) Anchor(anchor string) (Anchor, error) {
	/* the empty anchor is ok, it's the root ruleset. */
	if anchor == "" {
		return &OpenAnchor{pf: p}, nil
	}

	anchors, err := p.Anchors()
	if err != nil {
		return nil, err
	}

	for _, a := range anchors {
		if a == anchor {
			return &OpenAnchor{name: a, pf: p}, nil
		}
	}

	return nil, fmt.Errorf("no such anchor %q", anchor)
}

// Queues returns all queues in pf.
func (p *OpenPf) Queues() ([]Queue, error) {
	pq := &C.struct_pfioc_queue{}
	pqs := &C.struct_pfioc_qstats{}
	hfscstats := &C.struct_hfsc_class_stats{}

	err := ioctl(p.fd.Fd(), DIOCGETQUEUES, uintptr(unsafe.Pointer(pq)))
	if err != nil {
		return nil, err
	}

	queues := make([]Queue, 0)

	n := int(pq.nr)

	for i := 0; i < n; i++ {
		pqs.nr = C.u_int32_t(i)
		pqs.ticket = pq.ticket
		pqs.buf = unsafe.Pointer(hfscstats)
		pqs.nbytes = C.int(unsafe.Sizeof(C.struct_hfsc_class_stats{}))

		err := ioctl(p.fd.Fd(), DIOCGETQSTATS, uintptr(unsafe.Pointer(pqs)))
		if err != nil {
			return nil, err
		}

		qname := C.GoString(&pqs.queue.qname[0])
		if qname[0] == '_' {
			continue
		}

		qparent := C.GoString(&pqs.queue.parent[0])
		qifname := C.GoString(&pqs.queue.ifname[0])

		queue := Queue{
			Name:   qname,
			Parent: qparent,
			IfName: qifname,
			Stats: QueueStats{
				TransmitPackets: uint64(hfscstats.xmit_cnt.packets),
				TransmitBytes:   uint64(hfscstats.xmit_cnt.bytes),
				DroppedPackets:  uint64(hfscstats.drop_cnt.packets),
				DroppedBytes:    uint64(hfscstats.drop_cnt.bytes),
			},
		}

		queues = append(queues, queue)
	}

	return queues, nil
}

// Queue gets a queue by name.
func (p *OpenPf) Queue(queue string) (*Queue, error) {
	if queue == "" {
		return nil, fmt.Errorf("empty queue name")
	}

	queues, err := p.Queues()
	if err != nil {
		return nil, err
	}

	for _, q := range queues {
		if q.Name == queue {
			return &q, nil
		}
	}

	return nil, fmt.Errorf("no such queue %q", queue)
}
