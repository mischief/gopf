package pf

/*
#include <sys/types.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <sys/fcntl.h>
#include <net/if.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <net/altq/altq.h>
#include <net/altq/altq_cbq.h>
#include <net/altq/altq_hfsc.h>
#include <net/altq/altq_priq.h>
#include <net/pfvar.h>
#include <arpa/inet.h>

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

char*
pfgettblname(struct pf_addr_wrap *a)
{
	return a->v.tblname;
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

	/* ioctls */
	DIOCADDRULE     = C.DIOCADDRULE
	DIOCGETALTQS    = C.DIOCGETALTQS
	DIOCGETRULES    = C.DIOCGETRULES
	DIOCGETALTQ     = C.DIOCGETALTQ
	DIOCGETRULE     = C.DIOCGETRULE
	DIOCGETSTATUS   = C.DIOCGETSTATUS
	DIOCGETRULESETS = C.DIOCGETRULESETS
	DIOCGETRULESET  = C.DIOCGETRULESET
	DIOCXBEGIN      = C.DIOCXBEGIN
	DIOCXCOMMIT     = C.DIOCXCOMMIT
	DIOCCHANGERULE  = C.DIOCCHANGERULE
	DIOCGETQSTATS   = C.DIOCGETQSTATS

	/* DIOCCHANGERULE actions */
	PF_CHANGE_ADD_TAIL   = C.PF_CHANGE_ADD_TAIL
	PF_CHANGE_REMOVE     = C.PF_CHANGE_REMOVE
	PF_CHANGE_GET_TICKET = C.PF_CHANGE_GET_TICKET

	/* rule direction */
	PF_INOUT = C.PF_INOUT
	PF_IN    = C.PF_IN
	PF_OUT   = C.PF_OUT

	/* rule actions */
	PF_PASS  = C.PF_PASS
	PF_BLOCK = C.PF_DROP
	PF_MATCH = C.PF_MATCH
	PF_RDR   = C.PF_RDR
	Match     = PF_MATCH

	/* address types */
	PF_ADDR_ADDRMASK = C.PF_ADDR_ADDRMASK
	PF_ADDR_DYNIFTL  = C.PF_ADDR_DYNIFTL
	PF_ADDR_TABLE    = C.PF_ADDR_TABLE

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

func (a Action) String() string {
	switch a {
	case Block:
		return "block"
	case Pass:
		return "pass"
	}

	panic("unknown action")
}

func ioctl(fd, op uintptr, arg unsafe.Pointer) error {
	_, _, ep := syscall.Syscall(syscall.SYS_IOCTL, fd, op, uintptr(arg))
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

type FreeRule struct {
	r C.struct_pf_rule
}

func (r *FreeRule) Nr() uint {
	return uint(r.r.nr)
}

func (r FreeRule) IfName() string {
	return C.GoString(&r.r.ifname[0])
}

func (r FreeRule) string() string {
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

type FreePf struct {
	fd *os.File
}

func OpenFD(fd uintptr) Pf {
	return &FreePf{fd: os.NewFile(fd, "pf")}
}

func Open() (Pf, error) {
	pf := new(FreePf)

	fd, err := os.OpenFile("/dev/pf", os.O_RDWR, 0)
	if err != nil {
		return nil, err
	}

	pf.fd = fd

	return pf, nil
}

func (p *FreePf) Close() error {
	return p.fd.Close()
}

type FreeStats struct {
	s C.struct_pf_status
}

func (s *FreeStats) Enabled() bool {
	return s.s.running != 0
}

func (s *FreeStats) StateCount() int {
	return int(s.s.states)
}

func (s *FreeStats) StateSearches() int {
	return int(s.s.fcounters[0])
}

func (s *FreeStats) StateInserts() int {
	return int(s.s.fcounters[1])
}

func (s *FreeStats) StateRemovals() int {
	return int(s.s.fcounters[2])
}

func (s *FreeStats) IfStats() *IfStats {
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

func (p *FreePf) Stats() (Stats, error) {
	stats := C.struct_pf_status{}

	err := ioctl(p.fd.Fd(), DIOCGETSTATUS, unsafe.Pointer(&stats))
	if err != nil {
		return nil, err
	}

	return &FreeStats{s: stats}, nil
}

func (p *FreePf) Anchors() ([]string, error) {
	pr := &C.struct_pfioc_ruleset{}

	err := ioctl(p.fd.Fd(), DIOCGETRULESETS, unsafe.Pointer(pr))
	if err != nil {
		return nil, err
	}

	anchors := make([]string, 0)

	n := int(pr.nr)

	for i := 0; i < n; i++ {
		pr.nr = C.u_int32_t(i)

		err := ioctl(p.fd.Fd(), DIOCGETRULESET, unsafe.Pointer(pr))
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

func (p *FreePf) Anchor(anchor string) (Anchor, error) {
	if anchor == "" {
		return &FreeAnchor{pf: p}, nil
	}

	anchors, err := p.Anchors()
	if err != nil {
		return nil, err
	}

	for _, a := range anchors {
		if a == anchor {
			return &FreeAnchor{name: a, pf: p}, nil
		}
	}

	return nil, fmt.Errorf("no such anchor %q", anchor)
}

type FreeAnchor struct {
	name string
	pf   *FreePf
}

func (a *FreeAnchor) Rules() ([]Rule, error) {
	pr := &C.struct_pfioc_rule{}

	aname := C.CString(a.name)
	defer C.free(unsafe.Pointer(aname))
	C.strlcpy(&pr.anchor[0], aname, C.size_t(unsafe.Sizeof(pr.anchor)))

	if err := ioctl(a.pf.fd.Fd(), DIOCGETRULES, unsafe.Pointer(pr)); err != nil {
		return nil, err
	}

	count := int(pr.nr)
	ticket := pr.ticket
	var rules []Rule

	for i := 0; i < count; i++ {
		ir := &C.struct_pfioc_rule{}
		C.strlcpy(&ir.anchor[0], aname, C.size_t(unsafe.Sizeof(ir.anchor)))
		ir.ticket = ticket
		ir.nr = C.u_int32_t(i)

		if err := ioctl(a.pf.fd.Fd(), DIOCGETRULE, unsafe.Pointer(ir)); err != nil {
			return nil, err
		}

		if ir.anchor_call[0] != 0 {
			continue
		}

		r := Rule{Nr: uint32(ir.nr)}

		switch ir.rule.action {
		case PF_PASS:
			r.Action = Pass
		case PF_BLOCK:
			r.Action = Block
		case PF_MATCH:
			r.Action = Match
		default:
			return nil, fmt.Errorf("rule %d: unknown action %d", i, ir.rule.action)
		}

		switch ir.rule.direction {
		case PF_INOUT:
			r.Direction = InOut
		case PF_IN:
			r.Direction = In
		case PF_OUT:
			r.Direction = Out
		default:
			return nil, fmt.Errorf("rule %d: unknown direction %d", i, ir.rule.direction)
		}

		if ir.rule.log != 0 {
			r.Log = true
		}

		if ir.rule.quick != 0 {
			r.Quick = true
		}

		r.Interface = C.GoString(&ir.rule.ifname[0])
		r.Tag = C.GoString(&ir.rule.tagname[0])

		r.Src = Target{Port: ntohs(uint16(ir.rule.src.port[0]))}
		switch ir.rule.src.addr._type {
		case PF_ADDR_ADDRMASK:
			_, ipnet, err := net.ParseCIDR(addrwrapstr(&ir.rule.src.addr, int(ir.rule.af)))
			if err != nil {
				return nil, fmt.Errorf("rule %d: bad src addr: %w", i, err)
			}
			r.Src.Addr = AddrIPMask{*ipnet}
		case PF_ADDR_DYNIFTL:
			r.Src.Addr = AddrDynIf{addrwrapstr(&ir.rule.src.addr, int(ir.rule.af))}
		case PF_ADDR_TABLE:
			r.Src.Addr = AddrTable(C.GoString(C.pfgettblname(&ir.rule.src.addr)))
		default:
			return nil, fmt.Errorf("rule %d: unknown src addr type %d", i, ir.rule.src.addr._type)
		}

		r.Dst = Target{Port: ntohs(uint16(ir.rule.dst.port[0]))}
		switch ir.rule.dst.addr._type {
		case PF_ADDR_ADDRMASK:
			_, ipnet, err := net.ParseCIDR(addrwrapstr(&ir.rule.dst.addr, int(ir.rule.af)))
			if err != nil {
				return nil, fmt.Errorf("rule %d: bad dst addr: %w", i, err)
			}
			r.Dst.Addr = AddrIPMask{*ipnet}
		case PF_ADDR_DYNIFTL:
			r.Dst.Addr = AddrDynIf{addrwrapstr(&ir.rule.dst.addr, int(ir.rule.af))}
		case PF_ADDR_TABLE:
			r.Dst.Addr = AddrTable(C.GoString(C.pfgettblname(&ir.rule.dst.addr)))
		default:
			return nil, fmt.Errorf("rule %d: unknown dst addr type %d", i, ir.rule.dst.addr._type)
		}

		rules = append(rules, r)
	}

	return rules, nil
}

func (a *FreeAnchor) Insert(r *Rule) error {
	return fmt.Errorf("Insert not yet implemented for FreeBSD")
}

func (a *FreeAnchor) DeleteIndex(nr int) error {
	return fmt.Errorf("DeleteIndex not yet implemented for FreeBSD")
}

// RuleStats returns per-rule evaluation and traffic counters for this anchor.
func (a *FreeAnchor) RuleStats() ([]RuleStats, error) {
	pr := &C.struct_pfioc_rule{}

	aname := C.CString(a.name)
	defer C.free(unsafe.Pointer(aname))
	C.strlcpy(&pr.anchor[0], aname, C.size_t(unsafe.Sizeof(pr.anchor)))

	if err := ioctl(a.pf.fd.Fd(), DIOCGETRULES, unsafe.Pointer(pr)); err != nil {
		return nil, err
	}

	n := int(pr.nr)
	ticket := pr.ticket
	var rules []RuleStats

	for i := 0; i < n; i++ {
		ir := &C.struct_pfioc_rule{}
		C.strlcpy(&ir.anchor[0], aname, C.size_t(unsafe.Sizeof(ir.anchor)))
		ir.ticket = ticket
		ir.nr = C.u_int32_t(i)

		if err := ioctl(a.pf.fd.Fd(), DIOCGETRULE, unsafe.Pointer(ir)); err != nil {
			return nil, err
		}

		if ir.anchor_call[0] != 0 {
			continue
		}

		label := C.GoString(&ir.rule.label[0])
		if label == "" {
			label = fmt.Sprintf("@%d", i)
		}

		action := ""
		if int(ir.rule.action) < len(actiontypes) {
			action = actiontypes[ir.rule.action]
		}
		direction := ""
		if int(ir.rule.direction) < len(dirtypes) {
			direction = dirtypes[ir.rule.direction]
		}

		af := ""
		switch int(ir.rule.af) {
		case syscall.AF_INET:
			af = "inet"
		case syscall.AF_INET6:
			af = "inet6"
		}

		proto := ""
		switch int(ir.rule.proto) {
		case syscall.IPPROTO_ICMP:
			proto = "icmp"
		case syscall.IPPROTO_TCP:
			proto = "tcp"
		case syscall.IPPROTO_UDP:
			proto = "udp"
		case syscall.IPPROTO_ESP:
			proto = "esp"
		case syscall.IPPROTO_AH:
			proto = "ah"
		case syscall.IPPROTO_ICMPV6:
			proto = "icmp6"
		default:
			if ir.rule.proto != 0 {
				proto = fmt.Sprintf("%d", ir.rule.proto)
			}
		}

		rules = append(rules, RuleStats{
			Label:       label,
			Nr:          uint32(ir.rule.nr),
			AF:          af,
			Proto:       proto,
			Anchor:      a.name,
			Interface:   C.GoString(&ir.rule.ifname[0]),
			Action:      action,
			Direction:   direction,
			Evaluations: uint64(ir.rule.evaluations),
			PacketsIn:   uint64(ir.rule.packets[0]),
			PacketsOut:  uint64(ir.rule.packets[1]),
			BytesIn:     uint64(ir.rule.bytes[0]),
			BytesOut:    uint64(ir.rule.bytes[1]),
			StatesCur:   uint64(uintptr(unsafe.Pointer(ir.rule.states_cur))),
			StatesTot:   uint64(uintptr(unsafe.Pointer(ir.rule.states_tot))),
		})
	}

	return rules, nil
}

func (p *FreePf) qstats(altq *C.struct_pfioc_altq) (*QueueStats, error) {
	stats := C.struct_pfioc_qstats{}
	stats.ticket = altq.ticket
	stats.nr = altq.nr

	switch altq.altq.scheduler {
	case C.ALTQT_CBQ:
		st := C.class_stats_t{}
		stats.buf = unsafe.Pointer(&st)
		stats.nbytes = C.int(unsafe.Sizeof(st))

		if err := ioctl(p.fd.Fd(), DIOCGETQSTATS, unsafe.Pointer(&stats)); err != nil {
			return nil, err
		}

		stats := &QueueStats{
			TransmitBytes:   uint64(st.xmit_cnt.bytes),
			TransmitPackets: uint64(st.xmit_cnt.packets),
			DroppedBytes:    uint64(st.drop_cnt.bytes),
			DroppedPackets:  uint64(st.drop_cnt.packets),
		}

		return stats, nil

	case C.ALTQT_HFSC:
		st := C.struct_hfsc_classstats{}
		stats.buf = unsafe.Pointer(&st)
		stats.nbytes = C.int(unsafe.Sizeof(st))

		if err := ioctl(p.fd.Fd(), DIOCGETQSTATS, unsafe.Pointer(&stats)); err != nil {
			return nil, err
		}

		stats := &QueueStats{
			TransmitBytes:   uint64(st.xmit_cnt.bytes),
			TransmitPackets: uint64(st.xmit_cnt.packets),
			DroppedBytes:    uint64(st.drop_cnt.bytes),
			DroppedPackets:  uint64(st.drop_cnt.packets),
		}

		return stats, nil

	case C.ALTQT_PRIQ:
		st := C.struct_priq_classstats{}
		stats.buf = unsafe.Pointer(&st)
		stats.nbytes = C.sizeof_struct_priq_classstats

		if err := ioctl(p.fd.Fd(), DIOCGETQSTATS, unsafe.Pointer(&stats)); err != nil {
			return nil, err
		}

		stats := &QueueStats{
			TransmitBytes:   uint64(st.xmitcnt.bytes),
			TransmitPackets: uint64(st.xmitcnt.packets),
			DroppedBytes:    uint64(st.dropcnt.bytes),
			DroppedPackets:  uint64(st.dropcnt.packets),
		}

		return stats, nil
	default:
		return nil, fmt.Errorf("unhalded scheduler type %d", altq.altq.scheduler)
	}
}

// Queues returns all queues in pf.
func (p *FreePf) Queues() ([]Queue, error) {
	top := C.struct_pfioc_altq{}
	if err := ioctl(p.fd.Fd(), DIOCGETALTQS, unsafe.Pointer(&top)); err != nil {
		return nil, err
	}

	n := int(top.nr)
	var queues []Queue

	for i := 0; i < n; i++ {
		altq := C.struct_pfioc_altq{}
		altq.ticket = top.ticket
		altq.nr = C.u_int32_t(i)

		if err := ioctl(p.fd.Fd(), DIOCGETALTQ, unsafe.Pointer(&altq)); err != nil {
			return nil, err
		}

		// Root queue for non-CODEL types have no stats.
		if altq.altq.qid == 0 && altq.altq.scheduler != C.ALTQT_CODEL {
			continue
		}

		q := Queue{
			Name:   C.GoString(&altq.altq.qname[0]),
			Parent: C.GoString(&altq.altq.parent[0]),
			IfName: C.GoString(&altq.altq.ifname[0]),
		}

		stats, err := p.qstats(&altq)
		if err != nil {
			return nil, err
		} else {
			q.Stats = *stats
		}

		queues = append(queues, q)
	}

	return queues, nil
}

// Queue gets a queue by name.
func (p *FreePf) Queue(queue string) (*Queue, error) {
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
