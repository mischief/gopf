package pf

/*
#include <sys/types.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <sys/fcntl.h>
#include <sys/signal.h>
#include <net/if.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <net/pfvar.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

extern uint16_t chtons(uint16_t v);

char*
pfgettblname(struct pf_addr_wrap *a)
{
	return a->v.tblname;
}
*/
import "C"

import (
	"fmt"
	"net"
	"syscall"
	"unsafe"
)

type OpenAnchor struct {
	name string

	pf *OpenPf
}

func (a *OpenAnchor) release(ticket C.u_int32_t) error {
	return ioctl(a.pf.fd.Fd(), C.DIOCXEND, unsafe.Pointer(&ticket))
}

func (a *OpenAnchor) Rules() (r []Rule, oerr error) {
	pr := &C.struct_pfioc_rule{}

	aname := C.CString(a.name)
	defer C.free(unsafe.Pointer(aname))

	C.strlcpy(&pr.anchor[0], aname, C.size_t(unsafe.Sizeof(pr.anchor)))

	if err := ioctl(a.pf.fd.Fd(), DIOCGETRULES, unsafe.Pointer(pr)); err != nil {
		return nil, err
	}

	defer func() {
		if err := a.release(pr.ticket); err != nil {
			r = nil
			oerr = err
		}
	}()

	count := int(pr.nr)
	var rules []Rule

	for i := 0; i < count; i++ {
		pr.nr = C.u_int32_t(i)
		if err := ioctl(a.pf.fd.Fd(), DIOCGETRULE, unsafe.Pointer(pr)); err != nil {
			return nil, err
		}

		if pr.anchor_call[0] != 0 {
			continue
		}

		r := Rule{Nr: uint32(pr.nr)}

		switch pr.rule.action {
		case PF_PASS:
			r.Action = Pass
		case PF_BLOCK:
			r.Action = Block
		case PF_MATCH:
			r.Action = Match
		default:
			return nil, fmt.Errorf("rule %d: unknown action %d", i, pr.rule.action)
		}

		switch pr.rule.direction {
		case PF_INOUT:
			r.Direction = InOut
		case PF_IN:
			r.Direction = In
		case PF_OUT:
			r.Direction = Out
		default:
			return nil, fmt.Errorf("rule %d: unknown direction %d", i, pr.rule.direction)
		}

		if pr.rule.log != 0 {
			r.Log = true
		}

		if pr.rule.quick != 0 {
			r.Quick = true
		}

		r.Interface = C.GoString(&pr.rule.ifname[0])
		r.Tag = C.GoString(&pr.rule.tagname[0])

		r.Src = Target{Port: ntohs((uint16(pr.rule.src.port[0])))}

		switch pr.rule.src.addr._type {
		case PF_ADDR_ADDRMASK:
			_, net, err := net.ParseCIDR(addrwrapstr(&pr.rule.src.addr, int(pr.rule.af)))
			if err != nil {
				return nil, fmt.Errorf("rule %d: bad src addr: %w", i, err)
			}
			r.Src.Addr = AddrIPMask{*net}
		case PF_ADDR_DYNIFTL:
			r.Src.Addr = AddrDynIf{addrwrapstr(&pr.rule.src.addr, int(pr.rule.af))}
		case PF_ADDR_TABLE:
			r.Src.Addr = AddrTable(C.GoString(C.pfgettblname(&pr.rule.src.addr)))
		default:
			return nil, fmt.Errorf("rule %d: unknown src addr type %d", i, pr.rule.src.addr._type)
		}

		r.Dst = Target{Port: ntohs((uint16(pr.rule.dst.port[0])))}

		switch pr.rule.dst.addr._type {
		case PF_ADDR_ADDRMASK:
			_, net, err := net.ParseCIDR(addrwrapstr(&pr.rule.dst.addr, int(pr.rule.af)))
			if err != nil {
				return nil, fmt.Errorf("rule %d: bad dst addr: %w", i, err)
			}
			r.Dst.Addr = AddrIPMask{*net}
		case PF_ADDR_DYNIFTL:
			r.Dst.Addr = AddrDynIf{addrwrapstr(&pr.rule.dst.addr, int(pr.rule.af))}
		case PF_ADDR_TABLE:
			r.Dst.Addr = AddrTable(C.GoString(C.pfgettblname(&pr.rule.dst.addr)))
		default:
			return nil, fmt.Errorf("rule %d: unknown dst addr type %d", i, pr.rule.dst.addr._type)
		}

		if pr.rule.rdr.addr._type != PF_ADDR_NONE {
			r.Rdr = &Target{Port: uint16(pr.rule.rdr.proxy_port[0])}

			switch pr.rule.rdr.addr._type {
			case PF_ADDR_ADDRMASK:
				_, net, err := net.ParseCIDR(addrwrapstr(&pr.rule.rdr.addr, int(pr.rule.af)))
				if err != nil {
					return nil, fmt.Errorf("rule %d: bad rdr addr: %w", i, err)
				}
				r.Rdr.Addr = AddrIPMask{*net}
			case PF_ADDR_DYNIFTL:
				r.Rdr.Addr = AddrDynIf{addrwrapstr(&pr.rule.rdr.addr, int(pr.rule.af))}
			}
		}

		rules = append(rules, r)
	}

	return rules, nil
}

func (a *OpenAnchor) Insert(r *Rule) error {
	rule := C.struct_pfioc_rule{}

	aname := C.CString(a.name)
	C.strlcpy(&rule.anchor[0], aname, C.size_t(unsafe.Sizeof(rule.anchor)))
	C.free(unsafe.Pointer(aname))

	nr := &rule.rule

	// defaults
	nr.af = syscall.AF_INET
	nr.rtableid = C.int(-1)
	nr.onrdomain = C.int(-1)
	nr.keep_state = PF_STATE_NORMAL
	nr.flags = 0x2
	nr.flagset = 0x12
	nr.src.addr._type = PF_ADDR_ADDRMASK
	nr.dst.addr._type = PF_ADDR_ADDRMASK
	nr.nat.addr._type = PF_ADDR_NONE
	nr.rdr.addr._type = PF_ADDR_ADDRMASK

	switch r.Action {
	case Block:
		nr.action = PF_BLOCK
	case Pass:
		nr.action = PF_PASS
	case Match:
		nr.action = PF_MATCH
	}

	switch r.Direction {
	case InOut:
		nr.direction = PF_INOUT
	case In:
		nr.direction = PF_IN
	case Out:
		nr.direction = PF_OUT
	}

	if r.Log {
		nr.log = C.u_int8_t(1)
	}

	if r.Quick {
		nr.quick = C.u_int8_t(1)
	}

	ifname := C.CString(r.Interface)
	defer C.free(unsafe.Pointer(ifname))

	C.strlcpy(&nr.ifname[0], ifname, C.size_t(unsafe.Sizeof(nr.ifname)))

	tagname := C.CString(r.Tag)
	defer C.free(unsafe.Pointer(tagname))

	C.strlcpy(&nr.tagname[0], tagname, C.size_t(unsafe.Sizeof(nr.tagname)))

	if r.Src.Addr != nil {
		goaddrtopfaddr(r.Src.Addr, &nr.src.addr)
	}
	if r.Src.Port != 0 {
		nr.src.port_op = PF_OP_EQ
		nr.src.port[0] = C.u_int16_t(C.chtons(C.uint16_t(r.Src.Port)))
	}

	if r.Dst.Addr != nil {
		goaddrtopfaddr(r.Dst.Addr, &nr.dst.addr)
	}
	if r.Dst.Port != 0 {
		nr.dst.port_op = PF_OP_EQ
		nr.dst.port[0] = C.u_int16_t(C.chtons(C.uint16_t(r.Dst.Port)))
	}

	if r.Rdr != nil {
		if r.Rdr.Addr != nil {
			goaddrtopfaddr(r.Rdr.Addr, &nr.rdr.addr)
		}
		if r.Rdr.Port != 0 {
			//nr.rdr.port_op = PF_OP_EQ
			nr.rdr.proxy_port[0] = C.u_int16_t(r.Rdr.Port)
			nr.rdr.proxy_port[1] = C.u_int16_t(r.Rdr.Port)
		}
	}

	rule.action = PF_CHANGE_GET_TICKET

	err := ioctl(a.pf.fd.Fd(), DIOCCHANGERULE, unsafe.Pointer(&rule))
	if err != nil {
		return err
	}

	rule.action = PF_CHANGE_ADD_TAIL

	// insert rule into anchor
	err = ioctl(a.pf.fd.Fd(), DIOCCHANGERULE, unsafe.Pointer(&rule))
	if err != nil {
		return err
	}

	return nil
}

func (a *OpenAnchor) DeleteIndex(nr int) error {
	rule := C.struct_pfioc_rule{
		action: PF_CHANGE_GET_TICKET,
		nr:     C.u_int32_t(nr),
	}

	aname := C.CString(a.name)
	C.strlcpy(&rule.anchor[0], aname, C.size_t(unsafe.Sizeof(rule.anchor)))
	C.free(unsafe.Pointer(aname))

	err := ioctl(a.pf.fd.Fd(), DIOCCHANGERULE, unsafe.Pointer(&rule))
	if err != nil {
		return err
	}

	rule.action = PF_CHANGE_REMOVE

	err = ioctl(a.pf.fd.Fd(), DIOCCHANGERULE, unsafe.Pointer(&rule))
	if err != nil {
		return err
	}

	return nil
}

// RuleStats returns per-rule evaluation and traffic counters for this anchor.
func (a *OpenAnchor) RuleStats() (r []RuleStats, oerr error) {
	pr := &C.struct_pfioc_rule{}

	aname := C.CString(a.name)
	defer C.free(unsafe.Pointer(aname))
	C.strlcpy(&pr.anchor[0], aname, C.size_t(unsafe.Sizeof(pr.anchor)))

	if err := ioctl(a.pf.fd.Fd(), DIOCGETRULES, unsafe.Pointer(pr)); err != nil {
		return nil, err
	}

	defer func() {
		if err := a.release(pr.ticket); err != nil {
			r = nil
			oerr = err
		}
	}()

	count := int(pr.nr)

	for i := 0; i < count; i++ {
		ir := &C.struct_pfioc_rule{}
		C.strlcpy(&ir.anchor[0], aname, C.size_t(unsafe.Sizeof(ir.anchor)))
		ir.ticket = pr.ticket
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

		r = append(r, RuleStats{
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
			StatesCur:   uint64(ir.rule.states_cur),
			StatesTot:   uint64(ir.rule.states_tot),
		})
	}

	return r, nil
}
