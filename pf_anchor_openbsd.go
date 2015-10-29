package pf

/*
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <sys/fcntl.h>
#include <net/if.h>
#include <net/pfvar.h>

extern uint16_t chtons(uint16_t v);
*/
import "C"

import (
	"net"
	"syscall"
	"unsafe"
)

type OpenAnchor struct {
	name string

	pf *OpenPf
}

func (a *OpenAnchor) Rules() ([]Rule, error) {
	pr := &C.struct_pfioc_rule{}

	aname := C.CString(a.name)
	defer C.free(unsafe.Pointer(aname))

	C.strlcpy(&pr.anchor[0], aname, C.size_t(unsafe.Sizeof(pr.anchor)))

	err := ioctl(a.pf.fd.Fd(), DIOCGETRULES, uintptr(unsafe.Pointer(pr)))
	if err != nil {
		return nil, err
	}

	count := int(pr.nr)

	rules := make([]Rule, 0)

	for i := 0; i < count; i++ {
		pr.nr = C.u_int32_t(i)
		err := ioctl(a.pf.fd.Fd(), DIOCGETRULE, uintptr(unsafe.Pointer(pr)))
		if err != nil {
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
			panic("bad action")
		}

		switch pr.rule.direction {
		case PF_INOUT:
			r.Direction = InOut
		case PF_IN:
			r.Direction = In
		case PF_OUT:
			r.Direction = Out
		default:
			panic("bad direction")
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
				panic(err)
			}
			r.Src.Addr = AddrIPMask{*net}
		case PF_ADDR_DYNIFTL:
			r.Src.Addr = AddrDynIf{addrwrapstr(&pr.rule.src.addr, int(pr.rule.af))}
		default:
			panic("bad src")
		}

		r.Dst = Target{Port: ntohs((uint16(pr.rule.dst.port[0])))}

		switch pr.rule.dst.addr._type {
		case PF_ADDR_ADDRMASK:
			_, net, err := net.ParseCIDR(addrwrapstr(&pr.rule.dst.addr, int(pr.rule.af)))
			if err != nil {
				panic(err)
			}
			r.Dst.Addr = AddrIPMask{*net}
		case PF_ADDR_DYNIFTL:
			r.Dst.Addr = AddrDynIf{addrwrapstr(&pr.rule.dst.addr, int(pr.rule.af))}
		default:
			panic("bad dst")
		}

		if pr.rule.rdr.addr._type != PF_ADDR_NONE {
			r.Rdr = &Target{Port: uint16(pr.rule.rdr.proxy_port[0])}

			switch pr.rule.rdr.addr._type {
			case PF_ADDR_ADDRMASK:
				_, net, err := net.ParseCIDR(addrwrapstr(&pr.rule.rdr.addr, int(pr.rule.af)))
				if err != nil {
					panic(err)
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

	err := ioctl(a.pf.fd.Fd(), DIOCCHANGERULE, uintptr(unsafe.Pointer(&rule)))
	if err != nil {
		return err
	}

	rule.action = PF_CHANGE_ADD_TAIL

	// insert rule into anchor
	err = ioctl(a.pf.fd.Fd(), DIOCCHANGERULE, uintptr(unsafe.Pointer(&rule)))
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

	err := ioctl(a.pf.fd.Fd(), DIOCCHANGERULE, uintptr(unsafe.Pointer(&rule)))
	if err != nil {
		return err
	}

	rule.action = PF_CHANGE_REMOVE

	err = ioctl(a.pf.fd.Fd(), DIOCCHANGERULE, uintptr(unsafe.Pointer(&rule)))
	if err != nil {
		return err
	}

	return nil
}
