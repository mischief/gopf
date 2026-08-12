package pf

import (
	"encoding/binary"
	"fmt"
	"syscall"
	"time"
)

// Minimal generic netlink client. FreeBSD 15 serves pf rules here only.
const (
	afNetlink       = 38
	netlinkGeneric  = 16
	genlIDCtrl      = 16
	genlCtrlVersion = 2

	ctrlCmdGetFamily   = 3
	ctrlAttrFamilyID   = 1
	ctrlAttrFamilyName = 2

	nlmsgError = 2
	nlmsgDone  = 3

	nlmFRequest = 1
	nlmFAck     = 4

	nlmsgHdrLen = 16
	genlHdrLen  = 4
	nlaHdrLen   = 4
)

var native = binary.LittleEndian

type netlinkConn struct {
	fd     int
	seq    uint32
	family uint16
}

func nlAlign(n int) int {
	return (n + 3) &^ 3
}

func putAttr(b []byte, typ uint16, payload []byte) []byte {
	l := nlaHdrLen + len(payload)
	hdr := make([]byte, nlaHdrLen)
	native.PutUint16(hdr[0:2], uint16(l))
	native.PutUint16(hdr[2:4], typ)
	b = append(b, hdr...)
	b = append(b, payload...)
	for pad := nlAlign(l) - l; pad > 0; pad-- {
		b = append(b, 0)
	}
	return b
}

func putAttrString(b []byte, typ uint16, s string) []byte {
	return putAttr(b, typ, append([]byte(s), 0))
}

func putAttrU32(b []byte, typ uint16, v uint32) []byte {
	var p [4]byte
	native.PutUint32(p[:], v)
	return putAttr(b, typ, p[:])
}

func putAttrU8(b []byte, typ uint16, v uint8) []byte {
	return putAttr(b, typ, []byte{v})
}

// parseAttrs splits a netlink attribute stream. Repeated types keep the last
// value, which is all the pf rule attributes need.
func parseAttrs(b []byte) map[uint16][]byte {
	attrs := make(map[uint16][]byte)

	for len(b) >= nlaHdrLen {
		l := int(native.Uint16(b[0:2]))
		typ := native.Uint16(b[2:4]) & 0x3fff

		if l < nlaHdrLen || l > len(b) {
			break
		}

		attrs[typ] = b[nlaHdrLen:l]

		step := nlAlign(l)
		if step > len(b) {
			break
		}
		b = b[step:]
	}

	return attrs
}

func attrU8(attrs map[uint16][]byte, typ uint16) uint8 {
	if v, ok := attrs[typ]; ok && len(v) >= 1 {
		return v[0]
	}
	return 0
}

func attrU32(attrs map[uint16][]byte, typ uint16) uint32 {
	if v, ok := attrs[typ]; ok && len(v) >= 4 {
		return native.Uint32(v)
	}
	return 0
}

func attrU64(attrs map[uint16][]byte, typ uint16) uint64 {
	if v, ok := attrs[typ]; ok && len(v) >= 8 {
		return native.Uint64(v)
	}
	return 0
}

func attrString(attrs map[uint16][]byte, typ uint16) string {
	v, ok := attrs[typ]
	if !ok {
		return ""
	}
	for i, c := range v {
		if c == 0 {
			return string(v[:i])
		}
	}
	return string(v)
}

func nldial() (*netlinkConn, error) {
	fd, err := syscall.Socket(afNetlink, syscall.SOCK_RAW, netlinkGeneric)
	if err != nil {
		return nil, fmt.Errorf("netlink socket: %w", err)
	}

	tv := syscall.NsecToTimeval(int64(5 * time.Second))
	if err := syscall.SetsockoptTimeval(fd, syscall.SOL_SOCKET, syscall.SO_RCVTIMEO, &tv); err != nil {
		syscall.Close(fd)
		return nil, fmt.Errorf("netlink timeout: %w", err)
	}

	c := &netlinkConn{fd: fd}

	family, err := c.resolveFamily("pfctl")
	if err != nil {
		c.Close()
		return nil, err
	}
	c.family = family

	return c, nil
}

func (c *netlinkConn) Close() error {
	return syscall.Close(c.fd)
}

// exec sends one generic netlink command and returns the payload of every
// reply message, with the netlink and genl headers stripped.
func (c *netlinkConn) exec(family uint16, cmd, version uint8, attrs []byte) ([][]byte, error) {
	c.seq++
	seq := c.seq

	msg := make([]byte, nlmsgHdrLen+genlHdrLen)
	native.PutUint32(msg[0:4], uint32(len(msg)+len(attrs)))
	native.PutUint16(msg[4:6], family)
	native.PutUint16(msg[6:8], nlmFRequest|nlmFAck)
	native.PutUint32(msg[8:12], seq)
	msg[nlmsgHdrLen] = cmd
	msg[nlmsgHdrLen+1] = version
	msg = append(msg, attrs...)

	if _, err := syscall.Write(c.fd, msg); err != nil {
		return nil, fmt.Errorf("netlink send: %w", err)
	}

	var payloads [][]byte
	buf := make([]byte, 65536)

	for {
		n, err := syscall.Read(c.fd, buf)
		if err != nil {
			return nil, fmt.Errorf("netlink recv: %w", err)
		}

		b := buf[:n]
		done := false

		for len(b) >= nlmsgHdrLen {
			l := int(native.Uint32(b[0:4]))
			typ := native.Uint16(b[4:6])

			if l < nlmsgHdrLen || l > len(b) {
				return nil, fmt.Errorf("netlink: short message")
			}

			switch typ {
			case nlmsgError:
				code := int32(native.Uint32(b[nlmsgHdrLen : nlmsgHdrLen+4]))
				if code != 0 {
					return nil, fmt.Errorf("netlink: %w", syscall.Errno(-code))
				}
				done = true
			case nlmsgDone:
				done = true
			default:
				if l > nlmsgHdrLen+genlHdrLen {
					p := make([]byte, l-nlmsgHdrLen-genlHdrLen)
					copy(p, b[nlmsgHdrLen+genlHdrLen:l])
					payloads = append(payloads, p)
				}
			}

			b = b[nlAlign(l):]
		}

		if done {
			return payloads, nil
		}
	}
}

func (c *netlinkConn) resolveFamily(name string) (uint16, error) {
	attrs := putAttrString(nil, ctrlAttrFamilyName, name)

	replies, err := c.exec(genlIDCtrl, ctrlCmdGetFamily, genlCtrlVersion, attrs)
	if err != nil {
		return 0, err
	}

	for _, r := range replies {
		a := parseAttrs(r)
		if v, ok := a[ctrlAttrFamilyID]; ok && len(v) >= 2 {
			return native.Uint16(v), nil
		}
	}

	return 0, fmt.Errorf("netlink: no such genl family %q", name)
}
