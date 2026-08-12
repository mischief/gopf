package pf

import (
	"fmt"
	"net"
)

// Attribute and command numbers from netpfil/pf/pf_nl.h.
const (
	pfnlCmdGetRules = 6
	pfnlCmdGetRule  = 7
	pfnlVersion     = 0

	pfGRAnchor = 1
	pfGRAction = 2
	pfGRNr     = 3
	pfGRTicket = 4

	pfRTSrc         = 1
	pfRTDst         = 2
	pfRTLabels      = 4
	pfRTIfname      = 5
	pfRTTagname     = 8
	pfRTNr          = 23
	pfRTAction      = 34
	pfRTDirection   = 35
	pfRTAf          = 43
	pfRTProto       = 44
	pfRTPacketsIn   = 63
	pfRTPacketsOut  = 64
	pfRTBytesIn     = 65
	pfRTBytesOut    = 66
	pfRTEvaluations = 67
	pfRTStatesCur   = 69
	pfRTStatesTotal = 70

	pfRTLog   = 36
	pfRTQuick = 38

	pfRATAddr    = 1
	pfRATSrcPort = 2

	pfATAddr      = 1
	pfATMask      = 2
	pfATIfname    = 3
	pfATTablename = 4
	pfATType      = 5

	pfLTLabel = 1
)

// fetchRulesNetlink returns the attribute set of every rule in an anchor.
func fetchRulesNetlink(anchor string) ([]map[uint16][]byte, error) {
	c, err := nldial()
	if err != nil {
		return nil, err
	}
	defer c.Close()

	req := putAttrString(nil, pfGRAnchor, anchor)

	replies, err := c.exec(c.family, pfnlCmdGetRules, pfnlVersion, req)
	if err != nil {
		return nil, fmt.Errorf("pf: getrules: %w", err)
	}

	var count, ticket uint32
	for _, r := range replies {
		a := parseAttrs(r)
		if v := attrU32(a, pfGRNr); v != 0 {
			count = v
		}
		if v := attrU32(a, pfGRTicket); v != 0 {
			ticket = v
		}
	}

	rules := make([]map[uint16][]byte, 0, count)

	for nr := uint32(0); nr < count; nr++ {
		req := putAttrString(nil, pfGRAnchor, anchor)
		req = putAttrU32(req, pfGRTicket, ticket)
		req = putAttrU32(req, pfGRNr, nr)
		req = putAttrU8(req, pfGRAction, 0)

		replies, err := c.exec(c.family, pfnlCmdGetRule, pfnlVersion, req)
		if err != nil {
			return nil, fmt.Errorf("pf: getrule %d: %w", nr, err)
		}

		for _, r := range replies {
			rules = append(rules, parseAttrs(r))
		}
	}

	return rules, nil
}

// ruleStatsNetlink reads per-rule counters over generic netlink, the only
// interface FreeBSD 15 offers for them.
func ruleStatsNetlink(anchor string) ([]RuleStats, error) {
	fetched, err := fetchRulesNetlink(anchor)
	if err != nil {
		return nil, err
	}

	rules := make([]RuleStats, 0, len(fetched))

	for nr, a := range fetched {
		action := attrU8(a, pfRTAction)
		dir := attrU8(a, pfRTDirection)

		rs := RuleStats{
			Nr:          uint32(nr),
			Anchor:      anchor,
			Interface:   attrString(a, pfRTIfname),
			Proto:       protoName(attrU8(a, pfRTProto)),
			AF:          afName(attrU8(a, pfRTAf)),
			Evaluations: attrU64(a, pfRTEvaluations),
			PacketsIn:   attrU64(a, pfRTPacketsIn),
			PacketsOut:  attrU64(a, pfRTPacketsOut),
			BytesIn:     attrU64(a, pfRTBytesIn),
			BytesOut:    attrU64(a, pfRTBytesOut),
			StatesCur:   attrU64(a, pfRTStatesCur),
			StatesTot:   attrU64(a, pfRTStatesTotal),
		}

		if int(action) < len(actiontypes) {
			rs.Action = actiontypes[action]
		}
		if int(dir) < len(dirtypes) {
			rs.Direction = dirtypes[dir]
		}
		if nested, ok := a[pfRTLabels]; ok {
			rs.Label = attrString(parseAttrs(nested), pfLTLabel)
		}

		rules = append(rules, rs)
	}

	return rules, nil
}

func afName(af uint8) string {
	switch af {
	case 2:
		return "inet"
	case 28:
		return "inet6"
	}
	return ""
}

func protoName(p uint8) string {
	switch p {
	case 1:
		return "icmp"
	case 6:
		return "tcp"
	case 17:
		return "udp"
	case 58:
		return "ipv6-icmp"
	case 0:
		return ""
	}
	return fmt.Sprintf("%d", p)
}

// rulesNetlink decodes the rules of an anchor into their printable form.
func rulesNetlink(anchor string) ([]Rule, error) {
	fetched, err := fetchRulesNetlink(anchor)
	if err != nil {
		return nil, err
	}

	rules := make([]Rule, 0, len(fetched))

	for nr, a := range fetched {
		af := attrU8(a, pfRTAf)

		r := Rule{
			Nr:        uint32(nr),
			Action:    Action(attrU8(a, pfRTAction)),
			Direction: Direction(attrU8(a, pfRTDirection)),
			Log:       attrU8(a, pfRTLog) != 0,
			Quick:     attrU8(a, pfRTQuick) != 0,
			Interface: attrString(a, pfRTIfname),
			Tag:       attrString(a, pfRTTagname),
			Src:       ruleTargetNetlink(a[pfRTSrc], af),
			Dst:       ruleTargetNetlink(a[pfRTDst], af),
		}

		rules = append(rules, r)
	}

	return rules, nil
}

// ruleTargetNetlink decodes one nested pf_rule_addr_type_t attribute.
func ruleTargetNetlink(b []byte, af uint8) Target {
	// Rule printing dereferences Addr, so never leave it nil.
	t := Target{Addr: AddrIPMask{net.IPNet{IP: net.IPv4zero, Mask: net.IPMask(net.IPv4zero)}}}

	if b == nil {
		return t
	}

	ra := parseAttrs(b)
	if v, ok := ra[pfRATSrcPort]; ok && len(v) >= 2 {
		t.Port = ntohs(native.Uint16(v))
	}

	nested, ok := ra[pfRATAddr]
	if !ok {
		return t
	}

	aa := parseAttrs(nested)

	switch attrU8(aa, pfATType) {
	case PF_ADDR_TABLE:
		t.Addr = AddrTable(attrString(aa, pfATTablename))
	case PF_ADDR_DYNIFTL:
		t.Addr = AddrDynIf{Interface: attrString(aa, pfATIfname)}
	case PF_ADDR_ADDRMASK:
		ip, ok := aa[pfATAddr]
		mask, ok2 := aa[pfATMask]
		if !ok || !ok2 || len(ip) < 16 || len(mask) < 16 {
			return t
		}

		n := 16
		if af == 2 {
			n = 4
		}

		t.Addr = AddrIPMask{net.IPNet{
			IP:   net.IP(append([]byte(nil), ip[:n]...)),
			Mask: net.IPMask(append([]byte(nil), mask[:n]...)),
		}}
	}

	return t
}
