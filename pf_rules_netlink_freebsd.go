package pf

import "fmt"

// Attribute and command numbers from netpfil/pf/pf_nl.h.
const (
	pfnlCmdGetRules = 6
	pfnlCmdGetRule  = 7
	pfnlVersion     = 0

	pfGRAnchor = 1
	pfGRAction = 2
	pfGRNr     = 3
	pfGRTicket = 4

	pfRTLabels      = 4
	pfRTIfname      = 5
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

	pfLTLabel = 1
)

// ruleStatsNetlink reads per-rule counters over generic netlink, the only
// interface FreeBSD 15 offers for them.
func ruleStatsNetlink(anchor string) ([]RuleStats, error) {
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

	rules := make([]RuleStats, 0, count)

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
			a := parseAttrs(r)

			action := attrU8(a, pfRTAction)
			dir := attrU8(a, pfRTDirection)

			rs := RuleStats{
				Nr:          nr,
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
