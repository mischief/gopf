package pf

import (
	"net"
	"testing"
)

func TestPfOpen(t *testing.T) {
	pf, err := Open()
	if err != nil {
		t.Fatal(err)
	}
	pf.Close()
}

func TestPfStats(t *testing.T) {
	pf, err := Open()
	if err != nil {
		t.Fatal(err)
	}
	defer pf.Close()

	stats, err := pf.Stats()
	if err != nil {
		t.Fatal(err)
	}

	ifstats := stats.IfStats()
	if ifstats == nil {
		t.Log("no ifstats")
	} else {
		t.Logf("ifstats: %+v", ifstats)
	}
}

func TestPfAnchors(t *testing.T) {
	pf, err := Open()
	if err != nil {
		t.Fatal(err)
	}
	defer pf.Close()

	anchors, err := pf.Anchors()
	if err != nil {
		t.Fatal(err)
	}

	for _, a := range anchors {
		t.Logf("anchor: %s", a)
	}
}

func TestPfInsertDelete(t *testing.T) {
	pf, err := Open()
	if err != nil {
		t.Fatal(err)
	}
	defer pf.Close()

	/* root ruleset */
	anchor, err := pf.Anchor("ports")
	if err != nil {
		t.Fatal(err)
	}

	_, rdr, _ := net.ParseCIDR("127.0.0.1/32")

	r := &Rule{
		Action:    Pass,
		Direction: In,
		Log:       true,
		Interface: "egress",
		Tag:       "gopftest",
		Src:       Target{Addr: IPAny},
		Dst:       Target{Addr: AddrDynIf{"egress"}, Port: 8888},
		Rdr:       &Target{Addr: AddrIPMask{*rdr}, Port: 22},
	}

	err = anchor.Insert(r)
	if err != nil {
		t.Fatal(err)
	}

	err = anchor.DeleteIndex(0)
	if err != nil {
		t.Fatal(err)
	}
}

func TestPfRules(t *testing.T) {
	pf, err := Open()
	if err != nil {
		t.Fatal(err)
	}
	defer pf.Close()

	anchors := []string{""}
	a, err := pf.Anchors()
	if err != nil {
		t.Fatal(err)
	}

	anchors = append(anchors, a...)

	for _, aname := range anchors {
		t.Logf("anchor %q", aname)
		anchor, err := pf.Anchor(aname)
		if err != nil {
			t.Fatal(err)
		}

		rules, err := anchor.Rules()
		if err != nil {
			t.Fatal(err)
		}

		for _, a := range rules {
			t.Logf("rule: %+v", a)
		}
	}
}
