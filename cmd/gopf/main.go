package main

import (
	"fmt"
	"strings"
	"os"

	"github.com/mischief/gopf"
)

const exUsage = 64
const exOserr = 71

func stats(handle pf.Pf) error {
	st, err := handle.Stats()
	if err != nil {
		return err
	}

	fmt.Println("Enabled:", st.Enabled())
	fmt.Println("States:", st.StateCount())
	fmt.Println("State Searches:", st.StateSearches())
	fmt.Println("State Inserts:", st.StateInserts())
	fmt.Println("State Removals:", st.StateRemovals())

	ifs := st.IfStats()
	if ifs == nil {
		fmt.Println("No interface stats")
	} else {
		fmt.Println("Interface stats:", ifs.Name)
		fmt.Printf("IPv4: %+v\n", ifs.IPv4)
		fmt.Printf("IPv6: %+v\n", ifs.IPv6)
	}

	return nil
}

func queues(handle pf.Pf) error {
	queues, err := handle.Queues()
	if err != nil {
		return err
	}

	for _, q := range queues {
		fmt.Printf("%+v\n", q)
	}

	return nil
}

var subc = map[string]func(pf.Pf) error{
	"stats":  stats,
	"queues": queues,
}

func fatal(exc int, err error) {
	fmt.Fprintf(os.Stderr, "error: %s\n", err)
	os.Exit(exc)
}

func usage() {
	cmds := []string{}
	for k := range subc {
		cmds = append(cmds, k)
	}

	fmt.Fprintf(os.Stderr, "usage: %s %s\n", os.Args[0], strings.Join(cmds, "|"))
	os.Exit(exUsage)
}

func main() {
	if len(os.Args) < 2 {
		usage()
	}
	handle, err := pf.Open()
	if err != nil {
		fatal(exOserr, err)
	}

	defer handle.Close()

	c, ok := subc[os.Args[1]]
	if !ok {
		usage()
	}

	if err := c(handle); err != nil {
		fatal(exOserr, err)
	}
}
