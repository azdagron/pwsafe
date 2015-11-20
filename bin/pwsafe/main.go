package main

import (
	"flag"
	"fmt"
	"os"
	"path"
)

func main() {
	err := maine()
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func maine() (err error) {
	commands := map[string]command{
		"list": &listCommand{},
	}

	var cmdname string
	if len(os.Args) > 1 {
		cmdname = os.Args[1]
	} else {
		usage("missing command")
	}

	cmd := commands[cmdname]
	if cmd == nil {
		// help
		return nil
	}

	flagset := flag.NewFlagSet(cmdname, flag.ExitOnError)
	cmd.ConfigureFlags(flagset)
	if err = flagset.Parse(os.Args[2:]); err != nil {
		return err
	}

	return cmd.Execute(flagset.Args())
}

func usage(reason string) {
	r := os.Stdout
	if reason != "" {
		r := os.Stderr
		fmt.Fprintln(r, reason)
	}
	fmt.Fprintf(r, "usage: %s <command> (command args)\n",
		path.Base(os.Args[0]))
	if reason != "" {
		os.Exit(-1)
	} else {
		os.Exit(0)
	}
}
