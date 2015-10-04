package main

import (
	"flag"
	"fmt"
	"os"
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
	if reason != "" {
		fmt.Println(reason)
	}
	fmt.Println("usage: %s <command> (command args)")
	if reason != "" {
		os.Exit(-1)
	} else {
		os.Exit(0)
	}
}
