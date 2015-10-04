package main

import (
	"flag"
	"os/user"
	"path/filepath"

	"github.com/bgentry/speakeasy"
)

type command interface {
	ConfigureFlags(flagset *flag.FlagSet)
	Execute(args []string) error
}

type commonParams struct {
	Path       string
	Passphrase string
}

func (p *commonParams) AddFlags(flagset *flag.FlagSet) {
	flagset.StringVar(&p.Path, "path", defaultPath(), "path to database")
	flagset.StringVar(&p.Passphrase, "passphrase", "", "database passphrase")
}

func defaultPath() string {
	u, err := user.Current()
	if err != nil {
		panic(err)
	}
	return filepath.Join(u.HomeDir, "default.psafe")
}

func makePassphraseFn(passphrase string) func() (string, error) {
	return func() (string, error) {
		if passphrase == "" {
			return speakeasy.Ask("Passphrase: ")
		} else {
			return passphrase, nil
		}
	}
}
