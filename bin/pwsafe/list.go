package main

import (
	"flag"
	"fmt"
	"os"
	"regexp"
	"strings"
	"time"

	"github.com/atotto/clipboard"
	"github.com/azdagron/pwsafe"
)

type listCommand struct {
	commonParams
	Filter    string
	Unmask    bool
	Clipboard bool
}

func (c *listCommand) ConfigureFlags(flagset *flag.FlagSet) {
	c.commonParams.AddFlags(flagset)
	flagset.StringVar(&c.Filter, "filter", "", "regex used to filter list entries by title or group")
	flagset.BoolVar(&c.Unmask, "unmask", false, "if true, shows the passwords")
	flagset.BoolVar(&c.Clipboard, "clipboard", false, "if true, copies password to clipboard")
}

func (c *listCommand) Execute(args []string) (err error) {
	masker := func(x string) string {
		if c.Unmask {
			return x
		}
		if c.Clipboard {
			if err := clipboard.WriteAll(x); err != nil {
				fmt.Fprintf(os.Stderr, "error copying to clipboard: %s", err)
			}
		}
		return strings.Repeat("*", len(x))
	}

	db, err := pwsafe.Load(c.Path, makePassphraseFn(c.Passphrase))
	if err != nil {
		return err
	}

	var re *regexp.Regexp
	if c.Filter != "" {
		re, err = regexp.Compile(c.Filter)
		if err != nil {
			return err
		}
	}

	for _, record := range db.Records() {
		if re != nil &&
			!re.MatchString(record.Group) &&
			!re.MatchString(record.Title) {
			continue
		}
		fmt.Println("[", record.UUID, "]")
		printFields([]fieldDescription{
			{"Title", record.Title},
			{"Username", record.Username},
			{"Password", masker(record.Password)},
			{"Notes", record.Notes},
			{"Group", record.Group},
			{"URL", record.URL},
			{"Ctime", record.Ctime},
			{"Atime", record.Atime},
			{"Mtime", record.Mtime},
		})
		fmt.Println()
	}
	return nil
}

type fieldDescription struct {
	name  string
	value interface{}
}

func indent(s string, n int) string {
	return strings.Replace(s, "\n", "\n"+strings.Repeat(" ", n), -1)
}

func printFields(fields []fieldDescription) {
	width := 0
	for _, field := range fields {
		if width < len(field.name) {
			width = len(field.name)
		}
	}

	format := fmt.Sprintf("    %%-%ds: %%s\n", width+1)
	// calculate indentation (-1 for newline)
	indentation := len(fmt.Sprintf(format, "", "")) - 1
	for _, field := range fields {
		var value string
		switch t := field.value.(type) {
		case time.Time:
			if !t.IsZero() {
				value = t.String()
			}
		case string:
			value = t
		default:
		}
		if len(value) == 0 {
			continue
		}
		fmt.Printf(format, field.name, indent(value, indentation))
	}
}
