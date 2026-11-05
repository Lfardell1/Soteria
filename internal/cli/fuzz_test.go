package cli

import (
	"reflect"
	"strings"
	"testing"
	"unicode/utf8"
)

func FuzzDirectArgv(f *testing.F) {
	f.Add("plain argument")
	f.Add("$(not-a-shell); '*.txt'\n")
	f.Add("\x00")
	f.Add("\xff")
	f.Fuzz(func(t *testing.T, argument string) {
		if len(argument) > 40<<10 {
			t.Skip()
		}
		argv := []string{"tool", argument}
		options, err := parseRun(append([]string{"--"}, argv...), false)
		valid := utf8.ValidString(argument) && !strings.ContainsRune(argument, 0) && len("tool")+len(argument)+2 <= 32<<10
		if valid != (err == nil) || err == nil && !reflect.DeepEqual(options.argv, argv) {
			t.Fatalf("argv changed or validation bypassed: argv=%q parsed=%q err=%v", argv, options.argv, err)
		}
	})
}
