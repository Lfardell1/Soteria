// Package cli parses the public, unprivileged Soteria workflow.
package cli

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"runtime"
	"strconv"
	"strings"
	"unicode"
	"unicode/utf8"

	"github.com/Lfardell1/Soteria/internal/buildinfo"
	"github.com/Lfardell1/Soteria/internal/client"
	"github.com/Lfardell1/Soteria/internal/config"
	"github.com/Lfardell1/Soteria/internal/doctor"
)

const defaultConfigPath = "/etc/soteria/config.json"

const usage = `Usage:
  soteria run [OPTIONS] -- COMMAND ARG...
  soteria shell [OPTIONS]
  soteria doctor [--json] [--config ABS]
  soteria config check [--config ABS]
  soteria version
  soteria cleanup SESSION_ID
  soteria help [COMMAND]

Run/shell options:
  --config ABS             Strict version-1 JSON at a clean absolute path
  --network offline        Default, even if the config requests WireGuard
  --network wireguard --profile NAME
                           Explicitly select an administrator-provisioned profile
  --import HOST_PATH       Copy to /work/in/<basename>; repeatable
  --export HOST_DIRECTORY  Export /work/out to an existing directory, no overwrite

Configuration: /etc/soteria/config.json if it exists, otherwise explicit built-in
offline defaults. No current-directory or executable-relative discovery.
WireGuard requires BOTH explicit flags; configuration alone never enables it.
Commands execute argv directly in the curated runtime, never an implicit shell.
shell executes /bin/bash --noprofile --norc -i and requires terminal stdin/stdout.
For scripted Bash use run -- /bin/bash --noprofile --norc [ARG...].

Run as a non-root caller. Only run/shell/cleanup request one-shot authorization.
Linux amd64, Debian 13 or Ubuntu 24.04, systemd/cgroup v2, and an administrator-
installed runtime are required. Disposable VM backends are not implemented.
Doctor/config/version/help do not activate services, networking or privilege.
Swap/dump limitations warn; required isolation failures remain fatal.
On signal, disconnect or command failure, no export is authorized. Partial
multi-file exports are not rolled back. Stdout and exports may persist on host.
Exit status: child status, 125 infrastructure/cleanup failure, 2 invalid syntax.
`

var commandUsage = map[string]string{
	"run":     "Usage: soteria run [OPTIONS] -- COMMAND ARG...\nArguments after -- are passed unchanged, not through a shell. See soteria help.\n",
	"shell":   "Usage: soteria shell [OPTIONS]\nExecutes /bin/bash --noprofile --norc -i in a fresh PTY; stdin and stdout must be terminals.\nFor non-TTY Bash: soteria run -- /bin/bash --noprofile --norc [ARG...].\n",
	"doctor":  "Usage: soteria doctor [--json] [--config ABS]\nRead-only checks; no credential loading, authorization, service or network activation.\n",
	"config":  "Usage: soteria config check [--config ABS]\nValidate selected settings without opening profiles, keys or runtime services.\n",
	"version": "Usage: soteria version\n",
	"cleanup": "Usage: soteria cleanup SESSION_ID\nRequest cleanup of owned stale resources for one 32-character lowercase hexadecimal session ID.\n",
}

func Run(ctx context.Context, args []string, streams client.Streams) int {
	if streams.In == nil || streams.Out == nil || streams.Err == nil {
		return client.InfrastructureExit
	}
	if len(args) == 0 {
		return usageError(streams, "a command is required", usage)
	}
	switch args[0] {
	case "help", "--help", "-h":
		if len(args) == 1 {
			return output(streams, usage)
		}
		if args[0] == "help" && len(args) == 2 {
			if text, ok := commandUsage[args[1]]; ok {
				return output(streams, text)
			}
		}
		return usageError(streams, "help requires a public command name", usage)
	case "run", "shell":
		return runCommand(ctx, args[0], args[1:], streams)
	case "doctor":
		return doctorCommand(ctx, args[1:], streams)
	case "config":
		return configCommand(args[1:], streams)
	case "version":
		fs := flags("version")
		if err := fs.Parse(args[1:]); err != nil {
			return flagError(streams, err, commandUsage["version"])
		}
		if fs.NArg() != 0 {
			return usageError(streams, "version accepts no arguments", commandUsage["version"])
		}
		return output(streams, fmt.Sprintf("soteria %s\ncommit: %s\nruntime digest: %s\nGo: %s\nplatform: %s/%s\n",
			clean(buildinfo.Version, 128), clean(buildinfo.Commit, 128), clean(buildinfo.RuntimeDigest, 128), runtime.Version(), runtime.GOOS, runtime.GOARCH))
	case "cleanup":
		return cleanupCommand(ctx, args[1:], streams)
	default:
		return usageError(streams, "unknown command "+strconv.Quote(args[0]), usage)
	}
}

type repeatedPaths []string

func (p *repeatedPaths) String() string { return "" }
func (p *repeatedPaths) Set(value string) error {
	if value == "" || strings.ContainsRune(value, 0) {
		return errors.New("import path must be nonempty and contain no NUL")
	}
	*p = append(*p, value)
	return nil
}

type runOptions struct {
	path           string
	network        string
	profile        string
	export         string
	imports        repeatedPaths
	argv           []string
	configExplicit bool
	netExplicit    bool
	profileSet     bool
}

func parseRun(args []string, shell bool) (runOptions, error) {
	var options runOptions
	fs := flags("run")
	fs.StringVar(&options.path, "config", "", "absolute config path")
	fs.StringVar(&options.network, "network", "offline", "offline or wireguard")
	fs.StringVar(&options.profile, "profile", "", "profile ID")
	fs.StringVar(&options.export, "export", "", "existing output directory")
	fs.Var(&options.imports, "import", "input path (repeatable)")
	optionArgs := args
	separator := -1
	if !shell {
		for i, arg := range args {
			if arg == "--" {
				separator = i
				optionArgs, options.argv = args[:i], append([]string(nil), args[i+1:]...)
				break
			}
		}
	}
	if err := fs.Parse(optionArgs); err != nil {
		return options, err
	}
	if fs.NArg() != 0 {
		return options, errors.New("unexpected positional argument; options must precede -- COMMAND")
	}
	if shell {
		options.argv = []string{"/bin/bash", "--noprofile", "--norc", "-i"}
	} else if separator < 0 {
		return options, errors.New("run requires -- followed by COMMAND ARG...")
	}
	present := presence(fs)
	options.configExplicit, options.netExplicit, options.profileSet = present["config"], present["network"], present["profile"]
	if present["export"] && (options.export == "" || strings.ContainsRune(options.export, 0)) {
		return options, errors.New("export directory must be nonempty and contain no NUL")
	}
	if len(options.argv) == 0 || len(options.argv) > 256 || options.argv[0] == "" {
		return options, errors.New("command requires 1..256 argv entries")
	}
	bytes := 0
	for _, arg := range options.argv {
		if strings.ContainsRune(arg, 0) || !utf8.ValidString(arg) {
			return options, errors.New("command arguments must be UTF-8 without NUL")
		}
		bytes += len(arg) + 1
		if bytes > 32<<10 {
			return options, errors.New("command argv exceeds 32 KiB")
		}
	}
	return options, nil
}

func applyNetwork(cfg config.Config, options runOptions) (config.Config, error) {
	switch options.network {
	case "offline":
		if options.profileSet {
			return cfg, errors.New("--profile requires explicit --network=wireguard")
		}
		cfg.Network = config.NetworkConfig{Mode: "offline"}
	case "wireguard":
		if !options.netExplicit || !options.profileSet || options.profile == "" {
			return cfg, errors.New("WireGuard requires both explicit --network=wireguard and --profile NAME")
		}
		cfg.Network = config.NetworkConfig{Mode: "wireguard", Profile: options.profile}
	default:
		return cfg, errors.New("--network must be offline or wireguard")
	}
	return cfg, cfg.Validate()
}

func runCommand(ctx context.Context, command string, args []string, streams client.Streams) int {
	options, err := parseRun(args, command == "shell")
	if err != nil {
		return flagError(streams, err, commandUsage[command])
	}
	selected, err := selectConfig(options.path, options.configExplicit, defaultConfigPath)
	if err != nil {
		diagnostic(streams.Err, "configuration: "+err.Error())
		return client.InfrastructureExit
	}
	configuredNetwork := selected.cfg.Network.Mode
	selected.cfg, err = applyNetwork(selected.cfg, options)
	if err != nil {
		return usageError(streams, err.Error(), commandUsage[command])
	}
	if err := showConfig(streams.Err, selected); err != nil {
		return client.InfrastructureExit
	}
	if configuredNetwork == "wireguard" && selected.cfg.Network.Mode == "offline" {
		diagnostic(streams.Err, "configured WireGuard is not activated without explicit --network=wireguard --profile NAME; using offline")
	}
	if err := doctor.SupportError(runtime.GOOS, runtime.GOARCH); err != nil {
		diagnostic(streams.Err, err.Error())
		return client.InfrastructureExit
	}
	code, err := client.Run(ctx, client.Request{
		Config: selected.cfg, Argv: options.argv, Imports: options.imports,
		ExportDirectory: options.export, RequireTTY: command == "shell",
	}, streams)
	if err != nil {
		diagnostic(streams.Err, err.Error())
		return client.InfrastructureExit
	}
	return code
}

type selection struct {
	cfg    config.Config
	source string
}

func selectConfig(path string, explicit bool, defaultPath string) (selection, error) {
	if !explicit {
		if _, err := os.Lstat(defaultPath); errors.Is(err, os.ErrNotExist) {
			return selection{cfg: config.Default(), source: "built-in defaults (explicit builtin; no config file)"}, nil
		} else if err != nil {
			return selection{}, fmt.Errorf("inspect default config: %w", err)
		}
		path = defaultPath
	}
	cfg, err := config.Load(path)
	return selection{cfg: cfg, source: strconv.Quote(path)}, err
}

func showConfig(w io.Writer, selected selection) error {
	cfg := selected.cfg
	for _, size := range []*string{&cfg.Resources.MemoryMax, &cfg.Resources.WorkspaceSize, &cfg.Transfers.MaxBytes} {
		value, _ := config.ParseSize(*size)
		*size = config.FormatSize(value)
	}
	if cfg.Network.Profile != "" {
		cfg.Network.Profile = "<redacted>"
	}
	settings, err := json.Marshal(cfg)
	if err != nil {
		return err
	}
	_, err = fmt.Fprintf(w, "soteria: configuration: %s\nsoteria: effective settings (redacted): %s\n", clean(selected.source, 512), settings)
	return err
}

func doctorCommand(ctx context.Context, args []string, streams client.Streams) int {
	fs := flags("doctor")
	asJSON := fs.Bool("json", false, "JSON diagnostics")
	path := fs.String("config", "", "absolute config path")
	if err := fs.Parse(args); err != nil {
		return flagError(streams, err, commandUsage["doctor"])
	}
	if fs.NArg() != 0 {
		return usageError(streams, "doctor accepts no positional arguments", commandUsage["doctor"])
	}
	selected, err := selectConfig(*path, presence(fs)["config"], defaultConfigPath)
	if err != nil {
		diagnostic(streams.Err, "configuration: "+err.Error())
		return 1
	}
	if err := showConfig(streams.Err, selected); err != nil {
		return client.InfrastructureExit
	}
	report := doctor.Check(ctx, selected.cfg)
	if *asJSON {
		encoder := json.NewEncoder(streams.Out)
		encoder.SetIndent("", "  ")
		err = encoder.Encode(report)
	} else {
		_, err = fmt.Fprintln(streams.Out, "Soteria read-only diagnostics; no activation or privileged runtime checks")
		for _, check := range report.Checks {
			if err != nil {
				break
			}
			_, err = fmt.Fprintf(streams.Out, "%s %s: %s\n", clean(check.Status, 32), clean(check.Name, 64), clean(check.Detail, 768))
		}
	}
	if err != nil {
		diagnostic(streams.Err, "write diagnostics: "+err.Error())
		return client.InfrastructureExit
	}
	if !report.OK() {
		return 1
	}
	return 0
}

func configCommand(args []string, streams client.Streams) int {
	if len(args) == 1 && (args[0] == "--help" || args[0] == "-h") {
		return output(streams, commandUsage["config"])
	}
	if len(args) == 0 || args[0] != "check" {
		return usageError(streams, "config requires check", commandUsage["config"])
	}
	fs := flags("config check")
	path := fs.String("config", "", "absolute config path")
	if err := fs.Parse(args[1:]); err != nil {
		return flagError(streams, err, commandUsage["config"])
	}
	if fs.NArg() != 0 {
		return usageError(streams, "config check accepts no positional arguments", commandUsage["config"])
	}
	selected, err := selectConfig(*path, presence(fs)["config"], defaultConfigPath)
	if err != nil {
		diagnostic(streams.Err, "configuration: "+err.Error())
		return 1
	}
	if err := showConfig(streams.Out, selected); err != nil {
		return client.InfrastructureExit
	}
	return output(streams, "Configuration is valid. Profiles, keys and runtime prerequisites were not opened or activated.\n")
}

func cleanupCommand(ctx context.Context, args []string, streams client.Streams) int {
	fs := flags("cleanup")
	if err := fs.Parse(args); err != nil {
		return flagError(streams, err, commandUsage["cleanup"])
	}
	if fs.NArg() != 1 || !validSessionID(fs.Arg(0)) {
		return usageError(streams, "cleanup requires one 32-character lowercase hexadecimal session ID", commandUsage["cleanup"])
	}
	code, err := client.Cleanup(ctx, fs.Arg(0), streams)
	if err != nil {
		diagnostic(streams.Err, "cleanup: "+err.Error())
		return client.InfrastructureExit
	}
	return code
}

func validSessionID(id string) bool {
	if len(id) != 32 {
		return false
	}
	for _, c := range id {
		if !(c >= '0' && c <= '9' || c >= 'a' && c <= 'f') {
			return false
		}
	}
	return true
}

func flags(name string) *flag.FlagSet {
	fs := flag.NewFlagSet(name, flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	fs.Usage = func() {}
	return fs
}

func presence(fs *flag.FlagSet) map[string]bool {
	present := make(map[string]bool)
	fs.Visit(func(f *flag.Flag) { present[f.Name] = true })
	return present
}

func flagError(streams client.Streams, err error, text string) int {
	if errors.Is(err, flag.ErrHelp) {
		return output(streams, text)
	}
	return usageError(streams, err.Error(), text)
}

func usageError(streams client.Streams, message, text string) int {
	diagnostic(streams.Err, message)
	_, _ = io.WriteString(streams.Err, text)
	return 2
}

func output(streams client.Streams, text string) int {
	if _, err := io.WriteString(streams.Out, text); err != nil {
		diagnostic(streams.Err, "write output: "+err.Error())
		return client.InfrastructureExit
	}
	return 0
}

func diagnostic(w io.Writer, text string) {
	_, _ = fmt.Fprintln(w, "soteria: "+clean(text, 1024))
}

func clean(text string, limit int) string {
	var b strings.Builder
	for _, r := range text {
		if unicode.IsControl(r) || unicode.Is(unicode.Cf, r) {
			r = ' '
		}
		if b.Len()+len(string(r)) > limit-3 {
			b.WriteString("...")
			break
		}
		b.WriteRune(r)
	}
	return b.String()
}
