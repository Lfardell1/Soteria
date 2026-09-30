package main

import (
	"flag"
	"fmt"
	"os"
	"path/filepath"

	"github.com/Lfardell1/Soteria/internal/config"
	"github.com/Lfardell1/Soteria/internal/session"
)

func main() {
	configPath := flag.String("config", defaultConfigPath(), "path to Soteria config JSON")
	flag.Parse()

	cfg, err := config.Load(*configPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "soteria: load config: %v\n", err)
		os.Exit(1)
	}

	sess := session.New(cfg)
	if err := sess.Start(); err != nil {
		fmt.Fprintf(os.Stderr, "soteria: %v\n", err)
		os.Exit(1)
	}
}

func defaultConfigPath() string {
	candidates := []string{
		"config/config.json",
		"/etc/soteria/config.json",
	}
	if exe, err := os.Executable(); err == nil {
		candidates = append([]string{
			filepath.Join(filepath.Dir(exe), "config", "config.json"),
		}, candidates...)
	}
	for _, c := range candidates {
		if _, err := os.Stat(c); err == nil {
			return c
		}
	}
	return "config/config.json"
}
