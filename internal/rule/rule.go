package rule

import (
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"gopkg.in/yaml.v3"
)

type Alert struct {
	RuleID   string
	Severity string
	Message  string
}

type Engine struct {
	config Config
}

type Config struct {
	Version    int        `yaml:"version"`
	ExecRules  []ExecRule `yaml:"exec_rules"`
	FileIgnore FileIgnore `yaml:"file_ignore"`
	FileRules  []FileRule `yaml:"file_rules"`
}

type ExecRule struct {
	ID       string   `yaml:"id"`
	Severity string   `yaml:"severity"`
	Message  string   `yaml:"message"`
	Commands []string `yaml:"commands"`
}

type FileIgnore struct {
	PathPrefixes []string           `yaml:"path_prefixes"`
	ByCommPrefix []CommPrefixIgnore `yaml:"by_comm_prefix"`
}

type CommPrefixIgnore struct {
	CommPrefix   string   `yaml:"comm_prefix"`
	Paths        []string `yaml:"paths"`
	PathPrefixes []string `yaml:"path_prefixes"`
}

type FileRule struct {
	ID            string   `yaml:"id"`
	Severity      string   `yaml:"severity"`
	Message       string   `yaml:"message"`
	Access        string   `yaml:"access"`
	Exact         []string `yaml:"exact"`
	Prefixes      []string `yaml:"prefixes"`
	ProcSensitive bool     `yaml:"proc_sensitive"`
}

func Load(path string) (*Engine, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}

	var config Config
	if err := yaml.Unmarshal(data, &config); err != nil {
		return nil, err
	}

	return &Engine{config: config}, nil
}

func (e *Engine) MatchExec(filename string, argv []string, containerID string) *Alert {
	if containerID == "" {
		return nil
	}

	cmd := filepath.Base(filename)
	if cmd == "." || cmd == "/" || cmd == "" {
		if len(argv) > 0 {
			cmd = filepath.Base(argv[0])
		}
	}

	for _, rule := range e.config.ExecRules {
		for _, candidate := range rule.Commands {
			if cmd == candidate {
				return &Alert{
					RuleID:   rule.ID,
					Severity: rule.Severity,
					Message:  rule.Message,
				}
			}
		}
	}

	return nil
}

func (e *Engine) MatchFile(path string, flags uint32, containerID string) *Alert {
	if containerID == "" || path == "" {
		return nil
	}

	for _, rule := range e.config.FileRules {
		if !accessMatches(rule.Access, flags) {
			continue
		}

		if fileRuleMatches(rule, path) {
			return &Alert{
				RuleID:   rule.ID,
				Severity: rule.Severity,
				Message:  rule.Message,
			}
		}
	}

	return nil
}

func (e *Engine) IgnoreFile(comm string, path string) bool {
	if path == "" {
		return true
	}

	for _, prefix := range e.config.FileIgnore.PathPrefixes {
		if strings.HasPrefix(path, prefix) {
			return true
		}
	}

	for _, item := range e.config.FileIgnore.ByCommPrefix {
		if !strings.HasPrefix(comm, item.CommPrefix) {
			continue
		}

		for _, ignoredPath := range item.Paths {
			if path == ignoredPath {
				return true
			}
		}

		for _, prefix := range item.PathPrefixes {
			if strings.HasPrefix(path, prefix) {
				return true
			}
		}
	}

	return false
}

func fileRuleMatches(rule FileRule, path string) bool {
	for _, exact := range rule.Exact {
		if path == exact {
			return true
		}
	}

	for _, prefix := range rule.Prefixes {
		if strings.HasPrefix(path, prefix) {
			return true
		}
	}

	if rule.ProcSensitive && isSensitiveProcPath(path) {
		return true
	}

	return false
}

func accessMatches(access string, flags uint32) bool {
	switch access {
	case "", "any":
		return true
	case "write":
		return isWriteOpen(flags)
	case "read":
		return !isWriteOpen(flags)
	default:
		return false
	}
}

func isSensitiveProcPath(path string) bool {
	if path == "/proc/kcore" {
		return true
	}

	if !strings.HasPrefix(path, "/proc/") {
		return false
	}

	rest := strings.TrimPrefix(path, "/proc/")
	parts := strings.Split(rest, "/")
	if len(parts) < 2 {
		return false
	}

	if _, err := strconv.Atoi(parts[0]); err != nil {
		return false
	}

	switch parts[1] {
	case "mem", "root", "environ", "cmdline":
		return true
	default:
		return false
	}
}

func isWriteOpen(flags uint32) bool {
	const (
		oAccMode = 3
		oWrOnly  = 1
		oRdWr    = 2
		oCreat   = 64
		oTrunc   = 512
		oAppend  = 1024
	)

	accessMode := flags & oAccMode
	return accessMode == oWrOnly ||
		accessMode == oRdWr ||
		flags&oCreat != 0 ||
		flags&oTrunc != 0 ||
		flags&oAppend != 0
}
