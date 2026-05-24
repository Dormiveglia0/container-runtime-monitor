package rule

import "path/filepath"

type Alert struct {
	RuleID   string
	Severity string
	Message  string
}

func MatchExec(filename string, argv []string, containerID string) *Alert {
	if containerID == "" {
		return nil
	}

	cmd := filepath.Base(filename)
	if cmd == "." || cmd == "/" || cmd == "" {
		if len(argv) > 0 {
			cmd = filepath.Base(argv[0])
		}
	}

	switch cmd {
	case "bash", "sh":
		return &Alert{
			RuleID:   "exec.shell",
			Severity: "medium",
			Message:  "container started an interactive shell",
		}
	case "curl", "wget":
		return &Alert{
			RuleID:   "exec.downloader",
			Severity: "medium",
			Message:  "container executed a download tool",
		}
	case "nc", "ncat", "netcat":
		return &Alert{
			RuleID:   "exec.netcat",
			Severity: "high",
			Message:  "container executed netcat-like tool",
		}
	case "mount", "setns", "unshare", "nsenter":
		return &Alert{
			RuleID:   "exec.escape-tool",
			Severity: "high",
			Message:  "container executed a namespace or mount related tool",
		}
	case "chmod", "chown":
		return &Alert{
			RuleID:   "exec.permission-change",
			Severity: "low",
			Message:  "container executed a permission changing tool",
		}
	default:
		return nil
	}
}
