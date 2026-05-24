package container

import (
	"os"
	"regexp"
	"strings"
)

var dockerCgroupPatterns = []*regexp.Regexp{
	regexp.MustCompile(`docker-([0-9a-f]{64})\.scope`),
	regexp.MustCompile(`/docker/([0-9a-f]{64})`),
	regexp.MustCompile(`/docker-([0-9a-f]{64})`),
}

func ResolveDockerContainerID(pid uint32) string {
	data, err := os.ReadFile("/proc/" + u32ToString(pid) + "/cgroup")
	if err != nil {
		return ""
	}

	content := string(data)
	for _, pattern := range dockerCgroupPatterns {
		matches := pattern.FindStringSubmatch(content)
		if len(matches) == 2 {
			return matches[1]
		}
	}

	return ""
}

func ShortID(id string) string {
	if len(id) <= 12 {
		return id
	}
	return id[:12]
}

func IsContainerProcess(containerID string) bool {
	return strings.TrimSpace(containerID) != ""
}

func u32ToString(v uint32) string {
	if v == 0 {
		return "0"
	}

	var buf [10]byte
	i := len(buf)

	for v > 0 {
		i--
		buf[i] = byte('0' + v%10)
		v /= 10
	}

	return string(buf[i:])
}
