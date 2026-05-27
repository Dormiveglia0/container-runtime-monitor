package container

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"
)

type Metadata struct {
	ID      string
	ShortID string
	Name    string
	Image   string
	State   string
	PID     int
}

type DockerClient struct {
	socketPath string
	httpClient *http.Client
	cache      map[string]cacheEntry
	ttl        time.Duration
	mu         sync.RWMutex
}

type cacheEntry struct {
	metadata  Metadata
	expiresAt time.Time
}

type dockerInspectResponse struct {
	ID     string `json:"Id"`
	Name   string `json:"Name"`
	Image  string `json:"Image"`
	Config struct {
		Image string `json:"Image"`
	} `json:"Config"`
	State struct {
		Status  string `json:"Status"`
		Running bool   `json:"Running"`
		Pid     int    `json:"Pid"`
	} `json:"State"`
}

func NewDockerClient(socketPath string) *DockerClient {
	transport := &http.Transport{
		DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
			var dialer net.Dialer
			return dialer.DialContext(ctx, "unix", socketPath)
		},
	}

	return &DockerClient{
		socketPath: socketPath,
		httpClient: &http.Client{
			Transport: transport,
			Timeout:   2 * time.Second,
		},
		cache: make(map[string]cacheEntry),
		ttl:   30 * time.Second,
	}
}

func (c *DockerClient) Inspect(ctx context.Context, containerID string) (Metadata, error) {
	if containerID == "" {
		return Metadata{}, fmt.Errorf("empty container id")
	}

	now := time.Now()

	c.mu.RLock()
	entry, ok := c.cache[containerID]
	c.mu.RUnlock()

	if ok && now.Before(entry.expiresAt) {
		return entry.metadata, nil
	}

	req, err := http.NewRequestWithContext(
		ctx,
		http.MethodGet,
		"http://docker/containers/"+containerID+"/json",
		nil,
	)
	if err != nil {
		return Metadata{}, err
	}

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return Metadata{}, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return Metadata{}, fmt.Errorf("docker inspect status: %s", resp.Status)
	}

	var payload dockerInspectResponse
	if err := json.NewDecoder(resp.Body).Decode(&payload); err != nil {
		return Metadata{}, err
	}

	image := payload.Config.Image
	if image == "" {
		image = payload.Image
	}

	state := payload.State.Status
	if state == "" && payload.State.Running {
		state = "running"
	}

	meta := Metadata{
		ID:      payload.ID,
		ShortID: ShortID(payload.ID),
		Name:    strings.TrimPrefix(payload.Name, "/"),
		Image:   image,
		State:   state,
		PID:     payload.State.Pid,
	}

	if meta.ID == "" {
		meta.ID = containerID
		meta.ShortID = ShortID(containerID)
	}

	c.mu.Lock()
	c.cache[containerID] = cacheEntry{
		metadata:  meta,
		expiresAt: now.Add(c.ttl),
	}
	c.mu.Unlock()

	return meta, nil
}
