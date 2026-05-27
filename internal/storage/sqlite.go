package storage

import (
	"database/sql"
	"encoding/json"
	"time"

	_ "github.com/mattn/go-sqlite3"
)

type Store struct {
	db *sql.DB
}

type ExecEvent struct {
	Timestamp      uint64
	PID            uint32
	PPID           uint32
	UID            uint32
	GID            uint32
	Comm           string
	Filename       string
	Args           []string
	CgroupID       uint64
	ContainerID    string
	ContainerName  string
	ImageName      string
	ContainerState string
}

type FileEvent struct {
	Timestamp      uint64
	PID            uint32
	PPID           uint32
	UID            uint32
	GID            uint32
	Comm           string
	Path           string
	Flags          uint32
	CgroupID       uint64
	ContainerID    string
	ContainerName  string
	ImageName      string
	ContainerState string
}

type AlertEvent struct {
	Timestamp      uint64
	RuleID         string
	Severity       string
	Message        string
	ContainerID    string
	ContainerName  string
	ImageName      string
	ContainerState string
	PID            uint32
	EventID        int64
}

func Open(path string) (*Store, error) {
	db, err := sql.Open("sqlite3", path)
	if err != nil {
		return nil, err
	}

	store := &Store{db: db}
	if err := store.init(); err != nil {
		db.Close()
		return nil, err
	}

	return store, nil
}

func (s *Store) Close() error {
	return s.db.Close()
}

func (s *Store) init() error {
	if _, err := s.db.Exec(`PRAGMA journal_mode=WAL; PRAGMA busy_timeout=5000;`); err != nil {
		return err
	}

	_, err := s.db.Exec(`
CREATE TABLE IF NOT EXISTS events (
	id INTEGER PRIMARY KEY AUTOINCREMENT,
	ts_ns INTEGER NOT NULL,
	ts_text TEXT NOT NULL,
	event_type TEXT NOT NULL,
	pid INTEGER,
	ppid INTEGER,
	uid INTEGER,
	gid INTEGER,
	comm TEXT,
	filename TEXT,
	args_json TEXT,
	file_flags INTEGER,
	cgroup_id INTEGER,
	container_id TEXT,
	container_name TEXT,
	image_name TEXT,
	container_state TEXT
);

CREATE TABLE IF NOT EXISTS alerts (
	id INTEGER PRIMARY KEY AUTOINCREMENT,
	ts_ns INTEGER NOT NULL,
	ts_text TEXT NOT NULL,
	rule_id TEXT NOT NULL,
	severity TEXT NOT NULL,
	message TEXT,
	container_id TEXT,
	container_name TEXT,
	image_name TEXT,
	container_state TEXT,
	pid INTEGER,
	event_id INTEGER,
	FOREIGN KEY(event_id) REFERENCES events(id)
);

CREATE INDEX IF NOT EXISTS idx_events_type ON events(event_type);
CREATE INDEX IF NOT EXISTS idx_events_container_id ON events(container_id);
CREATE INDEX IF NOT EXISTS idx_events_container_name ON events(container_name);
CREATE INDEX IF NOT EXISTS idx_events_ts_ns ON events(ts_ns);
CREATE INDEX IF NOT EXISTS idx_alerts_container_id ON alerts(container_id);
CREATE INDEX IF NOT EXISTS idx_alerts_container_name ON alerts(container_name);
CREATE INDEX IF NOT EXISTS idx_alerts_severity ON alerts(severity);
`)
	return err
}

func (s *Store) InsertExecEvent(event ExecEvent) (int64, error) {
	argsJSON, err := json.Marshal(event.Args)
	if err != nil {
		return 0, err
	}

	result, err := s.db.Exec(`
INSERT INTO events (
	ts_ns, ts_text, event_type,
	pid, ppid, uid, gid,
	comm, filename, args_json, file_flags,
	cgroup_id, container_id,
	container_name, image_name, container_state
) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
`,
		event.Timestamp,
		formatKernelTime(event.Timestamp),
		"execve",
		event.PID,
		event.PPID,
		event.UID,
		event.GID,
		event.Comm,
		event.Filename,
		string(argsJSON),
		0,
		event.CgroupID,
		event.ContainerID,
		event.ContainerName,
		event.ImageName,
		event.ContainerState,
	)
	if err != nil {
		return 0, err
	}

	return result.LastInsertId()
}

func (s *Store) InsertFileEvent(event FileEvent) (int64, error) {
	result, err := s.db.Exec(`
INSERT INTO events (
	ts_ns, ts_text, event_type,
	pid, ppid, uid, gid,
	comm, filename, args_json, file_flags,
	cgroup_id, container_id,
	container_name, image_name, container_state
) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
`,
		event.Timestamp,
		formatKernelTime(event.Timestamp),
		"file_open",
		event.PID,
		event.PPID,
		event.UID,
		event.GID,
		event.Comm,
		event.Path,
		"[]",
		event.Flags,
		event.CgroupID,
		event.ContainerID,
		event.ContainerName,
		event.ImageName,
		event.ContainerState,
	)
	if err != nil {
		return 0, err
	}

	return result.LastInsertId()
}

func (s *Store) InsertAlert(alert AlertEvent) error {
	_, err := s.db.Exec(`
INSERT INTO alerts (
	ts_ns, ts_text, rule_id, severity, message,
	container_id, container_name, image_name, container_state,
	pid, event_id
) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
`,
		alert.Timestamp,
		formatKernelTime(alert.Timestamp),
		alert.RuleID,
		alert.Severity,
		alert.Message,
		alert.ContainerID,
		alert.ContainerName,
		alert.ImageName,
		alert.ContainerState,
		alert.PID,
		alert.EventID,
	)
	return err
}

func formatKernelTime(ts uint64) string {
	return time.Now().Format(time.RFC3339)
}
