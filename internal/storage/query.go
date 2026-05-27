package storage

type EventRecord struct {
	ID             int64  `json:"id"`
	TSText         string `json:"ts_text"`
	EventType      string `json:"event_type"`
	PID            int64  `json:"pid"`
	UID            int64  `json:"uid"`
	Comm           string `json:"comm"`
	Filename       string `json:"filename"`
	ArgsJSON       string `json:"args_json"`
	FileFlags      int64  `json:"file_flags"`
	ContainerID    string `json:"container_id"`
	ContainerName  string `json:"container_name"`
	ImageName      string `json:"image_name"`
	ContainerState string `json:"container_state"`
}

type AlertRecord struct {
	ID            int64  `json:"id"`
	TSText        string `json:"ts_text"`
	RuleID        string `json:"rule_id"`
	Severity      string `json:"severity"`
	Message       string `json:"message"`
	ContainerID   string `json:"container_id"`
	ContainerName string `json:"container_name"`
	ImageName     string `json:"image_name"`
	PID           int64  `json:"pid"`
	EventID       int64  `json:"event_id"`
}

type DashboardStats struct {
	TotalEvents    int64 `json:"total_events"`
	ExecEvents     int64 `json:"exec_events"`
	FileEvents     int64 `json:"file_events"`
	TotalAlerts    int64 `json:"total_alerts"`
	CriticalAlerts int64 `json:"critical_alerts"`
	HighAlerts     int64 `json:"high_alerts"`
	MediumAlerts   int64 `json:"medium_alerts"`
	LowAlerts      int64 `json:"low_alerts"`
	Containers     int64 `json:"containers"`
}

func (s *Store) ListEvents(limit int) ([]EventRecord, error) {
	limit = normalizeLimit(limit)

	rows, err := s.db.Query(`
SELECT
	id, ts_text, event_type,
	COALESCE(pid, 0), COALESCE(uid, 0),
	COALESCE(comm, ''), COALESCE(filename, ''),
	COALESCE(args_json, '[]'), COALESCE(file_flags, 0),
	COALESCE(container_id, ''), COALESCE(container_name, ''),
	COALESCE(image_name, ''), COALESCE(container_state, '')
FROM events
ORDER BY id DESC
LIMIT ?
`, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var records []EventRecord
	for rows.Next() {
		var r EventRecord
		if err := rows.Scan(
			&r.ID, &r.TSText, &r.EventType,
			&r.PID, &r.UID,
			&r.Comm, &r.Filename,
			&r.ArgsJSON, &r.FileFlags,
			&r.ContainerID, &r.ContainerName,
			&r.ImageName, &r.ContainerState,
		); err != nil {
			return nil, err
		}
		records = append(records, r)
	}

	return records, rows.Err()
}

func (s *Store) ListAlerts(limit int) ([]AlertRecord, error) {
	limit = normalizeLimit(limit)

	rows, err := s.db.Query(`
SELECT
	id, ts_text, rule_id, severity, message,
	COALESCE(container_id, ''), COALESCE(container_name, ''),
	COALESCE(image_name, ''), COALESCE(pid, 0), COALESCE(event_id, 0)
FROM alerts
ORDER BY id DESC
LIMIT ?
`, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var records []AlertRecord
	for rows.Next() {
		var r AlertRecord
		if err := rows.Scan(
			&r.ID, &r.TSText, &r.RuleID, &r.Severity, &r.Message,
			&r.ContainerID, &r.ContainerName,
			&r.ImageName, &r.PID, &r.EventID,
		); err != nil {
			return nil, err
		}
		records = append(records, r)
	}

	return records, rows.Err()
}

func (s *Store) Stats() (DashboardStats, error) {
	var stats DashboardStats

	items := []struct {
		dest *int64
		sql  string
	}{
		{&stats.TotalEvents, `SELECT COUNT(*) FROM events`},
		{&stats.ExecEvents, `SELECT COUNT(*) FROM events WHERE event_type = 'execve'`},
		{&stats.FileEvents, `SELECT COUNT(*) FROM events WHERE event_type = 'file_open'`},
		{&stats.TotalAlerts, `SELECT COUNT(*) FROM alerts`},
		{&stats.CriticalAlerts, `SELECT COUNT(*) FROM alerts WHERE severity = 'critical'`},
		{&stats.HighAlerts, `SELECT COUNT(*) FROM alerts WHERE severity = 'high'`},
		{&stats.MediumAlerts, `SELECT COUNT(*) FROM alerts WHERE severity = 'medium'`},
		{&stats.LowAlerts, `SELECT COUNT(*) FROM alerts WHERE severity = 'low'`},
		{&stats.Containers, `SELECT COUNT(DISTINCT container_id) FROM events WHERE container_id != ''`},
	}

	for _, item := range items {
		if err := s.db.QueryRow(item.sql).Scan(item.dest); err != nil {
			return stats, err
		}
	}

	return stats, nil
}

func normalizeLimit(limit int) int {
	if limit <= 0 {
		return 100
	}
	if limit > 500 {
		return 500
	}
	return limit
}
