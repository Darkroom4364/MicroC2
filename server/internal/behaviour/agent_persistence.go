package behaviour

import (
	"encoding/json"
	"fmt"
	"strings"
	"time"
	"unicode/utf8"

	"microc2/server/internal/tasks"
)

const (
	maxAgentMetadataCharacters = 512
	maxAgentIPEntries          = 32
	maxAgentCommandEntries     = 64
)

func (p *HTTPPollingProtocol) loadPersistedAgents() error {
	if p.database == nil {
		return nil
	}
	rows, err := p.database.SQL().Query(
		`SELECT agent_id, payload_id, os, hostname, ip, ip_list_json,
		        last_commands_json, last_seen_at
		 FROM agents
		 WHERE listener_id = ?
		 ORDER BY agent_id`,
		p.listenerID,
	)
	if err != nil {
		return err
	}
	defer rows.Close()

	for rows.Next() {
		var (
			agent        Agent
			ipListJSON   []byte
			commandsJSON []byte
			lastSeen     string
		)
		if err := rows.Scan(
			&agent.ID,
			&agent.PayloadID,
			&agent.OS,
			&agent.Hostname,
			&agent.IP,
			&ipListJSON,
			&commandsJSON,
			&lastSeen,
		); err != nil {
			return err
		}
		if err := json.Unmarshal(ipListJSON, &agent.IPList); err != nil {
			return fmt.Errorf("decode persisted agent %s IP list: %w", agent.ID, err)
		}
		if err := json.Unmarshal(commandsJSON, &agent.Commands); err != nil {
			return fmt.Errorf("decode persisted agent %s command list: %w", agent.ID, err)
		}
		agent.LastSeen, err = time.Parse(time.RFC3339Nano, lastSeen)
		if err != nil {
			return fmt.Errorf("decode persisted agent %s last_seen: %w", agent.ID, err)
		}
		agent.ListenerID = p.listenerID
		if err := validateAgentHeartbeat(agent); err != nil {
			return fmt.Errorf("validate persisted agent %s: %w", agent.ID, err)
		}
		agentCopy := agent
		p.agents.list[agent.ID] = &agentCopy
	}
	return rows.Err()
}

func (p *HTTPPollingProtocol) persistAgent(agent Agent) error {
	if p.database == nil {
		return nil
	}
	ipListJSON, err := json.Marshal(agent.IPList)
	if err != nil {
		return err
	}
	commandsJSON, err := json.Marshal(agent.Commands)
	if err != nil {
		return err
	}
	seenAt := agent.LastSeen.UTC().Round(0).Format(time.RFC3339Nano)
	_, err = p.database.SQL().Exec(
		`INSERT INTO agents (
			listener_id, agent_id, payload_id, os, hostname, ip,
			ip_list_json, last_commands_json, first_seen_at, last_seen_at
		) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
		ON CONFLICT(listener_id, agent_id) DO UPDATE SET
			payload_id = excluded.payload_id,
			os = excluded.os,
			hostname = excluded.hostname,
			ip = excluded.ip,
			ip_list_json = excluded.ip_list_json,
			last_commands_json = excluded.last_commands_json,
			last_seen_at = excluded.last_seen_at`,
		p.listenerID,
		agent.ID,
		agent.PayloadID,
		agent.OS,
		agent.Hostname,
		agent.IP,
		ipListJSON,
		commandsJSON,
		seenAt,
		seenAt,
	)
	return err
}

func validateAgentHeartbeat(agent Agent) error {
	if err := tasks.ValidateIdentifier("agent_id", agent.ID); err != nil {
		return err
	}
	for field, value := range map[string]string{
		"payload_id": agent.PayloadID,
		"os":         agent.OS,
		"hostname":   agent.Hostname,
		"ip":         agent.IP,
	} {
		if utf8.RuneCountInString(value) > maxAgentMetadataCharacters {
			return fmt.Errorf(
				"%s must be at most %d characters",
				field,
				maxAgentMetadataCharacters,
			)
		}
		if strings.ContainsRune(value, '\x00') {
			return fmt.Errorf("%s must not contain NUL", field)
		}
	}
	if len(agent.IPList) > maxAgentIPEntries {
		return fmt.Errorf("ip_list must contain at most %d entries", maxAgentIPEntries)
	}
	for _, address := range agent.IPList {
		if utf8.RuneCountInString(address) > maxAgentMetadataCharacters ||
			strings.ContainsRune(address, '\x00') {
			return fmt.Errorf("ip_list contains an invalid entry")
		}
	}
	if len(agent.Commands) > maxAgentCommandEntries {
		return fmt.Errorf(
			"last_commands must contain at most %d entries",
			maxAgentCommandEntries,
		)
	}
	for _, command := range agent.Commands {
		if utf8.RuneCountInString(command) > tasks.MaxCommandCharacters ||
			strings.ContainsRune(command, '\x00') {
			return fmt.Errorf("last_commands contains an invalid entry")
		}
	}
	return nil
}
