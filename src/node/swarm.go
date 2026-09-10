package node

import (
	"bytes"
	"crypto/ed25519"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"time"

	"session-email/src/crypto"
)

type Swarm struct {
	ID    string
	Nodes []string
}

func NewSwarm(id string, nodes []string) *Swarm {
	return &Swarm{
		ID:    id,
		Nodes: nodes,
	}
}

func (s *Swarm) BroadcastMessage(msg Message) error {
	jsonData, err := json.Marshal(msg)
	if err != nil {
		return fmt.Errorf("failed to marshal message: %w", err)
	}

	var lastErr error
	successCount := 0

	for _, nodeURL := range s.Nodes {
		endpoint := nodeURL + "/messages"

		resp, err := http.Post(endpoint, "application/json", bytes.NewBuffer(jsonData))
		if err != nil {
			lastErr = err
			fmt.Printf("Failed to post to node %s: %v\n", nodeURL, err)
			continue
		}
		resp.Body.Close()

		if resp.StatusCode == http.StatusCreated || resp.StatusCode == http.StatusOK {
			successCount++
		} else {
			lastErr = fmt.Errorf("node %s returned status %d", nodeURL, resp.StatusCode)
		}
	}

	if successCount == 0 && len(s.Nodes) > 0 {
		return fmt.Errorf("failed to broadcast message to any node, last error: %v", lastErr)
	}

	return nil
}

func (s *Swarm) FetchMessages(recipient string, privKey ed25519.PrivateKey) ([]Message, error) {
	var lastErr error

	timestamp := fmt.Sprintf("%d", time.Now().Unix())
	challenge := recipient + ":" + timestamp
	sig := crypto.SignMessage(privKey, []byte(challenge))

	for _, nodeURL := range s.Nodes {
		endpoint := fmt.Sprintf("%s/messages?recipient=%s", nodeURL, url.QueryEscape(recipient))

		req, err := http.NewRequest(http.MethodGet, endpoint, nil)
		if err != nil {
			lastErr = err
			continue
		}
		req.Header.Set("X-Timestamp", timestamp)
		req.Header.Set("X-Signature", sig)

		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			lastErr = err
			continue
		}

		if resp.StatusCode != http.StatusOK {
			resp.Body.Close()
			lastErr = fmt.Errorf("node %s returned status %d", nodeURL, resp.StatusCode)
			continue
		}

		var messages []Message
		err = json.NewDecoder(resp.Body).Decode(&messages)
		resp.Body.Close()

		if err != nil {
			lastErr = err
			continue
		}

		return messages, nil
	}

	return nil, fmt.Errorf("failed to fetch messages from any node in the swarm: %v", lastErr)
}

func FindSwarmForAccount(accountID string, swarms []*Swarm) *Swarm {
	//find closest swarm for accountId
	if len(swarms) == 0 {
		return nil
	}

	accBytes, err := hex.DecodeString(accountID)
	if err != nil {
		return nil
	}

	var closestSwarm *Swarm
	var minDistance []byte
	for _, swarm := range swarms {
		swarmBytes, err := hex.DecodeString(swarm.ID)
		if err != nil || len(swarmBytes) != len(accBytes) {
			continue
		}
		distance := make([]byte, len(accBytes))
		for i := 0; i < len(accBytes); i++ {
			distance[i] = accBytes[i] ^ swarmBytes[i]
		}
		if minDistance == nil || bytes.Compare(distance, minDistance) < 0 {
			minDistance = distance
			closestSwarm = swarm
		}

	}
	return closestSwarm
}

func StorageMessageForRecipient(msg Message, accountID string, swarms []*Swarm) error {
	swarm := FindSwarmForAccount(accountID, swarms)

	if swarm == nil {
		return fmt.Errorf("recipient swarm not found")
	}

	if err := swarm.BroadcastMessage(msg); err != nil {
		return err
	}

	return nil
}
