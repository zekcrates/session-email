package node

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"session-email/src/crypto"
	"sync"
	"time"
)

type Message struct {
	ID        string `json:"id"`
	Recipient string `json:"recipient"`
	Payload   []byte `json:"payload"`
	CreatedAt int64  `json:"created_at"`
}

type Server struct {
	mu       sync.RWMutex
	messages []Message

	PrivateKey ed25519.PrivateKey
	PublicKey  string
}

type OnionPacket struct {
	EphemeralKey []byte `json:"ephemeral_key"`
	Nonce        []byte `json:"nonce"`
	Ciphertext   []byte `json:"ciphertext"`
}
type UnWrappedPayload struct {
	NextNode     string `json:"next_node"` // next node or empty if destination
	InnerPayload []byte `json:"inner_payload"`
	Path         string `json:"path"`
	Method       string `json:"method"`
}

func NewServer(privKey ed25519.PrivateKey) *Server {
	pubKey := privKey.Public().(ed25519.PublicKey)
	return &Server{
		messages:   make([]Message, 0),
		PrivateKey: privKey,
		PublicKey:  hex.EncodeToString(pubKey),
	}
}
func (s *Server) HandlePostMessage(w http.ResponseWriter, r *http.Request) {

	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	var req struct {
		Recipient string `json:"recipient"`
		Payload   []byte `json:"payload"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid JSON body", http.StatusBadRequest)
		return
	}
	if req.Recipient == "" || len(req.Payload) == 0 {
		http.Error(w, "Missing recipient or payload", http.StatusBadRequest)
		return
	}
	idBuf := make([]byte, 16)
	rand.Read(idBuf)
	msgId := hex.EncodeToString(idBuf)
	msg := Message{
		ID:        msgId,
		Recipient: req.Recipient,
		Payload:   req.Payload,
		CreatedAt: time.Now().Unix(),
	}

	s.mu.Lock()
	s.messages = append(s.messages, msg)
	s.mu.Unlock()
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)
	json.NewEncoder(w).Encode(map[string]string{
		"status": "stored",
		"id":     msgId,
	})
}

func (s *Server) HandleGetMessages(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	recipient := r.URL.Query().Get("recipient")
	timestamp := r.Header.Get("X-Timestamp")
	signature := r.Header.Get("X-Signature")
	if recipient == "" || timestamp == "" || signature == "" {
		http.Error(w, "Missing recipient query parameter", http.StatusBadRequest)
		return
	}
	// recipient is an account ID ("05"+hex(pubkey)); strip the 05 prefix
	// for signature verification, but keep full ID for mailbox lookup.
	pubHex := recipient
	if raw, err := hex.DecodeString(recipient); err == nil && len(raw) == 33 && raw[0] == 0x05 {
		pubHex = hex.EncodeToString(raw[1:])
	}
	challenge := recipient + ":" + timestamp
	if !crypto.VerifySignature(pubHex, []byte(challenge), signature) {
		http.Error(w, "Unauthorized: Invalid mailbox signature", http.StatusUnauthorized)
		return
	}
	s.mu.RLock()
	var result []Message
	for _, msg := range s.messages {
		if msg.Recipient == recipient {
			result = append(result, msg)
		}
	}
	s.mu.RUnlock()
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(result)

}
func (s *Server) HandleOnion(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var packet OnionPacket
	if err := json.NewDecoder(r.Body).Decode(&packet); err != nil {
		http.Error(w, "Invalid outer onion packet format", http.StatusBadRequest)
		return
	}

	plaintext, err := crypto.DecryptLayer(s.PrivateKey, packet.EphemeralKey, packet.Nonce, packet.Ciphertext)
	if err != nil {
		http.Error(w, "Decryption failed: unauthorized or tampered layer", http.StatusUnauthorized)
		return
	}

	var payload UnWrappedPayload
	if err := json.Unmarshal(plaintext, &payload); err != nil {
		http.Error(w, "Malformed decrypted payload structure", http.StatusBadRequest)
		return
	}

	if payload.NextNode != "" {
		var nextPacket OnionPacket
		if err := json.Unmarshal(payload.InnerPayload, &nextPacket); err != nil {
			http.Error(w, "Inner payload is not a valid OnionPacket struct", http.StatusBadRequest)
			return
		}

		body, err := json.Marshal(nextPacket)
		if err != nil {
			http.Error(w, "Failed to marshal forwarded packet", http.StatusInternalServerError)
			return
		}

		resp, err := http.Post(payload.NextNode+"/onion", "application/json", bytes.NewReader(body))
		if err != nil {
			http.Error(w, "Failed to forward onion packet to next hop", http.StatusBadGateway)
			return
		}
		defer resp.Body.Close()

		w.WriteHeader(resp.StatusCode)
		return
	}

	localReq, err := http.NewRequest(payload.Method, payload.Path, bytes.NewReader(payload.InnerPayload))
	if err != nil {
		http.Error(w, "Invalid final internal request parameters", http.StatusBadRequest)
		return
	}

	s.Router().ServeHTTP(w, localReq)
}
func (s *Server) Router() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("/messages", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Access-Control-Allow-Origin", "*")
		w.Header().Set("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
		w.Header().Set("Access-Control-Allow-Headers", "Content-Type, X-Timestamp, X-Signature")
		if r.Method == http.MethodOptions {
			w.WriteHeader(http.StatusNoContent)
			return
		}
		switch r.Method {
		case http.MethodPost:
			s.HandlePostMessage(w, r)
		case http.MethodGet:
			s.HandleGetMessages(w, r)
		default:
			http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		}
	})
	mux.HandleFunc("/onion", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Access-Control-Allow-Origin", "*")
		w.Header().Set("Access-Control-Allow-Methods", "POST, OPTIONS")
		w.Header().Set("Access-Control-Allow-Headers", "Content-Type")
		if r.Method == http.MethodOptions {
			w.WriteHeader(http.StatusNoContent)
			return
		}
		s.HandleOnion(w, r)
	})
	return mux
}
