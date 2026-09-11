package main

import (
	"crypto/ed25519"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log"
	"net/http"

	"session-email/src/crypto"
	"session-email/src/node"
)

type NodeInfo struct {
	URL       string `json:"url"`
	PublicKey string `json:"publicKey"`
	AccountID string `json:"accountId"`
}

func main() {
	ports := []string{":8001", ":8002", ":8003"}
	names := []string{"A", "B", "C"}
	var nodes []NodeInfo

	for i, port := range ports {
		_, priv, _ := crypto.GeneratePublicPrivatePair()
		srv := node.NewServer(priv)
		pub := priv.Public().(ed25519.PublicKey)
		info := NodeInfo{
			URL:       "http://localhost" + port,
			PublicKey: hex.EncodeToString(pub),
			AccountID: crypto.GenerateAccountId(pub),
		}
		nodes = append(nodes, info)
		go http.ListenAndServe(port, srv.Router())
		fmt.Printf("Node %s on %s  (%s)\n", names[i], port, info.AccountID)
	}

	http.HandleFunc("/api/circuit", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Access-Control-Allow-Origin", "*")
		json.NewEncoder(w).Encode(nodes)
	})

	fmt.Println("Circuit config on http://localhost:8080/api/circuit")
	fmt.Println("Open client at http://localhost:5173")
	log.Fatal(http.ListenAndServe(":8080", nil))
}
