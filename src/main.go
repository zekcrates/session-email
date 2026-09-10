package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"net/http/httptest"
	"time"

	"session-email/src/crypto"
	"session-email/src/node"
)

func main() {
	fmt.Println("=== node/server auth-GET check ===")

	srv := &node.Server{}
	ts := httptest.NewServer(srv.Router())
	defer ts.Close()

	bobPub, bobPriv, _ := crypto.GeneratePublicPrivatePair()
	bobID := crypto.GenerateAccountId(bobPub)

	payload := []byte("hello bob")
	body, _ := json.Marshal(map[string]any{
		"recipient": bobID,
		"payload":   payload,
	})
	resp, err := http.Post(ts.URL+"/messages", "application/json", bytes.NewReader(body))
	if err != nil {
		log.Fatal(err)
	}
	var out map[string]string
	_ = json.NewDecoder(resp.Body).Decode(&out)
	resp.Body.Close()
	fmt.Printf("POST /messages -> %d id=%s\n", resp.StatusCode, out["id"])
	if resp.StatusCode != http.StatusCreated {
		log.Fatalf("FAIL: want 201, got %d", resp.StatusCode)
	}

	// signed GET
	stamp := fmt.Sprintf("%d", time.Now().Unix())
	sig := crypto.SignMessage(bobPriv, []byte(bobID+":"+stamp))
	req, _ := http.NewRequest(http.MethodGet, ts.URL+"/messages?recipient="+bobID, nil)
	req.Header.Set("X-Timestamp", stamp)
	req.Header.Set("X-Signature", sig)
	resp2, err := http.DefaultClient.Do(req)
	if err != nil {
		log.Fatal(err)
	}
	var msgs []node.Message
	_ = json.NewDecoder(resp2.Body).Decode(&msgs)
	resp2.Body.Close()
	fmt.Printf("GET (auth) -> %d n=%d\n", resp2.StatusCode, len(msgs))
	if resp2.StatusCode != 200 || len(msgs) != 1 || string(msgs[0].Payload) != string(payload) {
		log.Fatalf("FAIL: mismatch: %+v", msgs)
	}
	_ = bobPub

	fmt.Println("PASS: server store + auth fetch works")
}
