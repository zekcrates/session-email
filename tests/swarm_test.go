package tests

import (
	"bytes"
	"crypto/ed25519"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"session-email/src/crypto"
	"session-email/src/node"
)

// ---------- simple (no auth needed) ----------

func TestNewSwarmSimple(t *testing.T) {
	s := node.NewSwarm("abc", []string{"http://a", "http://b"})
	if s.ID != "abc" {
		t.Fatalf("id = %q, want abc", s.ID)
	}
	if len(s.Nodes) != 2 {
		t.Fatalf("nodes = %d, want 2", len(s.Nodes))
	}
	e := node.NewSwarm("x", nil)
	if e.Nodes == nil {
		e.Nodes = []string{}
	}
	if len(e.Nodes) != 0 {
		t.Fatal("expected 0 nodes")
	}
}

func TestFindSwarmSimple(t *testing.T) {
	if got := node.FindSwarmForAccount("0001", nil); got != nil {
		t.Fatal("empty swarm list should give nil")
	}
	swarms := []*node.Swarm{node.NewSwarm("0000", nil)}
	if got := node.FindSwarmForAccount("not-hex!!", swarms); got != nil {
		t.Fatal("bad account hex should give nil")
	}
	a := node.NewSwarm("0000", nil)
	b := node.NewSwarm("ffff", nil)
	got := node.FindSwarmForAccount("0001", []*node.Swarm{a, b})
	if got != a {
		t.Fatalf("expected swarm 0000, got %+v", got)
	}
	short := node.NewSwarm("00", nil)
	if got := node.FindSwarmForAccount("0001", []*node.Swarm{short}); got != nil {
		t.Fatal("mismatched id length should be skipped -> nil")
	}
}

func TestStorageNoSwarmSimple(t *testing.T) {
	msg := node.Message{Recipient: "bob", Payload: []byte("hi")}
	if err := node.StorageMessageForRecipient(msg, "0001", nil); err == nil {
		t.Fatal("expected error with no swarms")
	}
}

func TestBroadcastEmptySimple(t *testing.T) {
	s := node.NewSwarm("x", nil)
	if err := s.BroadcastMessage(node.Message{Recipient: "bob", Payload: []byte("hi")}); err != nil {
		t.Fatalf("empty broadcast should not error, got %v", err)
	}
}

// ---------- helpers for auth GET ----------

func liveServer(t *testing.T) (*node.Server, *httptest.Server) {
	t.Helper()
	s := &node.Server{}
	ts := httptest.NewServer(s.Router())
	t.Cleanup(ts.Close)
	return s, ts
}

func postFor(t *testing.T, baseURL, recipient string, payload []byte) {
	t.Helper()
	body, _ := json.Marshal(map[string]any{"recipient": recipient, "payload": payload})
	resp, err := http.Post(baseURL+"/messages", "application/json", bytes.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusCreated {
		t.Fatalf("POST status = %d, want 201", resp.StatusCode)
	}
}

// signed GET; returns raw response + decoded messages (if 200)
func authGet(t *testing.T, baseURL, recipient string, priv ed25519.PrivateKey) (int, []node.Message) {
	t.Helper()
	ts := fmt.Sprintf("%d", time.Now().Unix())
	sig := crypto.SignMessage(priv, []byte(recipient+":"+ts))
	req, _ := http.NewRequest(http.MethodGet, baseURL+"/messages?recipient="+recipient, nil)
	req.Header.Set("X-Timestamp", ts)
	req.Header.Set("X-Signature", sig)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return resp.StatusCode, nil
	}
	var msgs []node.Message
	if err := json.NewDecoder(resp.Body).Decode(&msgs); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if msgs == nil {
		msgs = []node.Message{}
	}
	return resp.StatusCode, msgs
}

// ---------- simple: new auth GET ----------

func TestAuthGetMissingHeadersSimple(t *testing.T) {
	_, ts := liveServer(t)
	// no headers at all
	resp, err := http.Get(ts.URL + "/messages?recipient=bob")
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("no-auth GET status = %d, want 400", resp.StatusCode)
	}
}

func TestAuthGetBadSignatureSimple(t *testing.T) {
	pub, _, _ := crypto.GeneratePublicPrivatePair()
	bobID := crypto.GenerateAccountId(pub)
	_, ts := liveServer(t)
	postFor(t, ts.URL, bobID, []byte("secret"))

	// random garbage signature
	req, _ := http.NewRequest(http.MethodGet, ts.URL+"/messages?recipient="+bobID, nil)
	req.Header.Set("X-Timestamp", fmt.Sprintf("%d", time.Now().Unix()))
	req.Header.Set("X-Signature", "deadbeef")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("bad-sig GET status = %d, want 401", resp.StatusCode)
	}
}

func TestAuthGetOKSimple(t *testing.T) {
	_, priv, _ := crypto.GeneratePublicPrivatePair()
	_ = priv
	bobPub, bobPriv, _ := crypto.GeneratePublicPrivatePair()
	bobID := crypto.GenerateAccountId(bobPub)
	_, ts := liveServer(t)
	postFor(t, ts.URL, bobID, []byte("hello mailbox"))

	code, msgs := authGet(t, ts.URL, bobID, bobPriv)
	if code != 200 {
		t.Fatalf("auth GET status = %d, want 200", code)
	}
	if len(msgs) != 1 || string(msgs[0].Payload) != "hello mailbox" {
		t.Fatalf("unexpected msgs %+v", msgs)
	}
}

// ---------- medium: auth GET + swarm ----------

func TestAuthGetIsolationMedium(t *testing.T) {
	alicePub, alicePriv, _ := crypto.GeneratePublicPrivatePair()
	_ = alicePub
	bobPub, bobPriv, _ := crypto.GeneratePublicPrivatePair()
	bobID := crypto.GenerateAccountId(bobPub)
	_, ts := liveServer(t)
	postFor(t, ts.URL, bobID, []byte("for bob only"))

	// alice signs a request FOR bob's mailbox -> must be 401
	code, _ := authGet(t, ts.URL, bobID, alicePriv)
	if code != http.StatusUnauthorized {
		t.Fatalf("cross-read status = %d, want 401", code)
	}
	// bob reads his own -> 200
	code, msgs := authGet(t, ts.URL, bobID, bobPriv)
	if code != 200 || len(msgs) != 1 {
		t.Fatalf("owner read failed: %d %+v", code, msgs)
	}
}

func TestSwarmAuthFetchMedium(t *testing.T) {
	_, ts1 := liveServer(t)
	_, ts2 := liveServer(t)

	bobPub, bobPriv, _ := crypto.GeneratePublicPrivatePair()
	bobID := crypto.GenerateAccountId(bobPub)

	sw := node.NewSwarm("sw1", []string{ts1.URL, ts2.URL})
	if err := sw.BroadcastMessage(node.Message{Recipient: bobID, Payload: []byte("hello swarm")}); err != nil {
		t.Fatalf("broadcast: %v", err)
	}
	got, err := sw.FetchMessages(bobID, bobPriv)
	if err != nil {
		t.Fatalf("auth fetch: %v", err)
	}
	found := false
	for _, m := range got {
		if string(m.Payload) == "hello swarm" && m.Recipient == bobID {
			found = true
		}
	}
	if !found {
		t.Fatalf("payload not found in %+v", got)
	}
	_ = bobPub
}

func TestSwarmFetchFallbackMedium(t *testing.T) {
	_, dead := liveServer(t)
	dead.Close()
	_, good := liveServer(t)

	bobPub, bobPriv, _ := crypto.GeneratePublicPrivatePair()
	bobID := crypto.GenerateAccountId(bobPub)
	_ = bobPub

	seeder := node.NewSwarm("s", []string{good.URL})
	if err := seeder.BroadcastMessage(node.Message{Recipient: bobID, Payload: []byte("fallback")}); err != nil {
		t.Fatal(err)
	}
	sw := node.NewSwarm("s", []string{dead.URL, good.URL})
	got, err := sw.FetchMessages(bobID, bobPriv)
	if err != nil {
		t.Fatalf("fetch should fall back to good node: %v", err)
	}
	if len(got) != 1 || string(got[0].Payload) != "fallback" {
		t.Fatalf("unexpected fetch result %+v", got)
	}
}

func TestBroadcastPartialFailureMedium(t *testing.T) {
	_, good := liveServer(t)
	_, dead := liveServer(t)
	dead.Close()

	sw := node.NewSwarm("sw", []string{dead.URL, good.URL})
	msg := node.Message{Recipient: "alice", Payload: []byte("survives one bad node")}
	if err := sw.BroadcastMessage(msg); err != nil {
		t.Fatalf("one good node should be enough, got %v", err)
	}
	allBad := node.NewSwarm("sw", []string{dead.URL, "http://127.0.0.1:1"})
	if err := allBad.BroadcastMessage(msg); err == nil {
		t.Fatal("all-bad broadcast should error")
	}
}

func TestStorageMessageAuthE2EMedium(t *testing.T) {
	_, ts1 := liveServer(t)
	_, ts2 := liveServer(t)

	// realistic 33-byte account-style IDs so routing + auth both work
	swPub1, _, _ := crypto.GeneratePublicPrivatePair()
	swPub2, _, _ := crypto.GeneratePublicPrivatePair()
	sw1 := node.NewSwarm(crypto.GenerateAccountId(swPub1), []string{ts1.URL})
	sw2 := node.NewSwarm(crypto.GenerateAccountId(swPub2), []string{ts2.URL})
	swarms := []*node.Swarm{sw1, sw2}

	bobPub, bobPriv, _ := crypto.GeneratePublicPrivatePair()
	bobID := crypto.GenerateAccountId(bobPub)
	_ = bobPub

	if err := node.StorageMessageForRecipient(node.Message{Recipient: bobID, Payload: []byte("route me")}, bobID, swarms); err != nil {
		t.Fatalf("store: %v", err)
	}
	// routed swarm holds it — fetch from whichever swarm is closest
	closest := node.FindSwarmForAccount(bobID, swarms)
	if closest == nil {
		t.Fatal("no closest swarm")
	}
	got, err := closest.FetchMessages(bobID, bobPriv)
	if err != nil || len(got) == 0 {
		t.Fatalf("expected msg on closest swarm: %v %+v", err, got)
	}
}
