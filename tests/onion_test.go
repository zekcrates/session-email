package tests

import (
	"bytes"
	"crypto/ed25519"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"session-email/src/crypto"
	"session-email/src/message"
	"session-email/src/node"
)

// ---------- key conversion ----------

func TestEd25519PublicKeyToX25519(t *testing.T) {
	pub, _, _ := crypto.GeneratePublicPrivatePair()
	x, err := crypto.Ed25519PublicKeyToX25519(pub)
	if err != nil {
		t.Fatalf("conversion failed: %v", err)
	}
	if len(x) != 32 {
		t.Fatalf("x25519 pub len = %d, want 32", len(x))
	}
}

func TestEd25519PublicKeyToX25519Deterministic(t *testing.T) {
	pub, _, _ := crypto.GeneratePublicPrivatePair()
	x1, _ := crypto.Ed25519PublicKeyToX25519(pub)
	x2, _ := crypto.Ed25519PublicKeyToX25519(pub)
	if x1 != x2 {
		t.Fatal("same key converted differently")
	}
}

func TestEd25519PrivateKeyToX25519(t *testing.T) {
	_, priv, _ := crypto.GeneratePublicPrivatePair()
	x := crypto.Ed25519PrivateKeyToX25519(priv)
	if len(x) != 32 {
		t.Fatalf("x25519 priv len = %d, want 32", len(x))
	}
	zero := [32]byte{}
	if x == zero {
		t.Fatal("private key converted to all zeros")
	}
}

// ---------- onion layer encrypt/decrypt ----------

func TestDecryptLayerRoundTrip(t *testing.T) {
	_, bobPriv, _ := crypto.GeneratePublicPrivatePair()
	bobPub := bobPriv.Public().(ed25519.PublicKey)

	payload := []byte("onion layer payload")
	packetBytes, err := node.BuildOnionPacket(payload, bobPub)
	if err != nil {
		t.Fatalf("build packet: %v", err)
	}

	var packet node.OnionPacket
	if err := json.Unmarshal(packetBytes, &packet); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}

	plaintext, err := crypto.DecryptLayer(bobPriv, packet.EphemeralKey, packet.Nonce, packet.Ciphertext)
	if err != nil {
		t.Fatalf("decrypt layer: %v", err)
	}
	if !bytes.Equal(plaintext, payload) {
		t.Fatalf("mismatch: got %q, want %q", plaintext, payload)
	}
}

func TestDecryptLayerWrongKey(t *testing.T) {
	_, bobPriv, _ := crypto.GeneratePublicPrivatePair()
	bobPub := bobPriv.Public().(ed25519.PublicKey)

	_, evePriv, _ := crypto.GeneratePublicPrivatePair()

	packetBytes, _ := node.BuildOnionPacket([]byte("secret"), bobPub)
	var packet node.OnionPacket
	json.Unmarshal(packetBytes, &packet)

	_, err := crypto.DecryptLayer(evePriv, packet.EphemeralKey, packet.Nonce, packet.Ciphertext)
	if err == nil {
		t.Fatal("wrong key decrypted onion layer, want error")
	}
}

func TestDecryptLayerTamperedCiphertext(t *testing.T) {
	_, bobPriv, _ := crypto.GeneratePublicPrivatePair()
	bobPub := bobPriv.Public().(ed25519.PublicKey)

	packetBytes, _ := node.BuildOnionPacket([]byte("secret"), bobPub)
	var packet node.OnionPacket
	json.Unmarshal(packetBytes, &packet)

	packet.Ciphertext[len(packet.Ciphertext)-1] ^= 0xFF
	_, err := crypto.DecryptLayer(bobPriv, packet.EphemeralKey, packet.Nonce, packet.Ciphertext)
	if err == nil {
		t.Fatal("tampered ciphertext decrypted, want error")
	}
}

func TestDecryptLayerTamperedEphemeralKey(t *testing.T) {
	_, bobPriv, _ := crypto.GeneratePublicPrivatePair()
	bobPub := bobPriv.Public().(ed25519.PublicKey)

	packetBytes, _ := node.BuildOnionPacket([]byte("secret"), bobPub)
	var packet node.OnionPacket
	json.Unmarshal(packetBytes, &packet)

	packet.EphemeralKey[0] ^= 0xFF
	_, err := crypto.DecryptLayer(bobPriv, packet.EphemeralKey, packet.Nonce, packet.Ciphertext)
	if err == nil {
		t.Fatal("tampered ephemeral key decrypted, want error")
	}
}

func TestDecryptLayerEmptyPayload(t *testing.T) {
	_, bobPriv, _ := crypto.GeneratePublicPrivatePair()
	bobPub := bobPriv.Public().(ed25519.PublicKey)

	packetBytes, _ := node.BuildOnionPacket([]byte{}, bobPub)
	var packet node.OnionPacket
	json.Unmarshal(packetBytes, &packet)

	plaintext, err := crypto.DecryptLayer(bobPriv, packet.EphemeralKey, packet.Nonce, packet.Ciphertext)
	if err != nil {
		t.Fatalf("empty payload decrypt: %v", err)
	}
	if len(plaintext) != 0 {
		t.Fatalf("expected empty, got %d bytes", len(plaintext))
	}
}

func TestDecryptLayerLargePayload(t *testing.T) {
	_, bobPriv, _ := crypto.GeneratePublicPrivatePair()
	bobPub := bobPriv.Public().(ed25519.PublicKey)

	big := bytes.Repeat([]byte("x"), 10000)
	packetBytes, _ := node.BuildOnionPacket(big, bobPub)
	var packet node.OnionPacket
	json.Unmarshal(packetBytes, &packet)

	plaintext, err := crypto.DecryptLayer(bobPriv, packet.EphemeralKey, packet.Nonce, packet.Ciphertext)
	if err != nil {
		t.Fatalf("large payload decrypt: %v", err)
	}
	if !bytes.Equal(plaintext, big) {
		t.Fatal("large payload mismatch")
	}
}

// ---------- 3-hop onion routing e2e ----------

func TestOnionRoutingThreeHopsE2E(t *testing.T) {
	keyA, privA, _ := crypto.GeneratePublicPrivatePair()
	keyB, privB, _ := crypto.GeneratePublicPrivatePair()
	keyC, privC, _ := crypto.GeneratePublicPrivatePair()

	srvA := node.NewServer(privA)
	srvB := node.NewServer(privB)
	srvC := node.NewServer(privC)

	tsA := httptest.NewServer(srvA.Router())
	tsB := httptest.NewServer(srvB.Router())
	tsC := httptest.NewServer(srvC.Router())
	t.Cleanup(tsA.Close)
	t.Cleanup(tsB.Close)
	t.Cleanup(tsC.Close)

	bobPub, bobPriv, _ := crypto.GeneratePublicPrivatePair()
	bobID := crypto.GenerateAccountId(bobPub)

	// Inner: POST /messages to Node C
	reqBody, _ := json.Marshal(map[string]any{
		"recipient": bobID,
		"payload":   []byte("onion-encrypted-message"),
	})
	inner, _ := json.Marshal(node.UnWrappedPayload{
		NextNode:     "",
		Method:       "POST",
		Path:         "/messages",
		InnerPayload: reqBody,
	})

	// Layer C
	packetC, err := node.BuildOnionPacket(inner, keyC)
	if err != nil {
		t.Fatalf("packetC: %v", err)
	}

	// Layer B → C
	mid, _ := json.Marshal(node.UnWrappedPayload{
		NextNode:     tsC.URL,
		InnerPayload: packetC,
	})
	packetB, err := node.BuildOnionPacket(mid, keyB)
	if err != nil {
		t.Fatalf("packetB: %v", err)
	}

	// Layer A → B
	outer, _ := json.Marshal(node.UnWrappedPayload{
		NextNode:     tsB.URL,
		InnerPayload: packetB,
	})
	packetA, err := node.BuildOnionPacket(outer, keyA)
	if err != nil {
		t.Fatalf("packetA: %v", err)
	}

	// Send to Node A
	resp, err := http.Post(tsA.URL+"/onion", "application/json", bytes.NewReader(packetA))
	if err != nil {
		t.Fatalf("post to A: %v", err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusCreated {
		t.Fatalf("A responded %d, want 201", resp.StatusCode)
	}

	// Fetch from Node C with auth
	ts := "1234567890"
	sig := crypto.SignMessage(bobPriv, []byte(bobID+":"+ts))
	req, _ := http.NewRequest(http.MethodGet, tsC.URL+"/messages?recipient="+bobID, nil)
	req.Header.Set("X-Timestamp", ts)
	req.Header.Set("X-Signature", sig)
	fetchResp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("fetch: %v", err)
	}
	defer fetchResp.Body.Close()

	var msgs []node.Message
	json.NewDecoder(fetchResp.Body).Decode(&msgs)
	if len(msgs) != 1 {
		t.Fatalf("expected 1 message, got %d", len(msgs))
	}
	if !bytes.Equal(msgs[0].Payload, []byte("onion-encrypted-message")) {
		t.Fatalf("payload mismatch: %q", msgs[0].Payload)
	}
}

func TestOnionRoutingWrongNodeKey(t *testing.T) {
	keyA, privA, _ := crypto.GeneratePublicPrivatePair()
	keyB, privB, _ := crypto.GeneratePublicPrivatePair()
	keyC, privC, _ := crypto.GeneratePublicPrivatePair()

	srvA := node.NewServer(privA)
	srvB := node.NewServer(privB)
	srvC := node.NewServer(privC)

	tsA := httptest.NewServer(srvA.Router())
	tsB := httptest.NewServer(srvB.Router())
	tsC := httptest.NewServer(srvC.Router())
	t.Cleanup(tsA.Close)
	t.Cleanup(tsB.Close)
	t.Cleanup(tsC.Close)

	// Encrypt B layer with wrong key (not keyB)
	_, wrongPriv, _ := crypto.GeneratePublicPrivatePair()

	reqBody, _ := json.Marshal(map[string]any{"recipient": "bob", "payload": []byte("x")})
	inner, _ := json.Marshal(node.UnWrappedPayload{Method: "POST", Path: "/messages", InnerPayload: reqBody})
	packetC, _ := node.BuildOnionPacket(inner, keyC)
	mid, _ := json.Marshal(node.UnWrappedPayload{NextNode: tsC.URL, InnerPayload: packetC})
	// Encrypt for wrong key instead of keyB
	packetB, _ := node.BuildOnionPacket(mid, wrongPriv.Public().(ed25519.PublicKey))
	outer, _ := json.Marshal(node.UnWrappedPayload{NextNode: tsB.URL, InnerPayload: packetB})
	packetA, _ := node.BuildOnionPacket(outer, keyA)

	resp, err := http.Post(tsA.URL+"/onion", "application/json", bytes.NewReader(packetA))
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	// A forwards to B, but B can't decrypt (encrypted for wrong key)
	if resp.StatusCode == http.StatusCreated {
		t.Fatal("wrong key onion succeeded, want failure")
	}
}

func TestOnionForwardFailure(t *testing.T) {
	keyA, privA, _ := crypto.GeneratePublicPrivatePair()
	_, privDead, _ := crypto.GeneratePublicPrivatePair()

	srvA := node.NewServer(privA)
	tsA := httptest.NewServer(srvA.Router())
	t.Cleanup(tsA.Close)

	// Build outer layer for A, inner pointing to dead URL
	inner, _ := json.Marshal(node.UnWrappedPayload{Method: "POST", Path: "/messages", InnerPayload: []byte("{}")})
	mid, _ := json.Marshal(node.UnWrappedPayload{NextNode: "http://127.0.0.1:1", InnerPayload: inner})
	_ = privDead
	packetOuter, _ := node.BuildOnionPacket(mid, keyA)

	resp, err := http.Post(tsA.URL+"/onion", "application/json", bytes.NewReader(packetOuter))
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	// A tries to forward to dead node → should fail
	if resp.StatusCode == http.StatusOK || resp.StatusCode == http.StatusCreated {
		t.Fatal("forward to dead node succeeded, want failure")
	}
}

// ---------- server HandleOnion ----------

func TestHandleOnionInvalidJSON(t *testing.T) {
	_, priv, _ := crypto.GeneratePublicPrivatePair()
	srv := node.NewServer(priv)
	ts := httptest.NewServer(srv.Router())
	t.Cleanup(ts.Close)

	resp, _ := http.Post(ts.URL+"/onion", "application/json", bytes.NewReader([]byte("not json")))
	resp.Body.Close()
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("bad JSON status = %d, want 400", resp.StatusCode)
	}
}

func TestHandleOnionMethodNotAllowed(t *testing.T) {
	_, priv, _ := crypto.GeneratePublicPrivatePair()
	srv := node.NewServer(priv)
	ts := httptest.NewServer(srv.Router())
	t.Cleanup(ts.Close)

	resp, _ := http.Get(ts.URL + "/onion")
	resp.Body.Close()
	if resp.StatusCode != http.StatusMethodNotAllowed {
		t.Fatalf("GET /onion status = %d, want 405", resp.StatusCode)
	}
}

func TestHandleOnionBadPacketDecryptFails(t *testing.T) {
	_, priv, _ := crypto.GeneratePublicPrivatePair()
	srv := node.NewServer(priv)
	ts := httptest.NewServer(srv.Router())
	t.Cleanup(ts.Close)

	badPacket, _ := json.Marshal(node.OnionPacket{
		EphemeralKey: make([]byte, 32),
		Nonce:        make([]byte, 24),
		Ciphertext:   make([]byte, 16),
	})
	resp, _ := http.Post(ts.URL+"/onion", "application/json", bytes.NewReader(badPacket))
	resp.Body.Close()
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("bad packet status = %d, want 401", resp.StatusCode)
	}
}

// ---------- CORS ----------

func TestCORSHeaders(t *testing.T) {
	_, priv, _ := crypto.GeneratePublicPrivatePair()
	srv := node.NewServer(priv)
	ts := httptest.NewServer(srv.Router())
	t.Cleanup(ts.Close)

	// OPTIONS on /messages
	resp, _ := http.NewRequest(http.MethodOptions, ts.URL+"/messages", nil)
	r, _ := http.DefaultClient.Do(resp)
	r.Body.Close()
	if r.Header.Get("Access-Control-Allow-Origin") != "*" {
		t.Fatal("missing CORS origin on /messages")
	}

	// OPTIONS on /onion
	resp2, _ := http.NewRequest(http.MethodOptions, ts.URL+"/onion", nil)
	r2, _ := http.DefaultClient.Do(resp2)
	r2.Body.Close()
	if r2.Header.Get("Access-Control-Allow-Origin") != "*" {
		t.Fatal("missing CORS origin on /onion")
	}
}

// ---------- message JSON round-trip ----------

func TestMessageJSONRoundTrip(t *testing.T) {
	orig := message.Message{
		From:      "05aabbcc",
		To:        "05ddeeff",
		Subject:   "json test",
		Body:      "hello json",
		TimeStamp: 12345,
	}
	data, err := json.Marshal(orig)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	var got message.Message
	if err := json.Unmarshal(data, &got); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if got.Subject != orig.Subject || got.Body != orig.Body {
		t.Fatalf("mismatch: %+v vs %+v", got, orig)
	}
}

// ---------- full send-through-onion-then-fetch ----------

func TestOnionSendThenFetchE2E(t *testing.T) {
	keyA, privA, _ := crypto.GeneratePublicPrivatePair()
	keyB, privB, _ := crypto.GeneratePublicPrivatePair()
	keyC, privC, _ := crypto.GeneratePublicPrivatePair()

	srvA := node.NewServer(privA)
	srvB := node.NewServer(privB)
	srvC := node.NewServer(privC)

	tsA := httptest.NewServer(srvA.Router())
	tsB := httptest.NewServer(srvB.Router())
	tsC := httptest.NewServer(srvC.Router())
	t.Cleanup(tsA.Close)
	t.Cleanup(tsB.Close)
	t.Cleanup(tsC.Close)

	alicePub, alicePriv, _ := crypto.GeneratePublicPrivatePair()
	bobPub, bobPriv, _ := crypto.GeneratePublicPrivatePair()
	bobID := crypto.GenerateAccountId(bobPub)

	// Alice builds email
	orig := message.Message{
		From:      crypto.GenerateAccountId(alicePub),
		To:        bobID,
		Subject:   "onion test",
		Body:      "through the hops",
	}
	padded := message.SerializeMessage(orig)
	sigHex := crypto.SignMessage(alicePriv, padded)
	sig, _ := hex.DecodeString(sigHex)
	packed := message.BuildSignedMessage(padded, []byte(alicePub), sig)
	env, _ := crypto.EncryptMessage(packed, bobPub)

	// Build onion A → B → C
	reqBody, _ := json.Marshal(map[string]any{"recipient": bobID, "payload": env})
	inner, _ := json.Marshal(node.UnWrappedPayload{Method: "POST", Path: "/messages", InnerPayload: reqBody})
	packetC, _ := node.BuildOnionPacket(inner, keyC)
	mid, _ := json.Marshal(node.UnWrappedPayload{NextNode: tsC.URL, InnerPayload: packetC})
	packetB, _ := node.BuildOnionPacket(mid, keyB)
	outer, _ := json.Marshal(node.UnWrappedPayload{NextNode: tsB.URL, InnerPayload: packetB})
	packetA, _ := node.BuildOnionPacket(outer, keyA)

	// Send
	resp, _ := http.Post(tsA.URL+"/onion", "application/json", bytes.NewReader(packetA))
	resp.Body.Close()
	if resp.StatusCode != http.StatusCreated {
		t.Fatalf("send status = %d, want 201", resp.StatusCode)
	}

	// Bob fetches from C
	ts := "9999999999"
	sig2 := crypto.SignMessage(bobPriv, []byte(bobID+":"+ts))
	req, _ := http.NewRequest(http.MethodGet, tsC.URL+"/messages?recipient="+bobID, nil)
	req.Header.Set("X-Timestamp", ts)
	req.Header.Set("X-Signature", sig2)
	fetchResp, _ := http.DefaultClient.Do(req)
	defer fetchResp.Body.Close()

	var msgs []node.Message
	json.NewDecoder(fetchResp.Body).Decode(&msgs)
	if len(msgs) != 1 {
		t.Fatalf("expected 1 message, got %d", len(msgs))
	}

	// Bob decrypts
	opened, err := crypto.DecryptMessage(msgs[0].Payload, bobPriv)
	if err != nil {
		t.Fatalf("bob decrypt: %v", err)
	}
	gotPadded := opened[:len(opened)-96]
	gotPub := opened[len(opened)-96 : len(opened)-64]
	gotSig := opened[len(opened)-64:]

	if !crypto.VerifyMessage(ed25519.PublicKey(gotPub), gotPadded, hex.EncodeToString(gotSig)) {
		t.Fatal("signature verification failed")
	}
	final := message.DeserializeMessage(gotPadded)
	if final.Subject != "onion test" || final.Body != "through the hops" {
		t.Fatalf("message mismatch: %+v", final)
	}
}
