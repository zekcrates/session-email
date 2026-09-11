package main

import (
	"bytes"
	"crypto/ed25519"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log"
	"net/http"

	"session-email/src/crypto"
	"session-email/src/message"
	"session-email/src/node"
)

func mustHex(s string) []byte {
	b, _ := hex.DecodeString(s)
	return b
}

func main() {
	keyA, Apriv, _ := crypto.GeneratePublicPrivatePair()
	keyB, Bpriv, _ := crypto.GeneratePublicPrivatePair()
	keyC, Cpriv, _ := crypto.GeneratePublicPrivatePair()

	srvA := node.NewServer(Apriv)
	srvB := node.NewServer(Bpriv)
	srvC := node.NewServer(Cpriv)

	go http.ListenAndServe(":8001", srvA.Router())
	go http.ListenAndServe(":8002", srvB.Router())
	go http.ListenAndServe(":8003", srvC.Router())
	fmt.Println("Node A on :8001")
	fmt.Println("Node B on :8002")
	fmt.Println("Node C (Bob's swarm) on :8003")
	alicePub, alicePriv, _ := crypto.GeneratePublicPrivatePair()
	aliceID := crypto.GenerateAccountId(alicePub)

	bobPub, bobPriv, _ := crypto.GeneratePublicPrivatePair()
	bobID := crypto.GenerateAccountId(bobPub)

	fmt.Printf("Alice ID: %s\nBob ID:   %s\n", aliceID, bobID)

	msg := message.Message{
		From:    aliceID,
		To:      bobID,
		Subject: "just checking if this works",
		Body:    "just setting up my mail",
	}

	padded := message.SerializeMessage(msg)
	signHex := crypto.SignMessage(alicePriv, padded)
	packed := message.BuildSignedMessage(padded, []byte(alicePub), mustHex(signHex))
	env, _ := crypto.EncryptMessage(packed, bobPub)
	fmt.Printf("Envelope: %d bytes\n", len(env))
	reqBody, _ := json.Marshal(map[string]any{
		"recipient": bobID,
		"payload":   env,
	})

	inner, _ := json.Marshal(node.UnWrappedPayload{
		NextNode:     "",
		Method:       "POST",
		Path:         "/messages",
		InnerPayload: reqBody,
	})

	packetC, _ := node.BuildOnionPacket(inner, keyC)

	mid, _ := json.Marshal(node.UnWrappedPayload{
		NextNode:     "http://localhost:8003",
		InnerPayload: packetC,
	})

	packetB, _ := node.BuildOnionPacket(mid, keyB)

	outer, _ := json.Marshal(node.UnWrappedPayload{
		NextNode:     "http://localhost:8002",
		InnerPayload: packetB,
	})
	packetA, _ := node.BuildOnionPacket(outer, keyA)
	fmt.Printf("Onion: %d bytes\n", len(packetA))
	resp, err := http.Post("http://localhost:8001/onion", "application/json", bytes.NewReader(packetA))
	if err != nil {
		log.Fatal(err)
	}
	fmt.Printf("Sent → A responded %d\n", resp.StatusCode)

	sw := node.NewSwarm("bob-swarm", []string{"http://localhost:8003"})
	msgs, err := sw.FetchMessages(bobID, bobPriv)
	if err != nil {
		log.Fatal(err)
	}
	fmt.Printf("Bob fetched %d message(s)\n", len(msgs))

	opened, _ := crypto.DecryptMessage(msgs[0].Payload, bobPriv)
	gotPadded := opened[:len(opened)-96]
	gotPub := opened[len(opened)-96 : len(opened)-64]
	gotSig := opened[len(opened)-64:]

	if !crypto.VerifyMessage(ed25519.PublicKey(gotPub), gotPadded, hex.EncodeToString(gotSig)) {
		log.Fatal("signature failed")
	}

	final := message.DeserializeMessage(gotPadded)
	fmt.Printf("\n=== MESSAGE ===\n")
	fmt.Printf("From:    %s\n", final.From)
	fmt.Printf("Subject: %s\n", final.Subject)
	fmt.Printf("Body:    %s\n", final.Body)
}
