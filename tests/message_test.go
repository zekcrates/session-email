package tests

import (
	"bytes"
	"encoding/hex"
	"testing"
	"time"

	"session-email/src/crypto"
	"session-email/src/message"
)

func sampleMessage() message.Message {
	alicePub, _, _ := crypto.GeneratePublicPrivatePair()
	bobPub, _, _ := crypto.GeneratePublicPrivatePair()
	return message.Message{
		From:      crypto.GenerateAccountId(alicePub),
		To:        crypto.GenerateAccountId(bobPub),
		TimeStamp: time.Now().Unix(),
		Subject:   "hello",
		Body:      "test body",
	}
}

// Simple: serialize then deserialize keeps fields.
func TestSerializeRoundTripSimple(t *testing.T) {
	orig := sampleMessage()
	orig.Subject = "hi bob"
	orig.Body = "how are you?"

	padded := message.SerializeMessage(orig)
	if len(padded) == 0 {
		t.Fatal("serialized is empty")
	}
	back := message.DeserializeMessage(padded)
	if back.Subject != orig.Subject || back.Body != orig.Body {
		t.Fatalf("mismatch: got %+v want %+v", back, orig)
	}
	if back.From != orig.From || back.To != orig.To {
		t.Fatalf("from/to lost: got %+v want %+v", back, orig)
	}
}

// Simple: padding grows to 160-byte blocks and unpads cleanly.
func TestPadUnpadSimple(t *testing.T) {
	cases := [][]byte{
		[]byte("short"),
		bytes.Repeat([]byte("a"), 159),
		bytes.Repeat([]byte("b"), 160),
		bytes.Repeat([]byte("c"), 161),
		bytes.Repeat([]byte("d"), 500),
	}
	for i, c := range cases {
		padded := message.PadMessage(c)
		if len(padded)%160 != 0 {
			// relaxed: current code returns input as-is when already aligned,
			// so only fail when it actually padded but misaligned.
			t.Fatalf("case %d: padded len %d not multiple of 160", i, len(padded))
		}
		if len(padded) < len(c) {
			t.Fatalf("case %d: padded shorter than input", i)
		}
		back := message.UnpadMessage(padded)
		if !bytes.Equal(back, c) {
			t.Fatalf("case %d: unpad mismatch", i)
		}
	}
}

// Simple: packed layout is padded + 32B pub + 64B sig.
func TestBuildSignedMessageSimple(t *testing.T) {
	pub, priv, _ := crypto.GeneratePublicPrivatePair()
	m := sampleMessage()
	padded := message.SerializeMessage(m)

	sigHex := crypto.SignMessage(priv, padded)
	sig, err := hex.DecodeString(sigHex)
	if err != nil {
		t.Fatalf("sig decode: %v", err)
	}

	packed := message.BuildSignedMessage(padded, []byte(pub), sig)
	if len(packed) != len(padded)+32+64 {
		t.Fatalf("packed len = %d, want %d", len(packed), len(padded)+96)
	}
	// last 96 bytes should be pub + sig
	if !bytes.Equal(packed[len(packed)-96:len(packed)-64], []byte(pub)) {
		t.Fatal("sender pub not at expected offset")
	}
}
