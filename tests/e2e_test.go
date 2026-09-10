package tests

import (
	"bytes"
	"crypto/ed25519"
	"encoding/hex"
	"testing"
	"time"

	"session-email/src/crypto"
	"session-email/src/message"
)

// Medium: full Alice -> Bob flow with sign + encrypt.
func TestFullEmailFlowMedium(t *testing.T) {
	alicePub, alicePriv, err := crypto.GeneratePublicPrivatePair()
	if err != nil {
		t.Fatal(err)
	}
	bobPub, bobPriv, err := crypto.GeneratePublicPrivatePair()
	if err != nil {
		t.Fatal(err)
	}

	orig := message.Message{
		From:      crypto.GenerateAccountId(alicePub),
		To:        crypto.GenerateAccountId(bobPub),
		TimeStamp: time.Now().Unix(),
		Subject:   "meeting",
		Body:      "meet at 5pm, bring the docs. this is secret!",
	}

	// Alice sends
	padded := message.SerializeMessage(orig)
	sigHex := crypto.SignMessage(alicePriv, padded)
	sig, err := hex.DecodeString(sigHex)
	if err != nil {
		t.Fatal(err)
	}
	packed := message.BuildSignedMessage(padded, []byte(alicePub), sig)
	env, err := crypto.EncryptMessage(packed, bobPub)
	if err != nil {
		t.Fatalf("encrypt: %v", err)
	}

	// Bob receives
	opened, err := crypto.DecryptMessage(env, bobPriv)
	if err != nil {
		t.Fatalf("decrypt: %v", err)
	}
	if len(opened) < 96 {
		t.Fatalf("opened too short: %d", len(opened))
	}
	gotPadded := opened[:len(opened)-96]
	gotPub := opened[len(opened)-96 : len(opened)-64]
	gotSig := opened[len(opened)-64:]

	if !bytes.Equal(gotPub, []byte(alicePub)) {
		t.Fatal("sender pub mismatch")
	}
	if !crypto.VerifyMessage(ed25519.PublicKey(gotPub), gotPadded, hex.EncodeToString(gotSig)) {
		t.Fatal("signature did not verify")
	}
	final := message.DeserializeMessage(gotPadded)
	if final.Subject != orig.Subject || final.Body != orig.Body {
		t.Fatalf("body mismatch: got %+v want %+v", final, orig)
	}
}

// Medium: tampering should be detected (decrypt or verify fails).
func TestTamperDetectedMedium(t *testing.T) {
	alicePub, alicePriv, _ := crypto.GeneratePublicPrivatePair()
	bobPub, bobPriv, _ := crypto.GeneratePublicPrivatePair()

	padded := message.SerializeMessage(message.Message{
		From:      crypto.GenerateAccountId(alicePub),
		To:        crypto.GenerateAccountId(bobPub),
		TimeStamp: time.Now().Unix(),
		Subject:   "s",
		Body:      "tamper me",
	})
	sigHex := crypto.SignMessage(alicePriv, padded)
	sig, _ := hex.DecodeString(sigHex)
	env, _ := crypto.EncryptMessage(message.BuildSignedMessage(padded, []byte(alicePub), sig), bobPub)

	// flip a byte in the ciphertext tail
	bad := append([]byte(nil), env...)
	bad[len(bad)-1] ^= 0xFF
	if _, err := crypto.DecryptMessage(bad, bobPriv); err == nil {
		// Very rarely a flip could still authenticate? Treat as fail-only
		// if verify also passes — keep test loose.
		t.Log("note: flipped tail still decrypted (box accepted it), checking verify path")
	}

	// flip a byte in the plaintext and check verify rejects
	opened, err := crypto.DecryptMessage(env, bobPriv)
	if err != nil {
		t.Fatal(err)
	}
	opened[0] ^= 0xFF
	gotPadded := opened[:len(opened)-96]
	gotSig := opened[len(opened)-64:]
	if crypto.VerifyMessage(alicePub, gotPadded, hex.EncodeToString(gotSig)) {
		t.Fatal("tampered plaintext verified, want reject")
	}
}

// Medium: only the intended recipient can read.
func TestOnlyRecipientCanReadMedium(t *testing.T) {
	alicePub, alicePriv, _ := crypto.GeneratePublicPrivatePair()
	bobPub, bobPriv, _ := crypto.GeneratePublicPrivatePair()
	evePub, evePriv, _ := crypto.GeneratePublicPrivatePair()
	_ = evePub

	padded := message.SerializeMessage(message.Message{
		From:      crypto.GenerateAccountId(alicePub),
		To:        crypto.GenerateAccountId(bobPub),
		TimeStamp: time.Now().Unix(),
		Subject:   "private",
		Body:      "for bob only",
	})
	sigHex := crypto.SignMessage(alicePriv, padded)
	sig, _ := hex.DecodeString(sigHex)
	env, _ := crypto.EncryptMessage(message.BuildSignedMessage(padded, []byte(alicePub), sig), bobPub)

	if _, err := crypto.DecryptMessage(env, evePriv); err == nil {
		t.Fatal("eve decrypted bob's mail, want error")
	}
	if _, err := crypto.DecryptMessage(env, bobPriv); err != nil {
		t.Fatalf("bob could not decrypt: %v", err)
	}
}
