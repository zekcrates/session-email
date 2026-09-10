package tests

import (
	"bytes"
	"testing"

	"session-email/src/crypto"
)

// Simple: keygen should give valid sizes and unique keys.
func TestGenerateKeysSimple(t *testing.T) {
	pub1, priv1, err := crypto.GeneratePublicPrivatePair()
	if err != nil {
		t.Fatalf("keygen failed: %v", err)
	}
	if len(pub1) != 32 {
		t.Fatalf("pub len = %d, want 32", len(pub1))
	}
	if len(priv1) != 64 {
		t.Fatalf("priv len = %d, want 64", len(priv1))
	}

	pub2, _, err := crypto.GeneratePublicPrivatePair()
	if err != nil {
		t.Fatalf("second keygen failed: %v", err)
	}
	if bytes.Equal(pub1, pub2) {
		t.Fatal("two keygens gave same pubkey, expected different")
	}
}

// Simple: account ID format (Session style: "05" + hex pubkey).
func TestAccountIDSimple(t *testing.T) {
	pub, _, err := crypto.GeneratePublicPrivatePair()
	if err != nil {
		t.Fatal(err)
	}
	id := crypto.GenerateAccountId(pub)
	if len(id) != 66 {
		t.Fatalf("account id len = %d, want 66", len(id))
	}
	if id[:2] != "05" {
		t.Fatalf("account id should start with 05, got %q", id[:2])
	}
}

// Simple: sign then verify passes.
func TestSignVerifySimple(t *testing.T) {
	pub, priv, _ := crypto.GeneratePublicPrivatePair()
	msg := []byte("hello world")

	sig := crypto.SignMessage(priv, msg)
	if len(sig) != 128 { // 64 bytes hex-encoded
		t.Fatalf("sig len = %d, want 128 hex chars", len(sig))
	}
	if !crypto.VerifyMessage(pub, msg, sig) {
		t.Fatal("valid signature did not verify")
	}
}

// Simple: tampered message or wrong key should fail.
func TestSignVerifyRejects(t *testing.T) {
	alicePub, alicePriv, _ := crypto.GeneratePublicPrivatePair()
	bobPub, _, _ := crypto.GeneratePublicPrivatePair()
	msg := []byte("important bytes")

	sig := crypto.SignMessage(alicePriv, msg)

	bad := append([]byte(nil), msg...)
	bad[0] ^= 0xFF
	if crypto.VerifyMessage(alicePub, bad, sig) {
		t.Fatal("tampered message verified, want reject")
	}
	if crypto.VerifyMessage(bobPub, msg, sig) {
		t.Fatal("wrong pubkey verified, want reject")
	}
	if crypto.VerifyMessage(alicePub, msg, "not-hex!!") {
		t.Fatal("bad hex signature verified, want reject")
	}
}

// Simple: encrypt -> decrypt round-trip.
func TestEncryptDecryptSimple(t *testing.T) {
	bobPub, bobPriv, err := crypto.GeneratePublicPrivatePair()
	if err != nil {
		t.Fatal(err)
	}

	cases := [][]byte{
		[]byte("hi"),
		[]byte("a medium length secret message for testing 12345"),
		bytes.Repeat([]byte("x"), 500),
	}

	for i, plain := range cases {
		env, err := crypto.EncryptMessage(plain, bobPub)
		if err != nil {
			t.Fatalf("case %d encrypt failed: %v", i, err)
		}
		if len(env) <= len(plain) {
			t.Fatalf("case %d: envelope not bigger than plaintext", i)
		}
		back, err := crypto.DecryptMessage(env, bobPriv)
		if err != nil {
			t.Fatalf("case %d decrypt failed: %v", i, err)
		}
		if !bytes.Equal(back, plain) {
			t.Fatalf("case %d mismatch: got %q want %q", i, back, plain)
		}
	}
}

// Medium: wrong key and truncated payload must fail, not panic.
func TestDecryptNegativeMedium(t *testing.T) {
	_, alicePriv, _ := crypto.GeneratePublicPrivatePair()
	bobPub, bobPriv, _ := crypto.GeneratePublicPrivatePair()

	env, err := crypto.EncryptMessage([]byte("secret"), bobPub)
	if err != nil {
		t.Fatal(err)
	}

	if _, err := crypto.DecryptMessage(env, alicePriv); err == nil {
		t.Fatal("decrypt with wrong key succeeded, want error")
	}
	if _, err := crypto.DecryptMessage(env, bobPriv); err != nil {
		t.Fatalf("correct key failed: %v", err)
	}
	if _, err := crypto.DecryptMessage([]byte{1, 2, 3}, bobPriv); err == nil {
		t.Fatal("tiny payload decrypted, want error")
	}
	if _, err := crypto.DecryptMessage(env[:len(env)-1], bobPriv); err == nil {
		t.Fatal("truncated envelope decrypted, want error")
	}
}
