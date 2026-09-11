package node

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"

	"golang.org/x/crypto/curve25519"

	"session-email/src/crypto"
)

func BuildOnionPacket(payload []byte, recipientPub ed25519.PublicKey) ([]byte, error) {
	var ephPriv [32]byte
	if _, err := rand.Read(ephPriv[:]); err != nil {
		return nil, err
	}
	ephPub, err := curve25519.X25519(ephPriv[:], curve25519.Basepoint)
	if err != nil {
		return nil, err
	}

	recipX, err := crypto.Ed25519PublicKeyToX25519(recipientPub)
	if err != nil {
		return nil, err
	}

	shared, err := curve25519.X25519(ephPriv[:], recipX[:])
	if err != nil {
		return nil, err
	}

	block, err := aes.NewCipher(shared)
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}

	nonce := make([]byte, gcm.NonceSize())
	ciphertext := gcm.Seal(nil, nonce, payload, nil)

	packet := OnionPacket{
		EphemeralKey: ephPub,
		Nonce:        nonce,
		Ciphertext:   ciphertext,
	}
	return json.Marshal(packet)
}
