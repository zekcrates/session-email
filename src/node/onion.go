package node

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"

	"golang.org/x/crypto/nacl/box"

	"session-email/src/crypto"
)

func BuildOnionPacket(payload []byte, recipientPub ed25519.PublicKey) ([]byte, error) {
	ephPub, ephPriv, err := box.GenerateKey(rand.Reader)
	if err != nil {
		return nil, err
	}

	recipX, err := crypto.Ed25519PublicKeyToX25519(recipientPub)
	if err != nil {
		return nil, err
	}

	var nonce [24]byte
	ciphertext := box.Seal(nil, payload, &nonce, &recipX, ephPriv)

	packet := OnionPacket{
		EphemeralKey: ephPub[:],
		Nonce:        nonce[:],
		Ciphertext:   ciphertext,
	}
	return json.Marshal(packet)
}
