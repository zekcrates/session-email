package crypto

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha512"
	"fmt"

	"filippo.io/edwards25519"
	"golang.org/x/crypto/nacl/box"
)

// Helper function to convert Ed25519 Public Key to X25519 Public Key
func Ed25519PublicKeyToX25519(pk ed25519.PublicKey) ([32]byte, error) {
	var out [32]byte
	pt, err := new(edwards25519.Point).SetBytes(pk)
	if err != nil {
		return out, fmt.Errorf("invalid ed25519 public key: %w", err)
	}
	copy(out[:], pt.BytesMontgomery())
	return out, nil
}
func Ed25519PrivateKeyToX25519(sk ed25519.PrivateKey) [32]byte {
	var out [32]byte
	h := sha512.Sum512(sk.Seed())
	h[0] &= 248
	h[31] &= 127
	h[31] |= 64
	copy(out[:], h[:32])
	return out
}

func EncryptMessage(message []byte, recvPublicKey ed25519.PublicKey) ([]byte, error) {
	ephemeralPub, ephimeralPriv, err := box.GenerateKey(rand.Reader)
	if err != nil {
		return nil, err
	}

	var nonce [24]byte
	recvPubArr, err := Ed25519PublicKeyToX25519(recvPublicKey)
	if err != nil {
		return nil, err
	}

	ciphertext := box.Seal(nonce[:], message, &nonce, &recvPubArr, ephimeralPriv)

	finalPayload := append(ephemeralPub[:], ciphertext...)
	return finalPayload, nil

}

func DecryptMessage(payload []byte, recvPrivateKey ed25519.PrivateKey) ([]byte, error) {
	if len(payload) < 72 {
		return nil, fmt.Errorf("payload too short")
	}
	var senderEphermalPub [32]byte
	copy(senderEphermalPub[:], payload[:32])
	var nonce [24]byte
	copy(nonce[:], payload[32:56])

	ciphertext := payload[56:]
	recvPrivArr := Ed25519PrivateKeyToX25519(recvPrivateKey)
	decrypted, ok := box.Open(nil, ciphertext, &nonce, &senderEphermalPub, &recvPrivArr)
	if !ok {
		return nil, fmt.Errorf("decryption/authentication failed")
	}

	return decrypted, nil

}
