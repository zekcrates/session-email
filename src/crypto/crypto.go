package crypto

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/ed25519"
	"crypto/sha512"

	"golang.org/x/crypto/curve25519"
)

func DecryptLayer(privKey ed25519.PrivateKey, ephemeralPubKey []byte, nonce []byte, ciphertext []byte) ([]byte, error) {
	curvePriv := ed25519PrivateKeyToCurve25519(privKey)

	sharedSecret, err := curve25519.X25519(curvePriv, ephemeralPubKey)
	if err != nil {
		return nil, err
	}

	block, err := aes.NewCipher(sharedSecret)
	if err != nil {
		return nil, err
	}

	aesgcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}

	return aesgcm.Open(nil, nonce, ciphertext, nil)
}

func ed25519PrivateKeyToCurve25519(pk ed25519.PrivateKey) []byte {
	seed := pk.Seed()

	h := sha512.Sum512(seed)

	out := make([]byte, 32)
	copy(out, h[:32])

	out[0] &= 248
	out[31] &= 127
	out[31] |= 64

	return out
}
