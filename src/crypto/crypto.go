package crypto

import (
	"crypto/ed25519"
	"fmt"

	"golang.org/x/crypto/nacl/box"
)

func DecryptLayer(privKey ed25519.PrivateKey, ephemeralPubKey []byte, nonce []byte, ciphertext []byte) ([]byte, error) {
	curvePriv := Ed25519PrivateKeyToX25519(privKey)

	var ephPub [32]byte
	copy(ephPub[:], ephemeralPubKey)

	opened, ok := box.Open(nil, ciphertext, (*[24]byte)(nonce), &ephPub, &curvePriv)
	if !ok {
		return nil, fmt.Errorf("onion layer decryption failed")
	}
	return opened, nil
}
