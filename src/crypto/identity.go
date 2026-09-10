package crypto

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/hex"
)

func GeneratePublicPrivatePair() (ed25519.PublicKey, ed25519.PrivateKey, error) {
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, nil, err
	}

	return publicKey, privateKey, nil
}

func GenerateAccountId(publicKey ed25519.PublicKey) string {
	total_pk := append([]byte{0x05}, publicKey...)
	accountId := hex.EncodeToString(total_pk)

	return accountId
}
