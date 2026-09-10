package crypto

import (
	"crypto/ed25519"
	"encoding/hex"
)

func SignMessage(privateKey ed25519.PrivateKey, message []byte) string {
	signature := ed25519.Sign(privateKey, message)

	return hex.EncodeToString(signature)
}

func VerifyMessage(publicKey ed25519.PublicKey, message []byte, signature string) bool {
	sign, err := hex.DecodeString(signature)
	if err != nil {
		return false

	}
	return ed25519.Verify(publicKey, message, sign)

}
func VerifySignature(pubKeyHex string, message []byte, signatureHex string) bool {
	pubKeyBytes, err := hex.DecodeString(pubKeyHex)
	if err != nil || len(pubKeyBytes) != ed25519.PublicKeySize {
		return false
	}

	return VerifyMessage(ed25519.PublicKey(pubKeyBytes), message, signatureHex)
}
