package message

import (
	"bytes"
	"encoding/json"
)

type Message struct {
	From      string
	To        string
	TimeStamp int64
	Subject   string
	Body      string
}

func SerializeMessage(message Message) []byte {
	data, err := json.Marshal(message)
	if err != nil {
		return nil
	}
	return PadMessage(data)
}

func DeserializeMessage(data []byte) Message {
	var message Message
	data = UnpadMessage(data)
	err := json.Unmarshal(data, &message)

	if err != nil {
		return Message{}
	}
	return message

}

func PadMessage(data []byte) []byte {
	const blockSize = 160
	padding := blockSize - (len(data) % blockSize)
	if padding == blockSize {
		return data
	}

	padded := make([]byte, len(data)+padding)
	copy(padded, data)
	return padded
}

func UnpadMessage(data []byte) []byte {
	return bytes.TrimRight(data, "\x00")
}

func BuildSignedMessage(paddedMessage []byte, senderPublicKey []byte, signature []byte) []byte {
	result := append(paddedMessage, senderPublicKey...)
	result = append(result, signature...)
	return result
}
