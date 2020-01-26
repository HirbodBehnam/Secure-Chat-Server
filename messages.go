package main

import (
	"encoding/json"
	"time"
)

// Types that client send to server

// Types that are message based
type ReceiveMessageStruct struct {
	Type    byte `json:"type"`
	Payload struct {
		To      string `json:"to"`
		Message string `json:"message"`
	} `json:"payload"`
}

// Types that are not message based
type HelloStruct struct { // User sends this when it's connecting to server
	Username string `json:"username"`
	Password string `json:"password"`
	Verify   string `json:"verify"`
}

// Types that server sends to client
type ClientUpdateTypeStruct struct {
	Type    byte `json:"type"` // 0 -> Text message / 1 -> File
	Payload struct {
		From    string    `json:"from"`    // The username of sender
		Date    time.Time `json:"date"`    // When the message is sent
		Message string    `json:"message"` // Base64 of the message with an ChaCha20 encryption on top of it
	}
}
type UserDataStruct struct {
	Name      string `json:"name"`
	Username  string `json:"username"`
	PublicKey string `json:"public_key"`
}

type StatusStruct struct {
	OK      bool   `json:"ok"`
	Message string `json:"message"`
}

func GenerateStatus(ok bool, msg string) []byte {
	b, _ := json.Marshal(StatusStruct{ok, msg})
	return b
}
