package main

import (
	"fmt"
	"log"

	"github.com/AegisSec/veil-server/internal/push"
)

func main() {
	privateKey, publicKey, err := push.GenerateVAPIDPrivateKey()
	if err != nil {
		log.Fatal(err)
	}
	fmt.Printf("VEIL_PUSH_VAPID_PRIVATE_KEY=%s\n", privateKey)
	fmt.Printf("# VAPID public key: %s\n", publicKey)
}
