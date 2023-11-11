package main

import (
	"encryptedMessenger/encryption"
	"fmt"
)

func main() {
	key := []uint8{0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00}
	// message := []uint8{0x00, 0x00, 0x01, 0x01,
	// 	0x03, 0x03, 0x07, 0x07,
	// 	0x0f, 0x0f, 0x1f, 0x1f,
	// 	0x3f, 0x3f, 0x7f, 0x7f}

	// encptedMessage := encryption.EncryptMessage(message, key)
	// fmt.Printf("Encrypted message:\n%x\n", encptedMessage)
	// decyptedMessage := encryption.DecryptMessage(encptedMessage, key)
	// fmt.Printf("Decrypted message:\n%x\n", decyptedMessage)
	message := "Nei så tjukk du har blit sdjewoifoiqfiqjfodifijnvirdqnwhnfqoierjnfoiuwedoiewoidjwqoidiqwehfiouuewqrhfioujdioursfoewinrfoerhbvyuthgoiejndskjbiuafseasjfhuieabisodhbcifebacse sarfiseahdoiasuncsoiduhefwaufbisahdnciaushfiuasbfiuashbfiaubs"
	data := encryption.EncryptAES_128(message, key)
	fmt.Printf("%x\n", data)
	fmt.Println(encryption.DecryptAES_128(data, key))

}
