package main

import (
	"fmt"

	keymanager "wallet-bitcoin/src/key_manager"
)

func main() {
	mnemonic, seed, err := keymanager.GenerateSeedEnt128()
	if err != nil {
		fmt.Println("error:", err)
		return
	}
	fmt.Println("mnemonic:", mnemonic)
	fmt.Printf("seed: %x\n, len: %d\n", seed, len(seed))
}
