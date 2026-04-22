package main

import (
	"BitcoinParser/src/block"
	"encoding/hex"
	"fmt"
	"log"
)

func main() {

	hex_block := "00000120892bd903087355158164339df69332fd413e99ad820f00000000000000000000baef6518eff11d4923b4d6d298918ee4de4b75825c1cebcf67f33031fe4748589664e76969130217323e3c09"

	rawBytes, err := hex.DecodeString(hex_block)
	if err != nil {
		log.Fatalf("Errore decodifica hex: %v", err)
	}

	blk := block.Parse(rawBytes)
	fmt.Println(blk.ToString())

	fmt.Printf("Target: %v\n", blk.ComputeTarget())

	fmt.Printf("Serialized Block Data: %v\n", blk.GetSerializedBlockHeaderHex())

	fmt.Printf("Hash: %v\n", blk.GetHashHex())

	fmt.Printf("Block is Valid? %v\n", blk.IsValid())
}
