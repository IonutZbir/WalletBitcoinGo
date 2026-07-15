package main

import (
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log"
	"os"

	wallet "wallet-bitcoin/src"
	keymanager "wallet-bitcoin/src/key_manager"

	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/btcutil"
	"github.com/btcsuite/btcd/chaincfg"
)

func generateDemoWallet() {
	mnemonic, seed, err := keymanager.GenerateSeedEnt128()
	if err != nil {
		fmt.Println("error: ", err)
		return
	}

	fmt.Println("mnemonic:", mnemonic)
	fmt.Printf("seed: %x\n, len: %d\n", seed, len(seed))

	master, err := keymanager.NewMasterKey(seed[:])
	if err != nil {
		fmt.Println("error: ", err)
	}

	path0 := []uint32{
		44 + keymanager.HardenedOffset,
		0 + keymanager.HardenedOffset,
		0 + keymanager.HardenedOffset,
		0,
		0,
	}

	key_path0, err := keymanager.DeriveKeyPath(master, path0)
	if err != nil {
		fmt.Println("error: ", err)
	}
	addressMain, err := keymanager.DeriveLegacyAddress(key_path0, false)
	addressTest, err := keymanager.DeriveLegacyAddress(key_path0, true)
	if err != nil {
		fmt.Println("error: ", err)
	}

	type WalletDemo struct {
		Mnemonic   []string `json:"mnemonic"`
		Seed       string   `json:"seed"`
		Address    string   `json:"address"`
		SigningKey string   `json:"signingKey"`
		PubKeyHash string   `json:"pubKeyHash"`
	}

	walletMain := WalletDemo{
		Mnemonic:   mnemonic[:],
		Seed:       fmt.Sprintf("%x", seed),
		Address:    addressMain.Address,
		SigningKey: fmt.Sprintf("%x", addressMain.SigningKey),
		PubKeyHash: fmt.Sprintf("%x", addressMain.PubKeyHash),
	}

	walletTest := WalletDemo{
		Mnemonic:   mnemonic[:],
		Seed:       fmt.Sprintf("%x", seed),
		Address:    addressTest.Address,
		SigningKey: fmt.Sprintf("%x", addressTest.SigningKey),
		PubKeyHash: fmt.Sprintf("%x", addressTest.PubKeyHash),
	}

	walletMainJson, err := json.MarshalIndent(walletMain, "", "  ")
	if err != nil {
		log.Fatalf("Failed to marshal Json: %v", err)
	}

	walletTestJson, err := json.MarshalIndent(walletTest, "", "  ")
	if err != nil {
		log.Fatalf("Failed to marshal Json: %v", err)
	}

	err = os.WriteFile("WalletMain.json", walletMainJson, 0644)
	if err != nil {
		log.Fatalf("Failed to write to file: %v", err)
	}

	err = os.WriteFile("WalletTest.json", walletTestJson, 0644)
	if err != nil {
		log.Fatalf("Failed to write to file: %v", err)
	}

	log.Println("JSON successfully written")
}

func skToWif() {
	// Your raw hex secret key
	skHex := "d124ebf7c4a1d335de47d81530ae81c5949ebf5945e09abce8a1a15d3076df33"

	skBytes, err := hex.DecodeString(skHex)
	if err != nil {
		log.Fatalf("Failed to decode hex: %v", err)
	}

	// Create a private key object
	privKey, _ := btcec.PrivKeyFromBytes(skBytes)

	// Create a Testnet WIF (true = compressed public key)
	wif, err := btcutil.NewWIF(privKey, &chaincfg.TestNet3Params, true)
	if err != nil {
		log.Fatalf("Failed to create WIF: %v", err)
	}

	// This is the string you will paste into Electrum!
	fmt.Printf("Your Testnet WIF is: %s\n", wif.String())
}

func main() {
	// generateDemoWallet()
	//skToWif()
	//transaction.TestBuildTransaction()
	// _, err := transaction.GetUtxoMempool("mw9xUefbEeFWis9u84y3HFMc42aDoKBqSM")
	// if err != nil {
	// 	log.Fatal(err)
	// }

	// txId := "eefbafa4006e77099db059eebe14687965813283e5754d317431d9984554735d"
	// address := "mw9xUefbEeFWis9u84y3HFMc42aDoKBqSM"
	// address := "mrmM2yFqNuzKhXZzEyhXG1dJ5aonL6pnmi"
	// transaction "wallet-bitcoin/src/transactions"
	// utxos, err :=  GetUtxoMempool(address)
	// if err != nil {
	// 	log.Fatal(err)
	// }

	// for t := range utxos {
	// 	fmt.Printf("%s\n", utxos[t].ToString())
	// }

	// _, _, _, _ = transaction.(3000, address)

	sk, _ := hex.DecodeString("d124ebf7c4a1d335de47d81530ae81c5949ebf5945e09abce8a1a15d3076df33")

	wallet := wallet.NewWallet()
	src := keymanager.Address{
		SigningKey: sk,
		PubKeyHash: nil,
		Address:    "mw9xUefbEeFWis9u84y3HFMc42aDoKBqSM",
		Legacy:     true,
		Path:       nil,
	}
	err := wallet.Send(3000, false, "mrmM2yFqNuzKhXZzEyhXG1dJ5aonL6pnmi", src)
	fmt.Print(err)
}
