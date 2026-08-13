package main

import (
	"encoding/hex"
	"flag"
	"fmt"
	"log"
	wallet "wallet-bitcoin/src/wallet"

	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/btcutil"
	"github.com/btcsuite/btcd/chaincfg"
)

func skToWif() error {
	skHex := "d124ebf7c4a1d335de47d81530ae81c5949ebf5945e09abce8a1a15d3076df33"

	skBytes, err := hex.DecodeString(skHex)
	if err != nil {
		return fmt.Errorf("failed to decode hex: %w", err)
	}

	privKey, _ := btcec.PrivKeyFromBytes(skBytes)

	wif, err := btcutil.NewWIF(privKey, &chaincfg.TestNet3Params, true)
	if err != nil {
		return fmt.Errorf("failed to create WIF: %w", err)
	}

	fmt.Printf("Your Testnet WIF is: %s\n", wif.String())
	return nil
}

/*
 * wallet -testnet -new w1 -password prova
 * wallet -testnet -load w1 -password prova
 */

func main() {
	help := flag.Bool("help", false, "Show help")
	password := flag.String("password", "", "Password for the wallet")
	walletName := flag.String("wallet", "", "Name of the wallet")
	action := flag.String("action", "", "Action to perform: new, load, send-legacy, send-segwit")
	testnet := flag.Bool("testnet", false, "Use testnet")
	amount := flag.Int("amount", 0, "Amount to send (satoshi)")
	dest := flag.String("dest", "", "Destination address")

	flag.Parse()

	if *help || *action == "" {
		flag.Usage()
		return
	}

	if *walletName == "" {
		log.Fatal("missing required flag: -wallet")
	}

	switch *action {
	case "new":
		if err := createWallet(*walletName, *password, *testnet); err != nil {
			log.Fatal(err)
		}
	case "load":
		if err := loadAndDescribeWallet(*walletName, *password, *testnet); err != nil {
			log.Fatal(err)
		}
	case "send-legacy":
		if err := sendLegacyTx(*walletName, *password, *testnet, *amount, *dest); err != nil {
			log.Fatal(err)
		}
	case "send-segwit":
		if err := sendSegwitTx(*walletName, *password, *testnet, *amount, *dest); err != nil {
			log.Fatal(err)
		}
	default:
		log.Fatalf("unknown action %q (expected: new, load, send-legacy)", *action)
	}
}

func createWallet(name, password string, testnet bool) error {
	w, err := wallet.NewWalletFromScratch(name, password, testnet)
	if err != nil {
		return fmt.Errorf("creating wallet: %w", err)
	}
	log.Println("Wallet created successfully")
	fmt.Println(w) // vedi nota sotto: evitare di stampare l'intero struct
	return nil
}

func loadAndDescribeWallet(name, password string, testnet bool) error {
	w, err := wallet.LoadWallet(name, password, testnet)
	if err != nil {
		return fmt.Errorf("loading wallet: %w", err)
	}
	log.Println("Wallet loaded successfully")
	fmt.Println(w)
	return nil
}

func sendLegacyTx(name, password string, testnet bool, amount int, dest string) error {
	if amount <= 0 {
		return fmt.Errorf("amount must be > 0")
	}
	if dest == "" {
		return fmt.Errorf("destination address is required")
	}

	w, err := wallet.LoadWallet(name, password, testnet)
	if err != nil {
		return fmt.Errorf("loading wallet: %w", err)
	}

	log.Println("Sending legacy transaction")
	// core = false per ora: l'idea è usare sempre btcCore e ricadere su mempool in caso di problemi.
	// Non specifico sourceAddr: il wallet usa tutti gli address disponibili.
	tx, err := w.SendLegacyTx(amount, false, dest)
	if err != nil {
		return fmt.Errorf("sending transaction: %w", err)
	}

	log.Println("Transaction sent successfully")
	fmt.Println(tx)
	return nil
}

func sendSegwitTx(name, password string, testnet bool, amount int, dest string) error {
	if amount <= 0 {
		return fmt.Errorf("amount must be > 0")
	}
	if dest == "" {
		return fmt.Errorf("destination address is required")
	}

	w, err := wallet.LoadWallet(name, password, testnet)
	if err != nil {
		return fmt.Errorf("loading wallet: %w", err)
	}

	log.Println("Sending segwit transaction")
	tx, err := w.SendSegwit(amount, dest, false)
	if err != nil {
		return fmt.Errorf("sending transaction: %w", err)
	}

	log.Println("Transaction sent successfully")
	fmt.Println(tx)
	return nil
}
