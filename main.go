package main

import (
	"flag"
	"fmt"
	"log"
	"os"
	"path/filepath"
	wallet "wallet-bitcoin/src/wallet"
)

const usageStr = `Usage:
  %s -action <action> [options]

Actions:
  new            Create a new wallet
  load           Load an existing wallet
  send-legacy    Send a legacy transaction
  send-segwit    Send a SegWit transaction
  export         Export the wallet
  import         Import a wallet

Options:
  -wallet    <name>    Wallet name
  -password  <pass>    Wallet password
  -testnet             Use testnet (default: false)
  -amount    <amt>     Amount to send (satoshis)
  -dest      <addr>    Destination address
  -type      <format>  Export/import format (default: json; accepted: json, csv)
  -file      <path>    Path to the CSV/JSON file (required for import)

Examples:
  %s -action new          -wallet mywallet -password secret -testnet
  %s -action load         -wallet mywallet -password secret -testnet
  %s -action send-segwit  -wallet mywallet -password secret -amount 0.05 -dest tb1q...
  %s -action export       -wallet mywallet -password secret -type json
  %s -action import       -wallet mywallet -password secret -file <path_to_file>
`

func main() {

	flag.Usage = func() {
		out := flag.CommandLine.Output()
		bin := filepath.Base(os.Args[0])

		fmt.Fprintf(out, usageStr, bin, bin, bin, bin, bin, bin)
	}

	help := flag.Bool("help", false, "Show help")
	password := flag.String("password", "", "Password for the wallet")
	walletName := flag.String("wallet", "", "Name of the wallet")
	action := flag.String("action", "", "Action to perform: new, load, send-legacy, send-segwit, export, import")
	testnet := flag.Bool("testnet", false, "Use testnet")
	amount := flag.Int("amount", 0, "Amount to send (satoshi)")
	dest := flag.String("dest", "", "Destination address")
	exportType := flag.String("type", "json", "Export/import format (default: json; accepted: json, csv)")
	file := flag.String("file", "", "Path to the WIF/CSV/JSON file (required for import)")

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
		if *amount == 0 {
			log.Fatal("missing required flag: -amount")
		}
		if *dest == "" {
			log.Fatal("missing required flag: -dest")
		}
		if err := sendLegacyTx(*walletName, *password, *testnet, *amount, *dest); err != nil {
			log.Fatal(err)
		}
	case "send-segwit":
		if *amount == 0 {
			log.Fatal("missing required flag: -amount")
		}
		if *dest == "" {
			log.Fatal("missing required flag: -dest")
		}
		if err := sendSegwitTx(*walletName, *password, *testnet, *amount, *dest); err != nil {
			log.Fatal(err)
		}
	case "export":
		if *exportType == "" {
			log.Fatal("missing required flag: -type")
		}
		if err := exportWallet(*walletName, *password, *testnet, *exportType); err != nil {
			log.Fatal(err)
		}
	case "import":
		if *file == "" {
			log.Fatal("missing required flag: -file")
		}
		if err := importWallet(*walletName, *password, *testnet, *file); err != nil {
			log.Fatal(err)
		}
	default:
		log.Fatalf("unknown action %q (expected: new, load, send-legacy, send-segwit, export, import)", *action)
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

func exportWallet(name, password string, testnet bool, exportType string) error {
	expectedTypes := map[string]string{"json": "json", "csv": "csv"}
	if _, ok := expectedTypes[exportType]; !ok {
		return fmt.Errorf("invalid export type %q (accepted: json, csv)", exportType)
	}

	w, err := wallet.LoadWallet(name, password, testnet)
	if err != nil {
		return fmt.Errorf("loading wallet: %w", err)
	}

	absPath, err := w.ExportKeys(exportType)
	if err != nil {
		return fmt.Errorf("exporting keys: %w", err)
	}

	numKeys := len(w.ReceiversLegacyAddresses) + len(w.ChangeLegacyAddresses) + len(w.ReceiversSegwitAddresses) + len(w.ChangeSegwitAddresses)
	log.Printf("Wallet exported successfully to %s (%d keys)", absPath, numKeys)
	return nil
}

func importWallet(name, password string, testnet bool, path string) error {
	w, err := wallet.ImportWalletFromFile(name, password, testnet, path)
	if err != nil {
		return fmt.Errorf("importing wallet: %w", err)
	}

	log.Printf("Wallet imported successfully from %s", path)
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
