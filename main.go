package main

import (
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log"
	"os"

	keymanager "wallet-bitcoin/src/key_manager"

	wallet "wallet-bitcoin/src"

	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/btcutil"
	"github.com/btcsuite/btcd/chaincfg"
)

type WalletDemo struct {
	Mnemonic   []string `json:"mnemonic"`
	Seed       string   `json:"seed"`
	Address    string   `json:"address"`
	SigningKey string   `json:"signingKey"`
	PubKeyHash string   `json:"pubKeyHash"`
}

func toWalletDemo(mnemonic []string, seed []byte, addr *keymanager.Address) WalletDemo {
	return WalletDemo{
		Mnemonic:   mnemonic,
		Seed:       fmt.Sprintf("%x", seed),
		Address:    addr.Address,
		SigningKey: fmt.Sprintf("%x", addr.SigningKey),
		PubKeyHash: fmt.Sprintf("%x", addr.PubKeyHash),
	}
}

func writeWalletJson(filename string, wallet WalletDemo) error {
	data, err := json.MarshalIndent(wallet, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal JSON: %w", err)
	}
	if err := os.WriteFile(filename, data, 0644); err != nil {
		return fmt.Errorf("failed to write file %s: %w", filename, err)
	}
	return nil
}

func generateDemoWallet() error {
	mnemonic, seed, err := keymanager.GenerateSeedEnt128()
	if err != nil {
		return fmt.Errorf("failed to generate seed: %w", err)
	}

	fmt.Println("mnemonic:", mnemonic)
	fmt.Printf("seed: %x\nlen: %d\n", seed, len(seed))

	master, err := keymanager.NewMasterKey(seed[:])
	if err != nil {
		return fmt.Errorf("failed to derive master key: %w", err)
	}

	// Indirizzo 0 di ricezione, legacy e segwit, mainnet e testnet
	addressLegacyMain, err := keymanager.DeriveLegacyAddress(
		master, keymanager.NetworkMainnet, keymanager.ChainExternal, 0)
	if err != nil {
		return fmt.Errorf("failed to derive legacy mainnet address: %w", err)
	}

	addressLegacyTest, err := keymanager.DeriveLegacyAddress(
		master, keymanager.NetworkTestnet, keymanager.ChainExternal, 0)
	if err != nil {
		return fmt.Errorf("failed to derive legacy testnet address: %w", err)
	}

	addressSegwitMain, err := keymanager.DeriveSegwitAddress(
		master, keymanager.NetworkMainnet, keymanager.ChainExternal, 0)
	if err != nil {
		return fmt.Errorf("failed to derive segwit mainnet address: %w", err)
	}

	addressSegwitTest, err := keymanager.DeriveSegwitAddress(
		master, keymanager.NetworkTestnet, keymanager.ChainExternal, 0)
	if err != nil {
		return fmt.Errorf("failed to derive segwit testnet address: %w", err)
	}

	walletLegacyMain := toWalletDemo(mnemonic[:], seed[:], addressLegacyMain)
	walletLegacyTest := toWalletDemo(mnemonic[:], seed[:], addressLegacyTest)
	walletSegwitMain := toWalletDemo(mnemonic[:], seed[:], addressSegwitMain)
	walletSegwitTest := toWalletDemo(mnemonic[:], seed[:], addressSegwitTest)

	if err := writeWalletJson("WalletMainLegacy.json", walletLegacyMain); err != nil {
		return err
	}
	if err := writeWalletJson("WalletTestLegacy.json", walletLegacyTest); err != nil {
		return err
	}
	if err := writeWalletJson("WalletMainSegwit.json", walletSegwitMain); err != nil {
		return err
	}
	if err := writeWalletJson("WalletTestSegwit.json", walletSegwitTest); err != nil {
		return err
	}

	log.Println("JSON successfully written")
	return nil
}

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

func main() {
	// if err := generateDemoWallet(); err != nil {
	// 	log.Fatal(err)
	// }

	// if err := skToWif(); err != nil {
	// 	log.Fatal(err)
	// }
	name := "walletTestNet1"
	password := "prova"
	testnet := false
	w, err := wallet.NewWalletFromScratch(name, password, testnet)
	if err != nil {
		log.Fatal(err)
	}
	log.Println("Wallet initialized successfully")
	// log.Println("Wallet address:", w.ReceiversLegacyAddresses)
	// log.Println("Wallet address:", w.ReceiversSegwitAddresses)
	log.Println("Wallet Mnemonic:", w.Mnemonic)
	log.Println("Wallet Seed:", w.Seed)
	log.Println("Wallet Xpub:", w.Xpub)
	log.Println("Wallet Xprv:", w.Xprv)
}
