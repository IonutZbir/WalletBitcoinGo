package src

import (
	"encoding/hex"
	"fmt"
	"wallet-bitcoin/src/api"
	keymanager "wallet-bitcoin/src/key_manager"
	"wallet-bitcoin/src/transactions"

	"github.com/btcsuite/btcd/btcutil"
	"github.com/btcsuite/btcd/chaincfg"
)

type Wallet struct {
	Path      string
	Addresses []keymanager.Address
	Balance   int
	Testnet   bool
}

func NewWallet() Wallet {
	return Wallet{"", nil, 0, false}
}

func (w *Wallet) buildInputs(amount int, core bool, address keymanager.Address) ([]api.TxInBuild, int, int, error) {
	if amount < 0 {
		return nil, 0, 0, fmt.Errorf("amount must be > 0")
	}

	var (
		inputs []api.TxInBuild
		fee    int
		change int
		err    error
	)
	// TODO: for every address inside the wallet
	if core {
		btcCoreApi := api.BtcCoreApi{}
		inputs, fee, change, err = btcCoreApi.GetInputs(amount, address)
	} else {
		mempoolApi := api.MempoolApi{}
		inputs, fee, change, err = mempoolApi.GetInputs(amount, address)
	}

	if err != nil {
		return nil, 0, 0, err
	}

	return inputs, fee, change, nil
}

func (w *Wallet) buildOutputs(amount int, change int, destAddr string, changeAddr keymanager.Address) ([]transactions.TxOut, error) {

	addrDestDecoded, err := btcutil.DecodeAddress(destAddr, &chaincfg.TestNet3Params)
	if err != nil {
		return nil, fmt.Errorf("could not decode the destination address: %v", err)
	}
	pkScript := transactions.P2PKHScript(addrDestDecoded.ScriptAddress())

	myOutput := transactions.NewTxOut(int64(amount), pkScript)

	addrChangeDecoded, err := btcutil.DecodeAddress(changeAddr.Address, &chaincfg.TestNet3Params)
	if err != nil {
		return nil, fmt.Errorf("could not decode the destination address: %v", err)
	}
	pkScriptChange := transactions.P2PKHScript(addrChangeDecoded.ScriptAddress())

	myOutputChange := transactions.NewTxOut(int64(amount), pkScriptChange)
	return []transactions.TxOut{myOutput, myOutputChange}, nil
}

func (w *Wallet) signInputs(tx *transactions.Tx, inputsBuild []api.TxInBuild, privKey []byte) error {
	for i, txInBuild := range inputsBuild {
		pubKeyScript := txInBuild.PubKeyScript
		prevScriptPubKey, err := hex.DecodeString(pubKeyScript.Script)
		if err != nil {
			return fmt.Errorf("cannot decode prevScriptPubKey: %v", err)
		}
		tx.SignInput(i, privKey, prevScriptPubKey)
	}
	return nil
}

func (w *Wallet) Send(amount int, core bool, destAddr string, sourceAddr keymanager.Address) error {
	/*
		1. Find the UTXO
		2. Compute the fee
		3. Build the Inputs and the Outputs
		4. Sign all inputs
		5. Build Tx and seriale
		6. Broadcast

	*/

	inputsBuild, _, change, err := w.buildInputs(amount, core, sourceAddr)
	if err != nil {
		return fmt.Errorf("could not get inputs: %v", err)
	}

	outputs, err := w.buildOutputs(amount, change, destAddr, sourceAddr)

	inputs := api.ExtractTxIns(inputsBuild)

	tx := transactions.NewTx(inputs, outputs)
	// for every address, i need to get the relative private key
	err = w.signInputs(&tx, inputsBuild, sourceAddr.SigningKey)
	if err != nil {
		return err
	}
	fmt.Println(tx.SerializeHex())
	return nil
}

// func Send() {

// 	// =========================================================================
// 	// 1. PREPARAZIONE DELL'INPUT
// 	// =========================================================================
// 	txidHex := "f0f2e01f478d8907c78aeaa77060f90d995246ebb200915558d451da07d6bd2d"
// 	vout := uint32(1)
// 	sequence := uint32(0xffffffff)

// 	myInput, err := NewTxIn(txidHex, vout, sequence)
// 	if err != nil {
// 		log.Fatalf("Errore nella creazione dell'input: %v", err)
// 	}

// 	// =========================================================================
// 	// 2. PREPARAZIONE DELL'OUTPUT
// 	// =========================================================================
// 	// 3000 satoshi iniziali - 384 satoshi di stima fee = 2616 satoshi
// 	amountToSend := int64(2616)
// 	addressStr := "mrmM2yFqNuzKhXZzEyhXG1dJ5aonL6pnmi"

// 	addr, err := btcutil.DecodeAddress(addressStr, &chaincfg.TestNet3Params)
// 	if err != nil {
// 		log.Fatalf("Errore decodifica indirizzo di destinazione: %v", err)
// 	}

// 	pkScript := P2PKHScript(addr.ScriptAddress())
// 	myOutput := NewTxOut(amountToSend, pkScript)

// 	// =========================================================================
// 	// 3. CREAZIONE DELLA TRANSAZIONE
// 	// =========================================================================
// 	tx := NewTx([]TxIn{myInput}, []TxOut{myOutput})

// 	// =========================================================================
// 	// 4. FIRMA DELLA TRANSAZIONE
// 	// =========================================================================

// 	// Il prevScriptPubKey preso direttamente dall'explorer (SCRIPT PUBKEY HEX)
// 	prevScriptHex := "76a914ab896e0a7a13287be3469edc0324da0233b2017a88ac"
// 	prevScriptPubKey, err := hex.DecodeString(prevScriptHex)
// 	if err != nil {
// 		log.Fatalf("Errore decodifica prevScriptPubKey: %v", err)
// 	}

// 	privateKeyHex := "d124ebf7c4a1d335de47d81530ae81c5949ebf5945e09abce8a1a15d3076df33"
// 	privKeyBytes, err := hex.DecodeString(privateKeyHex)
// 	if err != nil {
// 		log.Fatalf("Errore decodifica chiave privata: %v", err)
// 	}

// 	// Firmiamo l'input 0
// 	err = tx.SignInput(0, privKeyBytes, prevScriptPubKey)
// 	if err != nil {
// 		log.Fatalf("Errore durante la firma: %v", err)
// 	}

// 	// =========================================================================
// 	// 5. RISULTATO FINALE (Pronto per il broadcast)
// 	// =========================================================================
// 	fmt.Println("=== TRANSAZIONE FIRMATA (HEX) ===")
// 	// Questa è la stringa da incollare in un block explorer per fare il "Broadcast"
// 	fmt.Println(tx.SerializeHex())
// }
