package transactions

import (
	"encoding/hex"
	"fmt"
	"log"

	"github.com/btcsuite/btcd/btcutil"
	"github.com/btcsuite/btcd/chaincfg"
)

func TestBuildTransaction() {

	// =========================================================================
	// 1. PREPARAZIONE DELL'INPUT
	// =========================================================================
	txidHex := "f0f2e01f478d8907c78aeaa77060f90d995246ebb200915558d451da07d6bd2d"
	vout := uint32(1)
	sequence := uint32(0xffffffff)

	myInput, err := NewTxIn(txidHex, vout, sequence)
	if err != nil {
		log.Fatalf("Errore nella creazione dell'input: %v", err)
	}

	// =========================================================================
	// 2. PREPARAZIONE DELL'OUTPUT
	// =========================================================================
	// 3000 satoshi iniziali - 384 satoshi di stima fee = 2616 satoshi
	amountToSend := int64(2616)
	addressStr := "mrmM2yFqNuzKhXZzEyhXG1dJ5aonL6pnmi"

	addr, err := btcutil.DecodeAddress(addressStr, &chaincfg.TestNet3Params)
	if err != nil {
		log.Fatalf("Errore decodifica indirizzo di destinazione: %v", err)
	}

	pkScript := P2PKHScript(addr.ScriptAddress())
	myOutput := NewTxOut(amountToSend, pkScript)

	// =========================================================================
	// 3. CREAZIONE DELLA TRANSAZIONE
	// =========================================================================
	tx := NewTx([]TxIn{myInput}, []TxOut{myOutput})

	// =========================================================================
	// 4. FIRMA DELLA TRANSAZIONE
	// =========================================================================

	// Il prevScriptPubKey preso direttamente dall'explorer (SCRIPT PUBKEY HEX)
	prevScriptHex := "76a914ab896e0a7a13287be3469edc0324da0233b2017a88ac"
	prevScriptPubKey, err := hex.DecodeString(prevScriptHex)
	if err != nil {
		log.Fatalf("Errore decodifica prevScriptPubKey: %v", err)
	}

	// QUI DEVI INSERIRE LA TUA CHIAVE PRIVATA REALE (32 byte)
	// Attenzione: Questa deve essere la chiave privata derivata per l'indirizzo mrmM2y...
	// Per test, supponiamo tu l'abbia in formato HEX. (Non condividerla mai online!)
	privateKeyHex := "d124ebf7c4a1d335de47d81530ae81c5949ebf5945e09abce8a1a15d3076df33"
	privKeyBytes, err := hex.DecodeString(privateKeyHex)
	if err != nil {
		log.Fatalf("Errore decodifica chiave privata: %v", err)
	}

	// Firmiamo l'input 0
	err = tx.SignInput(0, privKeyBytes, prevScriptPubKey)
	if err != nil {
		log.Fatalf("Errore durante la firma: %v", err)
	}

	// =========================================================================
	// 5. RISULTATO FINALE (Pronto per il broadcast)
	// =========================================================================
	fmt.Println("=== TRANSAZIONE FIRMATA (HEX) ===")
	// Questa è la stringa da incollare in un block explorer per fare il "Broadcast"
	fmt.Println(tx.SerializeHex())
}

/*
Create a transaction from zero sending 0.4 mBTC (4000 satoshi).
from: mw9xUefbEeFWis9u84y3HFMc42aDoKBqSM
signing key: d124ebf7c4a1d335de47d81530ae81c5949ebf5945e09abce8a1a15d3076df33
pub key hash: ab896e0a7a13287be3469edc0324da0233b2017a

to: mrmM2yFqNuzKhXZzEyhXG1dJ5aonL6pnmi

*/
