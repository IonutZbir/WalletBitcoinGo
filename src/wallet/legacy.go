package wallet

import (
	"encoding/hex"
	"fmt"
	"wallet-bitcoin/src/api"
	keymanager "wallet-bitcoin/src/key_manager"
	"wallet-bitcoin/src/transactions"

	"github.com/btcsuite/btcd/btcutil"
	"github.com/btcsuite/btcd/chaincfg"
)

func (w *Wallet) buildInputsLegacy(amount int, core bool) ([]api.TxInBuild, int, int, error) {
	if amount <= 0 {
		return nil, 0, 0, fmt.Errorf("amount must be > 0")
	}

	// make a map of addresses to use for UTXO selection
	addresses := make(map[string]keymanager.Address)
	for _, addr := range w.ReceiversLegacyAddresses {
		addresses[addr.Address] = addr
	}
	for _, addr := range w.ChangeLegacyAddresses {
		addresses[addr.Address] = addr
	}

	if core {
		return w.BtcCore.GetInputs(amount, addresses)
	}
	return w.Mempool.GetInputs(amount, addresses)
}

func (w *Wallet) buildOutputsLegacy(amount int, change int, destAddr string, changeAddr keymanager.Address) ([]transactions.TxOut, error) {

	addrDestDecoded, err := btcutil.DecodeAddress(destAddr, &chaincfg.TestNet3Params)
	if err != nil {
		return nil, fmt.Errorf("could not decode the destination address: %v", err)
	}
	pkScript := transactions.P2PKHScript(addrDestDecoded.ScriptAddress())

	myOutput := transactions.NewTxOut(int64(amount), pkScript)

	if err != nil {
		return nil, fmt.Errorf("could not decode the destination address: %v", err)
	}
	pkScriptChange := transactions.P2PKHScript(changeAddr.PubKeyHash)

	myOutputChange := transactions.NewTxOut(int64(change), pkScriptChange)
	return []transactions.TxOut{myOutput, myOutputChange}, nil
}

func (w *Wallet) signInputsLegacy(tx *transactions.Tx, inputsBuild []api.TxInBuild) error {
	for i, txInBuild := range inputsBuild {
		pubKeyScript := txInBuild.PubKeyScript
		prevScriptPubKey, err := hex.DecodeString(pubKeyScript.Script)
		privKey := txInBuild.PrivateKey
		if err != nil {
			return fmt.Errorf("cannot decode prevScriptPubKey: %v", err)
		}
		tx.SignInput(i, privKey, prevScriptPubKey)
	}
	return nil
}

func (w *Wallet) SendLegacyTx(amount int, core bool, destAddr string) (string, error) {
	/*
		1. Find the UTXO
		2. Compute the fee
		3. Build the Inputs and the Outputs
		4. Sign all inputs
		5. Build Tx and serialize
		6. Broadcast

	*/
	// non devo specificare sourceAddr, il wallet deve usare tutti gli address
	// TODO: usare tutti gli address del wallet
	inputsBuild, _, change, err := w.buildInputsLegacy(amount, core)
	if err != nil {
		return "", fmt.Errorf("could not get inputs: %v", err)
	}

	// chose random change address
	changeAddr, err := w.randomChangeAddress()
	if err != nil {
		return "", fmt.Errorf("could not get change address: %v", err)
	}
	outputs, err := w.buildOutputsLegacy(amount, change, destAddr, changeAddr)
	if err != nil {
		return "", fmt.Errorf("could not build outputs: %v", err)
	}

	inputs := api.ExtractTxIns(inputsBuild)

	tx := transactions.NewTx(inputs, outputs)
	// for every address, i need to get the relative private key
	err = w.signInputsLegacy(&tx, inputsBuild)
	if err != nil {
		return "", fmt.Errorf("could not sign inputs: %v", err)
	}

	txId, err := w.Mempool.BroadcastTransaction(&tx)
	if err != nil {
		return "", fmt.Errorf("could not broadcast transaction: %v", err)
	}
	return txId, nil
}

func (w *Wallet) randomChangeAddress() (keymanager.Address, error) {
	if len(w.ChangeLegacyAddresses) == 0 {
		return keymanager.Address{}, fmt.Errorf("no change addresses available")
	}

	// Ranging over a Go map starts at a random bucket every time
	for _, addr := range w.ChangeLegacyAddresses {
		return addr, nil // Returns the very first item hit in the randomized loop
	}

	return keymanager.Address{}, fmt.Errorf("no change addresses available")
}
