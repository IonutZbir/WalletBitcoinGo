package wallet

import (
	"encoding/hex"
	"fmt"
	"math/rand"
	"wallet-bitcoin/src/api"
	keymanager "wallet-bitcoin/src/key_manager"
	"wallet-bitcoin/src/transactions"

	"github.com/btcsuite/btcd/btcutil"
	"github.com/btcsuite/btcd/chaincfg"
	"github.com/btcsuite/btcd/txscript"
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

func (w *Wallet) buildOutputs(amount int64, change int64, destAddr string, changeAddr keymanager.Address) ([]transactions.TxOut, error) {
	// 1. Output Principale
	addrDestDecoded, err := btcutil.DecodeAddress(destAddr, &chaincfg.TestNet3Params)
	if err != nil {
		return nil, fmt.Errorf("could not decode destination address: %v", err)
	}

	pkScriptDest, err := txscript.PayToAddrScript(addrDestDecoded)
	if err != nil {
		return nil, fmt.Errorf("could not build destination pkScript: %v", err)
	}

	outputs := []transactions.TxOut{
		transactions.NewTxOut(amount, pkScriptDest),
	}

	// 2. Output di Resto (solo se necessario)
	if change > 0 {
		addrChangeDecoded, err := btcutil.DecodeAddress(changeAddr.Address, &chaincfg.TestNet3Params)
		if err != nil {
			return nil, fmt.Errorf("could not decode change address: %v", err)
		}

		pkScriptChange, err := txscript.PayToAddrScript(addrChangeDecoded)
		if err != nil {
			return nil, fmt.Errorf("could not build change pkScript: %v", err)
		}

		outputs = append(outputs, transactions.NewTxOut(change, pkScriptChange))
	}

	return outputs, nil
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

	changeAddr, err := w.randomChangeAddress(false)
	if err != nil {
		return "", fmt.Errorf("could not get change address: %v", err)
	}
	outputs, err := w.buildOutputs(int64(amount), int64(change), destAddr, changeAddr)
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

// randomChangeAddress returns a random change address from the wallet's change
// addresses of the given kind (legacy or segwit).
func (w *Wallet) randomChangeAddress(segwit bool) (keymanager.Address, error) {
	addrMap := w.ChangeLegacyAddresses
	if addrMap == nil {
		addrMap = w.ReceiversLegacyAddresses
	}
	if segwit {
		addrMap = w.ChangeSegwitAddresses
		if addrMap == nil {
			addrMap = w.ReceiversSegwitAddresses
		}
	}

	if len(addrMap) == 0 {
		return keymanager.Address{}, fmt.Errorf("no change addresses available")
	}

	target := rand.Intn(len(addrMap))
	i := 0
	for _, addr := range addrMap {
		if i == target {
			return addr, nil
		}
		i++
	}

	// Irraggiungibile se addrMap non è vuota, ma richiesto per compilare.
	return keymanager.Address{}, fmt.Errorf("no change addresses available")
}
