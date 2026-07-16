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
	api.MempoolApi
	api.BtcCoreApi
}

func NewWallet() Wallet {
	return Wallet{"", nil, 0, false, api.MempoolApi{}, api.BtcCoreApi{}}
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
		inputs, fee, change, err = w.BtcCoreApi.GetInputs(amount, address)
	} else {
		inputs, fee, change, err = w.MempoolApi.GetInputs(amount, address)
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

	myOutputChange := transactions.NewTxOut(int64(change), pkScriptChange)
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

	err = w.MempoolApi.BroadcastTransaction(&tx)
	if err != nil {
		return err
	}

	return nil
}
