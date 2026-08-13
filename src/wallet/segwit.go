package wallet

import (
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"wallet-bitcoin/src/api"
	keymanager "wallet-bitcoin/src/key_manager"
	"wallet-bitcoin/src/transactions"
	"wallet-bitcoin/src/utils"

	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/btcutil"
	"github.com/btcsuite/btcd/chaincfg"
	"github.com/btcsuite/btcd/chaincfg/chainhash"
	"github.com/btcsuite/btcd/txscript"
	"github.com/btcsuite/btcd/wire"
)

func (w *Wallet) buildInputsSegwit(amount int, core bool) ([]api.TxInBuild, int, int, error) {
	// in segwit mode, we use all the receivers and change addresses (including legacy addresses)

	if amount <= 0 {
		return nil, 0, 0, fmt.Errorf("amount must be > 0")
	}

	// make a map of addresses to use for UTXO selection
	addresses := make(map[string]keymanager.Address)
	for _, addr := range w.ReceiversSegwitAddresses {
		addresses[addr.Address] = addr
	}
	for _, addr := range w.ChangeSegwitAddresses {
		addresses[addr.Address] = addr
	}
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

func (w *Wallet) buildOutputsSegwit(amount int64, change int64, destAddr string, changeAddr keymanager.Address) ([]transactions.TxOut, error) {

	addrDestDecoded, err := btcutil.DecodeAddress(destAddr, &chaincfg.TestNet3Params)
	if err != nil {
		return nil, fmt.Errorf("could not decode the destination address: %v", err)
	}
	pkScript, err := txscript.PayToAddrScript(addrDestDecoded)
	if err != nil {
		return nil, fmt.Errorf("could not build destination pkScript: %v", err)
	}
	myOutput := transactions.NewTxOut(amount, pkScript)

	addrChangeDecoded, err := btcutil.DecodeAddress(changeAddr.Address, &chaincfg.TestNet3Params)
	if err != nil {
		return nil, fmt.Errorf("could not decode the change address: %v", err)
	}

	pkScriptChange, err := txscript.PayToAddrScript(addrChangeDecoded)
	if err != nil {
		return nil, fmt.Errorf("could not build change pkScript: %v", err)
	}
	myOutputChange := transactions.NewTxOut(change, pkScriptChange)

	return []transactions.TxOut{myOutput, myOutputChange}, nil
}

/*
 * toWireMsgTx converts your custom Tx into a wire.MsgTx so txscript's
 * BIP143 sighash machinery (which is hardwired to *wire.MsgTx) can be used.
 * Assumes TxIn exposes PrevTxHash ([32]byte, big-endian as usually stored),
 * PrevTxIndex (uint32) and Sequence (uint32), and TxOut exposes Value/PkScript.
 */
func toWireMsgTx(tx *transactions.Tx) (*wire.MsgTx, error) {
	msgTx := wire.NewMsgTx(2)

	for _, in := range tx.GetInputs() {
		previosTxHash := in.PreviousTxHash()

		// Inverti i byte da Big-Endian a Little-Endian per la wire di btcd
		reversedHash := utils.ReverseBytes(previosTxHash[:])
		hash, err := chainhash.NewHash(reversedHash)
		if err != nil {
			return nil, fmt.Errorf("bad prev tx hash: %v", err)
		}

		previousTxIndex := in.PreviousTxIndex()
		outPoint := wire.NewOutPoint(hash, binary.BigEndian.Uint32(previousTxIndex[:]))
		txIn := wire.NewTxIn(outPoint, nil, nil)
		sequence := in.Sequence()
		txIn.Sequence = binary.BigEndian.Uint32(sequence[:])
		msgTx.AddTxIn(txIn)
	}

	for _, out := range tx.GetOutputs() {
		msgTx.AddTxOut(wire.NewTxOut(out.Value(), out.PkScript()))
	}

	return msgTx, nil
}

func (w *Wallet) signInputsSegwit(tx *transactions.Tx, inputsBuild []api.TxInBuild) (*wire.MsgTx, error) {
	msgTx, err := toWireMsgTx(tx)
	if err != nil {
		return nil, fmt.Errorf("could not convert to wire.MsgTx: %v", err)
	}

	// 1. Popoliamo il fetcher per i dati degli UTXO spesi
	fetcher := txscript.NewMultiPrevOutFetcher(nil)
	for i, in := range inputsBuild {
		prevScriptPubKey, err := hex.DecodeString(in.PubKeyScript.Script)
		if err != nil {
			return nil, fmt.Errorf("cannot decode prevScriptPubKey for input %d: %v", i, err)
		}
		fetcher.AddPrevOut(msgTx.TxIn[i].PreviousOutPoint, wire.NewTxOut(int64(in.Amount), prevScriptPubKey))
	}

	// Pre-calcolo degli hash BIP143 per gli input SegWit
	sigHashes := txscript.NewTxSigHashes(msgTx, fetcher)

	for i, in := range inputsBuild {
		prevScriptPubKey, err := hex.DecodeString(in.PubKeyScript.Script)
		if err != nil {
			return nil, fmt.Errorf("cannot decode prevScriptPubKey for input %d: %v", i, err)
		}

		privKey, _ := btcec.PrivKeyFromBytes(in.PrivateKey)

		// Riconosciamo il tipo di ScriptPubKey
		scriptClass, _, _, err := txscript.ExtractPkScriptAddrs(prevScriptPubKey, &chaincfg.TestNet3Params)
		if err != nil {
			return nil, fmt.Errorf("cannot parse scriptClass for input %d: %v", i, err)
		}

		switch scriptClass {

		case txscript.WitnessV0PubKeyHashTy: // --- INPUT SEGWIT NATIVO (P2WPKH) ---
			// WitnessSignature genera automaticamente lo stack [Signature, PubKey]
			witnessStack, err := txscript.WitnessSignature(
				msgTx,
				sigHashes,
				i,
				int64(in.Amount),
				prevScriptPubKey,
				txscript.SigHashAll,
				privKey,
				true, // compressed pubkey
			)
			if err != nil {
				return nil, fmt.Errorf("could not sign segwit input %d: %v", i, err)
			}
			msgTx.TxIn[i].Witness = witnessStack

		case txscript.PubKeyHashTy: // --- INPUT LEGACY (P2PKH) ---
			// Gli input Legacy usano SignatureScript (scriptSig) e l'hashing tradizionale (non BIP143)
			scriptSig, err := txscript.SignatureScript(
				msgTx,
				i,
				prevScriptPubKey,
				txscript.SigHashAll,
				privKey,
				true, // compressed pubkey
			)
			if err != nil {
				return nil, fmt.Errorf("could not sign legacy input %d: %v", i, err)
			}
			msgTx.TxIn[i].SignatureScript = scriptSig

		default:
			return nil, fmt.Errorf("unsupported script type at input %d: %v", i, scriptClass)
		}
	}

	return msgTx, nil
}

func (w *Wallet) SendSegwit(amount int, destAddr string, core bool) (string, error) {
	inputsBuild, _, change, err := w.buildInputsSegwit(amount, core)
	if err != nil {
		return "", fmt.Errorf("could not get inputs: %v", err)
	}

	changeAddr, err := w.randomChangeAddress(true)
	if err != nil {
		return "", fmt.Errorf("could not get change address: %v", err)
	}

	outputs, err := w.buildOutputsSegwit(int64(amount), int64(change), destAddr, changeAddr)
	if err != nil {
		return "", fmt.Errorf("could not build outputs: %v", err)
	}

	inputs := api.ExtractTxIns(inputsBuild)

	tx := transactions.NewTx(inputs, outputs)
	// for every address, i need to get the relative private key
	txWire, err := w.signInputsSegwit(&tx, inputsBuild)
	if err != nil {
		return "", err
	}

	txId, err := w.Mempool.BroadcastTransactionSegwit(txWire)
	if err != nil {
		return "", err
	}
	return txId, nil
}
