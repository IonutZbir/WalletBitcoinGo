package wallet

import (
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"wallet-bitcoin/src/api"
	keymanager "wallet-bitcoin/src/key_manager"
	"wallet-bitcoin/src/transactions"
	"wallet-bitcoin/src/utils"

	"github.com/btcsuite/btcd/btcutil"
	"github.com/btcsuite/btcd/chaincfg"
)

const (
	NumLegacyAddresses       = 10
	NumSegwitAddresses       = 10
	NumChangeLegacyAddresses = 5
	NumChangeSegwitAddresses = 5
	NumAddresses             = NumLegacyAddresses + NumSegwitAddresses + NumChangeLegacyAddresses + NumChangeSegwitAddresses
)

type Wallet struct {
	Path                     string
	ReceiversLegacyAddresses map[string]keymanager.Address
	ReceiversSegwitAddresses map[string]keymanager.Address
	ChangeLegacyAddresses    map[string]keymanager.Address
	ChangeSegwitAddresses    map[string]keymanager.Address
	Balance                  []api.Balance
	Testnet                  bool
	Mempool                  api.MempoolApi
	BtcCore                  api.BtcCoreApi
	Seed                     [64]byte
	Mnemonic                 [12]string
	Password                 string
	Name                     string
	Xpub                     []byte
	Xprv                     []byte
}

func (w *Wallet) String() string {
	var builder strings.Builder

	// Mappa address -> balance per lookup O(1) dentro printAddressMap
	balanceByAddress := make(map[string]int64, len(w.Balance))
	var totalBalance int64
	for _, b := range w.Balance {
		balanceByAddress[b.Address] = b.Balance
		totalBalance += b.Balance
	}

	// Header details
	fmt.Fprintf(&builder, "Path: %s\nTestnet: %t\nBalance: %d satoshis\n", w.Path, w.Testnet, totalBalance)

	// Format Mnemonic array
	fmt.Fprintf(&builder, "Mnemonic: %s %s %s %s %s %s %s %s %s %s %s %s\n",
		w.Mnemonic[0], w.Mnemonic[1], w.Mnemonic[2], w.Mnemonic[3],
		w.Mnemonic[4], w.Mnemonic[5], w.Mnemonic[6], w.Mnemonic[7],
		w.Mnemonic[8], w.Mnemonic[9], w.Mnemonic[10], w.Mnemonic[11],
	)

	// Total count
	totalAddresses := len(w.ReceiversLegacyAddresses) + len(w.ReceiversSegwitAddresses) +
		len(w.ChangeLegacyAddresses) + len(w.ChangeSegwitAddresses)
	fmt.Fprintf(&builder, "Total Addresses (%d):\n", totalAddresses)

	// Helper to print address maps, including the balance for each address
	printAddressMap := func(label string, addrMap map[string]keymanager.Address) {
		if len(addrMap) == 0 {
			return
		}
		fmt.Fprintf(&builder, "  -- %s --\n", label)
		for key, addr := range addrMap {
			bal, ok := balanceByAddress[key]
			if !ok {
				fmt.Fprintf(&builder, "    %v (balance unknown)\n", addr)
				continue
			}
			fmt.Fprintf(&builder, "    %v — %d satoshis\n", addr, bal)
		}
	}
	printAddressMap("Receivers (Legacy)", w.ReceiversLegacyAddresses)
	printAddressMap("Receivers (SegWit)", w.ReceiversSegwitAddresses)
	printAddressMap("Change (Legacy)", w.ChangeLegacyAddresses)
	printAddressMap("Change (SegWit)", w.ChangeSegwitAddresses)

	return builder.String()
}

func NewWalletFromScratch(name string, password string, testnet bool) (*Wallet, error) {
	mnemonic, _, err := keymanager.GenerateSeedEnt128()
	if err != nil {
		return nil, fmt.Errorf("error generating seed: %w", err)
	}

	return NewWalletFromMnemonic(name, password, testnet, mnemonic)
}

func NewWalletFromMnemonic(name string, password string, testnet bool, mnemonic [12]string) (*Wallet, error) {
	walletFilePath, err := getWalletPath(name)
	if err != nil {
		return nil, fmt.Errorf("error getting wallet path: %w", err)
	}

	seed, err := keymanager.GenerateSeedFromMnemonic(mnemonic[:])
	if err != nil {
		return nil, fmt.Errorf("error generating seed from mnemonic: %w", err)
	}

	// 3. Genera il Master Key BIP-32
	master, err := keymanager.NewMasterKey(seed[:])
	if err != nil {
		return nil, fmt.Errorf("error generating master key: %w", err)
	}

	xPub, err := utils.PrivToCompressedPub(master.Key)
	if err != nil {
		return nil, fmt.Errorf("error compressing public key: %w", err)
	}
	xPrv := master.Key

	// 4. Inizializza l'istanza di Wallet con le mappe per gli indirizzi
	w := &Wallet{
		Path:                     walletFilePath,
		ReceiversLegacyAddresses: make(map[string]keymanager.Address, NumLegacyAddresses),
		ReceiversSegwitAddresses: make(map[string]keymanager.Address, NumSegwitAddresses),
		ChangeLegacyAddresses:    make(map[string]keymanager.Address, NumChangeLegacyAddresses),
		ChangeSegwitAddresses:    make(map[string]keymanager.Address, NumChangeSegwitAddresses),
		Balance:                  make([]api.Balance, 0),
		Testnet:                  testnet,
		Mempool:                  api.MempoolApi{},
		BtcCore:                  api.BtcCoreApi{},
		Seed:                     seed,
		Mnemonic:                 mnemonic,
		Password:                 password,
		Name:                     name,
		Xpub:                     xPub,
		Xprv:                     xPrv,
	}

	// 5. Determina il network per la derivazione
	network := keymanager.NetworkMainnet
	if testnet {
		network = keymanager.NetworkTestnet
	}

	// 6. Deriva gli indirizzi e assegnali alle rispettive mappe
	for i := 0; i < NumLegacyAddresses; i++ {
		addr, err := keymanager.DeriveLegacyAddress(master, network, keymanager.ChainExternal, uint32(i))
		if err != nil {
			return nil, fmt.Errorf("error deriving legacy address: %w", err)
		}
		w.ReceiversLegacyAddresses[addr.Address] = *addr
	}
	for i := 0; i < NumSegwitAddresses; i++ {
		addr, err := keymanager.DeriveSegwitAddress(master, network, keymanager.ChainExternal, uint32(i))
		if err != nil {
			return nil, fmt.Errorf("error deriving segwit address: %w", err)
		}
		w.ReceiversSegwitAddresses[addr.Address] = *addr
	}
	for i := 0; i < NumChangeLegacyAddresses; i++ {
		addr, err := keymanager.DeriveLegacyAddress(master, network, keymanager.ChainChange, uint32(i))
		if err != nil {
			return nil, fmt.Errorf("error deriving change legacy address: %w", err)
		}
		w.ChangeLegacyAddresses[addr.Address] = *addr
	}
	for i := 0; i < NumChangeSegwitAddresses; i++ {
		addr, err := keymanager.DeriveSegwitAddress(master, network, keymanager.ChainChange, uint32(i))
		if err != nil {
			return nil, fmt.Errorf("error deriving change segwit address: %w", err)
		}
		w.ChangeSegwitAddresses[addr.Address] = *addr
	}

	// 7. Cifra e persisti il wallet su disco
	if err := w.EncryptAndSaveWallet(password, walletFilePath); err != nil {
		return nil, fmt.Errorf("error encrypting and saving wallet: %w", err)
	}

	core := false
	w.getBalance(core)

	return w, nil

}

// func NewWalletFromPrivateKey(name string, password string, testnet bool, prvKey []byte) (*Wallet, error) {}
// func (w *Wallet) ImportPrivateKey(name string, password string, testnet bool, prvKey []byte) (*Wallet, error) {}

func getWalletPath(name string) (string, error) {
	homeDir, err := os.UserHomeDir()
	if err != nil {
		return "", fmt.Errorf("error finding home directory: %w", err)
	}

	walletDir := filepath.Join(homeDir, baseDirName, name)
	if err := os.MkdirAll(walletDir, 0700); err != nil {
		return "", fmt.Errorf("error creating wallet directory: %w", err)
	}

	walletFilePath := filepath.Join(walletDir, name+".json")
	return walletFilePath, nil
}

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

func (w *Wallet) getBalance(core bool) error {
	allAddresses := make(map[string]keymanager.Address)
	for k, v := range w.ReceiversLegacyAddresses {
		allAddresses[k] = v
	}
	for k, v := range w.ChangeLegacyAddresses {
		allAddresses[k] = v
	}
	// + segwit se applicabile

	var balance []api.Balance
	var err error
	if core {
		balance, err = w.BtcCore.ComputeBalanceForAddresses(allAddresses)
	} else {
		balance, err = w.Mempool.ComputeBalanceForAddresses(allAddresses)
	}
	if err != nil {
		return err
	}

	w.Balance = balance
	return nil
}

// Segwit

// func (w *Wallet) buildInputsSegwit(amount int, core bool, address keymanager.Address) ([]api.TxInBuild, int, int, error) {
// 	if amount < 0 {
// 		return nil, 0, 0, fmt.Errorf("amount must be > 0")
// 	}

// 	var (
// 		inputs []api.TxInBuild
// 		fee    int
// 		change int
// 		err    error
// 	)
// 	if core {
// 		inputs, fee, change, err = w.BtcCoreApi.GetInputs(amount, address)
// 	} else {
// 		inputs, fee, change, err = w.MempoolApi.GetInputs(amount, address)
// 	}
// 	if err != nil {
// 		return nil, 0, 0, err
// 	}

// 	return inputs, fee, change, nil
// }

// func (w *Wallet) buildOutputsSegwit(amount int, change int, destAddr string, changeAddr keymanager.Address) ([]transactions.TxOut, error) {

// 	addrDestDecoded, err := btcutil.DecodeAddress(destAddr, &chaincfg.TestNet3Params)
// 	if err != nil {
// 		return nil, fmt.Errorf("could not decode the destination address: %v", err)
// 	}
// 	pkScript, err := txscript.PayToAddrScript(addrDestDecoded)
// 	if err != nil {
// 		return nil, fmt.Errorf("could not build destination pkScript: %v", err)
// 	}
// 	myOutput := transactions.NewTxOut(int64(amount), pkScript)

// 	addrChangeDecoded, err := btcutil.DecodeAddress(changeAddr.Address, &chaincfg.TestNet3Params)
// 	if err != nil {
// 		return nil, fmt.Errorf("could not decode the change address: %v", err)
// 	}
// 	pkScriptChange, err := txscript.PayToAddrScript(addrChangeDecoded)
// 	if err != nil {
// 		return nil, fmt.Errorf("could not build change pkScript: %v", err)
// 	}
// 	myOutputChange := transactions.NewTxOut(int64(change), pkScriptChange)

// 	return []transactions.TxOut{myOutput, myOutputChange}, nil
// }

// toWireMsgTx converts your custom Tx into a wire.MsgTx so txscript's
// BIP143 sighash machinery (which is hardwired to *wire.MsgTx) can be used.
// Assumes TxIn exposes PrevTxHash ([32]byte, big-endian as usually stored),
// PrevTxIndex (uint32) and Sequence (uint32), and TxOut exposes Value/PkScript.
// func toWireMsgTx(tx *transactions.Tx) (*wire.MsgTx, error) {
// 	msgTx := wire.NewMsgTx(2)

// 	for _, in := range tx.GetInputs() {
// 		previosTxHash := in.PreviousTxHash()
// 		hash, err := chainhash.NewHash(previosTxHash[:])
// 		if err != nil {
// 			return nil, fmt.Errorf("bad prev tx hash: %v", err)
// 		}
// 		previousTxIndex := in.PreviousTxIndex()
// 		outPoint := wire.NewOutPoint(hash, binary.BigEndian.Uint32(previousTxIndex[:]))
// 		txIn := wire.NewTxIn(outPoint, nil, nil)
// 		sequence := in.Sequence()
// 		txIn.Sequence = binary.BigEndian.Uint32(sequence[:])
// 		msgTx.AddTxIn(txIn)
// 	}

// 	for _, out := range tx.GetOutputs() {
// 		msgTx.AddTxOut(wire.NewTxOut(out.Value(), out.PkScript()))
// 	}

// 	return msgTx, nil
// }

// func (w *Wallet) signInputsSegwit(tx *transactions.Tx, inputsBuild []api.TxInBuild) error {
// 	msgTx, err := toWireMsgTx(tx)
// 	if err != nil {
// 		return fmt.Errorf("could not convert to wire.MsgTx: %v", err)
// 	}

// 	// Precompute the shared BIP143 hashes (hashPrevouts/hashSequence/hashOutputs) once.
// 	fetcher := txscript.NewMultiPrevOutFetcher(nil)
// 	for i, in := range inputsBuild {
// 		prevScriptPubKey, err := hex.DecodeString(in.PubKeyScript.Script)
// 		if err != nil {
// 			return fmt.Errorf("cannot decode prevScriptPubKey for input %d: %v", i, err)
// 		}
// 		fetcher.AddPrevOut(msgTx.TxIn[i].PreviousOutPoint, wire.NewTxOut(int64(in.Amount), prevScriptPubKey))
// 	}
// 	sigHashes := txscript.NewTxSigHashes(msgTx, fetcher)

// 	for i, in := range inputsBuild {
// 		prevScriptPubKey, err := hex.DecodeString(in.PubKeyScript.Script)
// 		if err != nil {
// 			return fmt.Errorf("cannot decode prevScriptPubKey for input %d: %v", i, err)
// 		}

// 		pubKeyHash := prevScriptPubKey[2:] // strip OP_0 <push>
// 		witnessScript, err := txscript.NewScriptBuilder().
// 			AddOp(txscript.OP_DUP).
// 			AddOp(txscript.OP_HASH160).
// 			AddData(pubKeyHash).
// 			AddOp(txscript.OP_EQUALVERIFY).
// 			AddOp(txscript.OP_CHECKSIG).
// 			Script()
// 		if err != nil {
// 			return fmt.Errorf("could not build witness script for input %d: %v", i, err)
// 		}

// 		witness, err := txscript.RawTxInWitnessSignature(
// 			msgTx, sigHashes, i, int64(in.Amount), witnessScript,
// 			txscript.SigHashAll, ,
// 		)
// 		if err != nil {
// 			return fmt.Errorf("could not sign input %d: %v", i, err)
// 		}

// 		msgTx.TxIn[i].Witness = witness
// 		tx.SetWitness(i, witness)
// 	}

// 	return nil
// }

// func (w *Wallet) SendSegwit(amount int64, sourceAddr string, destAddr string, core bool) error {
// 	inputsBuild, _, change, err := w.buildInputsSegwit(amount, core, w.Addresses[sourceAddr])
// 	if err != nil {
// 		return fmt.Errorf("could not get inputs: %v", err)
// 	}

// 	outputs, err := w.buildOutputsSegwit(amount, change, destAddr, w.Addresses[sourceAddr])
// 	if err != nil {
// 		return fmt.Errorf("could not build outputs: %v", err)
// 	}

// 	inputs := api.ExtractTxIns(inputsBuild)

// 	tx := transactions.NewTx(inputs, outputs)
// 	// for every address, i need to get the relative private key
// 	err = w.signInputsSegwit(&tx, inputsBuild, w.Addresses[sourceAddr].SigningKey)
// 	if err != nil {
// 		return err
// 	}

// 	err = w.MempoolApi.BroadcastTransaction(&tx)
// 	if err != nil {
// 		return err
// 	}
// 	fmt.Println("Transaction broadcasted successfully")
// 	return nil
// }
