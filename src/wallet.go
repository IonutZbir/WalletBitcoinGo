package src

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"wallet-bitcoin/src/api"
	keymanager "wallet-bitcoin/src/key_manager"
	"wallet-bitcoin/src/transactions"
	"wallet-bitcoin/src/utils"

	"github.com/btcsuite/btcd/btcutil"
	"github.com/btcsuite/btcd/chaincfg"
	"golang.org/x/crypto/scrypt"
)

const (
	NumLegacyAddresses       = 10
	NumSegwitAddresses       = 10
	NumChangeLegacyAddresses = 5
	NumChangeSegwitAddresses = 5
	NumAddresses             = NumLegacyAddresses + NumSegwitAddresses + NumChangeLegacyAddresses + NumChangeSegwitAddresses

	baseDirName = ".walletbitcoingo"
)

type Wallet struct {
	Path                     string
	ReceiversLegacyAddresses map[string]keymanager.Address
	ReceiversSegwitAddresses map[string]keymanager.Address
	ChangeLegacyAddresses    map[string]keymanager.Address
	ChangeSegwitAddresses    map[string]keymanager.Address
	Balance                  int
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

type CryptoEnvelope struct {
	Cipher     string                 `json:"cipher"`
	Ciphertext []byte                 `json:"ciphertext"`
	Nonce      []byte                 `json:"nonce"`
	KDF        string                 `json:"kdf"`
	KDFParams  map[string]interface{} `json:"kdfparams"`
}

func (w *Wallet) newDataToStore() (json.RawMessage, error) {
	data := map[string]interface{}{
		"keystore": map[string]interface{}{
			"type":     "bip32",
			"mnemonic": w.Mnemonic,
			"seed":     w.Seed,
			"xpub":     w.Xpub,
			"xprv":     w.Xprv,
		},
		"receivers": map[string]map[string]keymanager.Address{
			"legacy": w.ReceiversLegacyAddresses,
			"segwit": w.ReceiversSegwitAddresses,
		},
		"change": map[string]map[string]keymanager.Address{
			"legacy": w.ChangeLegacyAddresses,
			"segwit": w.ChangeSegwitAddresses,
		},
	}

	fmt.Println("Data stored on disk:", data)

	bytes, err := json.Marshal(data)
	if err != nil {
		return nil, fmt.Errorf("error marshaling wallet data: %w", err)
	}

	return json.RawMessage(bytes), nil
}

func (w *Wallet) EncryptAndSaveWallet(password string, filePath string) error {
	rawData, err := w.newDataToStore()
	if err != nil {
		return fmt.Errorf("error preparing wallet data: %w", err)
	}

	salt := make([]byte, 32)
	if _, err := io.ReadFull(rand.Reader, salt); err != nil {
		return fmt.Errorf("error generating salt: %w", err)
	}

	// Derivazione chiave AES-256 via scrypt (Parametri standard: N=262144, r=8, p=1, keyLen=32)
	key, err := scrypt.Key([]byte(password), salt, 262144, 8, 1, 32)
	if err != nil {
		return fmt.Errorf("error deriving AES key: %w", err)
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		return fmt.Errorf("error creating AES cipher: %w", err)
	}

	aesGCM, err := cipher.NewGCM(block)
	if err != nil {
		return fmt.Errorf("error creating GCM: %w", err)
	}

	nonce := make([]byte, aesGCM.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return fmt.Errorf("error generating nonce: %w", err)
	}

	ciphertext := aesGCM.Seal(nil, nonce, rawData, nil)

	envelope := CryptoEnvelope{
		Cipher:     "aes-256-gcm",
		Ciphertext: ciphertext,
		Nonce:      nonce,
		KDF:        "scrypt",
		KDFParams: map[string]interface{}{
			"n":      262144,
			"r":      8,
			"p":      1,
			"keyLen": 32,
			"salt":   salt,
		},
	}

	jsonData, err := json.MarshalIndent(envelope, "", "  ")
	if err != nil {
		return fmt.Errorf("error serializing JSON envelope: %w", err)
	}

	// Salva con permessi di lettura/scrittura esclusivi dell'utente (0600)
	if err := os.WriteFile(filePath, jsonData, 0600); err != nil {
		return fmt.Errorf("error saving file to disk: %w", err)
	}

	return nil
}

func NewWalletFromScratch(name string, password string, testnet bool) (*Wallet, error) {
	// 1. Risolvi il percorso assoluto della Home directory dell'utente
	homeDir, err := os.UserHomeDir()
	if err != nil {
		return nil, fmt.Errorf("error finding home directory: %w", err)
	}

	walletDir := filepath.Join(homeDir, baseDirName, name)
	if err := os.MkdirAll(walletDir, 0700); err != nil {
		return nil, fmt.Errorf("error creating wallet directory: %w", err)
	}

	walletFilePath := filepath.Join(walletDir, name+".json")

	// 2. Genera Mnemonic ed Entropia Seed
	mnemonic, seed, err := keymanager.GenerateSeedEnt128()
	if err != nil {
		return nil, fmt.Errorf("error generating seed: %w", err)
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
		Balance:                  0,
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

	return w, nil
}

func (w *Wallet) buildInputsLegacy(amount int, core bool, address keymanager.Address) ([]api.TxInBuild, int, int, error) {
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
		inputs, fee, change, err = w.BtcCore.GetInputs(amount, address)
	} else {
		inputs, fee, change, err = w.Mempool.GetInputs(amount, address)
	}

	if err != nil {
		return nil, 0, 0, err
	}

	return inputs, fee, change, nil
}

func (w *Wallet) buildOutputsLegacy(amount int, change int, destAddr string, changeAddr keymanager.Address) ([]transactions.TxOut, error) {

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

func (w *Wallet) signInputsLegacy(tx *transactions.Tx, inputsBuild []api.TxInBuild, privKey []byte) error {
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

func (w *Wallet) SendLegacy(amount int, core bool, destAddr string, sourceAddr string) error {
	/*
		1. Find the UTXO
		2. Compute the fee
		3. Build the Inputs and the Outputs
		4. Sign all inputs
		5. Build Tx and serialize
		6. Broadcast

	*/

	inputsBuild, _, change, err := w.buildInputsLegacy(amount, core, w.ReceiversLegacyAddresses[sourceAddr])
	if err != nil {
		return fmt.Errorf("could not get inputs: %v", err)
	}

	outputs, err := w.buildOutputsLegacy(amount, change, destAddr, w.ReceiversLegacyAddresses[sourceAddr])
	if err != nil {
		return fmt.Errorf("could not build outputs: %v", err)
	}

	inputs := api.ExtractTxIns(inputsBuild)

	tx := transactions.NewTx(inputs, outputs)
	// for every address, i need to get the relative private key
	err = w.signInputsLegacy(&tx, inputsBuild, w.ReceiversLegacyAddresses[sourceAddr].SigningKey)
	if err != nil {
		return err
	}

	err = w.Mempool.BroadcastTransaction(&tx)
	if err != nil {
		return err
	}
	fmt.Println("Transaction broadcasted successfully")
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
