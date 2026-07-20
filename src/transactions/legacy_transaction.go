package transactions

import (
	"bytes"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"wallet-bitcoin/src/utils"

	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/btcec/v2/ecdsa"
)

// ============================================================================
// CONSTANTS
// ============================================================================

const (
	TxVersionSize  = 4
	TxLocktimeSize = 4

	SighashAll uint32 = 0x00000001
)

type Tx struct {
	version  [4]byte // int32
	inputs   []TxIn
	outputs  []TxOut
	locktime [4]byte // uint32
}

// Costruttori Tx
func newTx(version [TxVersionSize]byte, inputs []TxIn, outputs []TxOut, locktime [TxLocktimeSize]byte) Tx {
	return Tx{
		version:  version,
		inputs:   inputs,
		outputs:  outputs,
		locktime: locktime,
	}
}

func NewTx(inputs []TxIn, outputs []TxOut) Tx {
	var version [TxVersionSize]byte
	binary.BigEndian.PutUint32(version[:], 1) // version 1, legacy

	var locktime [TxLocktimeSize]byte
	binary.BigEndian.PutUint32(locktime[:], 0) // niente locktime

	return newTx(version, inputs, outputs, locktime)
}

// GetInputs returns the inputs of the transaction
func (tx *Tx) GetInputs() []TxIn {
	return tx.inputs
}

// GetOutputs returns the outputs of the transaction
func (tx *Tx) GetOutputs() []TxOut {
	return tx.outputs
}

// Parsing Tx
func ParseTx(byteString []byte) Tx {
	reader := bytes.NewReader(byteString)

	var version [TxVersionSize]byte
	if _, err := io.ReadFull(reader, version[:]); err != nil {
		log.Fatalf("Failed to read version bytes: %v\n", err)
	}

	nInputs, err := utils.VarInt2Int(reader)
	if err != nil {
		log.Fatalf("Cannot convert from CompactSizeUInt")
	}

	inputs := make([]TxIn, 0, nInputs)
	for i := 0; i < int(nInputs); i++ {
		inputs = append(inputs, ParseTxIn(reader))
	}

	nOutputs, err := utils.VarInt2Int(reader)
	if err != nil {
		log.Fatalf("Cannot convert from CompactSizeUInt")
	}

	outputs := make([]TxOut, nOutputs)
	for i := 0; i < int(nOutputs); i++ {
		outputs[i] = ParseTxOut(reader)
	}

	var locktime [TxLocktimeSize]byte
	if _, err = io.ReadFull(reader, locktime[:]); err != nil {
		log.Fatalf("Failed to read locktime bytes: %v\n", err)
	}

	version = [4]byte(utils.ReverseBytes(version[:]))
	locktime = [4]byte(utils.ReverseBytes(locktime[:]))

	return newTx(version, inputs, outputs, locktime)
}

// Metodi Tx
func (tx *Tx) Serialize() []byte {
	var buf bytes.Buffer
	buf.Write(utils.ReverseBytes(tx.version[:]))

	utils.WriteVarInt(&buf, uint64(len(tx.inputs)))
	for i := range tx.inputs {
		buf.Write(tx.inputs[i].Serialize())
	}

	utils.WriteVarInt(&buf, uint64(len(tx.outputs)))
	for i := range tx.outputs {
		buf.Write(tx.outputs[i].Serialize())
	}

	buf.Write(utils.ReverseBytes(tx.locktime[:]))
	return buf.Bytes()
}

func (tx *Tx) SerializeHex() string {
	return hex.EncodeToString(tx.Serialize())
}

func (tx *Tx) ToJson() ([]byte, error) {
	data := make(map[string]any)
	data["version"] = hex.EncodeToString(tx.version[:])
	data["locktime"] = hex.EncodeToString(tx.locktime[:])

	var inputs []json.RawMessage
	for i := 0; i < len(tx.inputs); i++ {
		inputs = append(inputs, json.RawMessage(tx.inputs[i].ToString()))
	}
	data["inputs"] = inputs

	var outputs []json.RawMessage
	for i := 0; i < len(tx.outputs); i++ {
		outputs = append(outputs, json.RawMessage(tx.outputs[i].ToString()))
	}
	data["outputs"] = outputs

	jsonData, err := json.MarshalIndent(data, "", "  ")
	if err != nil {
		log.Printf("JSON marshaling failed: %v", err)
		return nil, err
	}
	return jsonData, nil
}

func (tx *Tx) ToString() string {
	out, err := tx.ToJson()
	if err != nil {
		log.Printf("Failed to convert to string JSON object: %v", err)
		return ""
	}
	return string(out)
}

// ============================================================================
// SCRIPTS & SIGNING
// ============================================================================

// P2PKHScript: OP_DUP OP_HASH160 <20 byte pubKeyHash> OP_EQUALVERIFY OP_CHECKSIG
func P2PKHScript(pubKeyHash []byte) []byte {
	var buf bytes.Buffer
	buf.WriteByte(0x76)                  // OP_DUP
	buf.WriteByte(0xa9)                  // OP_HASH160
	buf.WriteByte(byte(len(pubKeyHash))) // push 20 byte
	buf.Write(pubKeyHash)
	buf.WriteByte(0x88) // OP_EQUALVERIFY
	buf.WriteByte(0xac) // OP_CHECKSIG
	return buf.Bytes()
}

// buildScriptSig: <firma+sighashtype> <pubkey compressa>
func buildScriptSig(sig []byte, pubKey []byte) []byte {
	var buf bytes.Buffer
	buf.WriteByte(byte(len(sig)))
	buf.Write(sig)
	buf.WriteByte(byte(len(pubKey)))
	buf.Write(pubKey)
	return buf.Bytes()
}

// copyForSigning prepara la transazione per la firma legacy
func (tx *Tx) copyForSigning(inputIndex int, prevScriptPubKey []byte) Tx {
	newInputs := make([]TxIn, len(tx.inputs))
	for i, in := range tx.inputs {
		script := []byte{}
		if i == inputIndex {
			script = prevScriptPubKey
		}
		newInputs[i] = newTxIn(in.previousTxHash, in.previousTxIndex, script, in.sequence)
	}
	return newTx(tx.version, newInputs, tx.outputs, tx.locktime)
}

// LegacySigHash genera l'hash da firmare (pre-BIP143)
func (tx *Tx) LegacySigHash(inputIndex int, prevScriptPubKey []byte, sighashType uint32) []byte {
	copyTx := tx.copyForSigning(inputIndex, prevScriptPubKey)
	serialized := copyTx.Serialize()

	var sighashTypeBytes [4]byte
	binary.LittleEndian.PutUint32(sighashTypeBytes[:], sighashType)
	serialized = append(serialized, sighashTypeBytes[:]...)

	second := utils.Hash256(serialized)
	return second[:]
}

// SignInput firma l'input inputIndex e aggiorna lo scriptSig.
func (tx *Tx) SignInput(inputIndex int, privKeyBytes []byte, prevScriptPubKey []byte) error {
	if inputIndex < 0 || inputIndex >= len(tx.inputs) {
		return fmt.Errorf("inputIndex %d fuori range", inputIndex)
	}

	priv, pub := btcec.PrivKeyFromBytes(privKeyBytes)
	hash := tx.LegacySigHash(inputIndex, prevScriptPubKey, SighashAll)

	sig := ecdsa.Sign(priv, hash)
	derSig := sig.Serialize()
	sigWithHashType := append(derSig, byte(SighashAll))

	pubKeyCompressed := pub.SerializeCompressed()
	scriptSig := buildScriptSig(sigWithHashType, pubKeyCompressed)

	tx.inputs[inputIndex].SetScriptSig(scriptSig)

	return nil
}
