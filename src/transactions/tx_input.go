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
)

const (
	TxInPreviousTxHashSize  = 32
	TxInPreviousTxIndexSize = 4
	TxInSequenceSize        = 4
)

type TxIn struct {
	previousTxHash  [32]byte // [32]rune
	previousTxIndex [4]byte  // uint32
	scriptSig       []byte   // []rune
	sequence        [4]byte  // uint32
}

// Costruttori TxIn
func newTxIn(previousTxHash [TxInPreviousTxHashSize]byte, previousTxIndex [TxInPreviousTxIndexSize]byte, scriptSig []byte, sequence [TxInSequenceSize]byte) TxIn {
	return TxIn{
		previousTxHash:  previousTxHash,
		previousTxIndex: previousTxIndex,
		scriptSig:       scriptSig,
		sequence:        sequence,
	}
}

func NewTxIn(txidHex string, vout uint32, sequence uint32) (TxIn, error) {
	txidBytes, err := hex.DecodeString(txidHex)
	if err != nil {
		return TxIn{}, fmt.Errorf("invalid txid: %w", err)
	}
	if len(txidBytes) != TxInPreviousTxHashSize {
		return TxIn{}, fmt.Errorf("txid must be %d byte, received %d", TxInPreviousTxHashSize, len(txidBytes))
	}

	var prevHash [TxInPreviousTxHashSize]byte
	copy(prevHash[:], txidBytes)

	var idx [TxInPreviousTxIndexSize]byte
	binary.BigEndian.PutUint32(idx[:], vout)

	var seq [TxInSequenceSize]byte
	binary.BigEndian.PutUint32(seq[:], sequence)

	// scriptSig vuoto per ora: lo riempie SignInput più avanti
	return newTxIn(prevHash, idx, []byte{}, seq), nil
}

// Parsing TxIn
func ParseTxIn(reader *bytes.Reader) TxIn {
	// Do not invert bytes of ScriptSig
	var previousTxHash [TxInPreviousTxHashSize]byte
	if _, err := io.ReadFull(reader, previousTxHash[:]); err != nil {
		log.Fatalf("Failed to read previousTxHash bytes: %v\n", err)
	}

	var previousTxIndex [TxInPreviousTxIndexSize]byte
	if _, err := io.ReadFull(reader, previousTxIndex[:]); err != nil {
		log.Fatalf("Failed to read previousTxIndex bytes: %v\n", err)
	}

	scriptSigLen, err := utils.VarInt2Int(reader)
	if err != nil {
		log.Fatalf("Cannot convert from CompactSizeUInt")
	}

	scriptSig := make([]byte, scriptSigLen)
	if _, err = io.ReadFull(reader, scriptSig[:]); err != nil {
		log.Fatalf("Failed to read script bytes: %v\n", err)
	}

	var sequence [TxInSequenceSize]byte
	if _, err = io.ReadFull(reader, sequence[:]); err != nil {
		log.Fatalf("Failed to read sequence bytes: %v\n", err)
	}

	previousTxHash = [32]byte(utils.ReverseBytes(previousTxHash[:]))
	previousTxIndex = [4]byte(utils.ReverseBytes(previousTxIndex[:]))
	sequence = [4]byte(utils.ReverseBytes(sequence[:]))

	return newTxIn(previousTxHash, previousTxIndex, scriptSig, sequence)
}

// Metodi TxIn
func (tx *TxIn) SetScriptSig(script []byte) {
	tx.scriptSig = script
}

func (tx *TxIn) Serialize() []byte {
	var buf bytes.Buffer
	buf.Write(utils.ReverseBytes(tx.previousTxHash[:]))
	buf.Write(utils.ReverseBytes(tx.previousTxIndex[:]))
	utils.WriteVarInt(&buf, uint64(len(tx.scriptSig)))
	buf.Write(tx.scriptSig)
	buf.Write(utils.ReverseBytes(tx.sequence[:]))
	return buf.Bytes()
}

func (tx *TxIn) ToJson() ([]byte, error) {
	data := make(map[string]string)
	data["prev_tx"] = hex.EncodeToString(tx.previousTxHash[:])
	data["prev_index"] = hex.EncodeToString(tx.previousTxIndex[:])
	data["script_sig"] = hex.EncodeToString(tx.scriptSig[:])
	data["sequence"] = hex.EncodeToString(tx.sequence[:])

	jsonData, err := json.MarshalIndent(data, "", "  ")
	if err != nil {
		log.Printf("JSON marshaling failed: %v", err)
		return nil, err
	}
	return jsonData, nil
}

func (tx *TxIn) ToString() string {
	out, err := tx.ToJson()
	if err != nil {
		log.Printf("Failed to convert to string JSON object: %v", err)
		return ""
	}
	return string(out)
}
