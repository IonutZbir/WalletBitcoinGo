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

const TxOutValueSize = 8

type TxOut struct {
	value    [TxOutValueSize]byte // int64
	pkScript []byte               // []rune
}

// Costruttori TxOut
func newTxOut(value [TxOutValueSize]byte, pkScript []byte) TxOut {
	return TxOut{
		value:    value,
		pkScript: pkScript,
	}
}

// getters
func (tx *TxOut) Value() int64 {
	return int64(binary.BigEndian.Uint64(tx.value[:]))
}

func (tx *TxOut) PkScript() []byte {
	return tx.pkScript
}

func NewTxOut(valueSats int64, pkScript []byte) TxOut {
	var value [TxOutValueSize]byte
	binary.BigEndian.PutUint64(value[:], uint64(valueSats))
	return newTxOut(value, pkScript)
}

// Parsing TxOut
func ParseTxOut(reader *bytes.Reader) TxOut {
	// Do no invert bytes of PkScript
	var value [TxOutValueSize]byte
	if _, err := io.ReadFull(reader, value[:]); err != nil {
		log.Fatalf("Failed to read value bytes: %v\n", err)
	}

	pkScriptLen, err := utils.VarInt2Int(reader)
	if err != nil {
		log.Fatalf("Cannot convert from CompactSizeUInt")
	}

	pkScript := make([]byte, pkScriptLen)
	if _, err = io.ReadFull(reader, pkScript[:]); err != nil {
		log.Fatalf("Failed to read script bytes: %v\n", err)
	}

	value = [8]byte(utils.ReverseBytes(value[:]))
	return newTxOut(value, pkScript)
}

// Metodi TxOut
func (tx *TxOut) Serialize() []byte {
	var buf bytes.Buffer
	buf.Write(utils.ReverseBytes(tx.value[:])) // torna a little-endian per il wire
	utils.WriteVarInt(&buf, uint64(len(tx.pkScript)))
	buf.Write(tx.pkScript)
	return buf.Bytes()
}

func (tx *TxOut) ToJson() ([]byte, error) {
	data := make(map[string]string)
	data["value"] = fmt.Sprintf("%v", binary.BigEndian.Uint64(tx.value[:]))
	data["pk_script"] = hex.EncodeToString(tx.pkScript[:])

	jsonData, err := json.MarshalIndent(data, "", "  ")
	if err != nil {
		log.Printf("JSON marshaling failed: %v", err)
		return nil, err
	}
	return jsonData, nil
}

func (tx *TxOut) ToString() string {
	out, err := tx.ToJson()
	if err != nil {
		log.Printf("Failed to convert to string JSON object: %v", err)
		return ""
	}
	return string(out)
}
