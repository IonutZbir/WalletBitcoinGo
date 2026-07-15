package utils

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"log"
	"math/big"

	"github.com/btcsuite/btcd/btcec/v2"
	"golang.org/x/crypto/ripemd160"
)

var CurveOrder = btcec.S256().N // ordine n della curva secp256k1

func Hash256(data []byte) [32]byte {
	// Computes the digest of sha256(sha256(data).

	first := sha256.Sum256(data)
	second := sha256.Sum256(first[:])
	return second
}

func Hash160(data []byte) [20]byte {
	// Computes the digest of sha256(ripemd160(data)).
	sha := sha256.Sum256(data)
	r := ripemd160.New()
	r.Write(sha[:])
	h160 := r.Sum(nil)
	return [20]byte(h160)
}

const base58Alphabet = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"

func Base58CheckEncode(payload []byte) string {
	hash256 := Hash256(payload)
	checksum := hash256[:4]

	full := append(append([]byte(nil), payload...), checksum...)
	return Base58Encode(full)
}

func Base58Encode(b []byte) string {
	x := new(big.Int).SetBytes(b)
	zero := big.NewInt(0)
	base := big.NewInt(58)
	mod := new(big.Int)

	var out []byte
	for x.Cmp(zero) > 0 {
		x.DivMod(x, base, mod)
		out = append(out, base58Alphabet[mod.Int64()])
	}
	// leading zero bytes -> '1'
	for _, bb := range b {
		if bb != 0 {
			break
		}
		out = append(out, base58Alphabet[0])
	}
	// reverse
	for i, j := 0, len(out)-1; i < j; i, j = i+1, j-1 {
		out[i], out[j] = out[j], out[i]
	}
	return string(out)
}

func PrivToCompressedPub(priv []byte) ([]byte, error) {
	// Given a private key k, compute pub = k * G and returns the compressed serialized public key
	if len(priv) != 32 {
		return nil, errors.New("private key must be 32 bytes")
	}
	_, pub := btcec.PrivKeyFromBytes(priv)
	return pub.SerializeCompressed(), nil
}

func ValidPrivateScalar(b []byte) bool {
	v := new(big.Int).SetBytes(b)
	if v.Sign() == 0 {
		return false
	}
	return v.Cmp(CurveOrder) < 0
}

func VarInt2Int(reader *bytes.Reader) (uint64, error) {
	var firstByte [1]byte
	_, err := io.ReadFull(reader, firstByte[:])
	if err != nil {
		log.Fatalf("Failed to read the first byte to convert the number: %v\n", err)
	}

	firstInt := uint8(firstByte[0])

	if firstInt <= 252 {
		return uint64(firstInt), nil
	}
	if firstInt == 253 {
		var bytes [2]byte
		_, err := io.ReadFull(reader, bytes[:])
		if err != nil {
			log.Fatalf("Failed to read the first 3 bytes to convert the number: %v\n", err)
		}
		return uint64(binary.LittleEndian.Uint16(bytes[:])), nil
	}
	if firstInt == 254 {
		var bytes [4]byte
		_, err := io.ReadFull(reader, bytes[:])
		if err != nil {
			log.Fatalf("Failed to read the first 5 bytes to convert the number: %v\n", err)
		}
		return uint64(binary.LittleEndian.Uint32(bytes[:])), nil
	}
	if firstInt == 255 {
		var bytes [8]byte
		_, err := io.ReadFull(reader, bytes[:])
		if err != nil {
			log.Fatalf("Failed to read the first 9 bytes to convert the number: %v\n", err)
		}
		return binary.LittleEndian.Uint64(bytes[:]), nil
	}

	return 0, fmt.Errorf("invalid varint format")
}

func WriteVarInt(buf *bytes.Buffer, n uint64) {
	switch {
	case n < 0xfd:
		buf.WriteByte(byte(n))
	case n <= 0xffff:
		buf.WriteByte(0xfd)
		binary.Write(buf, binary.LittleEndian, uint16(n))
	case n <= 0xffffffff:
		buf.WriteByte(0xfe)
		binary.Write(buf, binary.LittleEndian, uint32(n))
	default:
		buf.WriteByte(0xff)
		binary.Write(buf, binary.LittleEndian, n)
	}
}

func ReverseBytes(b []byte) []byte {
	reversed := make([]byte, len(b))
	for i := range b {
		reversed[len(b)-1-i] = b[i]
	}
	return reversed
}
