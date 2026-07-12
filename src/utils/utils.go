package utils

import (
	"crypto/sha256"
	"errors"
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
