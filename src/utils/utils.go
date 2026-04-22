package utils

import "crypto/sha256"

// reverseBytes restituisce una nuova slice con i byte in ordine inverso (Big-Endian)
func ReverseBytes(b []byte) []byte {
	reversed := make([]byte, len(b))
	for i := range b {
		reversed[len(b)-1-i] = b[i]
	}
	return reversed
}

func Sha256sha256(data []byte) [32]byte {
	first := sha256.Sum256(data)
	second := sha256.Sum256(first[:])
	return second
}
