package keymanager

import (
	"crypto/pbkdf2"
	"crypto/rand"
	"crypto/sha256"
	"crypto/sha512"
	"embed"
	"fmt"
	"strings"

	"golang.org/x/text/unicode/norm"
)

/*
ENTBITS in {128, 160, 192, 224, 256}, tipicamente è 128.
*/

// type Entropy128 struct {
// 	lo uint64
// 	hi uint64
// }

//go:embed wordlists/english.txt wordlists/italian.txt
var wordlistsFS embed.FS

type Language string

const (
	English Language = "wordlists/english.txt"
	Italian Language = "wordlists/italian.txt"
)

func GenerateEnt128() ([16]byte, error) {
	var entropy [16]byte
	if _, err := rand.Read(entropy[:]); err != nil {
		return [16]byte{}, fmt.Errorf("could not generate entropy: %s", err)
	}
	return entropy, nil
}

func GenerateDataEnt128(entropy [16]byte) [17]byte {
	hash := sha256.Sum256(entropy[:])
	var data [17]byte
	copy(data[0:16], entropy[:])
	// store first checksum byte (only top 4 bits are used for 128-bit entropy per BIP-39)
	data[16] = hash[0]
	return data
}

func GenerateMnemonicEnt128(data [17]byte, lang Language) ([]string, error) {
	wordlist, err := wordlistsFS.ReadFile(string(lang))
	if err != nil {
		return nil, fmt.Errorf("could not open %s: %w", string(lang), err)
	}

	wordsList := strings.Split(strings.ReplaceAll(string(wordlist), "\r\n", "\n"), "\n")
	if len(wordsList) < 2048 {
		return nil, fmt.Errorf("invalid wordlist at: %s", string(lang))
	}

	words := make([]string, 0, 12)
	var acc uint32
	var bits uint
	for i := 0; i < len(data) && len(words) < 12; i++ {
		acc = (acc << 8) | uint32(data[i])
		bits += 8
		for bits >= 11 && len(words) < 12 {
			shift := bits - 11
			idx := (acc >> shift) & 0x7FF
			words = append(words, wordsList[idx])
			bits -= 11
			if bits == 0 {
				acc = 0
			} else {
				acc &= (1 << bits) - 1
			}
		}
	}
	return words, nil
}

/*
NFKD normalization matters. If your mnemonic or passphrase ever has non-ASCII characters (unlikely with the standard English wordlist, but relevant if you support other BIP39 wordlists), skipping normalization gives you a different, wrong seed. Cheap to include, so just always do it.
*/

func GenerateSeedEnt128() ([12]string, [64]byte, error) {
	entropy, err := GenerateEnt128()
	if err != nil {
		return [12]string{}, [64]byte{}, err
	}
	data := GenerateDataEnt128(entropy)
	mnemonic, err := GenerateMnemonicEnt128(data, English)
	if err != nil {
		return [12]string{}, [64]byte{}, err
	}

	passphrase := ""
	normMnemonic := norm.NFKD.String(strings.Join(mnemonic, " "))
	normPassphrase := norm.NFKD.String(passphrase)
	salt := "mnemonic" + normPassphrase

	seed, err := pbkdf2.Key(sha512.New, normMnemonic, []byte(salt), 2048, 64)
	if err != nil {
		return [12]string{}, [64]byte{}, err
	}

	return [12]string(mnemonic), [64]byte(seed), nil
}
