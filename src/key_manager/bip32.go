package keymanager

/*

Implementazione di BIP32 (Hierarchical Deterministic Wallets).
- en.bitcoin.it/wiki/BIP_0032

Ai fini del progetto, sono state implmenetate solo la funzione di derivazioned della master key e la "Private parent key → private child key"
*/

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha512"
	"encoding/binary"
	"errors"
	"math/big"
	"wallet-bitcoin/src/utils"
)

const (
	HardenedOffset = uint32(0x80000000) // 2^31

	versionPrivate = 0x0488ADE4 // xprv
	versionPublic  = 0x0488B21E // xpub
)

// ExtendedKey rappresenta un nodo dell'albero BIP32.
// Se IsPrivate: Key = 32 byte (k). Altrimenti: Key = 33 byte pubkey compressa (K).

type ExtendedKey struct {
	Key         []byte
	ChainCode   []byte // 32 byte
	Depth       byte
	ParentFP    [4]byte
	ChildNumber uint32
	IsPrivate   bool
}

// ---------- 4.7 Master key generation ----------

func NewMasterKey(seed []byte) (*ExtendedKey, error) {
	/*
		Input - seed: sequence of {128, 160, 192, 224, 256} bits of randomness generated bv a (P)RNG. In this use case is used the seed generated with BIP32 mnemonic sequence.
		Output - masterKey: the root of the tree keys.

		The function generates the master key, wich is the root of the tree keys following the standard procedure defined in BIP39.
		- https://en.bitcoin.it/wiki/BIP_0032#Master_key_generation
	*/

	if len(seed) < 16 || len(seed) > 64 {
		return nil, errors.New("seed must be between 128 and 512 bits")
	}

	//  I = HMAC-SHA512(Key = "Bitcoin seed", Data = seed)
	mac := hmac.New(sha512.New, []byte("Bitcoin seed"))
	mac.Write(seed)
	I := mac.Sum(nil)

	IL, IR := I[:32], I[32:]

	if !utils.ValidPrivateScalar(IL) {
		return nil, errors.New("invalid master key (IL=0 or IL>=n): regenerate the seed")
	}

	return &ExtendedKey{
		Key:         append([]byte(nil), IL...),
		ChainCode:   append([]byte(nil), IR...),
		Depth:       0,
		ParentFP:    [4]byte{0, 0, 0, 0},
		ChildNumber: 0,
		IsPrivate:   true,
	}, nil
}

// ---------- 4.3.1 CKDpriv: private parent -> private child ----------

func (k *ExtendedKey) DeriveChild(i uint32) (*ExtendedKey, error) {
	/*
		Input - i: i-th child to be generate
		Output - childKey: an extendedKey child generated from the parent key

		The function implements the CDKpriv (child key derivation function), wich generate a private child key from the private parent key  following the standard procedure defined in BIP39.
		- https://en.bitcoin.it/wiki/BIP_0032#Private_parent_key_%E2%86%92_private_child_key
	*/

	if !k.IsPrivate {
		return nil, errors.New("the key must be private for CKDpriv")
	}

	idxBytes := make([]byte, 4)
	binary.BigEndian.PutUint32(idxBytes, i)

	var data []byte
	if i >= HardenedOffset {
		// hardened: 0x00 || ser256(k_par) || ser32(i)
		data = make([]byte, 0, 37)
		data = append(data, 0x00)
		data = append(data, k.Key...)
	} else {
		// normal: serP(point(k_par)) || ser32(i)
		pub, err := utils.PrivToCompressedPub(k.Key)
		if err != nil {
			return nil, err
		}
		data = make([]byte, 0, 37)
		data = append(data, pub...)
	}
	data = append(data, idxBytes...)

	mac := hmac.New(sha512.New, k.ChainCode)
	mac.Write(data)
	I := mac.Sum(nil)
	IL, IR := I[:32], I[32:]

	ilInt := new(big.Int).SetBytes(IL)
	if ilInt.Cmp(utils.CurveOrder) >= 0 {
		// probability < 2^-127: repeat the procedure with i+1
		return nil, errors.New("IL >= n: repeat the derivation with i+1")
	}

	kParInt := new(big.Int).SetBytes(k.Key)
	childInt := new(big.Int).Add(ilInt, kParInt)
	childInt.Mod(childInt, utils.CurveOrder)

	if childInt.Sign() == 0 {
		return nil, errors.New("k_i = 0: riprovare la derivazione con indice i+1")
	}

	childKey := make([]byte, 32)
	childInt.FillBytes(childKey)

	return &ExtendedKey{
		Key:         childKey,
		ChainCode:   append([]byte(nil), IR...),
		Depth:       k.Depth + 1,
		ParentFP:    k.Fingerprint(),
		ChildNumber: i,
		IsPrivate:   true,
	}, nil
}

// ---------- Key identifiers / fingerprint (4.5) ----------

func (k *ExtendedKey) Fingerprint() [4]byte {
	pub := k.Key
	if k.IsPrivate {
		pub, _ = utils.PrivToCompressedPub(k.Key) // errore già validato a monte
	}

	h160 := utils.Hash160(pub)

	var fp [4]byte
	copy(fp[:], h160[:4])
	return fp
}

// ---------- Serializzazione xprv/xpub (4.6) ----------

func (k *ExtendedKey) Serialize() (string, error) {
	buf := new(bytes.Buffer)

	var version uint32
	if k.IsPrivate {
		version = versionPrivate
	} else {
		version = versionPublic
	}
	if err := binary.Write(buf, binary.BigEndian, version); err != nil {
		return "", err
	}
	buf.WriteByte(k.Depth)
	buf.Write(k.ParentFP[:])
	if err := binary.Write(buf, binary.BigEndian, k.ChildNumber); err != nil {
		return "", err
	}
	buf.Write(k.ChainCode)

	if k.IsPrivate {
		buf.WriteByte(0x00)
		buf.Write(k.Key) // 32 byte
	} else {
		buf.Write(k.Key) // 33 byte compressa
	}

	return utils.Base58CheckEncode(buf.Bytes()), nil
}
