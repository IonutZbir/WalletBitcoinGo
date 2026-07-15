package keymanager

import "wallet-bitcoin/src/utils"

/*

seed, mnemonic = BIP39()
master key <-> (k-master, c-master) = BIP32()
*/

type Address struct {
	SigningKey []byte
	PubKeyHash []byte
	Address    string
	Legacy     bool
	Path       []uint32
}

func DeriveKeyPath(master *ExtendedKey, path []uint32) (*ExtendedKey, error) {
	key := master
	var err error
	for _, idx := range path {
		key, err = key.DeriveChild(idx)
		if err != nil {
			return &ExtendedKey{}, err
		}
	}
	return key, nil
}

func DeriveLegacyAddress(secretKey *ExtendedKey, testnet bool) (*Address, error) {
	pubKeyCompressed, err := utils.PrivToCompressedPub(secretKey.Key)
	if err != nil {
		return &Address{}, err
	}

	pubKeyHash := utils.Hash160(pubKeyCompressed)

	version := byte(0x00) // mainnet P2PKH
	if testnet {
		version = 0x6F
	}

	payload := append([]byte{version}, pubKeyHash[:]...)
	address := utils.Base58CheckEncode(payload)

	return &Address{
		SigningKey: secretKey.Key,
		PubKeyHash: pubKeyHash[:],
		Address:    address,
		Legacy:     false,
		Path: []uint32{
			44 + HardenedOffset,
			0 + HardenedOffset,
			0 + HardenedOffset,
			0,
			0,
		},
	}, nil
}
