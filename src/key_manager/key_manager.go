package keymanager

import (
	"fmt"
	"wallet-bitcoin/src/utils"

	"github.com/btcsuite/btcd/btcutil"
	"github.com/btcsuite/btcd/chaincfg"
)

const (
	AddressTypeLegacy = "legacy" // BIP44, P2PKH
	AddressTypeSegwit = "segwit" // BIP84, P2WPKH

	ChainExternal = "external" // receiving addresses
	ChainChange   = "change"   // change outputs

	NetworkMainnet = "mainnet"
	NetworkTestnet = "testnet"
)

// coinType per BIP44: mainnet = 0', testnet (any) = 1'.
// This applies uniformly across purposes (44'/49'/84').
var coinType = map[string]uint32{
	NetworkMainnet: 0 + HardenedOffset,
	NetworkTestnet: 1 + HardenedOffset,
}

var purpose = map[string]uint32{
	AddressTypeLegacy: 44 + HardenedOffset,
	AddressTypeSegwit: 84 + HardenedOffset,
}

var changeIndex = map[string]uint32{
	ChainExternal: 0,
	ChainChange:   1,
}

// BuildPath returns the full derivation path for a given address type,
// network, chain, and index, e.g.
// BuildPath(AddressTypeSegwit, NetworkTestnet, ChainChange, 3)
// -> m/84'/1'/0'/1/3
func BuildPath(addressType, network, chain string, index uint32) ([]uint32, error) {
	p, ok := purpose[addressType]
	if !ok {
		return nil, fmt.Errorf("unknown address type: %s", addressType)
	}
	c, ok := coinType[network]
	if !ok {
		return nil, fmt.Errorf("unknown network: %s", network)
	}
	ch, ok := changeIndex[chain]
	if !ok {
		return nil, fmt.Errorf("unknown chain: %s", chain)
	}

	account := uint32(0) + HardenedOffset

	return []uint32{p, c, account, ch, index}, nil
}

type Address struct {
	SigningKey []byte   `json:"signingKey"`
	PubKeyHash []byte   `json:"pubKeyHash"`
	Address    string   `json:"address"`
	Legacy     bool     `json:"legacy"`
	Path       []uint32 `json:"path"`
}

func DeriveKeyPath(master *ExtendedKey, path []uint32) (*ExtendedKey, error) {
	key := master
	var err error
	for _, idx := range path {
		key, err = key.DeriveChild(idx)
		if err != nil {
			return nil, err
		}
	}
	return key, nil
}

func DeriveLegacyAddress(master *ExtendedKey, network, chain string, index uint32) (*Address, error) {
	path, err := BuildPath(AddressTypeLegacy, network, chain, index)
	if err != nil {
		return nil, err
	}
	secretKey, err := DeriveKeyPath(master, path)
	if err != nil {
		return nil, err
	}

	pubKeyCompressed, err := utils.PrivToCompressedPub(secretKey.Key)
	if err != nil {
		return nil, err
	}
	pubKeyHash := utils.Hash160(pubKeyCompressed)

	version := byte(0x00) // mainnet P2PKH
	if network == NetworkTestnet {
		version = 0x6F
	}
	payload := append([]byte{version}, pubKeyHash[:]...)
	address := utils.Base58CheckEncode(payload)

	return &Address{
		SigningKey: secretKey.Key,
		PubKeyHash: pubKeyHash[:],
		Address:    address,
		Legacy:     true,
		Path:       path,
	}, nil
}

func DeriveSegwitAddress(master *ExtendedKey, network, chain string, index uint32) (*Address, error) {
	path, err := BuildPath(AddressTypeSegwit, network, chain, index)
	if err != nil {
		return nil, err
	}
	secretKey, err := DeriveKeyPath(master, path)
	if err != nil {
		return nil, err
	}

	pubKeyCompressed, err := utils.PrivToCompressedPub(secretKey.Key)
	if err != nil {
		return nil, err
	}
	pubKeyHash := utils.Hash160(pubKeyCompressed)

	params := &chaincfg.MainNetParams
	if network == NetworkTestnet {
		params = &chaincfg.TestNet3Params
	}
	addr, err := btcutil.NewAddressWitnessPubKeyHash(pubKeyHash[:], params)
	if err != nil {
		return nil, fmt.Errorf("error encoding to bech32: %w", err)
	}

	return &Address{
		SigningKey: secretKey.Key,
		PubKeyHash: pubKeyHash[:],
		Address:    addr.EncodeAddress(),
		Legacy:     false,
		Path:       path,
	}, nil
}
