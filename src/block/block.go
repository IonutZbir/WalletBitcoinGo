package block

import (
	"BitcoinParser/src/utils"
	"bytes"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"io"
	"log"
	"math/big"
)

type HeaderField uint8

const (
	HeaderVersion    = 4
	HeaderPrevHash   = 32
	HeaderMerkleRoot = 32
	HeaderTime       = 4
	HeaderBits       = 4
	HeaderNonce      = 4
)

type BlockHeader struct {
	version    [HeaderVersion]byte
	prevHash   [HeaderPrevHash]byte
	merkleRoot [HeaderMerkleRoot]byte
	time       [HeaderTime]byte
	bits       [HeaderBits]byte
	nonce      [HeaderNonce]byte
}

// type Block struct {
// 	blockHeader BlockHeader
// 	txnCount CompactSizeUInt
// 	txns Tx
// }

func newBlockHeader(
	version [HeaderVersion]byte,
	prevHash [HeaderPrevHash]byte,
	merkleRoot [HeaderMerkleRoot]byte,
	time [HeaderTime]byte,
	bits [HeaderBits]byte,
	nonce [HeaderNonce]byte) BlockHeader {

	return BlockHeader{
		version:    version,
		prevHash:   prevHash,
		merkleRoot: merkleRoot,
		time:       time,
		bits:       bits,
		nonce:      nonce,
	}
}

func Parse(byteString []byte) BlockHeader {

	/*
		All the fields are in little endian, for human reading semplicity, all the Bitcoin Explorers, like Mempool or the bitcoin-cli converts them to big endian, so i do the same.
	*/

	reader := bytes.NewReader(byteString)

	var version [HeaderVersion]byte
	_, err := io.ReadFull(reader, version[:])
	if err != nil {
		log.Fatalf("Failed to read version bytes: %v\n", err)
	}

	var prevHash [HeaderPrevHash]byte
	_, err = io.ReadFull(reader, prevHash[:])
	if err != nil {
		log.Fatalf("Failed to read previous block header hash bytes: %v\n", err)
	}

	var merkleRoot [HeaderMerkleRoot]byte
	_, err = io.ReadFull(reader, merkleRoot[:])
	if err != nil {
		log.Fatalf("Failed to read merkle root bytes: %v\n", err)
	}

	var time [HeaderTime]byte
	_, err = io.ReadFull(reader, time[:])
	if err != nil {
		log.Fatalf("Failed to read time bytes: %v\n", err)
	}

	var bits [HeaderBits]byte
	_, err = io.ReadFull(reader, bits[:])
	if err != nil {
		log.Fatalf("Failed to read bits bytes: %v\n", err)
	}

	var nonce [HeaderNonce]byte
	_, err = io.ReadFull(reader, nonce[:])
	if err != nil {
		log.Fatalf("Failed to read nonce bytes: %v\n", err)
	}

	version = [4]byte(utils.ReverseBytes(version[:]))
	prevHash = [32]byte(utils.ReverseBytes(prevHash[:]))
	merkleRoot = [32]byte(utils.ReverseBytes(merkleRoot[:]))
	time = [4]byte(utils.ReverseBytes(time[:]))
	bits = [4]byte(utils.ReverseBytes(bits[:]))
	nonce = [4]byte(utils.ReverseBytes(nonce[:]))

	return newBlockHeader(version, prevHash, merkleRoot, time, bits, nonce)
}

func (b *BlockHeader) ComputeTarget() *big.Int {
	exp := int32(b.bits[0])
	mantissa := binary.BigEndian.Uint32([]byte{0, b.bits[1], b.bits[2], b.bits[3]})

	// target = mantissa * 265 ^ (exp - 3) -> int256, in Go we use big.Int to store this value
	// we compute the target using the "math/big" library

	target := big.NewInt(int64(mantissa))

	base := big.NewInt(256)
	exponent := big.NewInt(int64(exp - 3))

	target.Mul(target, new(big.Int).Exp(base, exponent, nil))

	// We can also compute this number directly using shifts
	// Mulitiplying byt 256 is equivalent of shifting the bits to left by 8 positions
	// if exp > 3 {
	// 	shift := (exp - 3) * 8
	// 	target.Lsh(target, uint(shift)) // target = target * (256 ^ (exp-3))
	// }

	return target
}

func (b *BlockHeader) serialize() []byte {
	// Serialize in canonical Bitcoin header order (80 bytes), little-endian on wire.
	serializedBlockHeader := make([]byte, 80)

	offset := 0
	copy(serializedBlockHeader[offset:offset+HeaderVersion], utils.ReverseBytes(b.version[:]))
	offset += HeaderVersion

	copy(serializedBlockHeader[offset:offset+HeaderPrevHash], utils.ReverseBytes(b.prevHash[:]))
	offset += HeaderPrevHash

	copy(serializedBlockHeader[offset:offset+HeaderMerkleRoot], utils.ReverseBytes(b.merkleRoot[:]))
	offset += HeaderMerkleRoot

	copy(serializedBlockHeader[offset:offset+HeaderTime], utils.ReverseBytes(b.time[:]))
	offset += HeaderTime

	copy(serializedBlockHeader[offset:offset+HeaderBits], utils.ReverseBytes(b.bits[:]))
	offset += HeaderBits

	copy(serializedBlockHeader[offset:offset+HeaderNonce], utils.ReverseBytes(b.nonce[:]))

	return serializedBlockHeader
}

func (b *BlockHeader) hash() []byte {
	serializedBlockHeader := b.serialize()
	hash := utils.Sha256sha256(serializedBlockHeader)
	return hash[:]
}

func (b *BlockHeader) IsValid() bool {
	target := b.ComputeTarget()
	temp, _ := binary.Varint(b.hash())
	hashInt := big.NewInt(temp)

	if hashInt.Cmp(target) <= 0 {
		return true
	}

	return false
}

func (b *BlockHeader) GetSerializedBlockHeaderHex() string {
	return hex.EncodeToString(b.serialize())
}

func (b *BlockHeader) GetHashHex() string {
	return hex.EncodeToString(utils.ReverseBytes(b.hash()))
}

func (b *BlockHeader) ToJson() ([]byte, error) {
	data := make(map[string]string)

	data["version_hex"] = hex.EncodeToString(b.version[:])
	data["prev_hash"] = hex.EncodeToString(b.prevHash[:])
	data["merkle_root"] = hex.EncodeToString(b.merkleRoot[:])
	data["time"] = hex.EncodeToString(b.time[:])
	data["bits"] = hex.EncodeToString(b.bits[:])
	data["nonce"] = hex.EncodeToString(b.nonce[:])

	jsonData, err := json.MarshalIndent(data, "", "  ")
	if err != nil {
		log.Printf("JSON marshaling failed: %v", err)
		return nil, err
	}

	return jsonData, nil
}

func (b *BlockHeader) ToString() string {
	out, err := b.ToJson()
	if err != nil {
		log.Printf("Failed to convert to string JSON object: %v", err)
		return ""
	}

	return string(out)
}
