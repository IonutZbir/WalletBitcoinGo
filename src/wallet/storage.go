package wallet

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"

	"wallet-bitcoin/src/api"
	keymanager "wallet-bitcoin/src/key_manager"

	"golang.org/x/crypto/scrypt"
)

const baseDirName = ".walletbitcoingo"

// scrypt parameters used for encrypting/decrypting the wallet at rest.
const (
	scryptN      = 262144
	scryptR      = 8
	scryptP      = 1
	scryptKeyLen = 32
	saltLen      = 32
)

type KDFParams struct {
	N      int    `json:"n"`
	R      int    `json:"r"`
	P      int    `json:"p"`
	KeyLen int    `json:"keyLen"`
	Salt   []byte `json:"salt"`
}

type CryptoEnvelope struct {
	Cipher     string    `json:"cipher"`
	Ciphertext []byte    `json:"ciphertext"`
	Nonce      []byte    `json:"nonce"`
	KDF        string    `json:"kdf"`
	KDFParams  KDFParams `json:"kdfparams"`
}

type KeystoreData struct {
	Mnemonic [12]string `json:"mnemonic"`
	Seed     [64]byte   `json:"seed"`
	Xpub     []byte     `json:"xpub"`
	Xprv     []byte     `json:"xprv"`
}

type AddressSet struct {
	Legacy map[string]keymanager.Address `json:"legacy"`
	Segwit map[string]keymanager.Address `json:"segwit"`
}

type Payload struct {
	Keystore  KeystoreData `json:"keystore"`
	Receivers AddressSet   `json:"receivers"`
	Change    AddressSet   `json:"change"`
}

// toPayload converts the in-memory Wallet into the serializable shape
// written to disk. The inverse of Payload.applyTo.
func (w *Wallet) toPayload() Payload {
	return Payload{
		Keystore: KeystoreData{
			Mnemonic: w.Mnemonic,
			Seed:     w.Seed,
			Xpub:     w.Xpub,
			Xprv:     w.Xprv,
		},
		Receivers: AddressSet{
			Legacy: w.ReceiversLegacyAddresses,
			Segwit: w.ReceiversSegwitAddresses,
		},
		Change: AddressSet{
			Legacy: w.ChangeLegacyAddresses,
			Segwit: w.ChangeSegwitAddresses,
		},
	}
}

// applyTo fills the wallet-specific fields of w from the payload. Fields
// like Path/Name/Password/Testnet are set by the caller separately since
// they aren't part of the serialized payload.
func (p Payload) applyTo(w *Wallet) {
	w.Mnemonic = p.Keystore.Mnemonic
	w.Seed = p.Keystore.Seed
	w.Xpub = p.Keystore.Xpub
	w.Xprv = p.Keystore.Xprv
	w.ReceiversLegacyAddresses = p.Receivers.Legacy
	w.ReceiversSegwitAddresses = p.Receivers.Segwit
	w.ChangeLegacyAddresses = p.Change.Legacy
	w.ChangeSegwitAddresses = p.Change.Segwit
}

func (w *Wallet) newDataToStore() (json.RawMessage, error) {
	bytes, err := json.Marshal(w.toPayload())
	if err != nil {
		return nil, fmt.Errorf("error marshaling wallet data: %w", err)
	}
	return json.RawMessage(bytes), nil
}

// deriveKey derives an AES-256 key from password using the given scrypt
// parameters (shared by both encryption and decryption paths).
func deriveKey(password string, params KDFParams) ([]byte, error) {
	return scrypt.Key([]byte(password), params.Salt, params.N, params.R, params.P, params.KeyLen)
}

// newAESGCM builds an AES-GCM AEAD from a raw key (shared by both paths).
func newAESGCM(key []byte) (cipher.AEAD, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("error creating AES cipher: %w", err)
	}
	return cipher.NewGCM(block)
}

func (w *Wallet) EncryptAndSaveWallet(password string, filePath string) error {
	rawData, err := w.newDataToStore()
	if err != nil {
		return fmt.Errorf("error preparing wallet data: %w", err)
	}

	salt := make([]byte, saltLen)
	if _, err := io.ReadFull(rand.Reader, salt); err != nil {
		return fmt.Errorf("error generating salt: %w", err)
	}

	params := KDFParams{N: scryptN, R: scryptR, P: scryptP, KeyLen: scryptKeyLen, Salt: salt}
	key, err := deriveKey(password, params)
	if err != nil {
		return fmt.Errorf("error deriving AES key: %w", err)
	}

	aesGCM, err := newAESGCM(key)
	if err != nil {
		return fmt.Errorf("error creating GCM: %w", err)
	}

	nonce := make([]byte, aesGCM.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return fmt.Errorf("error generating nonce: %w", err)
	}

	ciphertext := aesGCM.Seal(nil, nonce, rawData, nil)

	envelope := CryptoEnvelope{
		Cipher:     "aes-256-gcm",
		Ciphertext: ciphertext,
		Nonce:      nonce,
		KDF:        "scrypt",
		KDFParams:  params,
	}

	jsonData, err := json.MarshalIndent(envelope, "", "  ")
	if err != nil {
		return fmt.Errorf("error serializing JSON envelope: %w", err)
	}

	// Owner-only read/write permissions — this file holds key material.
	if err := os.WriteFile(filePath, jsonData, 0600); err != nil {
		return fmt.Errorf("error saving file to disk: %w", err)
	}

	return nil
}

func LoadWallet(name string, password string, testnet bool) (*Wallet, error) {
	homeDir, err := os.UserHomeDir()
	if err != nil {
		return nil, fmt.Errorf("error finding home directory: %w", err)
	}

	walletDir := filepath.Join(homeDir, baseDirName)
	if testnet {
		walletDir = filepath.Join(walletDir, "testnet")
	}
	walletDir = filepath.Join(walletDir, name)

	if _, err := os.Stat(walletDir); os.IsNotExist(err) {
		return nil, fmt.Errorf("wallet directory does not exist")
	}

	walletFilePath := filepath.Join(walletDir, name+".json")

	fileBytes, err := os.ReadFile(walletFilePath)
	if err != nil {
		return nil, fmt.Errorf("error reading wallet file: %w", err)
	}

	var envelope CryptoEnvelope
	if err := json.Unmarshal(fileBytes, &envelope); err != nil {
		return nil, fmt.Errorf("error parsing encrypted envelope: %w", err)
	}

	key, err := deriveKey(password, envelope.KDFParams)
	if err != nil {
		return nil, fmt.Errorf("error deriving key from password: %w", err)
	}

	aesGCM, err := newAESGCM(key)
	if err != nil {
		return nil, fmt.Errorf("error creating GCM mode: %w", err)
	}

	decryptedBytes, err := aesGCM.Open(nil, envelope.Nonce, envelope.Ciphertext, nil)
	if err != nil {
		return nil, fmt.Errorf("decryption failed (invalid password or corrupted data): %w", err)
	}

	var payload Payload
	if err := json.Unmarshal(decryptedBytes, &payload); err != nil {
		return nil, fmt.Errorf("error unmarshaling decrypted wallet data: %w", err)
	}

	wallet := &Wallet{
		Path:     walletFilePath,
		Name:     name,
		Password: password,
		Testnet:  testnet,
		Mempool:  api.NewMempoolApi(testnet),
		BtcCore:  api.NewBtcCoreApi(testnet),
	}
	payload.applyTo(wallet)
	core := false
	err = wallet.getBalance(core)
	if err != nil {
		return nil, fmt.Errorf("error getting balance: %w", err)
	}

	return wallet, nil
}
