package wallet

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"wallet-bitcoin/src/api"
	keymanager "wallet-bitcoin/src/key_manager"
	"wallet-bitcoin/src/utils"
)

const (
	NumLegacyAddresses       = 10
	NumSegwitAddresses       = 10
	NumChangeLegacyAddresses = 5
	NumChangeSegwitAddresses = 5
	NumAddresses             = NumLegacyAddresses + NumSegwitAddresses + NumChangeLegacyAddresses + NumChangeSegwitAddresses
)

type Wallet struct {
	Path                     string
	ReceiversLegacyAddresses map[string]keymanager.Address
	ReceiversSegwitAddresses map[string]keymanager.Address
	ChangeLegacyAddresses    map[string]keymanager.Address
	ChangeSegwitAddresses    map[string]keymanager.Address
	Balance                  []api.Balance
	Testnet                  bool
	Mempool                  *api.MempoolApi
	BtcCore                  *api.BtcCoreApi
	Seed                     [64]byte
	Mnemonic                 [12]string
	Password                 string
	Name                     string
	Xpub                     []byte
	Xprv                     []byte
}

func (w *Wallet) String() string {
	var builder strings.Builder

	// Mappa address -> balance per lookup O(1) dentro printAddressMap
	balanceByAddress := make(map[string]int64, len(w.Balance))
	var totalBalance int64
	for _, b := range w.Balance {
		balanceByAddress[b.Address] = b.Balance
		totalBalance += b.Balance
	}

	// Header details
	fmt.Fprintf(&builder, "Path: %s\nTestnet: %t\nBalance: %d satoshis\n", w.Path, w.Testnet, totalBalance)

	// Format Mnemonic array
	fmt.Fprintf(&builder, "Mnemonic: %s %s %s %s %s %s %s %s %s %s %s %s\n",
		w.Mnemonic[0], w.Mnemonic[1], w.Mnemonic[2], w.Mnemonic[3],
		w.Mnemonic[4], w.Mnemonic[5], w.Mnemonic[6], w.Mnemonic[7],
		w.Mnemonic[8], w.Mnemonic[9], w.Mnemonic[10], w.Mnemonic[11],
	)

	// Total count
	totalAddresses := len(w.ReceiversLegacyAddresses) + len(w.ReceiversSegwitAddresses) +
		len(w.ChangeLegacyAddresses) + len(w.ChangeSegwitAddresses)
	fmt.Fprintf(&builder, "Total Addresses (%d):\n", totalAddresses)

	// Helper to print address maps, including the balance for each address
	printAddressMap := func(label string, addrMap map[string]keymanager.Address) {
		if len(addrMap) == 0 {
			return
		}
		fmt.Fprintf(&builder, "  -- %s --\n", label)
		for key, addr := range addrMap {
			bal, ok := balanceByAddress[key]
			if !ok {
				fmt.Fprintf(&builder, "    %v (balance unknown)\n", addr)
				continue
			}
			fmt.Fprintf(&builder, "    %v — %d satoshis\n", addr, bal)
		}
	}
	printAddressMap("Receivers (Legacy)", w.ReceiversLegacyAddresses)
	printAddressMap("Receivers (SegWit)", w.ReceiversSegwitAddresses)
	printAddressMap("Change (Legacy)", w.ChangeLegacyAddresses)
	printAddressMap("Change (SegWit)", w.ChangeSegwitAddresses)

	return builder.String()
}

func NewWalletFromScratch(name string, password string, testnet bool) (*Wallet, error) {
	mnemonic, _, err := keymanager.GenerateSeedEnt128()
	if err != nil {
		return nil, fmt.Errorf("error generating seed: %w", err)
	}

	return NewWalletFromMnemonic(name, password, testnet, mnemonic)
}

func NewWalletFromMnemonic(name string, password string, testnet bool, mnemonic [12]string) (*Wallet, error) {
	walletFilePath, err := getWalletPath(name, testnet)
	if err != nil {
		return nil, fmt.Errorf("error getting wallet path: %w", err)
	}

	seed, err := keymanager.GenerateSeedFromMnemonic(mnemonic[:])
	if err != nil {
		return nil, fmt.Errorf("error generating seed from mnemonic: %w", err)
	}

	// 3. Genera il Master Key BIP-32
	master, err := keymanager.NewMasterKey(seed[:])
	if err != nil {
		return nil, fmt.Errorf("error generating master key: %w", err)
	}

	xPub, err := utils.PrivToCompressedPub(master.Key)
	if err != nil {
		return nil, fmt.Errorf("error compressing public key: %w", err)
	}
	xPrv := master.Key

	// 4. Inizializza l'istanza di Wallet con le mappe per gli indirizzi
	w := &Wallet{
		Path:                     walletFilePath,
		ReceiversLegacyAddresses: make(map[string]keymanager.Address, NumLegacyAddresses),
		ReceiversSegwitAddresses: make(map[string]keymanager.Address, NumSegwitAddresses),
		ChangeLegacyAddresses:    make(map[string]keymanager.Address, NumChangeLegacyAddresses),
		ChangeSegwitAddresses:    make(map[string]keymanager.Address, NumChangeSegwitAddresses),
		Balance:                  make([]api.Balance, 0),
		Testnet:                  testnet,
		Mempool:                  api.NewMempoolApi(testnet),
		BtcCore:                  api.NewBtcCoreApi(testnet),
		Seed:                     seed,
		Mnemonic:                 mnemonic,
		Password:                 password,
		Name:                     name,
		Xpub:                     xPub,
		Xprv:                     xPrv,
	}

	// 5. Determina il network per la derivazione
	network := keymanager.NetworkMainnet
	if testnet {
		network = keymanager.NetworkTestnet
	}

	// 6. Deriva gli indirizzi e assegnali alle rispettive mappe
	for i := 0; i < NumLegacyAddresses; i++ {
		addr, err := keymanager.DeriveLegacyAddress(master, network, keymanager.ChainExternal, uint32(i))
		if err != nil {
			return nil, fmt.Errorf("error deriving legacy address: %w", err)
		}
		w.ReceiversLegacyAddresses[addr.Address] = *addr
	}
	for i := 0; i < NumSegwitAddresses; i++ {
		addr, err := keymanager.DeriveSegwitAddress(master, network, keymanager.ChainExternal, uint32(i))
		if err != nil {
			return nil, fmt.Errorf("error deriving segwit address: %w", err)
		}
		w.ReceiversSegwitAddresses[addr.Address] = *addr
	}
	for i := 0; i < NumChangeLegacyAddresses; i++ {
		addr, err := keymanager.DeriveLegacyAddress(master, network, keymanager.ChainChange, uint32(i))
		if err != nil {
			return nil, fmt.Errorf("error deriving change legacy address: %w", err)
		}
		w.ChangeLegacyAddresses[addr.Address] = *addr
	}
	for i := 0; i < NumChangeSegwitAddresses; i++ {
		addr, err := keymanager.DeriveSegwitAddress(master, network, keymanager.ChainChange, uint32(i))
		if err != nil {
			return nil, fmt.Errorf("error deriving change segwit address: %w", err)
		}
		w.ChangeSegwitAddresses[addr.Address] = *addr
	}

	// 7. Cifra e persisti il wallet su disco
	if err := w.EncryptAndSaveWallet(password, walletFilePath); err != nil {
		return nil, fmt.Errorf("error encrypting and saving wallet: %w", err)
	}

	core := false
	w.getBalance(core)

	return w, nil

}

// func NewWalletFromPrivateKey(name string, password string, testnet bool, prvKey []byte) (*Wallet, error) {}
// func (w *Wallet) ImportPrivateKey(name string, password string, testnet bool, prvKey []byte) (*Wallet, error) {}

func getWalletPath(name string, testnet bool) (string, error) {
	homeDir, err := os.UserHomeDir()
	if err != nil {
		return "", fmt.Errorf("error finding home directory: %w", err)
	}

	walletDir := filepath.Join(homeDir, baseDirName)
	if testnet {
		walletDir = filepath.Join(walletDir, "testnet")
	}
	walletDir = filepath.Join(walletDir, name)

	walletFilePath := filepath.Join(walletDir, name+".json")

	// 1. Controlla se il file esiste già
	if _, err := os.Stat(walletFilePath); err == nil {
		// Il file esiste già
		return "", fmt.Errorf("wallet '%s' already exists at path: %s", name, walletFilePath)
	} else if !errors.Is(err, os.ErrNotExist) {
		// C'è stato un errore diverso (es. problemi di permessi)
		return "", fmt.Errorf("error checking if wallet exists: %w", err)
	}

	// 2. Crea la directory solo se il file non esiste
	if err := os.MkdirAll(walletDir, 0700); err != nil {
		return "", fmt.Errorf("error creating wallet directory: %w", err)
	}

	return walletFilePath, nil
}

func (w *Wallet) getBalance(core bool) error {
	allAddresses := make(map[string]keymanager.Address)
	for k, v := range w.ReceiversLegacyAddresses {
		allAddresses[k] = v
	}
	for k, v := range w.ChangeLegacyAddresses {
		allAddresses[k] = v
	}
	for k, v := range w.ReceiversSegwitAddresses {
		allAddresses[k] = v
	}
	for k, v := range w.ChangeSegwitAddresses {
		allAddresses[k] = v
	}

	var balance []api.Balance
	var err error
	if core {
		balance, err = w.BtcCore.ComputeBalanceForAddresses(allAddresses)
	} else {
		balance, err = w.Mempool.ComputeBalanceForAddresses(allAddresses)
	}
	if err != nil {
		return err
	}

	w.Balance = balance
	return nil
}
