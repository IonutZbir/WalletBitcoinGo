package wallet

import (
	"encoding/csv"
	"encoding/json"
	"fmt"
	"maps"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"wallet-bitcoin/src/api"
	keymanager "wallet-bitcoin/src/key_manager"
	"wallet-bitcoin/src/utils"

	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/btcutil"
	"github.com/btcsuite/btcd/chaincfg"
)

func (w *Wallet) SkToWif(sk []byte) (string, error) {
	privKey, _ := btcec.PrivKeyFromBytes(sk)

	wif, err := btcutil.NewWIF(privKey, &chaincfg.TestNet3Params, true)
	if err != nil {
		return "", fmt.Errorf("failed to create WIF: %w", err)
	}

	return wif.String(), nil
}

func (w *Wallet) WifToSk(wifStr string) ([]byte, error) {
	// Rimuove eventuali prefissi di tipo script (es. "p2wpkh:", "p2pkh:")
	if idx := strings.Index(wifStr, ":"); idx != -1 {
		wifStr = wifStr[idx+1:]
	}

	// Decodifica e verifica il checksum Base58
	wif, err := btcutil.DecodeWIF(wifStr)
	if err != nil {
		return nil, fmt.Errorf("failed to decode WIF: %w", err)
	}

	// Verifica opzionale della rete di appartenenza
	var expectedNet *chaincfg.Params = &chaincfg.MainNetParams
	if w.Testnet { // O &chaincfg.TestNet3Params in base al tuo campo
		expectedNet = &chaincfg.TestNet3Params
	}

	if !wif.IsForNet(expectedNet) {
		return nil, fmt.Errorf("WIF is not for the configured network (testnet=%t)", w.Testnet)
	}

	// Serializza la chiave privata nei suoi 32 byte raw
	return wif.PrivKey.Serialize(), nil
}

func (w *Wallet) ExportKeys(exportType string) (string, error) {
	allAddresses := make(map[string]keymanager.Address,
		len(w.ReceiversLegacyAddresses)+
			len(w.ChangeLegacyAddresses)+
			len(w.ReceiversSegwitAddresses)+
			len(w.ChangeSegwitAddresses),
	)

	// Copy all addresses
	maps.Copy(allAddresses, w.ReceiversLegacyAddresses)
	maps.Copy(allAddresses, w.ChangeLegacyAddresses)
	maps.Copy(allAddresses, w.ReceiversSegwitAddresses)
	maps.Copy(allAddresses, w.ChangeSegwitAddresses)

	// [ {"address": address, "signingKey": "type:signingKey"} , ... ]
	// [ {"address": dasdafaaf, "signingKey": "p2pkh:signingKey"} , ... ]
	// [ {"address": dasdafaaf, "signingKey": "p2wpkh:signingKey"} , ... ]
	exportData := make([]map[string]string, 0, len(allAddresses))
	for k, v := range allAddresses {
		if v.Legacy {
			sig, _ := w.SkToWif(v.SigningKey)
			exportData = append(exportData, map[string]string{
				"address":    k,
				"signingKey": "p2pkh:" + sig,
			})
		} else {
			sig, _ := w.SkToWif(v.SigningKey)
			exportData = append(exportData, map[string]string{
				"address":    k,
				"signingKey": "p2wpkh:" + sig,
			})
		}
	}

	// Ordinamento: prima p2wpkh:, poi p2pkh: (e per indirizzo a parità di tipo)
	sort.SliceStable(exportData, func(i, j int) bool {
		iSegwit := strings.HasPrefix(exportData[i]["signingKey"], "p2wpkh:")
		jSegwit := strings.HasPrefix(exportData[j]["signingKey"], "p2wpkh:")
		if iSegwit != jSegwit {
			return iSegwit
		}
		return exportData[i]["address"] < exportData[j]["address"]
	})

	homeDir, err := os.UserHomeDir()
	if err != nil {
		return "", fmt.Errorf("retrieving user home directory: %w", err)
	}
	filePath := filepath.Join(homeDir, fmt.Sprintf("%s_export.%s", w.Name, exportType))

	switch exportType {
	case "json":
		data, err := json.MarshalIndent(exportData, "", "  ")
		if err != nil {
			return "", fmt.Errorf("marshalling json: %w", err)
		}
		if err := os.WriteFile(filePath, data, 0600); err != nil {
			return "", fmt.Errorf("writing json file: %w", err)
		}

	case "csv":
		file, err := os.OpenFile(filePath, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0600)
		if err != nil {
			return "", fmt.Errorf("creating csv file: %w", err)
		}
		defer file.Close()

		writer := csv.NewWriter(file)
		defer writer.Flush()

		// Header CSV in stile Electrum/standard
		if err := writer.Write([]string{"address", "signingKey"}); err != nil {
			return "", fmt.Errorf("writing csv header: %w", err)
		}

		for _, entry := range exportData {
			if err := writer.Write([]string{entry["address"], entry["signingKey"]}); err != nil {
				return "", fmt.Errorf("writing csv record: %w", err)
			}
		}
	}

	absPath, _ := filepath.Abs(filePath)
	return absPath, nil
}

func ImportWalletFromFile(name string, password string, testnet bool, filePath string) (*Wallet, error) {
	extension := filepath.Ext(filePath)
	var addresses []map[string]string

	switch extension {
	case ".json":
		data, err := os.ReadFile(filePath)
		if err != nil {
			return nil, fmt.Errorf("reading file: %w", err)
		}
		if err := json.Unmarshal(data, &addresses); err != nil {
			return nil, fmt.Errorf("unmarshalling json: %w", err)
		}
	case ".csv":
		f, err := os.Open(filePath)
		if err != nil {
			return nil, fmt.Errorf("opening csv: %w", err)
		}
		defer f.Close()

		r := csv.NewReader(f)
		records, err := r.ReadAll()
		if err != nil {
			return nil, fmt.Errorf("reading csv: %w", err)
		}

		if len(records) < 1 {
			return nil, fmt.Errorf("empty csv")
		}

		// salta l'header
		for i, row := range records[1:] {
			if len(row) != 2 {
				return nil, fmt.Errorf("row %d: expected 2 columns, got %d", i+2, len(row))
			}
			address := strings.TrimSpace(row[0])
			signingKey := strings.TrimSpace(row[1])
			addresses = append(addresses, map[string]string{
				"address":    address,
				"signingKey": signingKey,
			})
		}
	default:
		return nil, fmt.Errorf("unsupported file type: %s", extension)
	}

	legacyAddresses := make(map[string]keymanager.Address)
	segwitAddresses := make(map[string]keymanager.Address)
	var w Wallet
	w.Testnet = testnet
	for _, entry := range addresses {
		signingKey, err := w.WifToSk(entry["signingKey"])
		if err != nil {
			return nil, fmt.Errorf("wif to sk: %w", err)
		}
		prefix := strings.Split(entry["signingKey"], ":")[0]
		pubKeyCompressed, err := utils.PrivToCompressedPub(signingKey)
		if err != nil {
			return nil, err
		}
		pubKeyHash := utils.Hash160(pubKeyCompressed)
		switch prefix {
		case "p2pkh":
			legacyAddresses[entry["address"]] = keymanager.Address{
				SigningKey: signingKey,
				PubKeyHash: pubKeyHash[:],
				Address:    entry["address"],
				Legacy:     true,
				Path:       nil,
				Balance:    0,
			}
		case "p2wpkh":
			segwitAddresses[entry["address"]] = keymanager.Address{
				SigningKey: signingKey,
				PubKeyHash: pubKeyHash[:],
				Address:    entry["address"],
				Legacy:     false,
				Path:       nil,
				Balance:    0,
			}
		}
	}

	walletFilePath, err := getWalletPath(name, testnet)
	if err != nil {
		return nil, fmt.Errorf("error getting wallet path: %w", err)
	}

	w.ReceiversLegacyAddresses = legacyAddresses
	w.ReceiversSegwitAddresses = segwitAddresses
	w.Balance = nil
	w.Mempool = api.NewMempoolApi(testnet)
	w.BtcCore = api.NewBtcCoreApi(testnet)
	w.Seed = [64]byte{}
	w.Mnemonic = [12]string{}
	w.Password = password
	w.Name = name
	w.Xpub = nil
	w.Xprv = nil
	w.ChangeLegacyAddresses = nil
	w.ChangeSegwitAddresses = nil
	w.Path = walletFilePath

	if err := w.EncryptAndSaveWallet(password, walletFilePath); err != nil {
		return nil, fmt.Errorf("error encrypting and saving wallet: %w", err)
	}

	core := false // TODO: fallback to mempool
	w.getBalance(core)

	return &w, nil

}
