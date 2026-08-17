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
	keymanager "wallet-bitcoin/src/key_manager"

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
