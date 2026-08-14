package api

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"sort"
	"strings"
	keymanager "wallet-bitcoin/src/key_manager"
	"wallet-bitcoin/src/transactions"
	"wallet-bitcoin/src/types"

	"github.com/btcsuite/btcd/wire"
)

const MEMPOOLMAINURL = "https://mempool.space/api/"
const MEMPOOLTESTURL = "https://mempool.space/testnet/api/"
const MEMPOOLTEST4URL = "https://mempool.space/testnet4/api/"

type MempoolApi struct {
	testnet bool
}

func NewMempoolApi(testnet bool) *MempoolApi {
	return &MempoolApi{testnet: testnet}
}

func (m *MempoolApi) GetTx(txId string) (map[string]interface{}, error) {
	// GET testnet/api/tx/:txid
	// TODO: refactor so this function returns a Tx data type instead of a map

	reqUrl := fmt.Sprintf("%stx/%s", MEMPOOLMAINURL, txId)
	if m.testnet {
		reqUrl = fmt.Sprintf("%stx/%s", MEMPOOLTESTURL, txId)
	}

	res, err := http.Get(reqUrl)
	if err != nil {
		return nil, fmt.Errorf("error fetching tx: %s - %v", txId, err)
	}

	var data map[string]interface{}
	err = json.NewDecoder(res.Body).Decode(&data)
	if res.StatusCode > 299 {
		return nil, fmt.Errorf("response failed with status code: %d and\nbody: %v\n", res.StatusCode, data)
	}

	return data, nil
}
func (m *MempoolApi) GetTxVout(txId string) ([]interface{}, error) {

	tx, err := m.GetTx(txId)
	if err != nil {
		return nil, err
	}
	vout, ok := tx["vout"].([]interface{})
	if !ok {
		return nil, fmt.Errorf("unexpected vout type in tx response")
	}
	return vout, nil
}

func (m *MempoolApi) GetUTXOSetForAddress(address keymanager.Address) ([]types.Utxo, error) {
	reqUrl := fmt.Sprintf("%saddress/%s/utxo", MEMPOOLMAINURL, address.Address)
	if m.testnet {
		reqUrl = fmt.Sprintf("%saddress/%s/utxo", MEMPOOLTESTURL, address.Address)
	}

	res, err := http.Get(reqUrl)
	if err != nil {
		return nil, fmt.Errorf("error fetching UTXO for address: %s - %v", address.Address, err)
	}
	defer res.Body.Close()

	var data []map[string]interface{}
	if err := json.NewDecoder(res.Body).Decode(&data); err != nil {
		return nil, err
	}
	if res.StatusCode > 299 {
		return nil, fmt.Errorf("response failed with status code: %d and\nbody: %v\n", res.StatusCode, data)
	}

	var utxos []types.Utxo
	for _, u := range data {
		var utxo types.Utxo
		utxo.TxId = u["txid"].(string)
		utxo.Vout = u["vout"].(float64)
		txVouts, err := m.GetTxVout(utxo.TxId)
		if err != nil {
			return nil, err
		}

		for v := range txVouts {
			if v != int(utxo.Vout) {
				continue
			}
			// bisogna convertire in un mappa di stringhe
			entry, ok := txVouts[v].(map[string]interface{})
			if !ok {
				return nil, fmt.Errorf("unexpected vout entry type for tx %s", utxo.TxId)
			}

			script, ok := entry["scriptpubkey"].(string)
			if !ok {
				return nil, fmt.Errorf("missing scriptpubkey for tx %s vout %d", utxo.TxId, v)
			}

			scriptType, ok := entry["scriptpubkey_type"].(string)
			if !ok {
				return nil, fmt.Errorf("missing scriptpubkey_type for tx %s vout %d", utxo.TxId, v)
			}

			utxo.PubKeyScript = types.PubKeyScript{
				Script:     script,
				ScriptType: scriptType,
			}
			valueFloat, ok := entry["value"].(float64)
			if !ok {
				return nil, fmt.Errorf("missing value for tx %s vout %d", utxo.TxId, v)
			}
			utxo.Value = int(valueFloat)

			break
		}

		utxos = append(utxos, utxo)
	}

	sort.Sort(types.UtxoByValue(utxos))

	return utxos, nil
}

func (m *MempoolApi) GetRecommendedFees() (*types.Fees, error) {
	reqUrl := fmt.Sprintf("%sv1/fees/recommended", MEMPOOLMAINURL)
	if m.testnet {
		reqUrl = fmt.Sprintf("%sv1/fees/recommended", MEMPOOLTEST4URL)
	}

	resp, err := http.Get(reqUrl)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	var fees types.Fees
	err = json.Unmarshal(body, &fees)
	if err != nil {
		return nil, err
	}

	return &fees, nil
}

type TxInBuild struct {
	TxIn         transactions.TxIn
	PubKeyScript types.PubKeyScript
	PrivateKey   []byte
	Amount       int64
}

func ExtractTxIns(builds []TxInBuild) []transactions.TxIn {
	// Pre-allochiamo lo slice con la stessa lunghezza dell'array di input
	txIns := make([]transactions.TxIn, len(builds))

	// Cicliamo e copiamo l'elemento interno 'TxIn' nella nuova fetta
	for i, build := range builds {
		txIns[i] = build.TxIn
	}
	return txIns
}

// collectUTXOs raccoglie gli UTXO da tutti gli indirizzi forniti in un unico pool.
func (m *MempoolApi) collectUTXOs(addresses map[string]keymanager.Address) ([]types.Utxo, error) {
	var pool []types.Utxo
	for _, address := range addresses {
		utxos, err := m.GetUTXOSetForAddress(address)
		if err != nil {
			return nil, fmt.Errorf("could not fetch UTXO set for %s: %v", address.Address, err)
		}
		for _, u := range utxos {
			pool = append(pool, types.Utxo{
				TxId:         u.TxId,
				Vout:         u.Vout,
				Value:        u.Value,
				PubKeyScript: u.PubKeyScript,
				PrivateKey:   address.SigningKey,
			})
		}
	}
	return pool, nil
}

type Balance struct {
	Address string
	Balance int64
}

// collectUTXOs raccoglie gli UTXO da tutti gli indirizzi forniti in un unico pool.
func (m *MempoolApi) ComputeBalanceForAddresses(addresses map[string]keymanager.Address) ([]Balance, error) {
	var balances []Balance
	for _, address := range addresses {
		utxos, err := m.GetUTXOSetForAddress(address)
		if err != nil {
			return nil, fmt.Errorf("could not fetch UTXO set for %s: %v", address.Address, err)
		}
		var balance int64
		for _, u := range utxos {
			balance += int64(u.Value)
		}
		balances = append(balances, Balance{
			Address: address.Address,
			Balance: balance,
		})
	}
	return balances, nil
}

// selectInputs esegue la coin selection su un pool di UTXO già aggregato,
// indipendentemente da quale indirizzo li abbia originati.
func selectInputs(pool []types.Utxo, amount int, feeRate int) ([]TxInBuild, int, int, error) {
	var selectedInputs []TxInBuild
	accumulated := 0
	fee := 0
	change := 0
	baseSize := 44 // header (10) + 1 output di destinazione (34)
	for _, utxo := range pool {
		accumulated += utxo.Value
		txIn, err := transactions.NewTxIn(utxo.TxId, uint32(utxo.Vout), 0xffffffff)
		if err != nil {
			return nil, 0, 0, fmt.Errorf("errore creazione TxIn: %v", err)
		}

		selectedInputs = append(selectedInputs, TxInBuild{TxIn: txIn, PubKeyScript: utxo.PubKeyScript, PrivateKey: utxo.PrivateKey, Amount: int64(utxo.Value)})

		currentSize := baseSize + (len(selectedInputs) * 148)
		fee = currentSize * feeRate

		if accumulated >= amount+fee {
			change = accumulated - amount - fee
			if change > 0 {
				sizeWithChange := currentSize + 34
				feeWithChange := sizeWithChange * feeRate
				newChange := accumulated - amount - feeWithChange
				if newChange < 0 {
					change = 0
				} else {
					fee = feeWithChange
					change = newChange
				}
			}
			break
		}
	}

	if accumulated < amount+fee {
		return nil, 0, 0, fmt.Errorf(
			"insufficient funds: the balance is %d satoshi, but %d are needed (included fee of %d)",
			accumulated, amount+fee, fee,
		)
	}
	return selectedInputs, fee, change, nil
}

func (m *MempoolApi) GetInputs(amount int, addresses map[string]keymanager.Address) ([]TxInBuild, int, int, error) {
	pool, err := m.collectUTXOs(addresses)
	if err != nil {
		return nil, 0, 0, err
	}

	mempoolFees, err := m.GetRecommendedFees()
	if err != nil {
		return nil, 0, 0, fmt.Errorf("error fetching fees: %v", err)
	}
	return selectInputs(pool, amount, mempoolFees.FastestFee)
}

func (m *MempoolApi) BroadcastTransaction(tx *transactions.Tx) (string, error) {
	txHex := tx.SerializeHex()
	_, err := m.broadcastTransaction(txHex)
	if err != nil {
		return "", err
	}
	return tx.ComputeTxID(), nil
}

func (m *MempoolApi) BroadcastTransactionSegwit(tx *wire.MsgTx) (string, error) {
	var buf bytes.Buffer
	if err := tx.Serialize(&buf); err != nil {
		return "", fmt.Errorf("failed to serialize transaction: %v", err)
	}
	txHex := hex.EncodeToString(buf.Bytes())

	_, err := m.broadcastTransaction(txHex)
	if err != nil {
		return "", err
	}

	return tx.TxID(), nil
}

func (m *MempoolApi) broadcastTransaction(txHex string) (string, error) {
	reqUrl := fmt.Sprintf("%s/tx", MEMPOOLMAINURL)
	if m.testnet {
		reqUrl = fmt.Sprintf("%s/tx", MEMPOOLTESTURL)
	}

	resp, err := http.Post(reqUrl, "application/x-www-form-urlencoded", bytes.NewBufferString(txHex))
	if err != nil {
		return "", fmt.Errorf("failed to broadcast transaction: %w", err)
	}
	defer resp.Body.Close()

	bodyBytes, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", fmt.Errorf("failed to read response body: %w", err)
	}

	bodyStr := strings.TrimSpace(string(bodyBytes))

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return "", fmt.Errorf("broadcast failed (status %d): %s", resp.StatusCode, bodyStr)
	}

	if bodyStr != "" {
		return bodyStr, nil
	}

	return txHex, nil
}
