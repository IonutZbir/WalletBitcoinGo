package api

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"sort"
	keymanager "wallet-bitcoin/src/key_manager"
	"wallet-bitcoin/src/transactions"
	"wallet-bitcoin/src/types"
)

const MEMPOOLTESTURL = "https://mempool.space/testnet/api/"
const MEMPOOLTEST4URL = "https://mempool.space/testnet4/api/"

type MempoolApi struct{}

func (m *MempoolApi) GetTx(txId string) (map[string]interface{}, error) {
	// GET testnet/api/tx/:txid
	// TODO: refactor so this function returns a Tx data type instead of a map

	reqUrl := fmt.Sprintf("%stx/%s", MEMPOOLTESTURL, txId)

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
	reqUrl := fmt.Sprintf("%saddress/%s/utxo", MEMPOOLTESTURL, address.Address)

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
	reqUrl := fmt.Sprintf("%sv1/fees/recommended", MEMPOOLTEST4URL)

	fmt.Println(reqUrl)
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

func (m *MempoolApi) GetInputs(amount int, address keymanager.Address) ([]TxInBuild, int, int, error) {
	/*
		1. Per prima cosa recupero lo UTXO set per un dato indirizzo
		2. Recupero la fee (sat/vB) (interrogando Mempool o il Bitcoin Core)
		3. Stima della dimensione delle TX
		4. Per ogni UTXO, creo il relativo input e ne calcolo la dimensione.
		5. Si continua cosi finchè i fondi accumulati dalle UTXO non coprono l'intero importo.
		6. Se lo coprono, si controlla se c'e del resto, se il resto è troppo poco per permettere la creazione di un ulteriore output, allora lo si lascia come mancia per i miner, altrimenti si crea un secondo output e si ricalcolano le fee.
	*/
	utxos, err := m.GetUTXOSetForAddress(address)
	if err != nil {
		return nil, 0, 0, fmt.Errorf("could not fetch UTXO set for %s: %v", address.Address, err)
	}

	mempoolFees, err := m.GetRecommendedFees()
	if err != nil {
		return nil, 0, 0, fmt.Errorf("error fetching fees: %v", err)
	}
	feeRate := mempoolFees.FastestFee // sat/vB

	var selectedInputs []TxInBuild
	accumulated := 0
	fee := 0
	change := 0

	// Dimensione base della transazione: 10 byte (Header) + 34 byte (1 Output di destinazione) = 44 vBytes
	baseSize := 44

	for _, utxo := range utxos {
		accumulated += utxo.Value

		// Creiamo l'input grezzo per questa UTXO.
		// Sequence standard per transazioni finali: 0xffffffff
		txIn, err := transactions.NewTxIn(utxo.TxId, uint32(utxo.Vout), 0xffffffff)
		if err != nil {
			return nil, 0, 0, fmt.Errorf("errore creazione TxIn: %v", err)
		}
		selectedInputs = append(selectedInputs, TxInBuild{TxIn: txIn, PubKeyScript: utxo.PubKeyScript})

		// Calcolo dinamico: ogni input aggiunto pesa circa 148 vBytes
		currentSize := baseSize + (len(selectedInputs) * 148)
		fee = currentSize * feeRate

		// Controllo se i fondi accumulati coprono l'importo + la fee calcolata finora
		if accumulated >= amount+fee {
			change = accumulated - amount - fee

			// Se c'è un resto, dovremmo creare un Output di resto (altri 34 byte).
			// Ricalcoliamo la fee per vedere se possiamo permettercelo.
			if change > 0 {
				sizeWithChange := currentSize + 34
				feeWithChange := sizeWithChange * feeRate
				newChange := accumulated - amount - feeWithChange

				if newChange < 0 {
					// Aggiungere l'output di resto renderebbe i fondi insufficienti.
					// Rinunciamo al resto e lo lasciamo come mancia al miner.
					change = 0
				} else {
					// C'è abbastanza resto da poter creare un output di resto
					fee = feeWithChange
					change = newChange
				}
			}
			break
		}
	}

	if accumulated < amount+fee {
		return nil, 0, 0, fmt.Errorf("insufficient funds: the balance is %d satoshi, but %d are needed (included fee of %d)", accumulated, amount+fee, fee)
	}

	return selectedInputs, fee, change, nil
}

func (m *MempoolApi) BroadcastTransaction(tx *transactions.Tx) error {
	reqUrl := fmt.Sprintf("%s/tx", MEMPOOLTESTURL)
	_, err := http.Post(reqUrl, "application/x-www-form-urlencoded", bytes.NewBufferString(tx.SerializeHex()))
	if err != nil {
		return fmt.Errorf("failed to broadcast transaction: %v", err)
	}
	return nil
}
