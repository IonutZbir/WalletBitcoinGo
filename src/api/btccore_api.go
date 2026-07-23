package api

import (
	"net/http"
	keymanager "wallet-bitcoin/src/key_manager"
	"wallet-bitcoin/src/transactions"
	"wallet-bitcoin/src/types"
)

const (
	host = "160.80.216.209:8000/api/"
)

type BtcCoreApi struct {
	client *http.Client
}

func NewBtcCoreApi() *BtcCoreApi {
	client := &http.Client{}
	return &BtcCoreApi{client: client}
}

func (b *BtcCoreApi) GetTx(txId string) (map[string]interface{}, error) {
	return nil, nil
}

func (b *BtcCoreApi) GetUTXOSetForAddress(address keymanager.Address) ([]types.Utxo, error) {
	return nil, nil
}
func (b *BtcCoreApi) GetTxVout(txId string) ([]interface{}, error) {
	return nil, nil
}
func (b *BtcCoreApi) GetRecommendedFees() (types.Fees, error) {
	return types.Fees{}, nil
}
func (b *BtcCoreApi) GetInputs(amount int, addresses map[string]keymanager.Address) ([]TxInBuild, int, int, error) {
	return nil, 0, 0, nil
}

func (b *BtcCoreApi) BroadcastTransaction(tx *transactions.Tx) error {
	return nil
}

func (b *BtcCoreApi) ComputeBalanceForAddresses(addresses map[string]keymanager.Address) ([]Balance, error) {
	return nil, nil
}
