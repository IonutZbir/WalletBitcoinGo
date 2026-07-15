package api

import (
	keymanager "wallet-bitcoin/src/key_manager"
	"wallet-bitcoin/src/types"
)

type BtcCoreApi struct{}

func (b *BtcCoreApi) GetUTXOSetForAddress(address keymanager.Address) ([]types.Utxo, error) {
	return nil, nil
}
func (b *BtcCoreApi) GetTx(txId string) (map[string]interface{}, error) {
	return nil, nil
}
func (b *BtcCoreApi) GetTxVout(txId string) ([]interface{}, error) {
	return nil, nil
}
func (b *BtcCoreApi) GetRecommendedFees() (types.Fees, error) {
	return types.Fees{}, nil
}
func (b *BtcCoreApi) GetInputs(amount int, address keymanager.Address) ([]TxInBuild, int, int, error) {
	return nil, 0, 0, nil
}
