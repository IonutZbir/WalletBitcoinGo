package api

import (
	keymanager "wallet-bitcoin/src/key_manager"
	"wallet-bitcoin/src/types"
)

type Api interface {
	GetUTXOSetForAddress(address keymanager.Address) ([]types.Utxo, error)
	GetTx(txId string) (map[string]interface{}, error)
	GetTxVout(txId string) ([]interface{}, error)
	GetRecommendedFees() (types.Fees, error)
	GetInputs(amount int, address keymanager.Address) ([]TxInBuild, int, int, error)
}
