package types

import "fmt"

type PubKeyScript struct {
	Script     string
	ScriptType string
}

func (p *PubKeyScript) ToString() string {
	return fmt.Sprintf("PubKeyScript{script: %s, scriptType: %s}", p.Script, p.ScriptType)
}

type Utxo struct {
	TxId         string
	Vout         float64
	Value        int
	PubKeyScript PubKeyScript
}

type UtxoByValue []Utxo

func (u UtxoByValue) Len() int           { return len(u) }
func (u UtxoByValue) Swap(i, j int)      { u[i], u[j] = u[j], u[i] }
func (u UtxoByValue) Less(i, j int) bool { return u[i].Value > u[j].Value }

func (u *Utxo) ToString() string {
	return fmt.Sprintf("Utxo{txId: %s, vout: %g, value: %d, pubKeyScript: %s", u.TxId, u.Vout, u.Value, u.PubKeyScript.ToString())
}

type Fees struct {
	FastestFee  int `json:"fastestFee"`  // Alta priorità (prossimo blocco)
	HalfHourFee int `json:"halfHourFee"` // Media priorità
	HourFee     int `json:"hourFee"`     // Bassa priorità
	EconomyFee  int `json:"economyFee"`  // Economica
	MinimumFee  int `json:"minimumFee"`  // Minima assoluta per il relay
}
