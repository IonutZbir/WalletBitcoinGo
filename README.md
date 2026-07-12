# Wallet Bitcoin Go

Repository contenente il progetto per l'esame di Principles of Cryptocurrency Design.

L'obiettivo del progetto è quello di progettare un wallet Bitcoin in Golang da zero. I principali problemi da affrontare sono sicuramente la gestione e la generazione delle chiavi private e degli indirizzi Bitcoin, la generazione di transazioni e infine la connessione con il nodo Bitcoin per permettere di inserire la transazione nella blockchain.

- https://pkg.go.dev/github.com/btcsuite/btcutil
- https://github.com/btcsuite/btcd

## 1. Chiavi Private e Derivazione Indirizzi Bitcoin

Generazione e memorizzazione della chiave privata master. Per questa sezione si farà riferimento a:

- https://github.com/iancoleman/bip39
- https://github.com/bitcoin/bips/tree/master/bip-0039 - https://github.com/bitcoin/bips/blob/master/bip-0039.mediawiki
- https://github.com/bitcoin/bips/tree/master/bip-0032 - https://github.com/bitcoin/bips/blob/master/bip-0032.mediawiki
- https://www.secg.org/sec2-v2.pdf

La generazione di chiavi private Bitcoin secondo gli standard BIP prevede la creazione di una frase seed composta da 12 o 24 parole (BIP39), il suo inserimento in un generatore di chiavi master (BIP32) e la derivazione di indirizzi specifici.

## 2. Memorizzazione su Disco

## 3. Generazione Transazioni

- https://github.com/bitcoin/bips/blob/master/bip-0141.mediawiki
- https://github.com/bitcoin/bips/blob/master/bip-0143.mediawiki
- https://github.com/bitcoin/bips/blob/master/bip-0144.mediawiki

## 4. Inserimento su Blockchain e Collegamento al Nodo

## Scenario consigliato: nodo per tutto, mempool.space solo come "vista"/backup

Il tuo nodo Bitcoin Core via RPC può fare **tutto** quello che ti serve per il wallet:

| Operazione | RPC method |
|---|---|
| Query UTXO di un indirizzo | `scantxoutset` (se non hai `-txindex`) o `listunspent` (se è wallet-aware) |
| Fee estimation | `estimatesmartfee <conf_target>` |
| Broadcast | `sendrawtransaction "<hex>"` |
| Verifica conferma | `gettransaction` / `getrawtransaction` con verbose |
| Stato mempool | `getmempoolentry <txid>` |

Se il tuo nodo **non ha `-txindex=1`** attivo, `scantxoutset` per recuperare UTXO di un indirizzo arbitrario è lento (scansiona tutto l'UTXO set on-demand). In quel caso mempool.space API è comodo come **complemento** solo per le query di UTXO/address history, mantenendo il tuo nodo per broadcast e fee estimation (dati più affidabili/diretti, zero terze parti nel path critico).

## Setup ibrido pratico per il tuo wallet Go

```
┌─────────────────────────────────────┐
│         Wallet Go                    │
├───────────────┬───────────────────────┤
│  Query UTXO    │  mempool.space API    │  (comodo, indicizzato, veloce)
│  (address→utxo)│  GET /api/address/{a}/utxo
├───────────────┼───────────────────────┤
│  Fee estimate  │  tuo nodo RPC         │  (dato diretto dalla tua mempool)
│                │  estimatesmartfee     │
├───────────────┼───────────────────────┤
│  Broadcast tx  │  tuo nodo RPC         │  (privacy: non esponi la tx
│                │  sendrawtransaction   │   a un servizio terzo prima
│                │                       │   che sia in mempool)
└───────────────┴───────────────────────┘
```

**Perché il broadcast dal tuo nodo e non da mempool.space?** Se trasmetti tramite un'API terza, quel servizio "vede" la tua transazione (e quindi il tuo indirizzo/pattern di spesa) prima ancora che sia sulla rete P2P. Se hai un nodo tuo, ha più senso fare `sendrawtransaction` direttamente lì — nessuna fuga di privacy verso terzi, e la tx entra comunque nella rete P2P globale.

## In Go, per l'RPC verso il tuo nodo

```go
import "github.com/btcsuite/btcd/rpcclient"

connCfg := &rpcclient.ConnConfig{
    Host:         "127.0.0.1:8332",
    User:         "tuouser",
    Pass:         "tuapassword",
    HTTPPostMode: true,
    DisableTLS:   true, // solo se locale/rete fidata
}
client, err := rpcclient.New(connCfg, nil)
```

```go
package broadcast

import (
    "fmt"
    "github.com/btcsuite/btcd/btcutil"
    "github.com/btcsuite/btcd/chaincfg/chainhash"
    "github.com/btcsuite/btcd/rpcclient"
    "github.com/btcsuite/btcd/wire"
)

func BroadcastViaNode(client *rpcclient.Client, rawTxHex string) (*chainhash.Hash, error) {
    txBytes, err := hex.DecodeString(rawTxHex)
    if err != nil {
        return nil, fmt.Errorf("decode hex: %w", err)
    }

    var msgTx wire.MsgTx
    if err := msgTx.Deserialize(bytes.NewReader(txBytes)); err != nil {
        return nil, fmt.Errorf("deserialize tx: %w", err)
    }

    txHash, err := client.SendRawTransaction(&msgTx, false) // false = non permettere high fees senza check
    if err != nil {
        return nil, fmt.Errorf("sendrawtransaction: %w", err)
    }

    return txHash, nil
}
```

```go
package broadcast

import (
    "bytes"
    "fmt"
    "io"
    "net/http"
)

func BroadcastViaMempoolSpace(rawTxHex string, testnet bool) (string, error) {
    baseURL := "https://mempool.space/api/tx"
    if testnet {
        baseURL = "https://mempool.space/testnet/api/tx"
    }

    resp, err := http.Post(baseURL, "text/plain", bytes.NewBufferString(rawTxHex))
    if err != nil {
        return "", fmt.Errorf("http post: %w", err)
    }
    defer resp.Body.Close()

    body, err := io.ReadAll(resp.Body)
    if err != nil {
        return "", fmt.Errorf("read response: %w", err)
    }

    if resp.StatusCode != http.StatusOK {
        return "", fmt.Errorf("mempool.space rejected tx (status %d): %s", resp.StatusCode, string(body))
    }

    // mempool.space risponde col txid in plain text nel body
    return string(body), nil
}
```

```go
func BroadcastToBoth(nodeClient *rpcclient.Client, rawTxHex string, testnet bool) {
    var wg sync.WaitGroup
    wg.Add(2)

    var nodeTxHash *chainhash.Hash
    var nodeErr error
    var mempoolTxID string
    var mempoolErr error

    go func() {
        defer wg.Done()
        nodeTxHash, nodeErr = BroadcastViaNode(nodeClient, rawTxHex)
    }()

    go func() {
        defer wg.Done()
        mempoolTxID, mempoolErr = BroadcastViaMempoolSpace(rawTxHex, testnet)
    }()

    wg.Wait()

    if nodeErr != nil {
        fmt.Printf("⚠️  Nodo fallito: %v\n", nodeErr)
    } else {
        fmt.Printf("✅ Nodo: txid = %s\n", nodeTxHash.String())
    }

    if mempoolErr != nil {
        fmt.Printf("⚠️  mempool.space fallito: %v\n", mempoolErr)
    } else {
        fmt.Printf("✅ mempool.space: txid = %s\n", mempoolTxID)
    }
}
```

Una volta costruita e firmata la transazione (serializzata in formato hex), va **trasmessa alla rete** perché possa essere inclusa in un blocco. Bitcoin non ha un endpoint centrale "giusto" a cui inviare: basta raggiungere un nodo ben connesso che la ripropaghi ai suoi peer (gossip P2P), finché non arriva ai miner.

## Perché usare sia il nodo che mempool.space

Avendo a disposizione un nodo Bitcoin Core proprio, ha senso usarlo come canale principale di broadcast (`sendrawtransaction` via RPC), e aggiungere mempool.space come canale secondario/ridondante. Vantaggi di questo approccio ibrido:

- **Ridondanza**: se un canale è temporaneamente irraggiungibile, l'altro garantisce comunque la propagazione
- **Verifica incrociata**: entrambe le fonti dovrebbero restituire lo stesso `txid` (essendo deterministico dall'hash della tx) — utile come sanity check in fase di sviluppo
- **Privacy**: broadcastare prima dal proprio nodo evita di esporre la transazione a un servizio terzo prima che sia effettivamente in rete; mempool.space resta un fallback/conferma

## Nota pratica

Se si invia a entrambi i canali, è normale che il secondo tentativo risponda con un errore tipo *"transazione già nota"* (es. `txn-already-known`) — non è un fallimento reale, ma la conseguenza attesa del fatto che la tx è già stata propagata dal primo canale. Va gestito come caso non critico, non come errore vero.

## Riepilogo endpoint utili

| Azione | Nodo (RPC) | mempool.space (REST) |
|---|---|---|
| Broadcast | `sendrawtransaction` | `POST /api/tx` |
| Verifica conferma | `gettransaction` | `GET /api/tx/{txid}` |
| Stato mempool | `getmempoolentry` | (dashboard pubblica) |

## RIASSUNTO

1. Genera/importa mnemonic (BIP39) → seed
2. Deriva master key (BIP32)
3. Deriva account key m/84'/0'/0', poi un paio di indirizzi fissi (indice 0, 1)
4. Mostra gli indirizzi all'utente ("manda fondi qui per testare")
5. Query al nodo: quali UTXO ci sono su questi indirizzi? (listunspent o scantxoutset)
6. L'utente specifica: destinatario + importo
7. Costruisci tx (seleziona UTXO semplice, calcola resto)
8. Firma con BIP143
9. sendrawtransaction al nodo