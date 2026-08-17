# WalletBitcoinGo

## 1. Introduzione

Bitcoin Wallet in Go è un progetto sviluppato per l'esame di *Principles of Cryptocurrency Design*. 
L'obiettivo è realizzare da zero un wallet Bitcoin modulare in Golang, coprendo l'intero ciclo di vita di un pagamento: dalla generazione sicura delle chiavi e degli indirizzi, alla costruzione e firma crittografica delle transazioni legacy e segwit, fino all'integrazione con un nodo Bitcoin locale per il broadcast e la conferma su blockchain.

## 2. Architettura

Il wallet Bitcoin in Go è organizzato in un'architettura modulare, con componenti separati per le varie funzionalità. Come possiamo vedere dall'albero del progetto, le principali componenti sono:

- `api`: contiene le interfacce e le implementazioni per le API di Bitcoin Core e Mempool.
- `key_manager`: gestisce la generazione e la gestione delle chiavi e degli indirizzi Bitcoin. Implementa gli standard BIP32 e BIP39.
- `transactions`: contiene le strutture e le funzioni per la costruzione e la firma delle transazioni. Implementa da zero le transazioni legacy `p2pkh` e utilizzando librerie esterne come `github.com/btcsuite/btcd/btcec` implementa le transazioni segwit `p2wpkh`.
- `wallet`: contiene la logica principale del wallet, come la gestione dello stato, il broadcast delle transazioni e l'integrazione con le API.

```bash
├── build.sh
├── go.mod
├── go.sum
├── main.go
├── README.md
└── src
    ├── api
    │   ├── btccore_api.go
    │   └── mempool_api.go
    ├── key_manager
    │   ├── bip32.go
    │   ├── bip39.go
    │   ├── key_manager.go
    │   └── wordlists
    │       ├── english.txt
    │       └── italian.txt
    ├── transactions
    │   ├── legacy_transaction.go
    │   ├── tx_input.go
    │   └── tx_output.go
    ├── types
    │   └── types.go
    ├── utils
    │   └── utils.go
    └── wallet
        ├── backup.go
        ├── legacy.go
        ├── segwit.go
        ├── storage.go
        └── wallet.go
```

## 3. Utilizzo

**Prerequisiti**

- Go (versione 1.26 o superiore)

Compilare il progetto eseguendo il comando `./build.sh`. L'eseguibile generato si troverà nella directory `build/`.
Eseguire `./build/wallet -help` per visualizzare l'elenco dei comandi disponibili.


**Esempi**

```bash
wallet -action new          -wallet mywallet -password secret -testnet
wallet -action load         -wallet mywallet -password secret -testnet
wallet -action send-segwit  -wallet mywallet -password secret -amount 0.05 -dest tb1q...
wallet -action export       -wallet mywallet -password secret -type json
wallet -action import       -wallet mywallet -password secret -file <path_to_file>
```
