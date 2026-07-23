package wallet


 func (w *Wallet) buildInputsSegwit(amount int, core bool, address keymanager.Address) ([]api.TxInBuild, int, int, error) {
 	if amount < 0 {
 		return nil, 0, 0, fmt.Errorf("amount must be > 0")
 	}

 	var (
 		inputs []api.TxInBuild
 		fee    int
 		change int
 		err    error
 	)
 	if core {
 		inputs, fee, change, err = w.BtcCoreApi.GetInputs(amount, address)
 	} else {
 		inputs, fee, change, err = w.MempoolApi.GetInputs(amount, address)
 	}
 	if err != nil {
 		return nil, 0, 0, err
 	}

// 	return inputs, fee, change, nil
// }

// func (w *Wallet) buildOutputsSegwit(amount int, change int, destAddr string, changeAddr keymanager.Address) ([]transactions.TxOut, error) {

// 	addrDestDecoded, err := btcutil.DecodeAddress(destAddr, &chaincfg.TestNet3Params)
// 	if err != nil {
// 		return nil, fmt.Errorf("could not decode the destination address: %v", err)
// 	}
// 	pkScript, err := txscript.PayToAddrScript(addrDestDecoded)
// 	if err != nil {
// 		return nil, fmt.Errorf("could not build destination pkScript: %v", err)
// 	}
// 	myOutput := transactions.NewTxOut(int64(amount), pkScript)

// 	addrChangeDecoded, err := btcutil.DecodeAddress(changeAddr.Address, &chaincfg.TestNet3Params)
// 	if err != nil {
// 		return nil, fmt.Errorf("could not decode the change address: %v", err)
// 	}
// 	pkScriptChange, err := txscript.PayToAddrScript(addrChangeDecoded)
// 	if err != nil {
// 		return nil, fmt.Errorf("could not build change pkScript: %v", err)
// 	}
// 	myOutputChange := transactions.NewTxOut(int64(change), pkScriptChange)

// 	return []transactions.TxOut{myOutput, myOutputChange}, nil
// }

// toWireMsgTx converts your custom Tx into a wire.MsgTx so txscript's
// BIP143 sighash machinery (which is hardwired to *wire.MsgTx) can be used.
// Assumes TxIn exposes PrevTxHash ([32]byte, big-endian as usually stored),
// PrevTxIndex (uint32) and Sequence (uint32), and TxOut exposes Value/PkScript.
// func toWireMsgTx(tx *transactions.Tx) (*wire.MsgTx, error) {
// 	msgTx := wire.NewMsgTx(2)

// 	for _, in := range tx.GetInputs() {
// 		previosTxHash := in.PreviousTxHash()
// 		hash, err := chainhash.NewHash(previosTxHash[:])
// 		if err != nil {
// 			return nil, fmt.Errorf("bad prev tx hash: %v", err)
// 		}
// 		previousTxIndex := in.PreviousTxIndex()
// 		outPoint := wire.NewOutPoint(hash, binary.BigEndian.Uint32(previousTxIndex[:]))
// 		txIn := wire.NewTxIn(outPoint, nil, nil)
// 		sequence := in.Sequence()
// 		txIn.Sequence = binary.BigEndian.Uint32(sequence[:])
// 		msgTx.AddTxIn(txIn)
// 	}

// 	for _, out := range tx.GetOutputs() {
// 		msgTx.AddTxOut(wire.NewTxOut(out.Value(), out.PkScript()))
// 	}

// 	return msgTx, nil
// }

// func (w *Wallet) signInputsSegwit(tx *transactions.Tx, inputsBuild []api.TxInBuild) error {
// 	msgTx, err := toWireMsgTx(tx)
// 	if err != nil {
// 		return fmt.Errorf("could not convert to wire.MsgTx: %v", err)
// 	}

// 	// Precompute the shared BIP143 hashes (hashPrevouts/hashSequence/hashOutputs) once.
// 	fetcher := txscript.NewMultiPrevOutFetcher(nil)
// 	for i, in := range inputsBuild {
// 		prevScriptPubKey, err := hex.DecodeString(in.PubKeyScript.Script)
// 		if err != nil {
// 			return fmt.Errorf("cannot decode prevScriptPubKey for input %d: %v", i, err)
// 		}
// 		fetcher.AddPrevOut(msgTx.TxIn[i].PreviousOutPoint, wire.NewTxOut(int64(in.Amount), prevScriptPubKey))
// 	}
// 	sigHashes := txscript.NewTxSigHashes(msgTx, fetcher)

// 	for i, in := range inputsBuild {
// 		prevScriptPubKey, err := hex.DecodeString(in.PubKeyScript.Script)
// 		if err != nil {
// 			return fmt.Errorf("cannot decode prevScriptPubKey for input %d: %v", i, err)
// 		}

// 		pubKeyHash := prevScriptPubKey[2:] // strip OP_0 <push>
// 		witnessScript, err := txscript.NewScriptBuilder().
// 			AddOp(txscript.OP_DUP).
// 			AddOp(txscript.OP_HASH160).
// 			AddData(pubKeyHash).
// 			AddOp(txscript.OP_EQUALVERIFY).
// 			AddOp(txscript.OP_CHECKSIG).
// 			Script()
// 		if err != nil {
// 			return fmt.Errorf("could not build witness script for input %d: %v", i, err)
// 		}

// 		witness, err := txscript.RawTxInWitnessSignature(
// 			msgTx, sigHashes, i, int64(in.Amount), witnessScript,
// 			txscript.SigHashAll, ,
// 		)
// 		if err != nil {
// 			return fmt.Errorf("could not sign input %d: %v", i, err)
// 		}

// 		msgTx.TxIn[i].Witness = witness
// 		tx.SetWitness(i, witness)
// 	}

// 	return nil
// }

// func (w *Wallet) SendSegwit(amount int64, sourceAddr string, destAddr string, core bool) error {
// 	inputsBuild, _, change, err := w.buildInputsSegwit(amount, core, w.Addresses[sourceAddr])
// 	if err != nil {
// 		return fmt.Errorf("could not get inputs: %v", err)
// 	}

// 	outputs, err := w.buildOutputsSegwit(amount, change, destAddr, w.Addresses[sourceAddr])
// 	if err != nil {
// 		return fmt.Errorf("could not build outputs: %v", err)
// 	}

// 	inputs := api.ExtractTxIns(inputsBuild)

// 	tx := transactions.NewTx(inputs, outputs)
// 	// for every address, i need to get the relative private key
// 	err = w.signInputsSegwit(&tx, inputsBuild, w.Addresses[sourceAddr].SigningKey)
// 	if err != nil {
// 		return err
// 	}

// 	err = w.MempoolApi.BroadcastTransaction(&tx)
// 	if err != nil {
// 		return err
// 	}
// 	fmt.Println("Transaction broadcasted successfully")
// 	return nil
