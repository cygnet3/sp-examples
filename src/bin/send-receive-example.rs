#![allow(dead_code, non_snake_case)]
use bdk::{
    bitcoin::{
        hashes::{sha256, Hash},
        schnorr::{TweakedPublicKey, UntweakedPublicKey},
        secp256k1::{PublicKey, Scalar, Secp256k1, SecretKey},
        util::bip32::{DerivationPath, ExtendedPrivKey},
        Address, KeyPair, OutPoint, PrivateKey, Transaction, Txid, XOnlyPublicKey,
    },
    blockchain::{ElectrumBlockchain, GetTx},
    descriptor::calc_checksum,
    electrum_client::Client,
    wallet::tx_builder::TxOrdering,
};
use serde::Deserialize;
use silentpayments::{
    receiving::Receiver,
    sending::{decode_scan_pubkey, generate_recipient_pubkey},
};
use std::{fs::File, io::Write, str::FromStr};

const IS_TESTNET: bool = true;

fn main() {
    // info from transaction to be spent
    let key_derivation_path = "m/84'/1'/0'/0/3";
    let txid = "28b6bd261af76ac1b089fc10ad6e7d020ae01273ab0fd1a9fccf81c92a61744c";
    let vout = 1;

    // get sender
    let alice = create_sender_keypair(key_derivation_path);

    // get recipient
    let bob = create_sp_receiver();

    // print address to send to
    sending_get_address(alice, &bob, txid, vout);

    // sender now sends to this taproot address, broadcasts transaction
    // txid for sent transaction:
    let txid = "df141f1c5af033f73eaf63010d85ef9b76f9dff35da61c483ecbe38d93dedd9c";

    // test receiving
    receiving_discover_private_key(alice, bob, txid);
}

fn sending_get_address(alice: KeyPair, bob: &Receiver, txid: &str, vout: u32) {
    let a_sum = alice.secret_key();
    let sp_address_to_be_paid = bob.get_receiving_address();
    let B_scan = decode_scan_pubkey(&sp_address_to_be_paid).unwrap();
    let outpoints_hash = hash_outpoints_used_in_input(txid, vout);

    let ecdh_shared_secret = sender_calculate_shared_secret(a_sum, B_scan, outpoints_hash);

    let output_for_bob =
        generate_recipient_pubkey(sp_address_to_be_paid, ecdh_shared_secret).unwrap();

    // this address can be paid to by the sender
    let p2tr_address = get_address(output_for_bob);
    eprintln!("p2tr address: {:?}", p2tr_address);

    let scriptpubkey = p2tr_address.script_pubkey();
    eprintln!("scriptpubkey in this address: {:?}", scriptpubkey);
}

fn receiving_discover_private_key(alice: KeyPair, bob: Receiver, txid: &str) {
    let tx = lookup_tx(&txid);

    let A_sum = get_A_sum_from_tx(&tx);
    assert_eq!(A_sum, alice.public_key());

    let outpoints_hash = get_outpoints_hash(tx);

    let secp = Secp256k1::new();
    let tweak_data = A_sum.mul_tweak(&secp, &outpoints_hash).unwrap();

    println!("expected tweak data: {}", tweak_data);

    let script_bytes = bob
        .get_script_bytes_from_tweak_data(&tweak_data, 0)
        .unwrap();
    let taproot_output_bytes = &script_bytes[2..];

    let taproot_output = XOnlyPublicKey::from_slice(taproot_output_bytes).unwrap();

    // look for outputs that belong to this recipient from a list of outputs (of length 1)
    let keys_found = bob
        .scan_transaction(&tweak_data, vec![taproot_output])
        .unwrap();

    // 1 key is found
    let found_key = keys_found.into_iter().next().unwrap();

    // this can be used to spend the received outpoint
    let privkey: PrivateKey = PrivateKey::new(found_key, bdk::bitcoin::Network::Signet);

    let rawtr = format!("rawtr({})", privkey.to_wif());
    let checksum = calc_checksum(&rawtr).unwrap();

    eprintln!("descriptor: {}#{}", rawtr, checksum);
}

fn lookup_tx(txid: &str) -> Transaction {
    let client = Client::new("ssl://node202.fra.mempool.space:60602").unwrap();
    let blockchain = ElectrumBlockchain::from(client);

    let txid = Txid::from_str(txid).unwrap();
    let tx = blockchain.get_tx(&txid).unwrap().unwrap();

    tx
}

#[derive(Deserialize, Debug)]
struct PersonWithKey {
    fingerprint: String,
    mnemonic: String,
    xprv: String,
}

fn create_sender_keypair(key_derivation_path: &str) -> KeyPair {
    let secp = Secp256k1::new();

    let alice: PersonWithKey =
        serde_json::from_reader(File::open("alice-key.json").unwrap()).unwrap();
    let alice_root_xprv: ExtendedPrivKey = ExtendedPrivKey::from_str(&alice.xprv).unwrap();

    let derivation_path: DerivationPath = DerivationPath::from_str(key_derivation_path).unwrap();

    let alice_keypair = alice_root_xprv
        .derive_priv(&secp, &derivation_path)
        .unwrap()
        .to_keypair(&secp);

    alice_keypair
}

fn create_sp_receiver() -> Receiver {
    let bob: PersonWithKey = serde_json::from_reader(File::open("bob-key.json").unwrap()).unwrap();

    let bob_root_xprv: ExtendedPrivKey = ExtendedPrivKey::from_str(&bob.xprv).unwrap();

    let (scan_path, spend_path) = match IS_TESTNET {
        true => ("m/352h/1h/0h/1h/0", "m/352h/1h/0h/0h/0"),
        false => ("m/352h/0h/0h/1h/0", "m/352h/0h/0h/0h/0"),
    };

    let scan_path: DerivationPath = DerivationPath::from_str(scan_path).unwrap();
    let spend_path: DerivationPath = DerivationPath::from_str(spend_path).unwrap();
    let secp = Secp256k1::new();
    let bob_scan_key = bob_root_xprv
        .derive_priv(&secp, &scan_path)
        .unwrap()
        .private_key;
    let bob_spend_key = bob_root_xprv
        .derive_priv(&secp, &spend_path)
        .unwrap()
        .private_key;
    let bob = Receiver::new(0, bob_scan_key, bob_spend_key, IS_TESTNET).unwrap();

    bob
}

fn get_address(key: UntweakedPublicKey) -> Address {
    let assumetweaked = TweakedPublicKey::dangerous_assume_tweaked(key);

    Address::p2tr_tweaked(assumetweaked, bdk::bitcoin::Network::Signet)
    // Address::p2tr(&secp, key, None, bdk::bitcoin::Network::Signet)
}

fn get_outpoints_hash(mut tx: Transaction) -> Scalar {
    TxOrdering::Bip69Lexicographic.sort_tx(&mut tx);

    let sending_data: Vec<OutPoint> = tx.input.into_iter().map(|x| x.previous_output).collect();

    let mut outpoints: Vec<Vec<u8>> = vec![];
    for outpoint in sending_data {
        let txid: [u8; 32] = outpoint.txid.into_inner();
        let vout: u32 = outpoint.vout;

        let mut bytes: Vec<u8> = Vec::new();
        bytes.extend_from_slice(&txid);
        bytes.extend_from_slice(&vout.to_le_bytes());
        outpoints.push(bytes);
    }
    outpoints.sort();

    let mut engine = sha256::HashEngine::default();

    for v in outpoints {
        engine.write_all(&v).unwrap();
    }

    Scalar::from_be_bytes(sha256::Hash::from_engine(engine).into_inner()).unwrap()
}

fn get_A_sum_from_tx(tx: &Transaction) -> PublicKey {
    let inputs = &tx.input;

    if inputs.len() != 1 {
        panic!("Only allow tx with 1 p2wpkh input");
    }

    let input = inputs[0].clone();

    let is_p2wpkh = input.script_sig.is_empty()
        && input.witness.len() == 2
        && PublicKey::from_slice(input.witness.last().unwrap()).is_ok();

    if !is_p2wpkh {
        panic!("not p2wpkh");
    }

    let pk = PublicKey::from_slice(input.witness.last().unwrap()).unwrap();

    pk
}

fn hash_outpoints_used_in_input(txid: &str, vout: u32) -> Scalar {
    let mut outpoints: Vec<Vec<u8>> = vec![];

    let txid: [u8; 32] = hex::decode(txid).unwrap().try_into().unwrap();

    let sending_data: Vec<([u8; 32], u32)> = vec![(txid, vout)];

    for outpoint in sending_data {
        let txid = outpoint.0;
        let vout = outpoint.1;

        let mut bytes: Vec<u8> = Vec::new();
        bytes.extend_from_slice(&txid);
        bytes.reverse();
        bytes.extend_from_slice(&vout.to_le_bytes());
        outpoints.push(bytes);
    }
    outpoints.sort();

    let mut engine = sha256::HashEngine::default();

    for v in outpoints {
        engine.write_all(&v).unwrap();
    }

    Scalar::from_be_bytes(sha256::Hash::from_engine(engine).into_inner()).unwrap()
}

fn sender_calculate_shared_secret(
    a_sum: SecretKey,
    B_scan: PublicKey,
    outpoints_hash: Scalar,
) -> PublicKey {
    let secp = Secp256k1::new();

    let diffie_hellman = B_scan.mul_tweak(&secp, &a_sum.into()).unwrap();
    diffie_hellman.mul_tweak(&secp, &outpoints_hash).unwrap()
}
