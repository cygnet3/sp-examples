#![allow(dead_code, non_snake_case)]
use bdk::{
    bitcoin::{
        hashes::{sha256, Hash},
        schnorr::{TweakedPublicKey, UntweakedPublicKey},
        secp256k1::{PublicKey, Scalar, Secp256k1, SecretKey},
        util::bip32::{DerivationPath, ExtendedPrivKey},
        Address, KeyPair, OutPoint, PrivateKey, Txid,
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
    let key_derivation_path = "m/84'/1'/0'/0/2";
    let txid = "33fb23469ea1add4e0a86407a7bde88f57eeeb48490a92d035211273bb3a3d8c";
    let vout = 0;

    // get sender
    let alice = create_sender_keypair(key_derivation_path);

    // get recipient
    let bob = create_sp_receiver();

    // test sending
    //input used
    sending_get_address(alice, &bob, txid, vout);

    // sender now sends to this taproot address, broadcasts transaction
    // txid for sent transaction:
    let txid = "41a9fb95b522e50ef9e0d3680d7fe851cf16ae99c37a721e8217307d9b6945ca";

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
    let p2tr_address = get_p2tr(output_for_bob);
    eprintln!("p2tr address = {:?}", p2tr_address);

    let scriptpubkey = p2tr_address.script_pubkey();
    eprintln!("scriptpubkey in this address = {:?}", scriptpubkey);
}

fn receiving_discover_private_key(alice: KeyPair, bob: Receiver, txid: &str) {
    let A_sum = alice.public_key();
    let outpoints_hash: Scalar = lookup_tx_and_get_outpoints_hash(txid);

    let recipient_tweak_data = calculate_tweak_data_for_recipient(A_sum, outpoints_hash);

    let taproot_output = bob
        .get_taproot_output_from_tweak_data(&recipient_tweak_data, 0)
        .unwrap();

    // look for outputs that belong to this recipient from a list of outputs (of length 1)
    let keys_found = bob
        .scan_transaction(&recipient_tweak_data, vec![taproot_output])
        .unwrap();

    // 1 key is found
    let found_key = keys_found.into_iter().next().unwrap();

    // this can be used to spend the received outpoint
    let privkey: PrivateKey = PrivateKey::new(found_key, bdk::bitcoin::Network::Signet);

    let rawtr = format!("rawtr({})", privkey.to_wif());
    let checksum = calc_checksum(&rawtr).unwrap();

    eprintln!("descriptor: {}#{}", rawtr, checksum);
}

fn lookup_tx_and_get_outpoints_hash(txid: &str) -> Scalar {
    let client = Client::new("ssl://node202.fra.mempool.space:60602").unwrap();
    let blockchain = ElectrumBlockchain::from(client);

    let txid = Txid::from_str(txid).unwrap();
    let mut tx = blockchain.get_tx(&txid).unwrap().unwrap();

    TxOrdering::Bip69Lexicographic.sort_tx(&mut tx);

    let outpoints: Vec<OutPoint> = tx.input.into_iter().map(|x| x.previous_output).collect();

    let outpoints_hash = hash_outpoints(&outpoints);

    outpoints_hash
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

fn get_p2tr(key: UntweakedPublicKey) -> Address {
    let assumetweaked = TweakedPublicKey::dangerous_assume_tweaked(key);

    Address::p2tr_tweaked(assumetweaked, bdk::bitcoin::Network::Signet)
    // Address::p2tr(&secp, key, None, bdk::bitcoin::Network::Signet)
}

fn hash_outpoints(sending_data: &Vec<OutPoint>) -> Scalar {
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

fn calculate_tweak_data_for_recipient(A_sum: PublicKey, outpoints_hash: Scalar) -> PublicKey {
    let secp = Secp256k1::new();

    A_sum.mul_tweak(&secp, &outpoints_hash).unwrap()
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
