#![allow(dead_code, non_snake_case)]
use std::{collections::HashMap, fs::File, net, str::FromStr, thread};

use bdk::bitcoin::{
    schnorr::TweakedPublicKey,
    secp256k1::{PublicKey, Secp256k1},
    util::{
        address::Payload,
        bip32::{DerivationPath, ExtendedPrivKey},
    },
    BlockHash, PrivateKey, Script, Transaction, TxOut, XOnlyPublicKey,
};
use nakamoto::{
    chain::filter::BlockFilter,
    client::{self, traits::Handle, Client, Config, Error, Network},
    common::network::Services,
    net::poll::Waker,
};
use serde::Deserialize;
use silentpayments::receiving::Receiver;

type Reactor = nakamoto::net::poll::Reactor<net::TcpStream>;

const IS_TESTNET: bool = true;
const TWEAK_DATA: &str = "026c8937d05d974a43443e2817b696055cdfc309a2b28b8661dcde150c2c17f0b7";

fn main() -> Result<(), Error> {
    // uncomment for showing nakamoto log output
    // env_logger::init();

    // create sp receiver using rust-silentpayments
    let bob = create_sp_receiver();

    // create handle for interacting with the light client
    let handle = start_nakamoto_client_and_get_handle()?;

    // get channels from which we get the result of our filter/block requests
    let filterchannel = handle.filters();
    let blkchannel = handle.blocks();

    // Wait for the client to be connected to a peer.
    handle.wait_for_peers(1, Services::default())?;

    // we will scan only 1 block
    // we know there is a match in block 158650
    let block_to_scan = 159658;

    // the tweak data provided for this block
    // should get this from some source like the bitcoin core index thingy
    let tweak_data_vec = get_tx_tweak_data();

    // request filter for just 1 block (we know there's a match in here)
    handle.request_filters(block_to_scan..=block_to_scan)?;

    // get filter, hash and height from channel
    let (blkfilter, blkhash, blkheight) = filterchannel.recv()?;

    println!("looking for match in block {}", blkheight);

    // calculate map of script pubkeys to their tweak data
    let mut scriptpubkeysmap = calculate_script_pubkeys(tweak_data_vec, &bob);

    // search for script pubkeys in the block filter
    let found = search_filter_for_script_pubkeys(
        scriptpubkeysmap.keys().cloned().collect(),
        blkfilter,
        blkhash,
    );

    if !found {
        println!("no match in this block found");
        return Ok(());
    }

    println!("match found! downloading full block");

    // request full block
    handle.request_block(&blkhash)?;
    let (blk, _) = blkchannel.recv().unwrap();

    // loop over all transactions in block
    for (i, tx) in blk.txdata.into_iter().enumerate() {
        println!("-- transaction {} --", i);

        // we first look if this tx is an 'eligible' sp transaction
        if !is_eligible_sp_transaction(&tx) {
            println!("not a valid tx");
            continue;
        }

        // collect all taproot scripts from transaction
        let (tweak_data, taproot_scripts) = get_tx_data(tx.output, &mut scriptpubkeysmap);

        // if we found the simplest case (n=0), at least 1 output belongs to us
        // we should look for outputs n>0
        if let Some(tweak_data) = tweak_data {
            let outputs = get_outputs(&bob, &tweak_data, taproot_scripts);

            let privkeys = bob.scan_transaction(&tweak_data, outputs).unwrap();
            for sk in privkeys {
                let key = PrivateKey::new(sk, bdk::bitcoin::Network::Signet);

                println!(
                    "!!! Secret key for spendable script found: {}",
                    key.to_wif()
                );
            }
        }
    }

    handle.shutdown()?;

    Ok(())
}

fn get_outputs(
    bob: &Receiver,
    tweak_data: &PublicKey,
    taproot_scripts: Vec<Script>,
) -> Vec<XOnlyPublicKey> {
    let mut outputs: Vec<XOnlyPublicKey> = vec![];
    let mut n = 0; // this can be optimized if we remember n=0

    loop {
        let taproot_output = bob
            .get_taproot_output_from_tweak_data(tweak_data, n)
            .unwrap();

        let assumetweaked = TweakedPublicKey::dangerous_assume_tweaked(taproot_output);
        let scriptpubkey = Payload::p2tr_tweaked(assumetweaked).script_pubkey();

        // this output has a script that is present in the transaction, add it to list
        if taproot_scripts.contains(&scriptpubkey) {
            outputs.push(taproot_output);
            n += 1;
        } else {
            // if no match, stop looking
            break;
        }
    }

    outputs
}

#[derive(Deserialize, Debug)]
struct PersonWithKey {
    fingerprint: String,
    mnemonic: String,
    xprv: String,
}

fn get_tx_data(
    output: Vec<TxOut>,
    map: &mut HashMap<Script, PublicKey>,
) -> (Option<PublicKey>, Vec<Script>) {
    let mut tweak_data = None;
    let taproot_scripts: Vec<Script> = output
        .into_iter()
        .filter_map(|x| {
            let script = x.script_pubkey;

            if let Some(given_tweak_data) = map.remove(&script) {
                println!("found taproot output that definitely belongs to us");
                tweak_data = Some(given_tweak_data);
                Some(script)
            } else if script.is_v1_p2tr() {
                println!("found taproot output script");
                Some(script)
            } else {
                println!("found non-taproot output script");
                None
            }
        })
        .collect();

    (tweak_data, taproot_scripts)
}

fn calculate_script_pubkeys(
    tweak_data_vec: Vec<PublicKey>,
    bob: &Receiver,
) -> HashMap<Script, PublicKey> {
    let mut res = HashMap::new();

    for tweak_data in tweak_data_vec {
        // using sp lib to get taproot output
        // we only need to look for the case n=0, we can look for the others if this matches
        let taproot_output = bob
            .get_taproot_output_from_tweak_data(&tweak_data, 0)
            .unwrap();

        // convert taproot output to scriptpubkey
        let assumetweaked = TweakedPublicKey::dangerous_assume_tweaked(taproot_output);
        let scriptpubkey = Payload::p2tr_tweaked(assumetweaked).script_pubkey();

        res.insert(scriptpubkey, tweak_data);
    }

    res
}

fn search_filter_for_script_pubkeys(
    scriptpubkeys: Vec<Script>,
    blkfilter: BlockFilter,
    blkhash: BlockHash,
) -> bool {
    // get bytes of every script
    let script_bytes: Vec<Vec<u8>> = scriptpubkeys.into_iter().map(|x| x.to_bytes()).collect();

    // the query for nakamoto filters is a iterator over the script byte slices
    let mut query = script_bytes.iter().map(|x| x.as_slice());

    // match our query against the block filter
    let found = blkfilter.match_any(&blkhash, &mut query).unwrap();

    found
}

fn start_nakamoto_client_and_get_handle() -> Result<client::Handle<Waker>, Error> {
    let cfg = Config::new(Network::Signet);

    // Create a client using the above network reactor.
    let client = Client::<Reactor>::new()?;
    let handle = client.handle();

    // Run the client on a different thread, to not block the main thread.
    thread::spawn(|| client.run(cfg).unwrap());

    Ok(handle)
}

fn is_eligible_sp_transaction(tx: &Transaction) -> bool {
    let outputs = &tx.output;

    // we check if the output has a taproot output
    let valid_outputs = outputs.iter().any(|x| x.script_pubkey.is_v1_p2tr());

    valid_outputs
}

// there's only 1 sp-transaction in this block
fn get_tx_tweak_data() -> Vec<PublicKey> {
    vec![PublicKey::from_str(TWEAK_DATA).unwrap()]
}

fn create_sp_receiver() -> Receiver {
    let bob: PersonWithKey = serde_json::from_reader(File::open("bob-key.json").unwrap()).unwrap();

    let bob_root_xprv: ExtendedPrivKey = ExtendedPrivKey::from_str(&bob.xprv).unwrap();

    let (scan_path, spend_path) = match IS_TESTNET {
        true => ("m/352h/1h/0h/1h/0", "m/352h/1h/0h/0h/0"),
        false => ("m/352h/0h/0h/1h/0", "m/352h/0h/0h/0h/0"),
    };

    let secp = Secp256k1::new();
    let scan_path: DerivationPath = DerivationPath::from_str(scan_path).unwrap();
    let spend_path: DerivationPath = DerivationPath::from_str(spend_path).unwrap();
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
