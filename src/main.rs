use std::str::FromStr;
use std::sync::mpsc::{channel, Receiver, Sender};
// use std::sync::spsc::{};
use std::fs;
use std::process::exit;
use std::thread::spawn;

// use toml::Value;
use serde::Deserialize;

use tracing::info;
use tracing_subscriber;

use chrono::Local;
use cote::*;

use bip39::{Language, Mnemonic};
use bitcoin::address::Address;
use bitcoin::bip32::{ChildNumber, DerivationPath, Xpriv, Xpub};
use bitcoin::key::{PublicKey, Secp256k1};
use bitcoin::network::Network;
use bitcoin::secp256k1::ffi::types::AlignedType;
use secp256k1::AllPreallocated;

use bip39::Language::English;

const VERSION: &str = "1.0-2024-02-29";
const USAGE: &str = "./addr [-p {report point}] [-t {threads}] [-c {config file}]
        -p {report point}:  report per times, default: 100,000
        -c {config file}:   set config file path
        -t {threads}:       set threads to run, if not set, use system process numbers";

#[derive(Debug, Clone, Deserialize)]
struct Config {
    words: String,

    head: bool,

    #[serde(default = "default_addr_type")]
    addr_type: String,

    expect_addr: String,
}

fn default_addr_type() -> String {
    "p2wpkh".to_string()
}

#[derive(Debug, Cote)]
struct MyArgs {
    #[arg(alias = "-t=c", value = "./config.toml", hint = "set config file")]
    config: String,

    #[arg(alias = "-t", value = 4u32, hint = "set threads")]
    threads: u32,

    #[arg(alias = "-p", value = 100000u64, hint = "set report point")]
    report: u64,

    #[arg(alias = "-h", value = false, hint = "print help info")]
    help: bool,
}

fn main() {
    let args = MyArgs::parse_env().unwrap();
    if args.help {
        println!("Usage: {}\n", USAGE);
        return;
    }

    let config_fn = args.config.clone();
    let conf = load_config(&config_fn);

    let n_threads = args.threads;
    let per_thread: usize = 2048 / (n_threads as usize);
    let mut start = 0;
    let mut end = per_thread as usize;
    let (tx, rx) = channel();

    tracing_subscriber::fmt::init();
    info!(
        "brute mnemonic words start, threads: {} version: {}",
        n_threads, VERSION
    );
    info!("mnemonic words: {}", conf.words);
    info!("expect address: {} {}", conf.addr_type, conf.expect_addr);

    for i in 0..n_threads {
        let thread_tx = tx.clone();
        let thread_conf = conf.clone();
        if i == n_threads - 1 {
            spawn(move || {
                brute_mnemonics(&thread_conf, start, end, &thread_tx, 1000);
            });
        } else {
            spawn(move || {
                brute_mnemonics(&thread_conf, start, 2049, &thread_tx, 1000);
            });
        }
        start = end;
        end = end + per_thread;
    }

    stats(rx, args.report);
}

fn load_config<'a>(filename: &'a str) -> Config {
    let config_content = fs::read_to_string(filename).expect("Unable to read file");

    toml::from_str(&config_content).unwrap()
    // // 解析 TOML 字符串
    // let parsed_config: Value = toml::from_str(&config_content).expect("Unable to parse TOML");

    // // 访问配置项
    // let words = parsed_config["words"].as_str().expect("Invalid words");
    // let head = parsed_config["head"].as_bool().expect("Invalid head");
    // let addr_type = parsed_config["addr_type"].as_str();
    // let expect_addr = parsed_config["expect_addr"]
    //     .as_str()
    //     .expect("Invalid expect address");

    // Config {
    //     words: words.to_string(),
    //     head: head,
    //     addr_type: addr_type.unwrap_or("p2wpkh").to_string(),
    //     expect_addr: expect_addr.to_string(),
    // }
}

// 尾部缺 word
fn brute_mnemonics<'a>(
    conf: &'a Config,
    start: usize,
    end: usize,
    tx: &Sender<u64>,
    report_point: u64,
) {
    let mut total: u64 = 0;
    let all_words = English.word_list();
    let nb_words = conf.words.split_whitespace().count();
    let postions: &mut Vec<usize> = &mut vec![0usize; (12 - nb_words + 1).try_into().unwrap()];
    let path = "m/44'/0'/0'";
    let mut buf: Vec<AlignedType> = Vec::new();
    buf.resize(Secp256k1::preallocate_size(), AlignedType::zeroed());
    let secp = Secp256k1::preallocated_new(buf.as_mut_slice()).unwrap();
    postions[12 - nb_words - 1] = start;
    let addr_type = conf.addr_type.clone();
    let expect_addr = conf.expect_addr.clone();
    let words = conf.words.clone();

    loop {
        let gap = fill_words(&all_words, postions);
        // println!("gap: {}", gap);
        let nwords = if conf.head {
            gap + " " + words.as_str()
        } else {
            words.to_string() + " " + gap.as_str()
        };
        if calc_addr_by_mnemonic(&nwords.as_str(), &path, &secp, &addr_type, &expect_addr) {
            info!("got mnemonic: {}", nwords);
            println!("got mnemonic: {}", nwords);
            exit(0);
        }
        if postions[12 - nb_words - 1] == end {
            info!("thread task complete!");
            return;
        }
        total = total + 1;
        if total >= report_point {
            let _ = tx.send(total);
            total = 0;
        }
        // if total % 10000000 == 0 {
        //     info!("bruted: {}", total);
        // }
    }
}

fn fill_words(all_words: &'static [&'static str; 2048], postions: &mut Vec<usize>) -> String {
    let count = postions.len() - 1;
    let mut gap: String = "".to_string();

    for i in 0..count {
        let mut idx = postions[i];
        if idx == 2048 {
            idx = 0;
            postions[i] = 0;
            postions[i + 1] = postions[i + 1] + 1;
        }
        gap = gap + " " + all_words[idx];
        //.to_string().as_str();
        // idx = idx + 1;
        // if idx == 2048 {
        //     idx = 0;
        //     postions[i + 1] = postions[i + 1] + 1;
        // }
        // postions[i] = idx;
    }
    postions[0] = postions[0] + 1;
    return gap;
}

fn calc_addr_by_mnemonic<'a>(
    words: &'a str,
    path: &'a str,
    secp: &'a Secp256k1<AllPreallocated<'a>>,
    addr_type: &'a str,
    expect_addr: &'a str,
) -> bool {
    if addr_type != "p2wpkh" {
        panic!("unsupport address format: {}", addr_type);
    }

    // println!("{}", words);
    // 使用助记词生成根私钥
    let mnemonic = Mnemonic::parse_in_normalized(Language::English, words);

    if mnemonic.is_err() {
        // println!("invalid mnemonic: {}", words);
        return false;
    }

    let seed = mnemonic.unwrap().to_seed("");
    let root = Xpriv::new_master(Network::Bitcoin, &seed).unwrap();

    // derive child xpub
    let path = DerivationPath::from_str(path).unwrap();
    let child = root.derive_priv(&secp, &path).unwrap();
    // println!("Child at {}: {}", path, child);
    let xpub = Xpub::from_priv(&secp, &child);
    // println!("Public key at {}: {}", path, xpub);

    // generate first receiving address at m/0/0
    // manually creating indexes this time
    let zero = ChildNumber::from_normal_idx(0).unwrap();
    let public_key = xpub.derive_pub(&secp, &[zero, zero]).unwrap().public_key;

    let address = Address::p2wpkh(&PublicKey::new(public_key), Network::Bitcoin);
    if address.is_err() {
        return false;
    }
    let addr = address.unwrap().to_string();
    // println!("addr: {}", addr);
    addr == expect_addr
}

fn stats(rx: Receiver<u64>, report_point: u64) {
    let mut total = 0;
    let mut points: u64 = 0;
    let mut prev_total: u64 = 0;
    let mut prev_ms: i64 = Local::now().timestamp_millis();

    loop {
        let times = rx.recv();
        if times.is_err() {
            println!(
                "{}: recv thread counter failed: {}",
                Local::now(),
                times.err().unwrap()
            );
            continue;
        }
        total += times.unwrap();
        let np = total / report_point;
        if np > points {
            let ms = Local::now().timestamp_millis();
            info!(
                "{}: {} {}/s",
                Local::now(),
                total,
                (total - prev_total) * 1000 / ((ms - prev_ms) as u64)
            );
            points = np;
            prev_ms = ms;
            prev_total = total;
        }
    }
}
