use std::{
    env, fs,
    fs::OpenOptions,
    io::{BufRead, BufReader, Read, Write},
    path::{Path, PathBuf},
    time::{SystemTime, UNIX_EPOCH},
};

use s3p_core::{
    aead::*,
    fountain::{
        join_blocks, partition_into_blocks, peel_decode, FountainEncoder, FountainParams, Packet,
    },
    merkle::*,
    pod::ProofOfDelivery,
    rs::*,
    series::SeriesCommit,
};

use base64::{engine::general_purpose, Engine as _};
use ed25519_dalek::SigningKey;
use rand::{rngs::OsRng, RngCore};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

//==================== Общие структуры/утилиты ====================//

#[derive(Serialize, Deserialize)]
struct Manifest {
    version: u8,
    scid: String,
    commit: SeriesCommit,
    aad: String,       // для простоты — строка
    nonce_hex: String, // 24 байта в hex
    ct_len: usize,     // длина шифртекста (без padding RS)
    data_shards: usize,
    parity_shards: usize,
    file_name: String, // имя исходного файла
}

#[derive(Serialize, Deserialize)]
struct StreamManifest {
    version: u8,
    scid: String,
    commit: SeriesCommit, // commit по готовым шард-файлам (как в RS-профиле)
    aad: String,
    file_name: String,
    size_bytes: usize,
    data_shards: usize,
    parity_shards: usize,
    chunk_size: usize,       // размер plaintext-чанка (перед AEAD)
    ct_len_per_chunk: usize, // = chunk_size + 16 (AEAD tag)
    chunks: usize,           // количество чанков
    nonce_base_hex: String,  // 24 байта — база для детерминированных nonce
}

fn hex_decode(s: &str) -> Result<Vec<u8>, String> {
    let s = s.trim();
    hex::decode(s).map_err(|e| format!("{e}"))
}

fn decode_hex_arg(name: &str, value: &str) -> Vec<u8> {
    match hex_decode(value) {
        Ok(bytes) => bytes,
        Err(err) => {
            eprintln!("error: invalid {name}: {err}");
            std::process::exit(2);
        }
    }
}

fn hex_encode(b: &[u8]) -> String {
    hex::encode(b)
}

fn read_all(p: &Path) -> Vec<u8> {
    fs::read(p).expect("read file")
}

fn write_all(p: &Path, bytes: &[u8]) {
    if let Some(parent) = p.parent() {
        fs::create_dir_all(parent).ok();
    }
    let mut f = fs::File::create(p).expect("create file");
    f.write_all(bytes).expect("write file");
}

fn usage() -> ! {
    eprintln!(
"Usage:
  s3p pack   <input_file> <out_dir> --data=<N> --parity=<M> --ikm-hex=<HEX> --salt-hex=<HEX> [--aad=<str>]
  s3p unpack <in_dir> <output_file> --ikm-hex=<HEX> --salt-hex=<HEX>

  s3p pack-fountain   <input_file> <out_dir> --ikm-hex=<HEX> --salt-hex=<HEX> [--aad=<str>] --k=<K> [--packets=<N> | --overhead=<x.y>] [--seed=<u64>] [--c=0.1] [--delta=0.05]
  s3p unpack-fountain <in_dir> <output_file> --ikm-hex=<HEX> --salt-hex=<HEX>

  s3p pack-stream      <input_file> <out_dir> --data=<N> --parity=<M> --ikm-hex=<HEX> --salt-hex=<HEX> --chunk=<bytes> [--aad=<str>] [--nonce-base-hex=<48hex>]
  s3p unpack-stream    <in_dir> <output_file> --ikm-hex=<HEX> --salt-hex=<HEX>
  s3p verify-pack      <in_dir>
  s3p verify-pack-stream <in_dir>

  s3p keygen         --out-dir=<dir>
  s3p pod-sign       <in_dir> --sk-hex=<64-hex-secret>
  s3p pod-verify     <in_dir>
  s3p pod-aggregate  <in_dir> [--out=<file>]

Notes:
  - RS-профиль: в <out_dir> будут shard_###.bin и manifest.json; после pod-sign — pod_###.json
  - Stream RS: manifest_stream.json + те же shard_###.bin (заполняются «полосами» по чанкам)
  - Fountain-профиль: fountain_meta.json + fountain_packets.jsonl
  - ikm-hex/salt-hex — ключевой материал в hex (ikm обычно 32 байта = 64 hex-символа)
  - sk-hex — 32-байтный секретный ключ Ed25519 в hex (ровно 64 hex-символа)"
    );
    std::process::exit(1)
}

fn arg_flag(args: &[String], name: &str) -> Option<String> {
    for a in args {
        if let Some(rest) = a.strip_prefix(&format!("--{}=", name)) {
            return Some(rest.to_string());
        }
    }
    None
}

#[inline]
fn require_flag(args: &[String], name: &str) -> String {
    if let Some(v) = arg_flag(args, name) {
        return v;
    }
    eprintln!("error: missing --{name}\n");
    usage();
}

fn arg_flag_default<T: std::str::FromStr>(args: &[String], name: &str, default: T) -> T {
    arg_flag(args, name)
        .and_then(|s| s.parse::<T>().ok())
        .unwrap_or(default)
}

//==================== RS-профиль: pack/unpack ====================//

fn pack_cmd(args: &[String]) {
    if args.len() < 3 {
        usage();
    }
    let input = PathBuf::from(&args[0]);
    let out_dir = PathBuf::from(&args[1]);

    let data_shards: usize = require_flag(args, "data")
        .parse()
        .expect("invalid --data (number)");
    let parity_shards: usize = require_flag(args, "parity")
        .parse()
        .expect("invalid --parity (number)");
    let ikm_hex = require_flag(args, "ikm-hex");
    let salt_hex = require_flag(args, "salt-hex");
    let aad = arg_flag(args, "aad").unwrap_or_else(|| "s3p-cli".to_string());

    if data_shards == 0 {
        eprintln!("error: --data must be > 0\n");
        usage();
    }
    if parity_shards == 0 {
        eprintln!("error: --parity must be > 0\n");
        usage();
    }

    let ikm = decode_hex_arg("--ikm-hex", &ikm_hex);
    let salt = decode_hex_arg("--salt-hex", &salt_hex);

    // читаем файл
    let plain = read_all(&input);
    // derive keys
    let ks = KeySchedule::derive(&ikm, &salt).expect("ks derive");
    // шифруем весь файл одним вызовом
    let (ciphertext, nonce) = ks.seal(aad.as_bytes(), &plain).expect("seal");
    let ct_len = ciphertext.len();

    // Reed–Solomon поверх ciphertext
    let shards = rs_encode(&ciphertext, data_shards, parity_shards).expect("rs_encode");

    // меркл-дерево шардов
    let leaf_hashes: Vec<[u8; 32]> = shards.iter().map(|s| leaf_hash(s)).collect();
    let root = merkle_root(leaf_hashes.clone()).expect("merkle_root");

    // commit + scid
    let commit = SeriesCommit {
        version: 1,
        size_bytes: plain.len(),
        chunk_size: ciphertext.len(), // исторически так (весь файл как один «чанк шифртекста»)
        erasure_data: data_shards,
        erasure_parity: parity_shards,
        aead_alg: "XChaCha20-Poly1305".to_string(),
        merkle_root: root,
    };
    let scid = commit.scid();

    // записываем шард-файлы
    fs::create_dir_all(&out_dir).expect("mkdir out_dir");
    for (i, s) in shards.iter().enumerate() {
        let path = out_dir.join(format!("shard_{:03}.bin", i));
        write_all(&path, s);
    }

    // манифест
    let manifest = Manifest {
        version: 1,
        scid,
        commit,
        aad,
        nonce_hex: hex_encode(&nonce),
        ct_len,
        data_shards,
        parity_shards,
        file_name: input
            .file_name()
            .and_then(|s| s.to_str())
            .unwrap_or("input.bin")
            .to_string(),
    };
    let mf_json = serde_json::to_vec_pretty(&manifest).expect("manifest json");
    write_all(&out_dir.join("manifest.json"), &mf_json);

    println!("Packed → {}", out_dir.display());
}

fn unpack_cmd(args: &[String]) {
    if args.len() < 3 {
        usage();
    }
    let in_dir = PathBuf::from(&args[0]);
    let output = PathBuf::from(&args[1]);

    let ikm_hex = require_flag(args, "ikm-hex");
    let salt_hex = require_flag(args, "salt-hex");

    let ikm = decode_hex_arg("--ikm-hex", &ikm_hex);
    let salt = decode_hex_arg("--salt-hex", &salt_hex);
    let ks = KeySchedule::derive(&ikm, &salt).expect("ks derive");

    // читаем манифест
    let mf_bytes = read_all(&in_dir.join("manifest.json"));
    let mf: Manifest = serde_json::from_slice(&mf_bytes).expect("manifest parse");

    // собираем список шардов
    let total = mf.data_shards + mf.parity_shards;
    let mut shards_opt: Vec<Option<Vec<u8>>> = vec![None; total];
    for (i, slot) in shards_opt.iter_mut().enumerate().take(total) {
        let p = in_dir.join(format!("shard_{:03}.bin", i));
        if p.exists() {
            *slot = Some(read_all(&p));
        }
    }

    // RS восстановление
    let recovered_joined =
        rs_reconstruct(shards_opt, mf.data_shards, mf.parity_shards).expect("rs_reconstruct");
    let ciphertext = &recovered_joined[..mf.ct_len];

    // расшифровка
    let mut nonce = [0u8; 24];
    let nonce_bytes = hex_decode(&mf.nonce_hex).expect("manifest nonce hex decode");
    if nonce_bytes.len() != 24 {
        eprintln!("error: manifest nonce must be 24 bytes");
        std::process::exit(2);
    }
    nonce.copy_from_slice(&nonce_bytes);

    let plain = ks
        .open(mf.aad.as_bytes(), &nonce, ciphertext)
        .expect("open");

    // финально — обрезать до заявленного в commit размера
    let mut out_bytes = plain;
    out_bytes.truncate(mf.commit.size_bytes);
    write_all(&output, &out_bytes);

    println!("Unpacked → {}", output.display());
}

//==================== Stream RS: pack-stream / unpack-stream ====================//

fn derive_nonce_from_base(base: &[u8; 24], idx: u64) -> [u8; 24] {
    // Простая детерминизация: XOR последних 8 байт с LE-счётчиком
    // Условие безопасности: уникальность nonce на ключ гарантирована при idx<2^64
    let mut n = *base;
    let ctr = idx.to_le_bytes();
    for j in 0..8 {
        n[16 + j] ^= ctr[j];
    }
    n
}

fn pack_stream_cmd(args: &[String]) {
    if args.len() < 3 {
        usage();
    }
    let input = PathBuf::from(&args[0]);
    let out_dir = PathBuf::from(&args[1]);

    let data_shards: usize = require_flag(args, "data").parse().expect("invalid --data");
    let parity_shards: usize = require_flag(args, "parity")
        .parse()
        .expect("invalid --parity");
    let ikm_hex = require_flag(args, "ikm-hex");
    let salt_hex = require_flag(args, "salt-hex");
    let chunk_size: usize = require_flag(args, "chunk")
        .parse()
        .expect("invalid --chunk");
    let aad = arg_flag(args, "aad").unwrap_or_else(|| "s3p-stream".to_string());

    if data_shards == 0 || parity_shards == 0 {
        eprintln!("--data and --parity must be > 0");
        std::process::exit(2);
    }
    if chunk_size == 0 {
        eprintln!("--chunk must be > 0");
        std::process::exit(2);
    }

    let ikm = decode_hex_arg("--ikm-hex", &ikm_hex);
    let salt = decode_hex_arg("--salt-hex", &salt_hex);
    let ks = KeySchedule::derive(&ikm, &salt).expect("ks derive");

    // nonce base
    let mut nonce_base = [0u8; 24];
    if let Some(nb_hex) = arg_flag(args, "nonce-base-hex") {
        let nb = match hex_decode(&nb_hex) {
            Ok(bytes) => bytes,
            Err(err) => {
                eprintln!("error: invalid --nonce-base-hex: {err}");
                std::process::exit(2);
            }
        };
        if nb.len() != 24 {
            eprintln!("error: --nonce-base-hex must be 24 bytes (48 hex)");
            std::process::exit(2);
        }
        nonce_base.copy_from_slice(&nb);
    } else {
        OsRng.fill_bytes(&mut nonce_base);
    }

    // входной файл (стримом)
    let mut f_in = fs::File::open(&input).expect("open input");
    let file_size = f_in.metadata().expect("meta").len() as usize;
    let chunks = file_size.div_ceil(chunk_size);
    let ct_len_per_chunk = chunk_size + 16; // XChaCha20-Poly1305 тег

    let total_shards = data_shards + parity_shards;
    fs::create_dir_all(&out_dir).expect("mkdir out_dir");

    // Подымаем писатели шард-файлов (append, truncate)
    let mut shard_files = Vec::with_capacity(total_shards);
    for i in 0..total_shards {
        let path = out_dir.join(format!("shard_{:03}.bin", i));
        let file = OpenOptions::new()
            .create(true)
            .write(true)
            .truncate(true)
            .open(path)
            .expect("open shard file");
        shard_files.push(file);
    }

    // Буферы
    let mut plain_chunk = vec![0u8; chunk_size];

    for idx in 0..chunks {
        // читаем максимум chunk_size
        let mut read_total = 0usize;
        while read_total < chunk_size {
            let n = f_in.read(&mut plain_chunk[read_total..]).expect("read");
            if n == 0 {
                break;
            }
            read_total += n;
        }
        if read_total < chunk_size {
            // добиваем нулями (padding)
            for b in &mut plain_chunk[read_total..] {
                *b = 0;
            }
        }

        // AEAD с детерминированным nonce
        let nonce = derive_nonce_from_base(&nonce_base, idx as u64);
        let ciphertext = ks
            .seal_with_nonce(aad.as_bytes(), &nonce, &plain_chunk)
            .expect("seal");

        // RS кодирование для этого чанка
        let shards = rs_encode(&ciphertext, data_shards, parity_shards).expect("rs");
        // аппенд в shard_###.bin
        for (i, s) in shards.iter().enumerate() {
            shard_files[i].write_all(s).expect("write shard");
        }
    }

    // сброс на диск
    for f in shard_files.iter_mut() {
        f.flush().ok();
    }

    // посчитаем Merkle по итоговым файлам
    let mut leaves = Vec::<[u8; 32]>::with_capacity(total_shards);
    for i in 0..total_shards {
        let p = out_dir.join(format!("shard_{:03}.bin", i));
        let bytes = read_all(&p);
        leaves.push(leaf_hash(&bytes));
    }
    let root = merkle_root(leaves).expect("merkle_root");

    // commit + scid (chunk_size = размер plaintext-чанка)
    let commit = SeriesCommit {
        version: 1,
        size_bytes: file_size,
        chunk_size,
        erasure_data: data_shards,
        erasure_parity: parity_shards,
        aead_alg: "XChaCha20-Poly1305".to_string(),
        merkle_root: root,
    };
    let scid = commit.scid();

    // манифест стрима
    let sm = StreamManifest {
        version: 1,
        scid,
        commit,
        aad,
        file_name: input
            .file_name()
            .and_then(|s| s.to_str())
            .unwrap_or("input.bin")
            .to_string(),
        size_bytes: file_size,
        data_shards,
        parity_shards,
        chunk_size,
        ct_len_per_chunk,
        chunks,
        nonce_base_hex: hex_encode(&nonce_base),
    };
    let sm_json = serde_json::to_vec_pretty(&sm).unwrap();
    write_all(&out_dir.join("manifest_stream.json"), &sm_json);

    println!(
        "Stream packed → {} ({} chunks, chunk={}B)",
        out_dir.display(),
        chunks,
        chunk_size
    );
}

fn unpack_stream_cmd(args: &[String]) {
    if args.len() < 3 {
        usage();
    }
    let in_dir = PathBuf::from(&args[0]);
    let output = PathBuf::from(&args[1]);

    let ikm_hex = require_flag(args, "ikm-hex");
    let salt_hex = require_flag(args, "salt-hex");

    let ikm = decode_hex_arg("--ikm-hex", &ikm_hex);
    let salt = decode_hex_arg("--salt-hex", &salt_hex);
    let ks = KeySchedule::derive(&ikm, &salt).expect("ks derive");

    // читаем stream-манифест
    let sm_bytes = read_all(&in_dir.join("manifest_stream.json"));
    let sm: StreamManifest = serde_json::from_slice(&sm_bytes).expect("manifest_stream parse");

    let total_shards = sm.data_shards + sm.parity_shards;
    let shard_size = sm.ct_len_per_chunk.div_ceil(sm.data_shards);

    // Открываем доступные шард-файлы как читатели
    let mut shard_readers: Vec<Option<BufReader<fs::File>>> = Vec::with_capacity(total_shards);
    for i in 0..total_shards {
        let p = in_dir.join(format!("shard_{:03}.bin", i));
        if let Ok(f) = fs::File::open(&p) {
            shard_readers.push(Some(BufReader::new(f)));
        } else {
            shard_readers.push(None);
        }
    }

    let mut out = fs::File::create(&output).expect("create output");

    for idx in 0..sm.chunks {
        // читаем очередную «полосу» по shard_size из каждого шард-файла
        let mut stripe: Vec<Option<Vec<u8>>> = Vec::with_capacity(total_shards);
        for r_opt in shard_readers.iter_mut() {
            if let Some(r) = r_opt {
                let mut buf = vec![0u8; shard_size];
                let mut read_total = 0usize;
                while read_total < shard_size {
                    let n = r.read(&mut buf[read_total..]).unwrap_or(0);
                    if n == 0 {
                        break;
                    }
                    read_total += n;
                }
                if read_total == shard_size {
                    stripe.push(Some(buf));
                } else if read_total == 0 {
                    // файл закончился — считаем шард потерян
                    stripe.push(None);
                } else {
                    // укороченный фрагмент — тоже считаем потерянным
                    stripe.push(None);
                }
            } else {
                stripe.push(None);
            }
        }

        // RS реконструкция полосы
        let joined =
            rs_reconstruct(stripe, sm.data_shards, sm.parity_shards).expect("rs_reconstruct");
        let ct_chunk = &joined[..sm.ct_len_per_chunk];

        // AEAD open с детерминированным nonce для idx
        let mut nonce_base = [0u8; 24];
        let base_bytes =
            hex_decode(&sm.nonce_base_hex).expect("stream manifest nonce-base hex decode");
        if base_bytes.len() != 24 {
            eprintln!("error: manifest_stream nonce-base must be 24 bytes");
            std::process::exit(2);
        }
        nonce_base.copy_from_slice(&base_bytes);
        let nonce = derive_nonce_from_base(&nonce_base, idx as u64);

        let pt = ks.open(sm.aad.as_bytes(), &nonce, ct_chunk).expect("open");
        out.write_all(&pt).expect("write pt");
    }

    // обрезаем до исходного размера
    out.flush().ok();
    out.set_len(sm.size_bytes as u64).ok();

    println!("Stream unpacked → {}", output.display());
}

//==================== Проверки паков ====================//

fn verify_pack_cmd(args: &[String]) {
    if args.is_empty() {
        usage();
    }
    let in_dir = PathBuf::from(&args[0]);

    // манифест
    let mf_bytes = read_all(&in_dir.join("manifest.json"));
    let mf: Manifest = serde_json::from_slice(&mf_bytes).expect("manifest parse");

    // требуем наличие всех шардов
    let total = mf.data_shards + mf.parity_shards;
    let mut leaves = Vec::<[u8; 32]>::with_capacity(total);
    for i in 0..total {
        let p = in_dir.join(format!("shard_{:03}.bin", i));
        if !p.exists() {
            eprintln!("missing shard_{:03}.bin", i);
            std::process::exit(2);
        }
        let bytes = read_all(&p);
        leaves.push(leaf_hash(&bytes));
    }

    // сверяем Merkle root
    let root = merkle_root(leaves).expect("merkle_root");
    if root != mf.commit.merkle_root {
        eprintln!("manifest merkle_root mismatch");
        std::process::exit(2);
    }

    // сверяем SCID
    let scid2 = mf.commit.scid();
    if scid2 != mf.scid {
        eprintln!("manifest scid mismatch");
        std::process::exit(2);
    }

    println!("verify-pack: OK (merkle_root & scid match)");
}

fn verify_pack_stream_cmd(args: &[String]) {
    if args.is_empty() {
        usage();
    }
    let in_dir = PathBuf::from(&args[0]);

    // читаем stream-манифест
    let sm_bytes = read_all(&in_dir.join("manifest_stream.json"));
    let sm: StreamManifest = serde_json::from_slice(&sm_bytes).expect("manifest_stream parse");

    let total = sm.data_shards + sm.parity_shards;
    let mut leaves = Vec::<[u8; 32]>::with_capacity(total);
    for i in 0..total {
        let p = in_dir.join(format!("shard_{:03}.bin", i));
        if !p.exists() {
            eprintln!("missing shard_{:03}.bin", i);
            std::process::exit(2);
        }
        let bytes = read_all(&p);
        leaves.push(leaf_hash(&bytes));
    }

    // сверяем Merkle root
    let root = merkle_root(leaves).expect("merkle_root");
    if root != sm.commit.merkle_root {
        eprintln!("manifest_stream merkle_root mismatch");
        std::process::exit(2);
    }

    // сверяем SCID
    let scid2 = sm.commit.scid();
    if scid2 != sm.scid {
        eprintln!("manifest_stream scid mismatch");
        std::process::exit(2);
    }

    println!("verify-pack-stream: OK (merkle_root & scid match)");
}

//==================== PoD: подписать/проверить/агрегировать ====================//

fn parse_sk_hex(sk_hex: &str) -> SigningKey {
    let sk_bytes = match hex_decode(sk_hex) {
        Ok(bytes) => bytes,
        Err(err) => {
            eprintln!("error: invalid sk-hex: {err}");
            std::process::exit(2);
        }
    };
    if sk_bytes.len() != 32 {
        eprintln!("error: sk-hex must be 32 bytes (64 hex chars)");
        std::process::exit(2);
    }
    let mut arr = [0u8; 32];
    arr.copy_from_slice(&sk_bytes);
    SigningKey::from_bytes(&arr)
}

fn pod_sign_cmd(args: &[String]) {
    if args.is_empty() {
        usage();
    }
    let in_dir = PathBuf::from(&args[0]);
    let sk_hex = require_flag(args, "sk-hex");
    let sk = parse_sk_hex(&sk_hex);

    // манифест
    let mf_bytes = read_all(&in_dir.join("manifest.json"));
    let mf: Manifest = serde_json::from_slice(&mf_bytes).expect("manifest parse");

    let total = mf.data_shards + mf.parity_shards;
    let mut signed = 0usize;

    for i in 0..total {
        let shard_path = in_dir.join(format!("shard_{:03}.bin", i));
        if !shard_path.exists() {
            continue;
        }
        let shard_bytes = read_all(&shard_path);

        // leaf hash = sha256(shard)
        let mut h = Sha256::new();
        h.update(&shard_bytes);
        let leaf_hash: [u8; 32] = h.finalize().into();

        let pod = ProofOfDelivery::sign(&sk, &mf.scid, i as u32, leaf_hash, None);
        let pod_json = serde_json::to_vec_pretty(&pod).expect("pod json");
        write_all(&in_dir.join(format!("pod_{:03}.json", i)), &pod_json);
        signed += 1;
    }

    println!(
        "PoD signed: {}/{} present shards → {}",
        signed,
        total,
        in_dir.display()
    );
}

fn pod_verify_cmd(args: &[String]) {
    if args.is_empty() {
        usage();
    }
    let in_dir = PathBuf::from(&args[0]);

    // манифест
    let mf_bytes = read_all(&in_dir.join("manifest.json"));
    let mf: Manifest = serde_json::from_slice(&mf_bytes).expect("manifest parse");

    let total = mf.data_shards + mf.parity_shards;
    let mut ok = 0usize;
    let mut bad = 0usize;
    let mut missing = 0usize;

    for i in 0..total {
        let pod_path = in_dir.join(format!("pod_{:03}.json", i));
        if !pod_path.exists() {
            missing += 1;
            continue;
        }
        let pod_bytes = read_all(&pod_path);
        let pod: ProofOfDelivery = serde_json::from_slice(&pod_bytes).expect("pod parse");

        // проверим scid
        if pod.scid != mf.scid {
            eprintln!("pod_{:03}.json: scid mismatch", i);
            bad += 1;
            continue;
        }
        // возьмём соответствующий шард и пересчитаем хэш
        let shard_path = in_dir.join(format!("shard_{:03}.bin", i));
        if !shard_path.exists() {
            eprintln!("pod_{:03}.json: shard file missing", i);
            bad += 1;
            continue;
        }
        let shard_bytes = read_all(&shard_path);
        let mut h = Sha256::new();
        h.update(&shard_bytes);
        let leaf_hash: [u8; 32] = h.finalize().into();
        if leaf_hash != pod.leaf_hash {
            eprintln!("pod_{:03}.json: leaf hash mismatch", i);
            bad += 1;
            continue;
        }
        // криптографическая проверка
        if pod.verify() {
            ok += 1;
        } else {
            eprintln!("pod_{:03}.json: signature invalid", i);
            bad += 1;
        }
    }

    println!(
        "PoD verify summary: ok={}, bad={}, missing={}",
        ok, bad, missing
    );
    if bad == 0 {
        // ok
    } else {
        std::process::exit(2);
    }
}

//— агрегатор PoD —//

#[derive(Serialize)]
struct PodAggregate {
    version: u8,
    scid: String,
    total_shards: usize,
    present_pods: usize,
    ok: usize,
    bad: usize,
    missing: usize,
    pod_root_hex: String,
    included_indexes: Vec<usize>,
    ts_unix_ms: u64,
}

fn pod_leaf_hash(pod: &ProofOfDelivery) -> [u8; 32] {
    // Детерминированное кодирование полей в строгом порядке
    let mut h = Sha256::new();
    h.update(b"s3p-pod-leaf-v1");
    h.update(pod.scid.as_bytes());
    h.update(pod.shard_index.to_le_bytes());
    h.update(pod.ts_unix_ms.to_le_bytes());
    h.update(pod.signer_pubkey);
    h.update(pod.leaf_hash);
    h.finalize().into()
}

fn pod_aggregate_cmd(args: &[String]) {
    if args.is_empty() {
        usage();
    }
    let in_dir = PathBuf::from(&args[0]);
    let out_path = arg_flag(args, "out")
        .map(PathBuf::from)
        .unwrap_or_else(|| in_dir.join("pod_aggregate.json"));

    // манифест
    let mf_bytes = read_all(&in_dir.join("manifest.json"));
    let mf: Manifest = serde_json::from_slice(&mf_bytes).expect("manifest parse");
    let total = mf.data_shards + mf.parity_shards;

    // собираем PoD
    let mut leaves = Vec::<[u8; 32]>::new();
    let mut included_indexes = Vec::<usize>::new();
    let mut ok = 0usize;
    let mut bad = 0usize;
    let mut missing = 0usize;
    let mut present = 0usize;

    for i in 0..total {
        let p = in_dir.join(format!("pod_{:03}.json", i));
        if !p.exists() {
            missing += 1;
            continue;
        }
        present += 1;
        let pod_bytes = read_all(&p);
        let pod: ProofOfDelivery = serde_json::from_slice(&pod_bytes).expect("pod parse");
        if pod.scid != mf.scid {
            eprintln!("pod_{:03}.json: scid mismatch", i);
            bad += 1;
            continue;
        }
        if !pod.verify() {
            eprintln!("pod_{:03}.json: signature invalid", i);
            bad += 1;
            continue;
        }
        ok += 1;
        included_indexes.push(i);
        leaves.push(pod_leaf_hash(&pod));
    }

    if leaves.is_empty() {
        eprintln!("no valid PoD to aggregate");
        std::process::exit(2);
    }

    let root = merkle_root(leaves).expect("pod merkle root");
    let pod_root_hex = hex_encode(&root);

    let now_ms = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as u64;

    let agg = PodAggregate {
        version: 1,
        scid: mf.scid,
        total_shards: total,
        present_pods: present,
        ok,
        bad,
        missing,
        pod_root_hex,
        included_indexes,
        ts_unix_ms: now_ms,
    };

    let json = serde_json::to_vec_pretty(&agg).unwrap();
    write_all(&out_path, &json);
    println!("PoD aggregate → {}", out_path.display());
}

//==================== Fountain-профиль: pack/unpack ====================//

#[derive(Serialize, Deserialize)]
struct FountainMeta {
    version: u8,
    file_name: String,
    size_bytes: usize,
    ct_len: usize,
    aad: String,
    nonce_hex: String,
    k: usize,
    block_len: usize,
    packets: usize,
    seed: u64,
    c: f64,
    delta: f64,
}

// JSON-представление пакета для jsonl (основная текущая схема)
#[derive(Serialize, Deserialize)]
struct JsonPkt {
    ids: Vec<usize>,
    body_hex: String,
}

// Универсальный парсер строки jsonl (на случай других схем)
#[derive(Deserialize)]
#[serde(untagged)]
enum WirePacketAny {
    Hex { ids: Vec<usize>, body_hex: String },
    // запасы на будущее:
    B64 { ids: Vec<usize>, body_b64: String },
    Raw { ids: Vec<usize>, body: String },
}

fn decode_wire_packet(wp: WirePacketAny) -> Packet {
    match wp {
        WirePacketAny::Hex { ids, body_hex } => Packet {
            ids,
            body: hex_decode(&body_hex).expect("packet body_hex decode"),
        },
        WirePacketAny::B64 { ids, body_b64 } => {
            let body = general_purpose::STANDARD
                .decode(&body_b64)
                .expect("bad base64 in body_b64");
            Packet { ids, body }
        }
        WirePacketAny::Raw { ids, body } => Packet {
            ids,
            body: hex_decode(&body).expect("packet body decode"),
        },
    }
}

// robust-soliton: μ = (ρ + τ) / Z
fn robust_soliton(k: usize, c: f64, delta: f64) -> Vec<(usize, f32)> {
    assert!(k >= 2, "k must be >= 2");
    let kf = k as f64;

    // ρ(d)
    let mut rho = vec![0.0f64; k + 1];
    rho[1] = 1.0 / kf;
    for (d, r) in rho.iter_mut().enumerate().take(k + 1).skip(2) {
        *r = 1.0 / ((d as f64) * ((d as f64) - 1.0));
    }

    // τ(d)
    let r = c * ((kf / delta).ln()) * kf.sqrt();
    let mut s = (kf / r).floor() as usize;
    if s < 1 {
        s = 1;
    }
    let mut tau = vec![0.0f64; k + 1];
    for (d, t) in tau.iter_mut().enumerate().take(k + 1).skip(1) {
        if d < s {
            *t = r / ((d as f64) * kf);
        } else if d == s {
            *t = (r * (r / delta).ln()) / kf;
        }
    }

    // μ(d) и нормировка
    let mut mu = vec![0.0f64; k + 1];
    let mut z = 0.0f64;
    for (m, (&rv, &tv)) in mu
        .iter_mut()
        .zip(rho.iter().zip(tau.iter()))
        .take(k + 1)
        .skip(1)
    {
        *m = rv + tv;
        z += *m;
    }
    for m in mu.iter_mut().take(k + 1).skip(1) {
        *m /= z;
    }

    // в (degree, prob)
    let mut out = Vec::with_capacity(k);
    for (d, &p) in mu.iter().enumerate().take(k + 1).skip(1) {
        let p32 = p as f32;
        if p32 > 0.0 {
            out.push((d, p32));
        }
    }
    out
}

fn pack_fountain_cmd(args: &[String]) {
    if args.len() < 2 {
        usage();
    }
    let input = PathBuf::from(&args[0]);
    let out_dir = PathBuf::from(&args[1]);

    let ikm_hex = require_flag(args, "ikm-hex");
    let salt_hex = require_flag(args, "salt-hex");
    let aad = arg_flag(args, "aad").unwrap_or_else(|| "s3p-fountain".to_string());

    let k: usize = require_flag(args, "k").parse().expect("invalid --k");
    let packets_opt = arg_flag(args, "packets").and_then(|s| s.parse::<usize>().ok());
    let overhead_opt = arg_flag(args, "overhead").and_then(|s| s.parse::<f64>().ok());
    let seed: u64 = arg_flag_default(args, "seed", 42u64);
    let c: f64 = arg_flag_default(args, "c", 0.1f64);
    let delta: f64 = arg_flag_default(args, "delta", 0.05f64);

    if packets_opt.is_some() && overhead_opt.is_some() {
        panic!("use either --packets or --overhead, not both");
    }

    let ikm = decode_hex_arg("--ikm-hex", &ikm_hex);
    let salt = decode_hex_arg("--salt-hex", &salt_hex);
    let ks = KeySchedule::derive(&ikm, &salt).expect("ks derive");

    let plain = read_all(&input);
    let (ciphertext, nonce) = ks.seal(aad.as_bytes(), &plain).expect("seal");
    let ct_len = ciphertext.len();

    let (blocks, block_len) = partition_into_blocks(&ciphertext, k);

    // robust-soliton → FountainEncoder
    let probs_vec = robust_soliton(k, c, delta);
    let probs_leaked: &'static [(usize, f32)] = Box::leak(probs_vec.into_boxed_slice());
    let params = FountainParams {
        degree_probs: probs_leaked,
        seed,
    };
    let mut enc = FountainEncoder::new(k, block_len, params);

    let mut total_packets = packets_opt.unwrap_or_else(|| {
        let ov = overhead_opt.unwrap_or(1.25); // 1.25*k по умолчанию
        ((ov * k as f64).ceil() as usize).max(k)
    });

    // Systematic-допинг: первые k пакетов — исходные блоки степени 1
    let mut pkts: Vec<Packet> = Vec::with_capacity(total_packets);
    for (i, b) in blocks.iter().enumerate().take(k) {
        pkts.push(Packet {
            ids: vec![i],
            body: b.clone(),
        });
    }
    if total_packets < k {
        total_packets = k;
    }
    while pkts.len() < total_packets {
        pkts.push(enc.next_packet(&blocks));
    }

    // Запись файлов
    fs::create_dir_all(&out_dir).expect("mkdir out_dir");
    // meta
    let meta = FountainMeta {
        version: 1,
        file_name: input
            .file_name()
            .and_then(|s| s.to_str())
            .unwrap_or("input.bin")
            .to_string(),
        size_bytes: plain.len(),
        ct_len,
        aad: aad.clone(),
        nonce_hex: hex_encode(&nonce),
        k,
        block_len,
        packets: pkts.len(),
        seed,
        c,
        delta,
    };
    let meta_json = serde_json::to_vec_pretty(&meta).unwrap();
    write_all(&out_dir.join("fountain_meta.json"), &meta_json);

    // packets.jsonl
    let mut f = fs::File::create(out_dir.join("fountain_packets.jsonl")).expect("create jsonl");
    for p in pkts {
        let jp = JsonPkt {
            ids: p.ids,
            body_hex: hex_encode(&p.body),
        };
        let line = serde_json::to_string(&jp).unwrap();
        writeln!(f, "{}", line).unwrap();
    }

    println!("Fountain packed → {}", out_dir.display());
}

fn unpack_fountain_cmd(args: &[String]) {
    if args.len() < 2 {
        usage();
    }
    let in_dir = PathBuf::from(&args[0]);
    let output = PathBuf::from(&args[1]);

    let ikm_hex = require_flag(args, "ikm-hex");
    let salt_hex = require_flag(args, "salt-hex");

    let ikm = decode_hex_arg("--ikm-hex", &ikm_hex);
    let salt = decode_hex_arg("--salt-hex", &salt_hex);
    let ks = KeySchedule::derive(&ikm, &salt).expect("ks derive");

    // meta
    let meta_bytes = read_all(&in_dir.join("fountain_meta.json"));
    let meta: FountainMeta = serde_json::from_slice(&meta_bytes).expect("meta parse");

    // Если fetch уже собрал recovered_ct.bin — используем его напрямую
    let recovered_ct_path = in_dir.join("recovered_ct.bin");
    let recovered_ct = if recovered_ct_path.exists() {
        read_all(&recovered_ct_path)
    } else {
        // читаем строки jsonl → Packet (устойчиво к разным вариантам)
        let file = fs::File::open(in_dir.join("fountain_packets.jsonl")).expect("open jsonl");
        let reader = std::io::BufReader::new(file);
        let mut packets: Vec<Packet> = Vec::new();
        for line in reader.lines() {
            let l = line.unwrap();
            if l.trim().is_empty() {
                continue;
            }
            let parsed: WirePacketAny =
                serde_json::from_str(&l).expect("jsonl parse (WirePacketAny)");
            packets.push(decode_wire_packet(parsed));
        }

        if packets.len() < meta.k {
            panic!(
                "insufficient packets: have {}, need at least {}",
                packets.len(),
                meta.k
            );
        }

        // peel decode
        let decoded = peel_decode(meta.k, meta.block_len, packets)
            .expect("peel decode failed (need more packets)");
        join_blocks(&decoded, meta.ct_len)
    };

    // AEAD open
    let mut nonce = [0u8; 24];
    let nonce_bytes = hex_decode(&meta.nonce_hex).expect("fountain meta nonce hex decode");
    if nonce_bytes.len() != 24 {
        eprintln!("error: fountain_meta nonce must be 24 bytes");
        std::process::exit(2);
    }
    nonce.copy_from_slice(&nonce_bytes);
    let mut pt = ks
        .open(meta.aad.as_bytes(), &nonce, &recovered_ct)
        .expect("open");

    pt.truncate(meta.size_bytes);
    write_all(&output, &pt);

    println!("Fountain unpacked → {}", output.display());
}

//==================== Сервисные: keygen ====================//

fn keygen_cmd(args: &[String]) {
    let out_dir = PathBuf::from(require_flag(args, "out-dir"));
    fs::create_dir_all(&out_dir).expect("mkdir out-dir");

    // генерируем случайный секрет (32 байта), делаем из него ключ
    let mut sk_bytes = [0u8; 32];
    OsRng.fill_bytes(&mut sk_bytes);
    let sk = SigningKey::from_bytes(&sk_bytes);
    let pk = sk.verifying_key();

    write_all(&out_dir.join("sk.hex"), hex_encode(&sk_bytes).as_bytes());
    write_all(
        &out_dir.join("pk.hex"),
        hex_encode(pk.as_bytes()).as_bytes(),
    );
    println!("keypair written → {}", out_dir.display());
}

//==================== main ====================//

fn main() {
    let mut args: Vec<String> = env::args().skip(1).collect();
    if args.is_empty() {
        usage();
    }
    if args.len() == 1 && (args[0] == "help" || args[0] == "--help" || args[0] == "-h") {
        usage();
    }
    let cmd = args.remove(0);
    match cmd.as_str() {
        "pack" => pack_cmd(&args),
        "unpack" => unpack_cmd(&args),
        "pack-fountain" => pack_fountain_cmd(&args),
        "unpack-fountain" => unpack_fountain_cmd(&args),
        "pack-stream" => pack_stream_cmd(&args),
        "unpack-stream" => unpack_stream_cmd(&args),
        "verify-pack" => verify_pack_cmd(&args),
        "verify-pack-stream" => verify_pack_stream_cmd(&args),
        "keygen" => keygen_cmd(&args),
        "pod-sign" => pod_sign_cmd(&args),
        "pod-verify" => pod_verify_cmd(&args),
        "pod-aggregate" => pod_aggregate_cmd(&args),
        _ => usage(),
    }
}
