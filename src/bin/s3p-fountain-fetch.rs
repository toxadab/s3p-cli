use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::{
    env,
    fs::{self, File, OpenOptions},
    io::{BufWriter, Write},
    net::UdpSocket,
    path::PathBuf,
    time::{Duration, Instant},
};

use s3p_core::fountain::{join_blocks, peel_decode, Packet};

fn usage() -> ! {
    eprintln!(
        "Usage:
  s3p-fountain-fetch <out_dir> --bind=<IP:port> [--timeout-ms=<N>]

Behavior:
  - Ждёт UDP-кадры:
      'M\\n' + JSON(meta) и 'P\\n' + JSON(packet)
  - Сохраняет:
      <out_dir>/fountain_meta.json           (первая принятая мета)
      <out_dir>/fountain_packets.jsonl       (дописывается по мере приёма; формат: {{ids, body_hex}})
  - На успешном peel-декоде:
      <out_dir>/recovered_ct.bin             (ciphertext, обрезанный до ct_len)
      и завершает работу (exit 0)."
    );
    std::process::exit(1)
}

fn flag(args: &[String], name: &str) -> Option<String> {
    for a in args {
        if let Some(rest) = a.strip_prefix(&format!("--{}=", name)) {
            return Some(rest.to_string());
        }
    }
    None
}

#[derive(Debug, Clone)]
struct WirePacket {
    ids: Vec<usize>,
    body: Vec<u8>,
}

#[derive(Debug, Clone, Serialize)]
struct WirePacketOut<'a> {
    ids: &'a [usize],
    body_hex: String,
}

#[derive(Debug, Clone, Deserialize)]
struct RecvMeta {
    k: usize,
    block_len: usize,
    ct_len: usize,
}

/// Поддерживаем варианты входного JSON для пакета:
///  { "ids":[...], "body":[u8,...] }
///  { "ids":[...], "body_hex":"<hex>" }
///  { "ids":[...], "body":"<hex>" }
fn parse_packet_json(v: &Value) -> Option<WirePacket> {
    // ids
    let ids_val = v.get("ids")?;
    let ids_arr = ids_val.as_array()?;
    let mut ids: Vec<usize> = Vec::with_capacity(ids_arr.len());
    for x in ids_arr {
        ids.push(x.as_u64()? as usize);
    }

    // body как массив?
    if let Some(body_arr) = v.get("body").and_then(|b| b.as_array()) {
        let mut body = Vec::with_capacity(body_arr.len());
        for x in body_arr {
            body.push(x.as_u64()? as u8);
        }
        return Some(WirePacket { ids, body });
    }

    // body_hex как строка?
    if let Some(hex_s) = v.get("body_hex").and_then(|b| b.as_str()) {
        if let Ok(bytes) = hex::decode(hex_s) {
            return Some(WirePacket { ids, body: bytes });
        }
    }

    // body как строка (пробуем как hex)
    if let Some(body_s) = v.get("body").and_then(|b| b.as_str()) {
        if body_s.len() % 2 == 0 && body_s.chars().all(|c| c.is_ascii_hexdigit()) {
            if let Ok(bytes) = hex::decode(body_s) {
                return Some(WirePacket { ids, body: bytes });
            }
        }
    }

    None
}

// MSRV 1.74: используем % с точечным allow, чтобы не ловить clippy::manual_is_multiple_of
#[inline]
#[allow(clippy::manual_is_multiple_of)]
fn is_mult_of(n: usize, k: usize) -> bool {
    k != 0 && n % k == 0
}

fn main() {
    let args: Vec<String> = env::args().skip(1).collect();
    if args.is_empty() {
        usage();
    }
    let out_dir = PathBuf::from(&args[0]);
    let bind = flag(&args, "bind").unwrap_or_else(|| usage());
    let timeout_ms: u64 = flag(&args, "timeout-ms")
        .unwrap_or_else(|| "0".into())
        .parse()
        .unwrap_or(0);

    let _ = fs::create_dir_all(&out_dir);
    let sock = UdpSocket::bind(&bind).expect("bind");
    let _ = sock.set_read_timeout(Some(Duration::from_millis(500)));
    eprintln!("listening on {bind}, writing to {}", out_dir.display());

    // Пути
    let meta_path = out_dir.join("fountain_meta.json");
    let jsonl_path = out_dir.join("fountain_packets.jsonl");

    // Гарантируем существование jsonl сразу
    let _ = OpenOptions::new()
        .create(true)
        .append(true)
        .open(&jsonl_path);

    let mut meta: Option<RecvMeta> = None;
    let mut meta_raw_cache: Option<Vec<u8>> = None;
    let mut recv_packets_mem: Vec<WirePacket> = Vec::new();

    let mut jsonl_writer: Option<BufWriter<File>> = OpenOptions::new()
        .create(true)
        .append(true)
        .open(&jsonl_path)
        .ok()
        .map(BufWriter::new);

    let mut buf = vec![0u8; 64 * 1024];
    let start = Instant::now();

    loop {
        if timeout_ms > 0 && start.elapsed() > Duration::from_millis(timeout_ms) {
            eprintln!("timeout, no solution");
            std::process::exit(3);
        }

        match sock.recv(&mut buf[..]) {
            Ok(n) if n >= 2 && &buf[1..2] == b"\n" => match buf[0] {
                b'M' => {
                    // META (дебаунс по байтам)
                    if meta.is_none()
                        || meta_raw_cache
                            .as_ref()
                            .map(|m| m.as_slice() != &buf[2..n])
                            .unwrap_or(true)
                    {
                        let v: Value = match serde_json::from_slice(&buf[2..n]) {
                            Ok(v) => v,
                            Err(e) => {
                                eprintln!("meta parse err: {e}");
                                continue;
                            }
                        };
                        let k = v.get("k").and_then(|x| x.as_u64()).unwrap_or(0) as usize;
                        let block_len =
                            v.get("block_len").and_then(|x| x.as_u64()).unwrap_or(0) as usize;
                        let ct_len = v.get("ct_len").and_then(|x| x.as_u64()).unwrap_or(0) as usize;
                        if k == 0 || block_len == 0 || ct_len == 0 {
                            eprintln!("meta missing k/block_len/ct_len");
                            continue;
                        }
                        meta = Some(RecvMeta {
                            k,
                            block_len,
                            ct_len,
                        });
                        let _ = fs::write(&meta_path, &buf[2..n]);
                        meta_raw_cache = Some(buf[2..n].to_vec());
                        eprintln!("meta received: k={k}, block_len={block_len}, ct_len={ct_len}");
                    }
                }
                b'P' => {
                    if meta.is_none() {
                        continue;
                    }
                    let v: Value = match serde_json::from_slice(&buf[2..n]) {
                        Ok(v) => v,
                        Err(_) => continue,
                    };
                    if let Some(wp) = parse_packet_json(&v) {
                        // Копим в памяти для декодера
                        recv_packets_mem.push(WirePacket {
                            ids: wp.ids.clone(),
                            body: wp.body.clone(),
                        });

                        // И пишем в jsonl по мере приёма — в ожидаемом формате (ids + body_hex)
                        if let Some(w) = jsonl_writer.as_mut() {
                            let out = WirePacketOut {
                                ids: &wp.ids,
                                body_hex: hex::encode(&wp.body),
                            };
                            let _ = serde_json::to_writer(&mut *w, &out);
                            let _ = w.write_all(b"\n");
                            let _ = w.flush();
                        }

                        let total = recv_packets_mem.len();
                        if is_mult_of(total, 20) {
                            eprintln!("received {total} packets...");
                        }

                        // Пробуем декодировать
                        let m = meta.as_ref().unwrap();
                        let packets: Vec<Packet> = recv_packets_mem
                            .iter()
                            .map(|w| Packet {
                                ids: w.ids.clone(),
                                body: w.body.clone(),
                            })
                            .collect();

                        if let Some(decoded) = peel_decode(m.k, m.block_len, packets) {
                            let ct = join_blocks(&decoded, m.ct_len);
                            fs::write(out_dir.join("recovered_ct.bin"), &ct).expect("write ct");
                            eprintln!(
                                "DECODED: {total} packets → recovered_ct.bin ({} bytes)",
                                ct.len()
                            );
                            if let Some(mut w) = jsonl_writer.take() {
                                let _ = w.flush();
                            }
                            std::process::exit(0);
                        }
                    }
                }
                _ => {}
            },
            Ok(_) => continue,
            Err(_) => continue,
        }
    }
}
