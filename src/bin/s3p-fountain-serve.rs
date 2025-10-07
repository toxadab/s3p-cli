use rand::{rngs::StdRng, Rng, SeedableRng};
use std::{
    env,
    fs::File,
    io::{BufRead, BufReader},
    net::UdpSocket,
    thread,
    time::Duration,
};

fn usage() -> ! {
    eprintln!(
"Usage:
  s3p-fountain-serve <fountain_dir> --to=<IP:port> [--bind=<IP:port>] [--loss=<0.0..1.0>] [--pps=<N>] [--loop]

Notes:
  - <fountain_dir> должен содержать fountain_meta.json и fountain_packets.jsonl (из 's3p pack-fountain')
  - --pps   : пакетов в секунду (по умолчанию 500)
  - --loss  : искусственная вероятность дропа пакета на передающей стороне (по умолчанию 0.0)
  - --loop  : по достижении конца файла пакетов — начать заново"
    );
    std::process::exit(1)
}

fn flag(args: &[String], name: &str) -> Option<String> {
    for a in args {
        if let Some(rest) = a.strip_prefix(&format!("--{}=", name)) {
            return Some(rest.to_string());
        }
        if a.as_str() == format!("--{}", name) {
            return Some(String::new());
        }
    }
    None
}

fn main() {
    let args: Vec<String> = env::args().skip(1).collect();
    if args.is_empty() {
        usage();
    }
    let dir = std::path::PathBuf::from(&args[0]);
    let to = flag(&args, "to").unwrap_or_else(|| usage());
    let bind = flag(&args, "bind").unwrap_or_else(|| "0.0.0.0:0".to_string());
    let loss: f32 = flag(&args, "loss")
        .unwrap_or_else(|| "0".into())
        .parse()
        .unwrap_or(0.0);
    let pps: u64 = flag(&args, "pps")
        .unwrap_or_else(|| "500".into())
        .parse()
        .unwrap_or(500);
    let do_loop = flag(&args, "loop").is_some();

    let meta_path = dir.join("fountain_meta.json");
    let pkts_path = dir.join("fountain_packets.jsonl");
    if !meta_path.exists() || !pkts_path.exists() {
        eprintln!(
            "missing files in {}: need fountain_meta.json + fountain_packets.jsonl",
            dir.display()
        );
        std::process::exit(2);
    }

    let sock = UdpSocket::bind(&bind).expect("bind");
    sock.connect(&to).expect("connect");
    eprintln!(
        "serving to {} (bind={}), pps={}, loss={}",
        to, bind, pps, loss
    );

    // Meta кадр ('M\n' + json)
    let meta_bytes = std::fs::read(&meta_path).expect("read meta");
    let mut meta_frame = Vec::with_capacity(2 + meta_bytes.len());
    meta_frame.extend_from_slice(b"M\n");
    meta_frame.extend_from_slice(&meta_bytes);
    sock.send(&meta_frame).expect("send meta");
    thread::sleep(Duration::from_millis(50));
    let _ = sock.send(&meta_frame); // дубликат на старт

    let sleep_per_pkt = if pps == 0 {
        None
    } else {
        Some(Duration::from_micros(1_000_000 / pps))
    };
    let mut rng = StdRng::seed_from_u64(0xF0F0_0041u64); // валидное u64 вместо 0xF0UNT41N

    loop {
        let f = File::open(&pkts_path).expect("open packets");
        let reader = BufReader::new(f);
        let mut sent = 0usize;

        for line in reader.lines() {
            let line = match line {
                Ok(s) => s,
                Err(_) => continue,
            };
            if line.trim().is_empty() {
                continue;
            }

            // искусственная потеря
            if loss > 0.0 && rng.gen::<f32>() < loss {
                // drop
            } else {
                let mut frame = Vec::with_capacity(2 + line.len());
                frame.extend_from_slice(b"P\n");
                frame.extend_from_slice(line.as_bytes());
                let _ = sock.send(&frame);
                sent += 1;
            }

            if let Some(d) = sleep_per_pkt {
                thread::sleep(d);
            }
        }

        eprintln!("batch finished, sent={} (loop={})", sent, do_loop);
        if !do_loop {
            break;
        }
        // перед повтором продублируем мету снова
        let _ = sock.send(&meta_frame);
        thread::sleep(Duration::from_millis(200));
    }
}
