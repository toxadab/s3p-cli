use clap::{Parser, Subcommand};

#[derive(Parser)]
#[command(name="s3p", version, about="BlockNet S³P CLI")]
struct Cli {
    #[command(subcommand)]
    cmd: Cmd,
}

#[derive(Subcommand)]
enum Cmd {
    /// Pack a file into RS shards (and optional fountain)
    Pack {
        input: String,
        out_dir: String,
        #[arg(long, default_value_t=20)] data: usize,
        #[arg(long, default_value_t=8)] parity: usize,
        #[arg(long)] ikm_hex: Option<String>,
        #[arg(long)] salt_hex: Option<String>,
        #[arg(long)] aad: Option<String>,
    },
    /// Unpack (RS / fountain / stream)
    Unpack {
        in_path: String,
        output: String,
        #[arg(long)] ikm_hex: Option<String>,
        #[arg(long)] salt_hex: Option<String>,
    },
    /// PoD sign/verify/aggregate
    Pod {
        #[command(subcommand)]
        sub: PodCmd
    },
    /// Fountain pack/unpack (offline files)
    Fountain {
        #[command(subcommand)]
        sub: FountainCmd
    },
}

#[derive(Subcommand)]
enum PodCmd {
    Sign   { dir: String, #[arg(long)] sk_hex: String },
    Verify { dir: String },
    Agg    { dir: String, #[arg(long, default_value="pod_epoch.json")] out: String },
}

#[derive(Subcommand)]
enum FountainCmd {
    Pack {
        input: String, out_dir: String,
        #[arg(long, default_value_t=32)] k: usize,
        #[arg(long, default_value_t=2.0)] overhead: f32,
        #[arg(long, default_value_t=42)] seed: u64,
        #[arg(long)] ikm_hex: Option<String>,
        #[arg(long)] salt_hex: Option<String>,
        #[arg(long)] aad: Option<String>,
    },
    Unpack {
        in_path: String, output: String,
        #[arg(long)] ikm_hex: Option<String>,
        #[arg(long)] salt_hex: Option<String>,
    }
}

fn main() {
    let cli = Cli::parse();
    match cli.cmd {
        Cmd::Pack { input, out_dir, data, parity, ikm_hex, salt_hex, aad } => {
            // TODO: вызвать s3p_core::* как у тебя делалось в старом s3p.rs
            // pack -> rs_encode -> (опционально fountain) -> записать out_dir
            println!("pack {input} -> {out_dir} (d={data}, p={parity})");
        }
        Cmd::Unpack { in_path, output, ikm_hex, salt_hex } => {
            // TODO: rs_reconstruct / unpack-fountain / stream
            println!("unpack {in_path} -> {output}");
        }
        Cmd::Pod { sub } => match sub {
            PodCmd::Sign { dir, sk_hex } => { println!("pod sign {dir}"); }
            PodCmd::Verify { dir } => { println!("pod verify {dir}"); }
            PodCmd::Agg { dir, out } => { println!("pod agg {dir} -> {out}"); }
        },
        Cmd::Fountain { sub } => match sub {
            FountainCmd::Pack { input, out_dir, k, overhead, seed, ikm_hex, salt_hex, aad } => {
                println!("fountain pack {input} -> {out_dir} (k={k}, overhead={overhead}, seed={seed})");
            }
            FountainCmd::Unpack { in_path, output, ikm_hex, salt_hex } => {
                println!("fountain unpack {in_path} -> {output}");
            }
        }
    }
}
