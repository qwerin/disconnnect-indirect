//! `cdctl` – jednoduché CLI nad knihovnou connect-direct.
//!
//! Připojení se bere z proměnných prostředí (nebo z přepínačů):
//!   CDWS_URL, CD_NODE_HOST, CD_NODE_PORT, CD_PROTOCOL, CD_USER, CD_PASSWORD,
//!   CDWS_CA_CERT (cesta k PEM), CDWS_INSECURE=true

use std::path::PathBuf;
use std::process::ExitCode;
use std::time::Duration;

use clap::{Args, Parser, Subcommand};
use connect_direct::{
    completion_code, extract_process_number, CdClient, Config, CopyProcess, DeleteProcess,
    Direction, Disp, Method, Protocol, Query, SubmitProcess,
};
use serde_json::Value;

#[derive(Parser)]
#[command(
    name = "cdctl",
    version,
    about = "CLI pro IBM Connect:Direct Web Services"
)]
struct Cli {
    #[command(flatten)]
    conn: Conn,
    #[command(subcommand)]
    cmd: Cmd,
}

#[derive(Args)]
struct Conn {
    /// Base URL CDWS, např. https://cdws:9443
    #[arg(long, env = "CDWS_URL", global = true, default_value = "")]
    url: String,
    /// Host C:D uzlu
    #[arg(long, env = "CD_NODE_HOST", global = true, default_value = "")]
    node_host: String,
    #[arg(long, env = "CD_NODE_PORT", global = true, default_value_t = 1363)]
    node_port: u16,
    /// TCPIP | NONE | TLS1.2 | TLS1.3 | ...
    #[arg(long, env = "CD_PROTOCOL", global = true, default_value = "TCPIP")]
    protocol: String,
    #[arg(long, env = "CD_USER", global = true, default_value = "")]
    user: String,
    #[arg(
        long,
        env = "CD_PASSWORD",
        global = true,
        default_value = "",
        hide_env_values = true
    )]
    password: String,
    /// PEM s CA certifikátem CDWS
    #[arg(long, env = "CDWS_CA_CERT", global = true)]
    ca_cert: Option<PathBuf>,
    /// Neověřovat TLS certifikát (jen test!)
    #[arg(long, env = "CDWS_INSECURE", global = true)]
    insecure: bool,
}

#[derive(Subcommand)]
enum Cmd {
    /// Verze CDWS
    Version,
    /// Submit procesu z lokálního .cdp souboru (pošle se jeho text)
    Submit {
        /// Lokální .cdp soubor
        #[arg(long, conflicts_with = "server_file")]
        file: Option<PathBuf>,
        /// Cesta k .cdp souboru na serveru C:D
        #[arg(long)]
        server_file: Option<String>,
        /// Přepsat SNODE
        #[arg(long)]
        snode: Option<String>,
        #[command(flatten)]
        wait: WaitArgs,
    },
    /// Odeslat soubor PNODE -> SNODE
    Send(CopyArgs),
    /// Stáhnout soubor SNODE -> PNODE
    Receive(CopyArgs),
    /// Statistiky procesu
    Stats {
        #[arg(long)]
        process_number: Option<u64>,
        #[arg(long)]
        process_name: Option<String>,
    },
    /// Procesy ve frontě
    Processes {
        #[arg(long)]
        process_number: Option<u64>,
        #[arg(long)]
        process_name: Option<String>,
    },
    /// Smazat proces z fronty
    Delete {
        #[arg(long)]
        process_number: u64,
        #[arg(long)]
        force: bool,
    },
    /// Libovolné volání: cdctl raw GET netmapnodes -q name=X --json '{...}'
    Raw {
        method: String,
        path: String,
        #[arg(short, long = "query", value_parser = parse_kv)]
        query: Vec<(String, String)>,
        #[arg(long)]
        json: Option<String>,
    },
}

#[derive(Args)]
struct CopyArgs {
    #[arg(long)]
    snode: String,
    #[arg(long)]
    from: String,
    #[arg(long)]
    to: String,
    /// Jméno procesu (max 8 znaků)
    #[arg(long, default_value = "CDCTL")]
    name: String,
    /// NEW | OLD | MOD | RPL | SHR
    #[arg(long, default_value = "RPL")]
    disp: Disp,
    /// SYSOPTS pro FROM, vloženo doslova (např. '":datatype=text:"')
    #[arg(long)]
    from_sysopts: Option<String>,
    #[arg(long)]
    to_sysopts: Option<String>,
    /// Jen vypsat vygenerovaný proces, nic neposílat
    #[arg(long)]
    dry_run: bool,
    #[command(flatten)]
    wait: WaitArgs,
}

#[derive(Args)]
struct WaitArgs {
    /// Počkat na dokončení procesu (polling statistik)
    #[arg(long)]
    wait: bool,
    /// Timeout čekání v sekundách
    #[arg(long, default_value_t = 600)]
    wait_timeout: u64,
}

fn parse_kv(s: &str) -> Result<(String, String), String> {
    s.split_once('=')
        .map(|(k, v)| (k.to_string(), v.to_string()))
        .ok_or_else(|| format!("expected key=value, got `{s}`"))
}

fn build_client(c: &Conn) -> Result<CdClient, Box<dyn std::error::Error>> {
    for (name, val) in [
        ("CDWS_URL / --url", &c.url),
        ("CD_NODE_HOST / --node-host", &c.node_host),
        ("CD_USER / --user", &c.user),
    ] {
        if val.is_empty() {
            return Err(format!("missing {name}").into());
        }
    }
    let mut cfg = Config::new(&c.url, &c.node_host, &c.user, &c.password);
    cfg.node_port = c.node_port;
    cfg.protocol = c.protocol.parse::<Protocol>().unwrap();
    cfg.accept_invalid_certs = c.insecure;
    if let Some(p) = &c.ca_cert {
        cfg.extra_root_certs_pem.push(std::fs::read(p)?);
    }
    Ok(CdClient::new(cfg)?)
}

fn print(v: &Value) {
    println!(
        "{}",
        serde_json::to_string_pretty(v).unwrap_or_else(|_| v.to_string())
    );
}

async fn submit_and_maybe_wait(
    client: &CdClient,
    sp: SubmitProcess,
    w: &WaitArgs,
) -> Result<bool, Box<dyn std::error::Error>> {
    let resp = client.submit_process(&sp).await?;
    print(&resp);
    if !w.wait {
        return Ok(true);
    }
    let pnum =
        extract_process_number(&resp).ok_or("process number not found in submit response")?;
    eprintln!("Čekám na dokončení procesu {pnum} ...");
    let rec = client
        .wait_for_process_end(
            pnum,
            Duration::from_secs(5),
            Duration::from_secs(w.wait_timeout),
        )
        .await?;
    print(&rec);
    let cc = completion_code(&rec);
    eprintln!("Completion code: {}", cc.as_deref().unwrap_or("?"));
    Ok(matches!(cc.as_deref(), Some("0") | None))
}

async fn run(cli: Cli) -> Result<bool, Box<dyn std::error::Error>> {
    // dry-run nepotřebuje připojení
    if let Cmd::Send(a) | Cmd::Receive(a) = &cli.cmd {
        if a.dry_run {
            let dir = if matches!(cli.cmd, Cmd::Send(_)) {
                Direction::Send
            } else {
                Direction::Receive
            };
            print!("{}", copy_process(dir, a).render()?);
            return Ok(true);
        }
    }

    let client = build_client(&cli.conn)?;
    let ok = match &cli.cmd {
        Cmd::Version => {
            print(&client.version().await?);
            true
        }
        Cmd::Submit {
            file,
            server_file,
            snode,
            wait,
        } => {
            let process_file = match (file, server_file) {
                (Some(f), _) => std::fs::read_to_string(f)?,
                (None, Some(s)) => s.clone(),
                (None, None) => return Err("use --file or --server-file".into()),
            };
            let mut sp = SubmitProcess::new(process_file);
            if let Some(s) = snode {
                sp = sp.secondary_node(s);
            }
            submit_and_maybe_wait(&client, sp, wait).await?
        }
        Cmd::Send(a) | Cmd::Receive(a) => {
            let dir = if matches!(cli.cmd, Cmd::Send(_)) {
                Direction::Send
            } else {
                Direction::Receive
            };
            let text = copy_process(dir, a).render()?;
            submit_and_maybe_wait(&client, SubmitProcess::new(text), &a.wait).await?
        }
        Cmd::Stats {
            process_number,
            process_name,
        } => {
            print(
                &client
                    .select_statistics(&query(*process_number, process_name))
                    .await?,
            );
            true
        }
        Cmd::Processes {
            process_number,
            process_name,
        } => {
            print(
                &client
                    .select_process(&query(*process_number, process_name))
                    .await?,
            );
            true
        }
        Cmd::Delete {
            process_number,
            force,
        } => {
            let mut d = DeleteProcess::by_number(*process_number);
            if *force {
                d = d.force();
            }
            print(&client.delete_process(&d).await?);
            true
        }
        Cmd::Raw {
            method,
            path,
            query: q,
            json,
        } => {
            let method = Method::from_bytes(method.to_ascii_uppercase().as_bytes())?;
            let body: Option<Value> = json.as_deref().map(serde_json::from_str).transpose()?;
            let mut query = Query::new();
            for (k, v) in q {
                query = query.param(k, v);
            }
            print(&client.call(method, path, &query, body.as_ref()).await?);
            true
        }
    };

    if let Err(e) = client.sign_out().await {
        eprintln!("warning: sign-out failed: {e}");
    }
    Ok(ok)
}

fn copy_process(dir: Direction, a: &CopyArgs) -> CopyProcess {
    let mut p = CopyProcess::new(dir, &a.name, &a.snode, &a.from, &a.to).disp(a.disp);
    if let Some(s) = &a.from_sysopts {
        p = p.from_sysopts(s);
    }
    if let Some(s) = &a.to_sysopts {
        p = p.to_sysopts(s);
    }
    p
}

fn query(n: Option<u64>, name: &Option<String>) -> Query {
    let mut q = Query::new();
    if let Some(n) = n {
        q = q.param("processNumber", n.to_string());
    }
    if let Some(name) = name {
        q = q.param("processName", name);
    }
    q
}

#[tokio::main]
async fn main() -> ExitCode {
    match run(Cli::parse()).await {
        Ok(true) => ExitCode::SUCCESS,
        Ok(false) => ExitCode::from(2),
        Err(e) => {
            eprintln!("error: {e}");
            ExitCode::FAILURE
        }
    }
}
