//! # connect-direct
//!
//! Async klient pro **IBM Sterling Connect:Direct Web Services (CDWS)** REST API.
//!
//! ```no_run
//! use connect_direct::{CdClient, Config, CopyProcess, SubmitProcess, extract_process_number};
//!
//! # async fn run() -> connect_direct::Result<()> {
//! let client = CdClient::new(Config::new(
//!     "https://cdws.example.com:9443", "cdnode1.example.com", "cduser", "secret",
//! ))?;
//!
//! let text = CopyProcess::send("PAYOUT", "PARTNER01", "/data/out/pay.csv", "/in/pay.csv").render()?;
//! let resp = client.submit_process(&SubmitProcess::new(text)).await?;
//! println!("process number: {:?}", extract_process_number(&resp));
//!
//! client.sign_out().await?;
//! # Ok(()) }
//! ```

mod client;
mod error;
mod models;
mod process;

pub use client::{CdClient, Config, Credentials};
pub use error::{Error, Result};
pub use models::{
    completion_code, extract_process_number, find_stat_record, DeleteProcess, Protocol, Query,
    SubmitProcess,
};
pub use process::{CopyProcess, Direction, Disp};

/// Re-export, aby šlo volat [`CdClient::call`] bez přímé závislosti na reqwest.
pub use reqwest::Method;
