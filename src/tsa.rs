use chrono::{DateTime, Utc};
use rfc3161::{TimestampRequest, TimestampResponse};
use std::time::SystemTime;
use crate::TimestampRequest;

pub struct TsaResponse {
    pub timestamp: DateTime<Utc>,
    pub signature: Vec<u8>,
}

pub fn get_timestamp_from_tsa(
    hash: &[u8],
    tsa_urls: &[String],
) -> Result<TsaResponse, Box<dyn std::error::Error + Send + Sync>> {
    if tsa_urls.is_empty() {
        return Err("No TSA URLs provided".into());
    }

    let tsa_url = &tsa_urls[0];

    let req = TimestampRequest::from_digest_sha256(hash)?;
    let der = req.encode()?;

    let client = reqwest::blocking::Client::new();
    let res = client
        .post(tsa_url)
        .header("Content-Type", "application/timestamp-query")
        .body(der)
        .send()?;

    let body = res.bytes()?;
    let tsr = TimestampResponse::from_der(&body)?;

    let time = tsr
        .gen_time()
        .unwrap_or(SystemTime::now()); // Fallback en caso de fallo

    let timestamp = DateTime::<Utc>::from(time);

    Ok(TsaResponse {
        timestamp,
        signature: body.to_vec(),
    })
}
