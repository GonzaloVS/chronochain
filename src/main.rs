use chronochain::TimestampRequest;
fn main() {
    let data = b"Esto es un documento importante";

    let tsa_urls = vec![
        "https://rfc3161timestamp.globalsign.com/advanced".into()
    ];

    match TimestampRequest::new(data).with_tsas(tsa_urls).generate() {
        Ok(ts) => {
            println!("✅ Timestamp: {}", ts.timestamp);
            println!("🧾 TSA signature: {} bytes", ts.tsa_signature.len());
        }
        Err(e) => {
            eprintln!("❌ Error: {}", e);
        }
    }
}
