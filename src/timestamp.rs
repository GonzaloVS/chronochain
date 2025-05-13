use crate::tsa;
use crate::signer;
use chrono::{DateTime, Utc};

pub struct TimestampRequest<'a> {
    pub data: &'a [u8],
    pub tsa_urls: Vec<String>,
}

pub struct TrustedTimestamp {
    pub timestamp: DateTime<Utc>,
    pub tsa_signature: Vec<u8>,
    pub local_signature: Vec<u8>,
    pub hash: Vec<u8>,
}

impl<'a> TimestampRequest<'a> {
    pub fn new(data: &'a [u8]) -> Self {
        Self {
            data,
            tsa_urls: vec![],
        }
    }

    pub fn with_tsas(mut self, urls: Vec<String>) -> Self {
        self.tsa_urls = urls;
        self
    }

    pub fn generate(self) -> Result<TrustedTimestamp, Box<dyn std::error::Error + Send + Sync>> {
        let hash = signer::hash_data(self.data);
        let tsa_response = tsa::get_timestamp_from_tsa(&hash, &self.tsa_urls)?;
        let local_signature = signer::sign_data(&hash)?;

        Ok(TrustedTimestamp {
            timestamp: tsa_response.timestamp,
            tsa_signature: tsa_response.signature,
            local_signature,
            hash,
        })
    }
}

impl TrustedTimestamp {
    /// Verifica la firma local (de momento) del timestamp
    pub fn verify(&self) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        signer::verify_signature(&self.hash, &self.local_signature)
            .map_err(|e| Box::<dyn std::error::Error + Send + Sync>::from(format!("Signature error: {:?}", e)))?;
        // En el futuro aquí también se debería verificar tsa_signature
        Ok(())
    }
}


#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_generate_real_timestamp() {
        let data = b"Documento de prueba para sello de tiempo";

        let result = TimestampRequest::new(data)
            .with_tsas(vec![
                "https://rfc3161timestamp.globalsign.com/advanced".into()
            ])
            .generate();

        match result {
            Ok(stamp) => {
                println!("✅ Timestamp: {}", stamp.timestamp);
                println!("🧾 TSA signature bytes: {}", stamp.tsa_signature.len());
                println!("🔐 Local signature bytes: {}", stamp.local_signature.len());

                assert!(stamp.tsa_signature.len() > 10, "TSA signature debería existir");
            },
            Err(e) => panic!("❌ Error generando timestamp: {}", e),
        }
    }
}
