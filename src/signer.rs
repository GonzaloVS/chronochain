use ring::digest::{Context, SHA256};
use ring::signature::{Ed25519KeyPair, KeyPair, ED25519};

static KEYPAIR_BYTES: [u8; 32] = [13; 32]; // Genera y guarda una real en producción

pub fn hash_data(data: &[u8]) -> Vec<u8> {
    let mut ctx = Context::new(&SHA256);
    ctx.update(data);
    ctx.finish().as_ref().to_vec()
}

pub fn sign_data(data: &[u8]) -> Result<Vec<u8>, Box<dyn std::error::Error + Send + Sync>> {
    let keypair = Ed25519KeyPair::from_seed_unchecked(&KEYPAIR_BYTES)
        .map_err(|e| format!("KeyRejected: {:?}", e))?;
    let sig = keypair.sign(data);
    Ok(sig.as_ref().to_vec())
}

pub fn verify_signature(data: &[u8], sig: &[u8]) -> Result<(), ring::error::Unspecified> {
    let keypair = Ed25519KeyPair::from_seed_unchecked(&KEYPAIR_BYTES)?;
    ring::signature::UnparsedPublicKey::new(&ED25519, keypair.public_key().as_ref())
        .verify(data, sig)
}
