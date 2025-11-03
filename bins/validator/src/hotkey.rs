use anyhow::Result;
use sp_core::crypto::Ss58Codec;
use sp_core::{sr25519, Pair};
use tracing::info;

pub fn derive_hotkey_from_mnemonic(mnemonic: &str) -> Result<String> {
    let (pair, _seed) = sr25519::Pair::from_phrase(mnemonic, None)
        .map_err(|e| anyhow::anyhow!("Failed to derive keypair from mnemonic: {}", e))?;

    let ss58_address = pair.public().to_ss58check();
    info!("Derived hotkey from mnemonic: {}", ss58_address);

    Ok(ss58_address)
}

pub fn get_keypair_from_mnemonic(mnemonic: &str) -> Result<sr25519::Pair> {
    let (pair, _seed) = sr25519::Pair::from_phrase(mnemonic, None)
        .map_err(|e| anyhow::anyhow!("Failed to derive keypair from mnemonic: {}", e))?;

    Ok(pair)
}

pub fn sign_message(mnemonic: &str, message: &[u8]) -> Result<sr25519::Signature> {
    let pair = get_keypair_from_mnemonic(mnemonic)?;
    let signature = pair.sign(message);
    Ok(signature)
}
