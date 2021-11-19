use std::error::Error;
use std::path::Path;
use std::fs::File;
use rsa::{RsaPrivateKey, RsaPublicKey};
use rsa::pkcs1::{ToRsaPrivateKey, ToRsaPublicKey};
use rand::rngs::OsRng;

use chachat::get_public_key_path;
use chachat::get_private_key_path;

pub fn keygen(handle: &str) -> Result<(), Box<dyn Error>> {
    let private_key_path = get_private_key_path(handle);
    let public_key_path = get_public_key_path(handle);

    println!("Generating private key at {}...", private_key_path);
    println!("Generating public key at {}...", public_key_path);

    let public_key_path = Path::new(&public_key_path);
    let private_key_path = Path::new(&private_key_path);

    // Generate the RSA keys
    let mut rng = OsRng;
    let bits = 2048;
    let private_key = RsaPrivateKey::new(&mut rng, bits)?;
    let public_key = RsaPublicKey::from(&private_key);

    // Create the files
    File::create(private_key_path)?;
    File::create(public_key_path)?;

    // Write the keys to the files
    private_key.write_pkcs1_pem_file(private_key_path)?;
    public_key.write_pkcs1_pem_file(public_key_path)?;

    Ok(())
}