use std::io;
use std::error::Error;
use std::path::Path;
use std::fs::File;
use std::env;
use rsa::{RsaPrivateKey, RsaPublicKey};
use rsa::pkcs1::{ToRsaPrivateKey, ToRsaPublicKey};
use rand::rngs::OsRng;

use chachat::expand_tilde;

pub fn keygen() -> Result<(), Box<dyn Error>> {
    let default_path = format!("{}/.chachat/id_rsa", env::var("HOME")?);
    println!("Enter file in which to save the key ({}):", default_path);

    // Get paths for keys
    let mut private_key_path = String::new();
    io::stdin().read_line(&mut private_key_path)?;
    let private_key_path = match private_key_path.trim() {
        "" => default_path,
        path => expand_tilde(path),
    };
    let public_key_path = format!("{}.pub", private_key_path);

    let public_key_path = Path::new(&public_key_path);
    let private_key_path = Path::new(&private_key_path);

    // Generate the RSA keys
    println!("Generating key...");
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