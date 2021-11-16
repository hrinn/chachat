use std::convert::TryInto;
use std::error::Error;
use std::fmt;
use std::fs::File;
use std::io::Read;
use std::env;
use bytes::{BufMut, BytesMut};
use rand::rngs::OsRng;
use rand_chacha::ChaCha20Rng;
use rand::prelude::*;
use rsa::pkcs1::{FromRsaPrivateKey, FromRsaPublicKey};
use rsa::{PaddingScheme, RsaPrivateKey, RsaPublicKey, PublicKey};
use tokio::net::tcp::OwnedReadHalf;
use tokio::io::*;
use chacha20poly1305::{ChaCha20Poly1305 as ChaCha20, Key};
use chacha20poly1305::aead::NewAead;
use sha2::{Sha256, Digest};

pub struct PDU {
    buffer: BytesMut,
}

macro_rules! pdu_impl {
    ($t:ident) => {
        impl $t {
            // Creates a PDU from an existing bytes buffer
            pub fn from_bytes(bytes: BytesMut) -> $t {
                $t { pdu: PDU::from_bytes(bytes) }
            }

             // Returns the length of the PDU in bytes
            pub fn len(&self) -> usize {
                self.pdu.len()
            }

            // Returns the flag of the PDU
            pub fn get_flag(&self) -> u8 {
                self.pdu.get_flag()
            }

            // Returns a bytes slice representation of the buffer
            pub fn as_bytes(&self) -> &[u8] {
                self.pdu.as_bytes()
            }

            // Returns a vector representation of the buffer
            pub fn as_vec(&self) -> Vec<u8> {
                self.pdu.as_vec()
            }
        }
    }
}

impl PDU {
    // Creates a PDU from an existing bytes buffer
    pub fn from_bytes(bytes: BytesMut) -> PDU {
        PDU { buffer: bytes }
    }

    // Returns the length of the PDU in bytes
    pub fn len(&self) -> usize {
        let len_slice: [u8; 2] = self.buffer[0..2]
            .try_into().unwrap();
        u16::from_be_bytes(len_slice).into()
    }

    // Returns the flag of the PDU
    pub fn get_flag(&self) -> u8 {
        self.buffer[2]
    }

    // Returns a bytes slice representation of the buffer
    pub fn as_bytes(&self) -> &[u8] {
        &self.buffer[..]
    }

    // Returns a vector representation of the buffer
    pub fn as_vec(&self) -> Vec<u8> {
        self.buffer[..].to_vec()
    }
}

pub struct HandlePDU {
    pdu: PDU
}

pdu_impl!(HandlePDU);
impl HandlePDU {
    // Creates a HandlePDU from a handle
    pub fn new(handle: &str) -> HandlePDU {
        // Create bytes buffer
        let mut buffer = BytesMut::with_capacity(handle.len() + 3);

        // Fill bytes buffer
        let header_len: u16 = (handle.len() + 3).try_into().unwrap();
        buffer.put_u16(header_len);    // PDU Length
        buffer.put_u8(1);              // Flag
        buffer.put(handle.as_bytes()); // Handle

        HandlePDU { pdu: PDU { buffer }}
    }

    // Returns the handle as a UTF8 String
    pub fn get_handle(&self) -> String {
        String::from_utf8_lossy(&self.pdu.buffer[3..self.pdu.len()]).to_string()
    }
}

pub struct MessagePDU {
    pdu: PDU,
}

pdu_impl!(MessagePDU);
impl MessagePDU {
    pub fn new(src_handle: &str, dest_handle: &str, nonce: &[u8], ciphertext: &[u8]) -> MessagePDU {
        let len = 3 + 1 + src_handle.len() + 1 + dest_handle.len() + 12 + ciphertext.len();

        // Create bytes buffer
        let mut buffer = BytesMut::with_capacity(len);

        // Fill bytes buffer
        buffer.put_u16(len.try_into().unwrap());                // PDU Length [2B]
        buffer.put_u8(7);                                       // Flag [1B]
        buffer.put_u8(src_handle.len().try_into().unwrap());    // Src Handle Len [1B]
        buffer.put(src_handle.as_bytes());                      // Src Handle
        buffer.put_u8(dest_handle.len().try_into().unwrap());   // Dest Handle Len [1B]
        buffer.put(dest_handle.as_bytes());                     // Dest Handle
        buffer.put(nonce);                                      // Nonce [12B]
        buffer.put(ciphertext);                                 // Message

        MessagePDU { pdu: PDU { buffer }}
    }

    pub fn get_src_handle_len(&self) -> usize {
        self.pdu.buffer[3].into()
    }

    pub fn get_src_handle(&self) -> String {
        let start = 4;
        let end = start + self.get_src_handle_len();

        String::from_utf8_lossy(&self.pdu.buffer[start..end]).to_string()
    }

    pub fn get_dest_handle_len(&self) -> usize {
        let src_handle_len = self.get_src_handle_len();
        self.pdu.buffer[src_handle_len + 4].into()
    }

    pub fn get_dest_handle(&self) -> String {
        let start = self.get_src_handle_len() + 5;
        let end = start + self.get_dest_handle_len();

        String::from_utf8_lossy(&self.pdu.buffer[start..end]).to_string()
    }

    pub fn get_nonce(&self) -> &[u8] {
        let start = 5 + self.get_src_handle_len() + self.get_dest_handle_len();
        let end = start + 12;
        &self.pdu.buffer[start..end]
    }

    pub fn get_ciphertext(&self) -> &[u8] {
        let start = 17 + self.get_src_handle_len() + self.get_dest_handle_len();
        &self.pdu.buffer[start..]
    }
}

pub struct FlagOnlyPDU {
    pdu: PDU,
}

pdu_impl!(FlagOnlyPDU);
impl FlagOnlyPDU {
    pub fn new(flag: u8) -> FlagOnlyPDU {
        let mut buffer = BytesMut::with_capacity(3);
        buffer.put_u16(3);
        buffer.put_u8(flag);
        FlagOnlyPDU { pdu: PDU { buffer }}
    }
}

pub struct KeyExchangePDU {
    pdu: PDU,
}

pdu_impl!(KeyExchangePDU);
impl KeyExchangePDU {
    pub fn new(src_handle: &str, dest_handle: &str, sig: &[u8], key: &[u8]) -> KeyExchangePDU {

        let len = 3 + 1 + src_handle.len() + 1 + dest_handle.len() + 1 + sig.len() + key.len() + 32;

        let mut buffer = BytesMut::with_capacity(len);
        let sig_block_size = sig.len() / 256;

        buffer.put_u16(len.try_into().unwrap());                // PDU Length
        buffer.put_u8(4);                                       // Flag
        buffer.put_u8(src_handle.len().try_into().unwrap());    // Src Handle Len
        buffer.put(src_handle.as_bytes());                      // Src Handle
        buffer.put_u8(dest_handle.len().try_into().unwrap());   // Dest Handle Len
        buffer.put(dest_handle.as_bytes());                     // Dest Handle
        buffer.put_u8(sig_block_size.try_into().unwrap());      // Signature Len (blocks of 256B)
        buffer.put(sig);                                        // Signature
        buffer.put(key);                                        // Encrypted Key

        let mut hasher = Sha256::new();                         
        hasher.update(buffer.to_vec());
        let digest = hasher.finalize();
        buffer.put(digest.as_slice());

        KeyExchangePDU { pdu: PDU { buffer }}
    }

    pub fn get_src_handle_len(&self) -> usize {
        self.pdu.buffer[3].into()
    }

    pub fn get_src_handle(&self) -> String {
        let start = 4;
        let end = start + self.get_src_handle_len();

        String::from_utf8_lossy(&self.pdu.buffer[start..end]).to_string()
    }

    pub fn get_dest_handle_len(&self) -> usize {
        let src_handle_len = self.get_src_handle_len();
        self.pdu.buffer[src_handle_len + 4].into()
    }

    pub fn get_dest_handle(&self) -> String {
        let start = self.get_src_handle_len() + 5;
        let end = start + self.get_dest_handle_len();

        String::from_utf8_lossy(&self.pdu.buffer[start..end]).to_string()
    }

    pub fn get_signature_len(&self) -> usize {
        let src_handle_len = self.get_src_handle_len();
        let dest_handle_len = self.get_dest_handle_len();
        let blocksize: usize = self.pdu.buffer[5 + src_handle_len + dest_handle_len].into();
        return blocksize * 256;
    }

    pub fn get_signature(&self) -> &[u8] {
        let start = self.get_src_handle_len() + self.get_dest_handle_len() + 6;
        let end = start + self.get_signature_len();
        
        &self.pdu.buffer[start..end]
    }

    pub fn get_key(&self) -> &[u8] {
        let start = self.get_src_handle_len() + self.get_dest_handle_len() + self.get_signature_len() + 6;

        &self.pdu.buffer[start..]
    }
}

#[derive(Debug)]
pub struct ClientDisconnectError;
impl fmt::Display for ClientDisconnectError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "Client disconnect") // user-facing output
    }
}

impl Error for ClientDisconnectError {
    fn description(&self) -> &str {
       return "client disconnect";
    }
}

pub struct SessionInfo {
    cipher: ChaCha20,
}

impl SessionInfo {
    pub fn from_key(key: &[u8]) -> SessionInfo {
        SessionInfo {
            cipher: ChaCha20::new(Key::from_slice(key)),
        }
    }

    pub fn get_cipher(&self) -> &ChaCha20 {
        &self.cipher
    }
}

pub struct RSAInfo {
    private_key: RsaPrivateKey,
    rng: OsRng,
    session_key_gen: ChaCha20Rng,
}

impl RSAInfo {
    pub fn new(key_str: &str) -> RSAInfo {
        let private_key = RsaPrivateKey::from_pkcs1_pem(key_str).unwrap();
        let rng = OsRng;
        let session_key_gen = ChaCha20Rng::from_entropy();

        RSAInfo { private_key, rng, session_key_gen }
    }

    // Hash with SHA256 and encrypt with my private key
    pub fn sign(&mut self, data: &[u8]) -> Vec<u8> {
        let padding = PaddingScheme::new_pkcs1v15_sign(Some(rsa::Hash::SHA2_256));

        // Hash data with Sha256
        let mut hasher = Sha256::new();
        hasher.update(data);
        let digest = hasher.finalize();

        // Sign with private key
        self.private_key.sign(padding, &digest).expect("Failed to RSA sign")
    }

    // Encrypt with other's public key
    pub fn encrypt(&mut self, data: &[u8], key_str: &str) -> Vec<u8> {
        let public_key = RsaPublicKey::from_pkcs1_pem(key_str).unwrap();
        let padding = PaddingScheme::new_pkcs1v15_encrypt();
        public_key.encrypt(&mut self.rng, padding, data).expect("Failed to RSA encrypt")
    }

    // Decrypt with my private key
    pub fn decrypt(&mut self, ciphertext: &[u8]) -> Vec<u8> {
        let padding = PaddingScheme::new_pkcs1v15_encrypt();
        self.private_key.decrypt(padding, ciphertext).expect("Failed to RSA decrypt")
    }

    // Decrypt with other's public key
    pub fn verify(&mut self, sig: &[u8], expected: &str, key_str: &str) -> std::result::Result<(), rsa::errors::Error> {
        let public_key = RsaPublicKey::from_pkcs1_pem(key_str).unwrap();
        let padding = PaddingScheme::new_pkcs1v15_sign(Some(rsa::Hash::SHA2_256));

        // Hash expected
        let mut hasher = Sha256::new();
        hasher.update(expected);
        let digest = hasher.finalize();

        // Verify hash with public key
        public_key.verify(padding, &digest, sig)
    }

    pub fn generate_session_key(&mut self) -> Vec<u8> {
        let mut key = [0u8; 32];
        self.session_key_gen.fill(&mut key);
        key.to_vec()
    }
}

pub fn key_path_to_str(key_path: &str) -> Result<String> {
    let key_path = expand_tilde(key_path);
    let mut file = File::open(&key_path)?;
    let mut contents = String::new();
    file.read_to_string(&mut contents)?;
    Ok(contents)
}

pub async fn read_pdu(client: &mut OwnedReadHalf) -> Result<BytesMut> {
    let mut len_buf: [u8; 2] = [0; 2];
    client.read_exact(&mut len_buf).await?;

    let len = u16::from_be_bytes(len_buf);

    // Read the remaining bytes of the PDU.
    let rem_len: usize = (len-2).into();
    let mut rem_buf = vec![0u8; rem_len]; 

    client.read_exact(&mut rem_buf).await?;
    
    // Place the bytes in the PDU buffer
    let mut buffer = BytesMut::with_capacity(len.into());
    buffer.put_u16(len);
    buffer.put(rem_buf.as_slice());

    Ok(buffer)
}

pub fn get_flag_from_bytes(bytes: &BytesMut) -> u8 {
    bytes[2]
}

// Replaces ~'s in a path with the user's home directory
pub fn expand_tilde(path: &str) -> String {
    // Find location of ~ and split string
    let i = match path.find('~') {
        Some(i) => i,
        None => return path.to_string(),
    };

    let p1 = &path[..i];
    let p2 = &path[i+1..];

    format!("{}{}{}", p1, env::var("HOME").unwrap(), p2)
}