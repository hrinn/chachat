use std::convert::TryInto;
use std::error::Error;
use std::fmt;
use bytes::{BufMut, BytesMut};
use tokio::net::tcp::OwnedReadHalf;
use tokio::io::*;
use chacha20poly1305::{ChaCha20Poly1305 as ChaCha20, Key};
use chacha20poly1305::aead::NewAead;
use rand::prelude::*;
use rand_chacha::ChaCha20Rng;
use rand_seeder::Seeder;

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

pub struct HandleRespPDU {
    pdu: PDU,
}

pdu_impl!(HandleRespPDU);
impl HandleRespPDU {
    pub fn new(accept: bool) -> HandleRespPDU {
        let mut buffer = BytesMut::with_capacity(3);
        buffer.put_u16(3);
        if accept {
            buffer.put_u8(2);
        } else {
            buffer.put_u8(3);
        }
        HandleRespPDU { pdu: PDU { buffer }}
    }

    pub fn is_accept(&self) -> bool {
        self.pdu.buffer[2] == 2
    }
}

pub struct KeyExchangePDU {
    pdu: PDU,
}

pdu_impl!(KeyExchangePDU);
impl KeyExchangePDU {
    pub fn new(src_handle: &str, dest_handle: &str, sig: &[u8], key: &[u8]) -> KeyExchangePDU {
        let len = 3 + 1 + src_handle.len() + 1 + dest_handle.len() + 1 + sig.len() + key.len();

        let mut buffer = BytesMut::with_capacity(len);

        buffer.put_u16(len.try_into().unwrap());
        buffer.put_u8(4);
        buffer.put_u8(src_handle.len().try_into().unwrap());
        buffer.put(src_handle.as_bytes());
        buffer.put_u8(dest_handle.len().try_into().unwrap());
        buffer.put(dest_handle.as_bytes());
        buffer.put_u8(sig.len().try_into().unwrap());
        buffer.put(sig);
        buffer.put(key);

        KeyExchangePDU { pdu: PDU {buffer }}
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
        self.pdu.buffer[5 + src_handle_len + dest_handle_len].into()
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
    nonce_gen: ChaCha20Rng,
}

impl SessionInfo {
    pub fn from_key(key: &[u8]) -> SessionInfo {
        SessionInfo {
            cipher: ChaCha20::new(Key::from_slice(key)),
            nonce_gen: Seeder::from(key).make_rng(),
        }
    }

    pub fn get_cipher(&self) -> &ChaCha20 {
        &self.cipher
    }

    pub fn next_nonce(&mut self) -> Vec<u8> {
        let mut nonce = [0u8; 12];
        self.nonce_gen.fill(&mut nonce);
        nonce.to_vec()
    }
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