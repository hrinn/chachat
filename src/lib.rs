use std::convert::TryInto;
use bytes::{BufMut, BytesMut};
use tokio::net::TcpStream;
use std::error::Error;
use std::fmt;

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
    pub fn new(src_handle: &str, dest_handle: &str, message: &str) -> MessagePDU {
        let len = 3 + src_handle.len() + 1 + dest_handle.len() + 1 + message.len();

        // Create bytes buffer
        let mut buffer = BytesMut::with_capacity(len);

        // Fill bytes buffer
        buffer.put_u16(len.try_into().unwrap());               // PDU Length
        buffer.put_u8(7);                                      // Flag
        buffer.put_u8(src_handle.len().try_into().unwrap());   // Src Handle Len
        buffer.put(src_handle.as_bytes());                     // Src Handle
        buffer.put_u8(dest_handle.len().try_into().unwrap());  // Dest Handle Len
        buffer.put(dest_handle.as_bytes());                    // Dest Handle
        buffer.put(message.as_bytes());                        // Message

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

    pub fn get_message(&self) -> String {
        let start = 5 + self.get_src_handle_len() + self.get_dest_handle_len();

        String::from_utf8_lossy(&self.pdu.buffer[start..]).to_string()
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

pub async fn read_stream(client: &TcpStream, buf: &mut[u8]) -> Result<usize, Box<dyn Error>> {
    client.readable().await?;
    let n = match client.try_read(buf) {
        Ok(0) => {
            return Err(Box::new(ClientDisconnectError{}))
        },
        Ok(n) => {
            n
        },
        Err(e) => {
            return Err(e.into());
        }
    };

    Ok(n)
}

pub async fn write_stream(client: &TcpStream, buf: &[u8]) -> usize {
    client.writable().await.unwrap();
    client.try_write(buf).expect("failed to write to client")
}

pub async fn read_pdu(client: &TcpStream) -> Result<BytesMut, Box<dyn Error>> {
    let mut len_buf: [u8; 2] = [0; 2];
    let n_read = read_stream(client, &mut len_buf).await?;
    if n_read != 2 {
        panic!("invalid pdu");
    }

    let len = u16::from_be_bytes(len_buf);
    // Read the remaining bytes of the PDU.
    let rem_len: usize = (len-2).into();
    let mut rem_buf = vec![0u8; rem_len]; 
    let n_read = read_stream(client, rem_buf.as_mut()).await?;
    if n_read != rem_len {
        panic!("invalid pdu");
    }
    
    // Place the bytes in the PDU buffer
    let mut buffer = BytesMut::with_capacity(len.into());
    buffer.put_u16(len);
    buffer.put(rem_buf.as_slice());

    Ok(buffer)
}

pub fn get_flag_from_bytes(bytes: &BytesMut) -> u8 {
    bytes[2]
}