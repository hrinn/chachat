use std::convert::TryInto;
use bytes::{BufMut, BytesMut};
use mio::net::TcpStream;
use std::io::{self, prelude::*};

pub struct HandlePDU {
    // Application level PDU for establishing user handle
    // Length: 2B
    // Flag 1: 1B
    // Handle: 1-100B
    buf: BytesMut,
}

impl HandlePDU {
    // Creates a HandlePDU from a handle
    pub fn new(handle: &str) -> HandlePDU {
        // Create bytes buffer
        let mut buf = BytesMut::with_capacity(handle.len() + 3);

        // Fill bytes buffer
        let header_len: u16 = (handle.len() + 3).try_into().unwrap();
        buf.put_u16(header_len);    // PDU Length
        buf.put_u8(1);              // Flag
        buf.put(handle.as_bytes()); // Handle

        HandlePDU { buf }
    }

    // Reads a PDU from a TCP Stream and creates a HandlePDU
    pub fn read_pdu(mut client: &TcpStream) -> HandlePDU {
        let buf = get_bytes_from_read(&mut client).unwrap();
        HandlePDU { buf }
    }

    // Returns an array of bytes of the entire PDU
    pub fn as_bytes(&self) -> &[u8] {
        &self.buf[..]
    }

    // Returns the length of the pdu
    pub fn get_pdu_len(&self) -> usize {
        let len_bytes: [u8; 2] = self.buf[0..2]
            .try_into()
            .expect("Slice with incorrect length");
        u16::from_be_bytes(len_bytes).into()
    }

    // Returns the handle as a UTF8 String
    pub fn get_handle(&self) -> String {
        let pdu_len = self.get_pdu_len();
        String::from_utf8_lossy(&self.buf[3..pdu_len]).to_string()
    }
}

pub struct MessagePDU {
    // Application level PDU for sending a message to another user
    // Length: 2B
    // Flag 5: 1B
    // Src Handle Length: 1B
    // Src Handle: 1-100B
    // Dest Handle Length: 1B
    // Dest Handle: 1-100B
    // Message: 1-3891B
    buf: BytesMut,
}

impl MessagePDU {
    pub fn new(src_handle: &str, dest_handle: &str, message: &str) -> MessagePDU {
        let len = 3 + src_handle.len() + 1 + dest_handle.len() + 1 + message.len();

        // Create bytes buffer
        let mut buf = BytesMut::with_capacity(len);

        // Fill bytes buffer
        buf.put_u16(len.try_into().unwrap());               // PDU Length
        buf.put_u8(7);                                      // Flag
        buf.put_u8(src_handle.len().try_into().unwrap());   // Src Handle Len
        buf.put(src_handle.as_bytes());                     // Src Handle
        buf.put_u8(dest_handle.len().try_into().unwrap());  // Dest Handle Len
        buf.put(dest_handle.as_bytes());                    // Dest Handle
        buf.put(message.as_bytes());                        // Message

        MessagePDU { buf }
    }

    pub fn from_bytes(bytes: BytesMut) -> MessagePDU {
        // Trim bytes to only necessary size
        MessagePDU { buf: bytes }
    }

    pub fn get_pdu_len(&self) -> usize {
        let len_bytes: [u8; 2] = self.buf[0..2]
            .try_into()
            .expect("Slice with incorrect length");
        u16::from_be_bytes(len_bytes).into()
    }

    pub fn get_src_handle_len(&self) -> usize {
        self.buf[3].into()
    }

    pub fn get_src_handle(&self) -> String {
        let start = 4;
        let end = start + self.get_src_handle_len();

        String::from_utf8_lossy(&self.buf[start..end]).to_string()
    }

    pub fn get_dest_handle_len(&self) -> usize {
        let src_handle_len = self.get_src_handle_len();
        self.buf[src_handle_len + 4].into()
    }

    pub fn get_dest_handle(&self) -> String {
        let start = self.get_src_handle_len() + 5;
        let end = start + self.get_dest_handle_len();

        String::from_utf8_lossy(&self.buf[start..end]).to_string()
    }

    pub fn get_message(&self) -> String {
        let start = 5 + self.get_src_handle_len() + self.get_dest_handle_len();

        String::from_utf8_lossy(&self.buf[start..]).to_string()
    }

    // Returns an array of bytes of the entire PDU
    pub fn as_bytes(&self) -> &[u8] {
        &self.buf[..]
    }

    pub fn as_vec(&self) -> Vec<u8> {
        self.buf[..].to_vec()
    }
}

pub struct HandleRespPDU {
    // PDU for accepting/rejecting handle
    // Length: 2B
    // Flag: 1B (2 = accept, 3 = reject)
    buf: BytesMut,
}

impl HandleRespPDU {
    pub fn new(accept: bool) -> HandleRespPDU {
        let mut buf = BytesMut::with_capacity(3);
        buf.put_u16(3);
        if accept {
            buf.put_u8(2);
        } else {
            buf.put_u8(3);
        }
        HandleRespPDU { buf }
    }

    pub fn read_pdu(mut client: &TcpStream) -> HandleRespPDU {
        let buf = get_bytes_from_read(&mut client).unwrap();
        HandleRespPDU { buf }
    }

    pub fn is_accept(&self) -> bool {
        self.buf[2] == 2
    }

     // Returns an array of bytes of the entire PDU
     pub fn as_bytes(&self) -> &[u8] {
        &self.buf[..]
    }
}

pub fn get_bytes_from_read(mut client: &TcpStream) -> Result<BytesMut, io::Error> {
    // Read the first 2 bytes from the TCP stream, this will be the PDU Len
    let mut len_buf: [u8; 2] = [0; 2];
    client.read_exact(&mut len_buf)?;

    let len = u16::from_be_bytes(len_buf);

    // Read the remaining bytes of the PDU.
    let mut rem_buf = vec![0u8; (len - 2).into()]; 
    client.read_exact(&mut rem_buf).unwrap();
    
    // Place the bytes in the PDU buffer
    let mut buffer = BytesMut::with_capacity(len.into());
    buffer.put_u16(len);
    buffer.put(rem_buf.as_slice());

    Ok(buffer)
}

pub fn get_flag_from_bytes(bytes: &BytesMut) -> u8 {
    bytes[2]
}