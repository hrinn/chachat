use std::convert::TryInto;
use bytes::{BufMut, BytesMut};
use std::net::TcpStream;
use std::io::prelude::*;

pub struct HandlePDU {
    buf: BytesMut,
}

impl HandlePDU {
    // Creates a HandlePDU from a handle
    pub fn from_handle(handle: &str) -> HandlePDU {
        // Create bytes buffer
        let mut buf = BytesMut::with_capacity(handle.len() + 3);

        // Fill bytes buffer
        let header_len: u16 = (handle.len() + 3).try_into().unwrap();
        buf.put_u16(header_len);
        buf.put_u8(1);
        buf.put(handle.as_bytes());

        HandlePDU { buf }
    }

    // Reads a PDU from a TCP Stream and creates a HandlePDU
    pub fn read_pdu(mut client: &TcpStream) -> HandlePDU {
        let buf = bytes_from_read(&mut client);
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

fn bytes_from_read(mut client: &TcpStream) -> BytesMut {
    // Read the first 2 bytes from the TCP stream, this will be the PDU Len
    let mut len_buf: [u8; 2] = [0; 2];
    client.read_exact(&mut len_buf).unwrap();
    let len = u16::from_be_bytes(len_buf);

    // Read the remaining bytes of the PDU.
    let mut rem_buf = vec![0u8; (len - 2).into()]; 
    client.read_exact(&mut rem_buf).unwrap();
    
    // Place the bytes in the PDU buffer
    let mut buffer = BytesMut::with_capacity(len.into());
    buffer.put_u16(len);
    buffer.put(rem_buf.as_slice());

    buffer
}