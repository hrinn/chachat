use std::convert::TryInto;
use bytes::{BufMut, BytesMut};
use mio::net::TcpStream;
use std::io::{self, prelude::*};

pub struct PDU {
    buffer: BytesMut,
}

impl PDU {
    // Creates a PDU from an existing bytes buffer
    pub fn from_bytes(bytes: BytesMut) -> PDU {
        PDU { buffer: bytes }
    }

    // Reads a packet from the TCP Stream and creates a PDU
    pub fn from_stream_read(mut stream: &TcpStream) -> PDU {
        let buffer = get_bytes_from_read(&mut stream).unwrap();
        PDU { buffer }
    }

    // Returns the length of the PDU in bytes
    pub fn get_pdu_len(&self) -> usize {
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
        self.buf[..].to_vec()
    }
}

pub struct HandlePDU {
    pdu: PDU
}

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

        HandlePDU { pdu { buffer }}
    }

    // Returns the handle as a UTF8 String
    pub fn get_handle(&self) -> String {
        let pdu_len = self.pdu.get_pdu_len();
        String::from_utf8_lossy(&self.buf[3..pdu_len]).to_string()
    }
}

pub struct MessagePDU {
    pdu: PDU,
}

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

        MessagePDU { pdu { buffer }}
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

        String::from_utf8_lossy(&self.buf[start..]).to_string()
    }
}

pub struct HandleRespPDU {
    pdu: PDU,
}

impl HandleRespPDU {
    pub fn new(accept: bool) -> HandleRespPDU {
        let mut buffer = BytesMut::with_capacity(3);
        buffer.put_u16(3);
        if accept {
            buffer.put_u8(2);
        } else {
            buffer.put_u8(3);
        }
        HandleRespPDU { pdu { buffer }}
    }

    pub fn is_accept(&self) -> bool {
        self.pdu.buffer[2] == 2
    }
}

pub fn get_bytes_from_read(mut client: &TcpStream) -> Result<BytesMut, io::Error> {
    // Read the first 2 bytes from the TCP stream, this will be the PDU Len
    let mut len_buf: [u8; 2] = [0; 2];
    client.read_exact(&mut len_buf)?;

    let len = u16::from_be_bytes(len_buf);

    // Read the remaining bytes of the PDU.
    let mut rem_buf = vec![0u8; (len - 2).into()]; 
    client.read_exact(&mut rem_buf)?;
    
    // Place the bytes in the PDU buffer
    let mut buffer = BytesMut::with_capacity(len.into());
    buffer.put_u16(len);
    buffer.put(rem_buf.as_slice());

    Ok(buffer)
}

pub fn get_flag_from_bytes(bytes: &BytesMut) -> u8 {
    bytes[2]
}