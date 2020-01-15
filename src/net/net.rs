use std::io::prelude::*;
use std::net::{TcpListener, TcpStream};

pub fn send(addr: String, port: String, msg: bytes::Bytes) -> Result<(), std::io::Error> {
    let mut stream = TcpStream::connect(format!("{}:{}", addr, port))?;

    stream.write(&[1])?;
    stream.read(&mut [0; 128])?;

    Ok(())
}

pub fn recv(addr: String, port: String) -> bytes::Bytes {
    let listener = TcpListener::bind("127.0.0.1:80").unwrap();
}