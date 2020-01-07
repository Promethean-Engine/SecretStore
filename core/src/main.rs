extern crate parity_bytes as bytes;
extern crate parity_crypto as crypto;

use codec::{Decode, Encode};

use jsonrpc_core_client::transports::local;
use jsonrpc_core::futures::future::{self, Future, FutureResult};
use jsonrpc_core::{Error, IoHandler, Result};
use jsonrpc_derive::rpc;

mod database;
mod keys;
mod math;
mod types;

#[rpc]
pub trait Rpc {
	#[rpc(name = "protocolVersion")]
	fn protocol_version(&self) -> Result<String>;

	#[rpc(name = "add", alias("callAsyncMetaAlias"))]
	fn add(&self, a: u64, b: u64) -> Result<u64>;

	#[rpc(name = "callAsync")]
	fn call(&self, a: u64) -> FutureResult<String, Error>;
}

struct RpcImpl;

impl Rpc for RpcImpl {
	fn protocol_version(&self) -> Result<String> {
		Ok("version1".into())
	}

	fn add(&self, a: u64, b: u64) -> Result<u64> {
		Ok(a + b)
	}

	fn call(&self, _: u64) -> FutureResult<String, Error> {
		future::ok("OK".to_owned())
	}
}

fn main() {
	let mut io = IoHandler::new();
	io.extend_with(RpcImpl.to_delegate());

	let fut = {
		let (client, server) = local::connect::<gen_client::Client, _, _>(io);
		client.add(5, 6).map(|res| println!("5 + 6 = {}", res)).join(server)
	};
	fut.wait().unwrap();
}