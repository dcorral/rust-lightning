//! A module to provide RGB functionality

use crate::io;
use crate::ln::chan_utils::{
	get_countersigner_payment_script, BuiltCommitmentTransaction, ClosingTransaction,
	CommitmentTransaction, HTLCOutputInCommitment,
};
use crate::ln::channel::{ChannelContext, ChannelError, FundingScope};
use crate::ln::channel_state::ChannelDetails;
use crate::ln::channelmanager::MsgHandleErrInternal;
use crate::ln::types::ChannelId;
use crate::sign::SignerProvider;
use crate::types::features::ChannelTypeFeatures;
use crate::types::payment::PaymentHash;
use crate::util::persist::KVStoreSync;

use bitcoin::blockdata::transaction::Transaction;
use bitcoin::hex::DisplayHex;
use bitcoin::psbt::{ExtractTxError, Psbt};
use bitcoin::secp256k1::PublicKey;
use bitcoin::TxOut;
use rgb_lib::{
	bitcoin::psbt::Psbt as RgbLibPsbt,
	wallet::{
		rust_only::{AssetColoringInfo, ColoringInfo},
		DatabaseType, WalletData,
	},
	AssetSchema, Assignment, BitcoinNetwork, ConsignmentExt, ContractId, Error as RgbLibError,
	FileContent, RgbTransfer, RgbTransport, RgbTxid, Wallet, WitnessOrd,
};
use serde::{Deserialize, Serialize};
use tokio::runtime::Handle;

use core::ops::Deref;
use std::collections::HashMap;
use std::fs;
use std::path::{Path, PathBuf};
use std::str::FromStr;

/// Static blinding costant (will be removed in the future)
pub const STATIC_BLINDING: u64 = 777;
/// Name of the file containing the bitcoin network
pub const BITCOIN_NETWORK_FNAME: &str = "bitcoin_network";
/// Name of the file containing the electrum URL
pub const INDEXER_URL_FNAME: &str = "indexer_url";
/// Name of the file containing the wallet fingerprint
pub const WALLET_FINGERPRINT_FNAME: &str = "wallet_fingerprint";
/// Name of the file containing the account-level xPub of the vanilla-side of the wallet
pub const WALLET_ACCOUNT_XPUB_VANILLA_FNAME: &str = "wallet_account_xpub_vanilla";
/// Name of the file containing the account-level xPub of the colored-side of the wallet
pub const WALLET_ACCOUNT_XPUB_COLORED_FNAME: &str = "wallet_account_xpub_colored";
/// Name of the file containing the master fingerprint of the wallet
pub const WALLET_MASTER_FINGERPRINT_FNAME: &str = "wallet_master_fingerprint";
const INBOUND_EXT: &str = "inbound";
const OUTBOUND_EXT: &str = "outbound";

/// Primary namespace for RGB data persistence
pub const RGB_PERSISTENCE_PRIMARY_NAMESPACE: &str = "rgb";
/// Secondary namespace for RGB transfer info data
pub const RGB_TRANSFER_INFO_NAMESPACE: &str = "transfer_info";
/// Secondary namespace for RGB channel info data
pub const RGB_CHANNEL_INFO_NAMESPACE: &str = "channel_info";
/// Secondary namespace for pending RGB channel info data
pub const RGB_CHANNEL_INFO_PENDING_NAMESPACE: &str = "channel_info_pending";
/// Secondary namespace for inbound RGB payment info data
pub const RGB_PAYMENT_INFO_INBOUND_NAMESPACE: &str = "payment_info_inbound";
/// Secondary namespace for outbound RGB payment info data
pub const RGB_PAYMENT_INFO_OUTBOUND_NAMESPACE: &str = "payment_info_outbound";
/// Secondary namespace for pending inbound RGB payment info data
pub const RGB_PAYMENT_INFO_INBOUND_PENDING_NAMESPACE: &str = "payment_info_inbound_pending";
/// Secondary namespace for pending outbound RGB payment info data
pub const RGB_PAYMENT_INFO_OUTBOUND_PENDING_NAMESPACE: &str = "payment_info_outbound_pending";
/// Secondary namespace for RGB consignment data
pub const RGB_CONSIGNMENT_NAMESPACE: &str = "consignment";

/// Filesystem-backed KVStore for RGB data, maintains backwards compatibility with legacy file layout
pub struct RgbFilesystemKVStore {
	base_dir: PathBuf,
}

impl RgbFilesystemKVStore {
	/// Create a new RgbFilesystemKVStore
	pub fn new(base_dir: PathBuf) -> Self {
		Self { base_dir }
	}

	fn get_path(&self, primary_namespace: &str, secondary_namespace: &str, key: &str) -> PathBuf {
		assert_eq!(primary_namespace, RGB_PERSISTENCE_PRIMARY_NAMESPACE);

		match secondary_namespace {
			RGB_TRANSFER_INFO_NAMESPACE => self.base_dir.join(format!("{}_transfer_info", key)),
			RGB_CHANNEL_INFO_NAMESPACE => self.base_dir.join(key),
			RGB_CHANNEL_INFO_PENDING_NAMESPACE => self.base_dir.join(format!("{}.pending", key)),
			RGB_PAYMENT_INFO_INBOUND_NAMESPACE => self.base_dir.join(format!("{}.inbound", key)),
			RGB_PAYMENT_INFO_OUTBOUND_NAMESPACE => self.base_dir.join(format!("{}.outbound", key)),
			RGB_PAYMENT_INFO_INBOUND_PENDING_NAMESPACE => {
				self.base_dir.join(format!("{}.inbound_pending", key))
			},
			RGB_PAYMENT_INFO_OUTBOUND_PENDING_NAMESPACE => {
				self.base_dir.join(format!("{}.outbound_pending", key))
			},
			RGB_CONSIGNMENT_NAMESPACE => self.base_dir.join(format!("consignment_{}", key)),
			_ => panic!("Unknown RGB namespace: {}", secondary_namespace),
		}
	}
}

fn std_io_err_to_io_err(e: std::io::Error) -> io::Error {
	let kind = match e.kind() {
		std::io::ErrorKind::NotFound => io::ErrorKind::NotFound,
		std::io::ErrorKind::PermissionDenied => io::ErrorKind::PermissionDenied,
		std::io::ErrorKind::AlreadyExists => io::ErrorKind::AlreadyExists,
		std::io::ErrorKind::InvalidInput => io::ErrorKind::InvalidInput,
		std::io::ErrorKind::InvalidData => io::ErrorKind::InvalidData,
		std::io::ErrorKind::UnexpectedEof => io::ErrorKind::UnexpectedEof,
		_ => io::ErrorKind::Other,
	};
	io::Error::new(kind, e.to_string())
}

impl KVStoreSync for RgbFilesystemKVStore {
	fn read(
		&self, primary_namespace: &str, secondary_namespace: &str, key: &str,
	) -> Result<Vec<u8>, io::Error> {
		let path = self.get_path(primary_namespace, secondary_namespace, key);
		fs::read(&path).map_err(std_io_err_to_io_err)
	}

	fn write(
		&self, primary_namespace: &str, secondary_namespace: &str, key: &str, buf: Vec<u8>,
	) -> Result<(), io::Error> {
		let path = self.get_path(primary_namespace, secondary_namespace, key);
		fs::write(&path, buf).map_err(std_io_err_to_io_err)
	}

	fn remove(
		&self, primary_namespace: &str, secondary_namespace: &str, key: &str, _lazy: bool,
	) -> Result<(), io::Error> {
		let path = self.get_path(primary_namespace, secondary_namespace, key);
		match fs::remove_file(&path) {
			Ok(()) => Ok(()),
			Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
			Err(e) => Err(std_io_err_to_io_err(e)),
		}
	}

	fn list(
		&self, primary_namespace: &str, secondary_namespace: &str,
	) -> Result<Vec<String>, io::Error> {
		assert_eq!(primary_namespace, RGB_PERSISTENCE_PRIMARY_NAMESPACE);

		let mut keys = Vec::new();
		let entries = match fs::read_dir(&self.base_dir) {
			Ok(e) => e,
			Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(keys),
			Err(e) => return Err(std_io_err_to_io_err(e)),
		};

		for entry in entries {
			let entry = match entry {
				Ok(e) => e,
				Err(e) => return Err(std_io_err_to_io_err(e)),
			};
			let filename = entry.file_name().to_string_lossy().to_string();

			let key = match secondary_namespace {
				RGB_TRANSFER_INFO_NAMESPACE if filename.ends_with("_transfer_info") => {
					Some(filename.trim_end_matches("_transfer_info").to_string())
				},
				RGB_CHANNEL_INFO_PENDING_NAMESPACE if filename.ends_with(".pending") => {
					Some(filename.trim_end_matches(".pending").to_string())
				},
				RGB_PAYMENT_INFO_INBOUND_NAMESPACE
					if filename.ends_with(".inbound")
						&& !filename.ends_with(".inbound_pending") =>
				{
					Some(filename.trim_end_matches(".inbound").to_string())
				},
				RGB_PAYMENT_INFO_OUTBOUND_NAMESPACE
					if filename.ends_with(".outbound")
						&& !filename.ends_with(".outbound_pending") =>
				{
					Some(filename.trim_end_matches(".outbound").to_string())
				},
				RGB_PAYMENT_INFO_INBOUND_PENDING_NAMESPACE
					if filename.ends_with(".inbound_pending") =>
				{
					Some(filename.trim_end_matches(".inbound_pending").to_string())
				},
				RGB_PAYMENT_INFO_OUTBOUND_PENDING_NAMESPACE
					if filename.ends_with(".outbound_pending") =>
				{
					Some(filename.trim_end_matches(".outbound_pending").to_string())
				},
				RGB_CONSIGNMENT_NAMESPACE if filename.starts_with("consignment_") => {
					Some(filename.trim_start_matches("consignment_").to_string())
				},
				_ => None,
			};

			if let Some(k) = key {
				keys.push(k);
			}
		}
		Ok(keys)
	}
}

/// RGB channel info
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct RgbInfo {
	/// Channel contract ID
	#[serde(with = "contract_id_serde")]
	pub contract_id: ContractId,
	/// Channel schema
	pub schema: AssetSchema,
	/// Channel RGB local amount
	pub local_rgb_amount: u64,
	/// Channel RGB remote amount
	pub remote_rgb_amount: u64,
}

/// RGB payment info
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct RgbPaymentInfo {
	/// RGB contract ID
	#[serde(with = "contract_id_serde")]
	pub contract_id: ContractId,
	/// RGB payment amount
	pub amount: u64,
	/// RGB local amount
	pub local_rgb_amount: u64,
	/// RGB remote amount
	pub remote_rgb_amount: u64,
	/// Whether the RGB amount in route should be overridden
	pub swap_payment: bool,
	/// Whether the payment is inbound
	pub inbound: bool,
}

/// RGB transfer info
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct TransferInfo {
	/// Transfer contract ID
	#[serde(with = "contract_id_serde")]
	pub contract_id: ContractId,
	/// Transfer RGB amount
	pub rgb_amount: u64,
}

mod contract_id_serde {
	use super::*;
	use serde::{Deserializer, Serializer};
	use std::str::FromStr;

	pub fn serialize<S>(id: &ContractId, serializer: S) -> Result<S::Ok, S::Error>
	where
		S: Serializer,
	{
		serializer.serialize_str(&id.to_string())
	}

	pub fn deserialize<'de, D>(deserializer: D) -> Result<ContractId, D::Error>
	where
		D: Deserializer<'de>,
	{
		let s = String::deserialize(deserializer)?;
		ContractId::from_str(&s).map_err(serde::de::Error::custom)
	}
}

fn _get_file_in_parent(ldk_data_dir: &Path, fname: &str) -> PathBuf {
	ldk_data_dir.parent().unwrap().join(fname)
}

fn _read_file_in_parent(ldk_data_dir: &Path, fname: &str) -> String {
	fs::read_to_string(_get_file_in_parent(ldk_data_dir, fname)).unwrap()
}

fn _get_rgb_wallet_dir(ldk_data_dir: &Path) -> PathBuf {
	let fingerprint = _read_file_in_parent(ldk_data_dir, WALLET_FINGERPRINT_FNAME);
	_get_file_in_parent(ldk_data_dir, &fingerprint)
}

fn _get_bitcoin_network(ldk_data_dir: &Path) -> BitcoinNetwork {
	let bitcoin_network = _read_file_in_parent(ldk_data_dir, BITCOIN_NETWORK_FNAME);
	BitcoinNetwork::from_str(&bitcoin_network).unwrap()
}

fn _get_account_xpub_colored(ldk_data_dir: &Path) -> String {
	_read_file_in_parent(ldk_data_dir, WALLET_ACCOUNT_XPUB_COLORED_FNAME)
}

fn _get_account_xpub_vanilla(ldk_data_dir: &Path) -> String {
	_read_file_in_parent(ldk_data_dir, WALLET_ACCOUNT_XPUB_VANILLA_FNAME)
}

fn _get_master_fingerprint(ldk_data_dir: &Path) -> String {
	_read_file_in_parent(ldk_data_dir, WALLET_MASTER_FINGERPRINT_FNAME)
}

fn _get_indexer_url(ldk_data_dir: &Path) -> String {
	_read_file_in_parent(ldk_data_dir, INDEXER_URL_FNAME)
}

fn _new_rgb_wallet(
	data_dir: String, bitcoin_network: BitcoinNetwork, account_xpub_vanilla: String,
	account_xpub_colored: String, master_fingerprint: String,
) -> Wallet {
	Wallet::new(WalletData {
		data_dir,
		bitcoin_network,
		database_type: DatabaseType::Sqlite,
		max_allocations_per_utxo: 1,
		account_xpub_vanilla,
		account_xpub_colored,
		master_fingerprint,
		mnemonic: None,
		vanilla_keychain: None,
		supported_schemas: vec![AssetSchema::Nia, AssetSchema::Cfa, AssetSchema::Uda],
	})
	.expect("valid rgb-lib wallet")
}

fn _get_wallet_data(ldk_data_dir: &Path) -> (String, BitcoinNetwork, String, String, String) {
	let data_dir = ldk_data_dir.parent().unwrap().to_string_lossy().to_string();
	let bitcoin_network = _get_bitcoin_network(ldk_data_dir);
	let account_xpub_vanilla = _get_account_xpub_vanilla(ldk_data_dir);
	let account_xpub_colored = _get_account_xpub_colored(ldk_data_dir);
	let master_fingerprint = _get_master_fingerprint(ldk_data_dir);
	(data_dir, bitcoin_network, account_xpub_vanilla, account_xpub_colored, master_fingerprint)
}

async fn _get_rgb_wallet(ldk_data_dir: &Path) -> Wallet {
	let (data_dir, bitcoin_network, account_xpub_vanilla, account_xpub_colored, master_fingerprint) =
		_get_wallet_data(ldk_data_dir);
	tokio::task::spawn_blocking(move || {
		_new_rgb_wallet(
			data_dir,
			bitcoin_network,
			account_xpub_vanilla,
			account_xpub_colored,
			master_fingerprint,
		)
	})
	.await
	.unwrap()
}

async fn _accept_transfer(
	ldk_data_dir: &Path, funding_txid: String, consignment_endpoint: RgbTransport,
) -> Result<(RgbTransfer, Vec<Assignment>), RgbLibError> {
	let funding_vout = 1;
	let (data_dir, bitcoin_network, account_xpub_vanilla, account_xpub_colored, master_fingerprint) =
		_get_wallet_data(ldk_data_dir);
	let indexer_url = _get_indexer_url(ldk_data_dir);
	tokio::task::spawn_blocking(move || {
		let mut wallet = _new_rgb_wallet(
			data_dir,
			bitcoin_network,
			account_xpub_vanilla,
			account_xpub_colored,
			master_fingerprint,
		);
		wallet.go_online(true, indexer_url).unwrap();
		wallet.accept_transfer(
			funding_txid.clone(),
			funding_vout,
			consignment_endpoint,
			STATIC_BLINDING,
		)
	})
	.await
	.unwrap()
}

fn get_payment_info_namespace(inbound: bool, pending: bool) -> &'static str {
	match (inbound, pending) {
		(true, true) => RGB_PAYMENT_INFO_INBOUND_PENDING_NAMESPACE,
		(true, false) => RGB_PAYMENT_INFO_INBOUND_NAMESPACE,
		(false, true) => RGB_PAYMENT_INFO_OUTBOUND_PENDING_NAMESPACE,
		(false, false) => RGB_PAYMENT_INFO_OUTBOUND_NAMESPACE,
	}
}

fn get_channel_info_namespace(pending: bool) -> &'static str {
	if pending {
		RGB_CHANNEL_INFO_PENDING_NAMESPACE
	} else {
		RGB_CHANNEL_INFO_NAMESPACE
	}
}

/// Read RGB transfer info from KVStore, with fallback to legacy file-based storage
pub fn read_rgb_transfer_info_kv<K: KVStoreSync>(
	kv_store: &K, txid: &str, ldk_data_dir: Option<&Path>,
) -> TransferInfo {
	if let Ok(bytes) =
		kv_store.read(RGB_PERSISTENCE_PRIMARY_NAMESPACE, RGB_TRANSFER_INFO_NAMESPACE, txid)
	{
		let serialized = String::from_utf8(bytes).expect("valid utf8");
		return serde_json::from_str(&serialized).expect("valid transfer info");
	}

	if let Some(dir) = ldk_data_dir {
		let path = dir.join(format!("{}_transfer_info", txid));
		if path.exists() {
			let serialized = fs::read_to_string(&path).expect("able to read");
			let info: TransferInfo = serde_json::from_str(&serialized).expect("valid");

			kv_store
				.write(
					RGB_PERSISTENCE_PRIMARY_NAMESPACE,
					RGB_TRANSFER_INFO_NAMESPACE,
					txid,
					serialized.into_bytes(),
				)
				.expect("migration write");

			let _ = fs::remove_file(&path);
			return info;
		}
	}

	panic!("transfer info not found for txid: {}", txid);
}

/// Write RGB transfer info to KVStore
pub fn write_rgb_transfer_info_kv<K: KVStoreSync>(kv_store: &K, txid: &str, info: &TransferInfo) {
	let serialized = serde_json::to_string(&info).expect("valid transfer info");
	kv_store
		.write(
			RGB_PERSISTENCE_PRIMARY_NAMESPACE,
			RGB_TRANSFER_INFO_NAMESPACE,
			txid,
			serialized.into_bytes(),
		)
		.expect("able to write transfer info")
}

/// Read RGB channel info from KVStore, with fallback to legacy file-based storage
pub fn read_rgb_channel_info_kv<K: KVStoreSync>(
	kv_store: &K, channel_id: &str, pending: bool, ldk_data_dir: Option<&Path>,
) -> RgbInfo {
	let namespace = get_channel_info_namespace(pending);

	if let Ok(bytes) = kv_store.read(RGB_PERSISTENCE_PRIMARY_NAMESPACE, namespace, channel_id) {
		let serialized = String::from_utf8(bytes).expect("valid utf8");
		return serde_json::from_str(&serialized).expect("valid rgb info");
	}

	if let Some(dir) = ldk_data_dir {
		let filename =
			if pending { format!("{}.pending", channel_id) } else { channel_id.to_string() };
		let path = dir.join(filename);
		if path.exists() {
			let serialized = fs::read_to_string(&path).expect("able to read");
			let info: RgbInfo = serde_json::from_str(&serialized).expect("valid");

			kv_store
				.write(
					RGB_PERSISTENCE_PRIMARY_NAMESPACE,
					namespace,
					channel_id,
					serialized.into_bytes(),
				)
				.expect("migration write");

			let _ = fs::remove_file(&path);
			return info;
		}
	}

	panic!("rgb channel info not found for channel_id: {}", channel_id);
}

/// Write RGB channel info to KVStore
pub fn write_rgb_channel_info_kv<K: KVStoreSync>(
	kv_store: &K, channel_id: &str, info: &RgbInfo, pending: bool,
) {
	let namespace = get_channel_info_namespace(pending);
	let serialized = serde_json::to_string(&info).expect("valid rgb info");
	kv_store
		.write(RGB_PERSISTENCE_PRIMARY_NAMESPACE, namespace, channel_id, serialized.into_bytes())
		.expect("able to write rgb info")
}

/// Check if RGB channel info exists in KVStore or legacy file storage
pub fn rgb_channel_info_exists_kv<K: KVStoreSync>(
	kv_store: &K, channel_id: &str, pending: bool, ldk_data_dir: Option<&Path>,
) -> bool {
	let namespace = get_channel_info_namespace(pending);

	if kv_store.read(RGB_PERSISTENCE_PRIMARY_NAMESPACE, namespace, channel_id).is_ok() {
		return true;
	}

	if let Some(dir) = ldk_data_dir {
		let filename =
			if pending { format!("{}.pending", channel_id) } else { channel_id.to_string() };
		let path = dir.join(filename);
		if path.exists() {
			return true;
		}
	}

	false
}

/// Remove RGB channel info from KVStore
pub fn remove_rgb_channel_info_kv<K: KVStoreSync>(kv_store: &K, channel_id: &str, pending: bool) {
	let namespace = get_channel_info_namespace(pending);
	let _ = kv_store.remove(RGB_PERSISTENCE_PRIMARY_NAMESPACE, namespace, channel_id, false);
}

/// Read RGB payment info from KVStore, with fallback to legacy file-based storage
pub fn read_rgb_payment_info_kv<K: KVStoreSync>(
	kv_store: &K, payment_hash: &str, inbound: bool, pending: bool, ldk_data_dir: Option<&Path>,
) -> RgbPaymentInfo {
	let namespace = get_payment_info_namespace(inbound, pending);

	if let Ok(bytes) = kv_store.read(RGB_PERSISTENCE_PRIMARY_NAMESPACE, namespace, payment_hash) {
		let serialized = String::from_utf8(bytes).expect("valid utf8");
		return serde_json::from_str(&serialized).expect("valid rgb payment info");
	}

	if let Some(dir) = ldk_data_dir {
		let ext = match (inbound, pending) {
			(true, true) => "inbound_pending",
			(true, false) => "inbound",
			(false, true) => "outbound_pending",
			(false, false) => "outbound",
		};
		let path = dir.join(format!("{}.{}", payment_hash, ext));
		if path.exists() {
			let serialized = fs::read_to_string(&path).expect("able to read");
			let info: RgbPaymentInfo = serde_json::from_str(&serialized).expect("valid");

			kv_store
				.write(
					RGB_PERSISTENCE_PRIMARY_NAMESPACE,
					namespace,
					payment_hash,
					serialized.into_bytes(),
				)
				.expect("migration write");

			let _ = fs::remove_file(&path);
			return info;
		}
	}

	panic!("rgb payment info not found for payment_hash: {}", payment_hash);
}

/// Write RGB payment info to KVStore
pub fn write_rgb_payment_info_kv<K: KVStoreSync>(
	kv_store: &K, payment_hash: &str, info: &RgbPaymentInfo, inbound: bool, pending: bool,
) {
	let namespace = get_payment_info_namespace(inbound, pending);
	let serialized = serde_json::to_string(&info).expect("valid rgb payment info");
	kv_store
		.write(RGB_PERSISTENCE_PRIMARY_NAMESPACE, namespace, payment_hash, serialized.into_bytes())
		.expect("able to write rgb payment info")
}

/// Check if RGB payment info exists in KVStore or legacy file storage
pub fn rgb_payment_info_exists_kv<K: KVStoreSync>(
	kv_store: &K, payment_hash: &str, inbound: bool, ldk_data_dir: Option<&Path>,
) -> bool {
	let namespace = get_payment_info_namespace(inbound, false);

	if kv_store.read(RGB_PERSISTENCE_PRIMARY_NAMESPACE, namespace, payment_hash).is_ok() {
		return true;
	}

	if let Some(dir) = ldk_data_dir {
		let ext = if inbound { "inbound" } else { "outbound" };
		let path = dir.join(format!("{}.{}", payment_hash, ext));
		if path.exists() {
			return true;
		}
	}

	false
}

/// Remove RGB payment info from KVStore
pub fn remove_rgb_payment_info_kv<K: KVStoreSync>(
	kv_store: &K, payment_hash: &str, inbound: bool, pending: bool,
) {
	let namespace = get_payment_info_namespace(inbound, pending);
	let _ = kv_store.remove(RGB_PERSISTENCE_PRIMARY_NAMESPACE, namespace, payment_hash, false);
}

/// Write RGB consignment to KVStore
pub fn write_rgb_consignment_kv<K: KVStoreSync>(
	kv_store: &K, key: &str, consignment: &RgbTransfer,
) {
	let mut bytes = Vec::new();
	consignment.save(&mut bytes).expect("valid serialization");
	kv_store
		.write(RGB_PERSISTENCE_PRIMARY_NAMESPACE, RGB_CONSIGNMENT_NAMESPACE, key, bytes)
		.expect("able to write consignment")
}

/// Read RGB consignment from KVStore, with fallback to legacy file-based storage
pub fn read_rgb_consignment_kv<K: KVStoreSync>(
	kv_store: &K, key: &str, ldk_data_dir: Option<&Path>,
) -> RgbTransfer {
	if let Ok(bytes) =
		kv_store.read(RGB_PERSISTENCE_PRIMARY_NAMESPACE, RGB_CONSIGNMENT_NAMESPACE, key)
	{
		return RgbTransfer::load(&bytes[..]).expect("valid consignment");
	}

	if let Some(dir) = ldk_data_dir {
		let path = dir.join(format!("consignment_{}", key));
		if path.exists() {
			let consignment = RgbTransfer::load_file(&path).expect("valid consignment file");

			let mut bytes = Vec::new();
			consignment.save(&mut bytes).expect("valid serialization");
			kv_store
				.write(RGB_PERSISTENCE_PRIMARY_NAMESPACE, RGB_CONSIGNMENT_NAMESPACE, key, bytes)
				.expect("migration write");

			let _ = fs::remove_file(&path);
			return consignment;
		}
	}

	panic!("consignment not found for key: {}", key);
}

/// Rename RGB channel info in KVStore from old channel ID to new channel ID
pub fn rename_rgb_channel_info_kv<K: KVStoreSync>(
	kv_store: &K, old_id: &str, new_id: &str, pending: bool, ldk_data_dir: Option<&Path>,
) {
	let info = read_rgb_channel_info_kv(kv_store, old_id, pending, ldk_data_dir);
	write_rgb_channel_info_kv(kv_store, new_id, &info, pending);
	remove_rgb_channel_info_kv(kv_store, old_id, pending);

	if let Some(dir) = ldk_data_dir {
		let filename = if pending { format!("{}.pending", old_id) } else { old_id.to_string() };
		let _ = fs::remove_file(dir.join(filename));
	}
}

/// Rename RGB consignment in KVStore from old key to new key
pub fn rename_rgb_consignment_kv<K: KVStoreSync>(
	kv_store: &K, old_key: &str, new_key: &str, ldk_data_dir: Option<&Path>,
) {
	let consignment = read_rgb_consignment_kv(kv_store, old_key, ldk_data_dir);
	write_rgb_consignment_kv(kv_store, new_key, &consignment);
	let _ = kv_store.remove(
		RGB_PERSISTENCE_PRIMARY_NAMESPACE,
		RGB_CONSIGNMENT_NAMESPACE,
		old_key,
		false,
	);

	if let Some(dir) = ldk_data_dir {
		let _ = fs::remove_file(dir.join(format!("consignment_{}", old_key)));
	}
}

/// Update RGB channel amounts based on HTLC offered and received amounts
pub fn update_rgb_channel_amount_kv<K: KVStoreSync>(
	kv_store: &K, channel_id: &str, rgb_offered_htlc: u64, rgb_received_htlc: u64, pending: bool,
	ldk_data_dir: Option<&Path>,
) {
	let mut rgb_info = read_rgb_channel_info_kv(kv_store, channel_id, pending, ldk_data_dir);

	if rgb_offered_htlc > rgb_received_htlc {
		let spent = rgb_offered_htlc - rgb_received_htlc;
		rgb_info.local_rgb_amount -= spent;
		rgb_info.remote_rgb_amount += spent;
	} else {
		let received = rgb_received_htlc - rgb_offered_htlc;
		rgb_info.local_rgb_amount += received;
		rgb_info.remote_rgb_amount -= received;
	}

	write_rgb_channel_info_kv(kv_store, channel_id, &rgb_info, pending)
}

/// Check if a payment is an RGB payment (has associated RGB payment info)
pub fn is_payment_rgb_kv<K: KVStoreSync>(
	kv_store: &K, payment_hash: &PaymentHash, ldk_data_dir: Option<&Path>,
) -> bool {
	let payment_hash_str = payment_hash.0.as_hex().to_string();
	rgb_payment_info_exists_kv(kv_store, &payment_hash_str, false, ldk_data_dir)
		|| rgb_payment_info_exists_kv(kv_store, &payment_hash_str, true, ldk_data_dir)
}

/// Filter first hops based on RGB contract ID and amount, returning the contract ID and amount
pub fn filter_first_hops_kv<K: KVStoreSync>(
	kv_store: &K, payment_hash: &PaymentHash, first_hops: &mut Vec<ChannelDetails>,
	ldk_data_dir: Option<&Path>,
) -> (ContractId, u64) {
	let payment_hash_str = payment_hash.0.as_hex().to_string();
	let rgb_payment_info =
		read_rgb_payment_info_kv(kv_store, &payment_hash_str, false, false, ldk_data_dir);
	let contract_id = rgb_payment_info.contract_id;
	let rgb_amount = rgb_payment_info.amount;

	first_hops.retain(|h| {
		let channel_id_str = h.channel_id.0.as_hex().to_string();
		if !rgb_channel_info_exists_kv(kv_store, &channel_id_str, false, ldk_data_dir) {
			return false;
		}
		let rgb_info = read_rgb_channel_info_kv(kv_store, &channel_id_str, false, ldk_data_dir);
		rgb_info.contract_id == contract_id && rgb_info.local_rgb_amount >= rgb_amount
	});

	(contract_id, rgb_amount)
}

/// Read TransferInfo file
pub fn read_rgb_transfer_info(path: &Path) -> TransferInfo {
	let filename = path.file_name().unwrap().to_string_lossy();
	let txid = filename.trim_end_matches("_transfer_info");
	let base_dir = path.parent().unwrap().to_path_buf();

	let kv_store = RgbFilesystemKVStore::new(base_dir);
	read_rgb_transfer_info_kv(&kv_store, txid, None)
}

/// Write TransferInfo file
pub fn write_rgb_transfer_info(path: &PathBuf, info: &TransferInfo) {
	let filename = path.file_name().unwrap().to_string_lossy();
	let txid = filename.trim_end_matches("_transfer_info");
	let base_dir = path.parent().unwrap().to_path_buf();

	let kv_store = RgbFilesystemKVStore::new(base_dir);
	write_rgb_transfer_info_kv(&kv_store, txid, info)
}

fn _counterparty_output_index(
	outputs: &[TxOut], channel_type_features: &ChannelTypeFeatures, payment_key: &PublicKey,
) -> Option<usize> {
	let counterparty_payment_script =
		get_countersigner_payment_script(channel_type_features, payment_key);
	outputs
		.iter()
		.enumerate()
		.find(|(_, out)| out.script_pubkey == counterparty_payment_script)
		.map(|(idx, _)| idx)
}

/// Return the position of the OP_RETURN output, if present
pub fn op_return_position(tx: &Transaction) -> Option<usize> {
	tx.output.iter().position(|o| o.script_pubkey.is_op_return())
}

/// Whether the transaction is colored (i.e. it has an OP_RETURN output)
pub fn is_tx_colored(tx: &Transaction) -> bool {
	op_return_position(tx).is_some()
}

/// Color commitment transaction
pub(crate) fn color_commitment<SP: Deref, K: KVStoreSync>(
	channel_context: &ChannelContext<SP>, funding_scope: &FundingScope,
	commitment_transaction: &mut CommitmentTransaction, counterparty: bool, kv_store: &K,
	ldk_data_dir: Option<&Path>,
) -> Result<(), ChannelError>
where
	<SP as std::ops::Deref>::Target: SignerProvider,
{
	let channel_id = &channel_context.channel_id;
	let wallet_data_dir = channel_context.ldk_data_dir.as_path();

	let commitment_tx = commitment_transaction.clone().built.transaction;

	let channel_id_str = channel_id.0.as_hex().to_string();
	let rgb_info = get_rgb_channel_info(&channel_id_str, kv_store, ldk_data_dir, true);
	let contract_id = rgb_info.contract_id;

	let chan_id = channel_id.0.as_hex();
	let mut rgb_offered_htlc = 0;
	let mut rgb_received_htlc = 0;
	let mut last_rgb_payment_info = None;
	let mut output_map = HashMap::new();

	for htlc in commitment_transaction.nondust_htlcs() {
		if htlc.rgb_payment.is_none_or(|(_, a)| a == 0) {
			continue;
		}
		let (_, htlc_amount_rgb) = htlc.rgb_payment.expect("this HTLC has RGB assets");

		let htlc_vout = htlc.transaction_output_index.unwrap();

		let inbound = htlc.offered == counterparty;

		let htlc_payment_hash = htlc.payment_hash.0.as_hex().to_string();
		let htlc_proxy_id = format!("{chan_id}{htlc_payment_hash}");

		if rgb_payment_info_exists_kv(kv_store, &htlc_payment_hash, inbound, ldk_data_dir) {
			if let Ok(mut rgb_payment_info) =
				std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
					read_rgb_payment_info_kv(
						kv_store,
						&htlc_payment_hash,
						inbound,
						true,
						ldk_data_dir,
					)
				})) {
				rgb_payment_info.local_rgb_amount = rgb_info.local_rgb_amount;
				rgb_payment_info.remote_rgb_amount = rgb_info.remote_rgb_amount;
				write_rgb_payment_info_kv(
					kv_store,
					&htlc_proxy_id,
					&rgb_payment_info,
					inbound,
					false,
				);
				remove_rgb_payment_info_kv(kv_store, &htlc_payment_hash, inbound, true);
			}
		}

		let rgb_payment_info =
			if rgb_payment_info_exists_kv(kv_store, &htlc_proxy_id, inbound, ldk_data_dir) {
				read_rgb_payment_info_kv(kv_store, &htlc_proxy_id, inbound, false, ldk_data_dir)
			} else {
				let rgb_payment_info = RgbPaymentInfo {
					contract_id,
					amount: htlc_amount_rgb,
					local_rgb_amount: rgb_info.local_rgb_amount,
					remote_rgb_amount: rgb_info.remote_rgb_amount,
					swap_payment: true,
					inbound,
				};
				write_rgb_payment_info_kv(
					kv_store,
					&htlc_proxy_id,
					&rgb_payment_info,
					inbound,
					false,
				);
				write_rgb_payment_info_kv(
					kv_store,
					&htlc_payment_hash,
					&rgb_payment_info,
					inbound,
					false,
				);
				rgb_payment_info
			};

		if inbound {
			rgb_received_htlc += rgb_payment_info.amount
		} else {
			rgb_offered_htlc += rgb_payment_info.amount
		};

		output_map.insert(htlc_vout, rgb_payment_info.amount);

		last_rgb_payment_info = Some(rgb_payment_info);
	}

	let (local_amt, remote_amt) = if let Some(last_rgb_payment_info) = last_rgb_payment_info {
		(
			last_rgb_payment_info.local_rgb_amount - rgb_offered_htlc,
			last_rgb_payment_info.remote_rgb_amount - rgb_received_htlc,
		)
	} else {
		(rgb_info.local_rgb_amount, rgb_info.remote_rgb_amount)
	};
	let (vout_p2wpkh_amt, vout_p2wsh_amt) =
		if counterparty { (local_amt, remote_amt) } else { (remote_amt, local_amt) };

	let payment_point = if counterparty {
		funding_scope.get_holder_pubkeys().payment_point
	} else {
		funding_scope.get_counterparty_pubkeys().payment_point
	};

	if let Some(vout_p2wpkh) = _counterparty_output_index(
		&commitment_tx.output,
		funding_scope.get_channel_type(),
		&payment_point,
	) {
		output_map.insert(vout_p2wpkh as u32, vout_p2wpkh_amt);
	}

	if let Some(vout_p2wsh) = commitment_transaction.trust().revokeable_output_index() {
		output_map.insert(vout_p2wsh as u32, vout_p2wsh_amt);
	}

	let asset_coloring_info =
		AssetColoringInfo { output_map, static_blinding: Some(STATIC_BLINDING) };
	let coloring_info = ColoringInfo {
		asset_info_map: HashMap::from_iter([(contract_id, asset_coloring_info)]),
		static_blinding: Some(STATIC_BLINDING),
		nonce: None,
	};
	let psbt = Psbt::from_unsigned_tx(commitment_tx.clone()).unwrap();
	let mut psbt = RgbLibPsbt::from_str(&psbt.to_string()).unwrap();
	let handle = Handle::current();
	let _ = handle.enter();
	let wallet = futures::executor::block_on(_get_rgb_wallet(wallet_data_dir));
	let (fascia, _) = wallet.color_psbt(&mut psbt, coloring_info).unwrap();
	let psbt = Psbt::from_str(&psbt.to_string()).unwrap();
	let modified_tx = match psbt.extract_tx() {
		Ok(tx) => tx,
		Err(ExtractTxError::MissingInputValue { tx }) => tx,
		Err(e) => panic!("should never happen: {e}"),
	};

	let txid = modified_tx.compute_txid();
	commitment_transaction.built = BuiltCommitmentTransaction { transaction: modified_tx, txid };

	wallet
		.consume_fascia(
			fascia.clone(),
			RgbTxid::from_str(&txid.to_string()).unwrap(),
			Some(WitnessOrd::Ignored),
		)
		.unwrap();

	// save RGB transfer data to KVStore
	let rgb_amount = if counterparty {
		vout_p2wpkh_amt + rgb_offered_htlc
	} else {
		vout_p2wsh_amt + rgb_received_htlc
	};
	let transfer_info = TransferInfo { contract_id, rgb_amount };
	write_rgb_transfer_info_kv(kv_store, &txid.to_string(), &transfer_info);

	Ok(())
}

/// Color HTLC transaction
pub(crate) fn color_htlc<K: KVStoreSync>(
	htlc_tx: &mut Transaction, htlc: &HTLCOutputInCommitment, kv_store: &K,
	ldk_data_dir: Option<&Path>,
) -> Result<(), ChannelError> {
	if htlc.rgb_payment.is_none_or(|(_, a)| a == 0) {
		return Ok(());
	}
	let (_, htlc_amount_rgb) = htlc.rgb_payment.expect("this HTLC has RGB assets");

	let consignment_htlc_outpoint = htlc_tx.input.first().unwrap().previous_output;
	let commitment_txid = consignment_htlc_outpoint.txid.to_string();

	let transfer_info = read_rgb_transfer_info_kv(kv_store, &commitment_txid, ldk_data_dir);
	let contract_id = transfer_info.contract_id;

	let asset_coloring_info = AssetColoringInfo {
		output_map: HashMap::from([(0, htlc_amount_rgb)]),
		static_blinding: Some(STATIC_BLINDING),
	};
	let coloring_info = ColoringInfo {
		asset_info_map: HashMap::from_iter([(contract_id, asset_coloring_info)]),
		static_blinding: Some(STATIC_BLINDING),
		nonce: Some(1),
	};
	let psbt = Psbt::from_unsigned_tx(htlc_tx.clone()).unwrap();
	let mut psbt = RgbLibPsbt::from_str(&psbt.to_string()).unwrap();
	let handle = Handle::current();
	let _ = handle.enter();
	let wallet_data_dir = ldk_data_dir.expect("ldk_data_dir required for RGB HTLC coloring");
	let wallet = futures::executor::block_on(_get_rgb_wallet(wallet_data_dir));
	let (fascia, _) = wallet.color_psbt(&mut psbt, coloring_info).unwrap();
	let psbt = Psbt::from_str(&psbt.to_string()).unwrap();
	let modified_tx = match psbt.extract_tx() {
		Ok(tx) => tx,
		Err(ExtractTxError::MissingInputValue { tx }) => tx,
		Err(e) => panic!("should never happen: {e}"),
	};
	let txid = &modified_tx.compute_txid();

	wallet
		.consume_fascia(
			fascia.clone(),
			RgbTxid::from_str(&txid.to_string()).unwrap(),
			Some(WitnessOrd::Ignored),
		)
		.unwrap();

	// save RGB transfer data to KVStore
	let transfer_info = TransferInfo { contract_id, rgb_amount: htlc_amount_rgb };
	write_rgb_transfer_info_kv(kv_store, &txid.to_string(), &transfer_info);

	Ok(())
}

/// Color closing transaction
pub(crate) fn color_closing<K: KVStoreSync>(
	channel_id: &ChannelId, closing_transaction: &mut ClosingTransaction, kv_store: &K,
	ldk_data_dir: Option<&Path>,
) -> Result<(), ChannelError> {
	let closing_tx = closing_transaction.clone().built;

	let rgb_info =
		get_rgb_channel_info(&channel_id.0.as_hex().to_string(), kv_store, ldk_data_dir, true);
	let contract_id = rgb_info.contract_id;

	let holder_vout_amount = rgb_info.local_rgb_amount;
	let counterparty_vout_amount = rgb_info.remote_rgb_amount;

	let mut output_map = HashMap::new();

	if closing_transaction.to_holder_value_sat() > 0 {
		let holder_vout = closing_tx
			.output
			.iter()
			.position(|o| &o.script_pubkey == closing_transaction.to_holder_script())
			.unwrap();
		output_map.insert(holder_vout as u32, holder_vout_amount);
	}

	if closing_transaction.to_counterparty_value_sat() > 0 {
		let counterparty_vout = closing_tx
			.output
			.iter()
			.position(|o| &o.script_pubkey == closing_transaction.to_counterparty_script())
			.unwrap();
		output_map.insert(counterparty_vout as u32, counterparty_vout_amount);
	}

	let asset_coloring_info =
		AssetColoringInfo { output_map, static_blinding: Some(STATIC_BLINDING) };
	let coloring_info = ColoringInfo {
		asset_info_map: HashMap::from_iter([(contract_id, asset_coloring_info)]),
		static_blinding: Some(STATIC_BLINDING),
		nonce: None,
	};
	let psbt = Psbt::from_unsigned_tx(closing_tx.clone()).unwrap();
	let mut psbt = RgbLibPsbt::from_str(&psbt.to_string()).unwrap();
	let handle = Handle::current();
	let _ = handle.enter();
	let wallet_data_dir = ldk_data_dir.expect("ldk_data_dir required for RGB closing coloring");
	let wallet = futures::executor::block_on(_get_rgb_wallet(wallet_data_dir));
	let (fascia, _) = wallet.color_psbt(&mut psbt, coloring_info).unwrap();
	let psbt = Psbt::from_str(&psbt.to_string()).unwrap();
	let modified_tx = match psbt.extract_tx() {
		Ok(tx) => tx,
		Err(ExtractTxError::MissingInputValue { tx }) => tx,
		Err(e) => panic!("should never happen: {e}"),
	};

	let txid = &modified_tx.compute_txid();
	closing_transaction.built = modified_tx;

	wallet
		.consume_fascia(
			fascia.clone(),
			RgbTxid::from_str(&txid.to_string()).unwrap(),
			Some(WitnessOrd::Ignored),
		)
		.unwrap();

	// save RGB transfer data to KVStore
	let transfer_info = TransferInfo { contract_id, rgb_amount: holder_vout_amount };
	write_rgb_transfer_info_kv(kv_store, &txid.to_string(), &transfer_info);

	Ok(())
}

/// Get RgbPaymentInfo file path
pub fn get_rgb_payment_info_path(
	payment_hash: &PaymentHash, ldk_data_dir: &Path, inbound: bool,
) -> PathBuf {
	let mut path = ldk_data_dir.join(payment_hash.0.as_hex().to_string());
	path.set_extension(if inbound { INBOUND_EXT } else { OUTBOUND_EXT });
	path
}

/// Parse RgbPaymentInfo
pub fn parse_rgb_payment_info(rgb_payment_info_path: &PathBuf) -> RgbPaymentInfo {
	let filename = rgb_payment_info_path.file_name().unwrap().to_string_lossy();
	let base_dir = rgb_payment_info_path.parent().unwrap().to_path_buf();

	let (payment_hash, inbound, pending) = if filename.ends_with(".inbound_pending") {
		(filename.trim_end_matches(".inbound_pending"), true, true)
	} else if filename.ends_with(".outbound_pending") {
		(filename.trim_end_matches(".outbound_pending"), false, true)
	} else if filename.ends_with(".inbound") {
		(filename.trim_end_matches(".inbound"), true, false)
	} else if filename.ends_with(".outbound") {
		(filename.trim_end_matches(".outbound"), false, false)
	} else {
		panic!("Invalid payment info path: {}", filename);
	};

	let kv_store = RgbFilesystemKVStore::new(base_dir);
	read_rgb_payment_info_kv(&kv_store, payment_hash, inbound, pending, None)
}

/// Get RgbInfo file path
pub fn get_rgb_channel_info_path(channel_id: &str, ldk_data_dir: &Path, pending: bool) -> PathBuf {
	let mut info_file_path = ldk_data_dir.join(channel_id);
	if pending {
		info_file_path.set_extension("pending");
	}
	info_file_path
}

/// Get RgbInfo file
pub(crate) fn get_rgb_channel_info<K: KVStoreSync>(
	channel_id: &str, kv_store: &K, ldk_data_dir: Option<&Path>, pending: bool,
) -> RgbInfo {
	read_rgb_channel_info_kv(kv_store, channel_id, pending, ldk_data_dir)
}

/// Get pending RgbInfo file
pub fn get_rgb_channel_info_pending(
	channel_id: &ChannelId, ldk_data_dir: &Path,
) -> (RgbInfo, PathBuf) {
	let kv_store = RgbFilesystemKVStore::new(ldk_data_dir.to_path_buf());
	let info = get_rgb_channel_info(&channel_id.0.as_hex().to_string(), &kv_store, None, true);
	let info_file_path =
		get_rgb_channel_info_path(&channel_id.0.as_hex().to_string(), ldk_data_dir, true);
	(info, info_file_path)
}

/// Parse RgbInfo
pub fn parse_rgb_channel_info(rgb_channel_info_path: &PathBuf) -> RgbInfo {
	let filename = rgb_channel_info_path.file_name().unwrap().to_string_lossy();
	let base_dir = rgb_channel_info_path.parent().unwrap().to_path_buf();

	let (channel_id, pending) = if filename.ends_with(".pending") {
		(filename.trim_end_matches(".pending").to_string(), true)
	} else {
		(filename.to_string(), false)
	};

	let kv_store = RgbFilesystemKVStore::new(base_dir);
	read_rgb_channel_info_kv(&kv_store, &channel_id, pending, None)
}

/// Whether the channel data for a channel exist
pub fn is_channel_rgb(channel_id: &ChannelId, ldk_data_dir: &Path) -> bool {
	let kv_store = RgbFilesystemKVStore::new(ldk_data_dir.to_path_buf());
	rgb_channel_info_exists_kv(&kv_store, &channel_id.0.as_hex().to_string(), false, None)
}

/// Write RgbInfo file
pub fn write_rgb_channel_info(path: &PathBuf, rgb_info: &RgbInfo) {
	let filename = path.file_name().unwrap().to_string_lossy();
	let base_dir = path.parent().unwrap().to_path_buf();

	let (channel_id, pending) = if filename.ends_with(".pending") {
		(filename.trim_end_matches(".pending").to_string(), true)
	} else {
		(filename.to_string(), false)
	};

	let kv_store = RgbFilesystemKVStore::new(base_dir);
	write_rgb_channel_info_kv(&kv_store, &channel_id, rgb_info, pending)
}

fn _append_pending_extension(path: &Path) -> PathBuf {
	let mut new_path = path.to_path_buf();
	new_path.set_extension(format!("{}_pending", new_path.extension().unwrap().to_string_lossy()));
	new_path
}

/// Write RGB payment info to file
pub fn write_rgb_payment_info_file(
	ldk_data_dir: &Path, payment_hash: &PaymentHash, contract_id: ContractId, amount_rgb: u64,
	swap_payment: bool, inbound: bool,
) {
	let payment_hash_str = payment_hash.0.as_hex().to_string();
	let rgb_payment_info = RgbPaymentInfo {
		contract_id,
		amount: amount_rgb,
		local_rgb_amount: 0,
		remote_rgb_amount: 0,
		swap_payment,
		inbound,
	};

	let kv_store = RgbFilesystemKVStore::new(ldk_data_dir.to_path_buf());
	write_rgb_payment_info_kv(&kv_store, &payment_hash_str, &rgb_payment_info, inbound, false);
	write_rgb_payment_info_kv(&kv_store, &payment_hash_str, &rgb_payment_info, inbound, true);
}

/// Rename RGB files from temporary to final channel ID
pub(crate) fn rename_rgb_files<K: KVStoreSync>(
	channel_id: &ChannelId, temporary_channel_id: &ChannelId, kv_store: &K,
	ldk_data_dir: Option<&Path>,
) {
	let temp_chan_id = temporary_channel_id.0.as_hex().to_string();
	let chan_id = channel_id.0.as_hex().to_string();

	rename_rgb_channel_info_kv(kv_store, &temp_chan_id, &chan_id, false, ldk_data_dir);
	rename_rgb_channel_info_kv(kv_store, &temp_chan_id, &chan_id, true, ldk_data_dir);

	if kv_store
		.read(RGB_PERSISTENCE_PRIMARY_NAMESPACE, RGB_CONSIGNMENT_NAMESPACE, &temp_chan_id)
		.is_ok()
	{
		rename_rgb_consignment_kv(kv_store, &temp_chan_id, &chan_id, ldk_data_dir);
	}
}

/// Handle funding on the receiver side
pub(crate) fn handle_funding<K: KVStoreSync>(
	temporary_channel_id: &ChannelId, funding_txid: String, ldk_data_dir: &Path,
	consignment_endpoint: RgbTransport, kv_store: &K,
) -> Result<(), MsgHandleErrInternal> {
	let handle = Handle::current();
	let _ = handle.enter();
	let accept_res = futures::executor::block_on(_accept_transfer(
		ldk_data_dir,
		funding_txid.clone(),
		consignment_endpoint,
	));
	let (consignment, remote_rgb_assignments) = match accept_res {
		Ok(res) => res,
		Err(RgbLibError::InvalidConsignment) => {
			return Err(MsgHandleErrInternal::send_err_msg_no_close(
				"Invalid RGB consignment for funding".to_owned(),
				*temporary_channel_id,
			))
		},
		Err(RgbLibError::NoConsignment) => {
			return Err(MsgHandleErrInternal::send_err_msg_no_close(
				"Failed to find RGB consignment".to_owned(),
				*temporary_channel_id,
			))
		},
		Err(RgbLibError::UnknownRgbSchema { schema_id }) => {
			return Err(MsgHandleErrInternal::send_err_msg_no_close(
				format!("Unknown RGB schema: {schema_id}"),
				*temporary_channel_id,
			))
		},
		Err(RgbLibError::UnsupportedSchema { asset_schema }) => {
			return Err(MsgHandleErrInternal::send_err_msg_no_close(
				format!("Unsupported RGB schema: {asset_schema}"),
				*temporary_channel_id,
			))
		},
		Err(e) => {
			return Err(MsgHandleErrInternal::send_err_msg_no_close(
				format!("Unexpected error: {e}"),
				*temporary_channel_id,
			))
		},
	};

	write_rgb_consignment_kv(kv_store, &funding_txid, &consignment);
	let temporary_channel_id_str = temporary_channel_id.0.as_hex().to_string();
	write_rgb_consignment_kv(kv_store, &temporary_channel_id_str, &consignment);

	if remote_rgb_assignments.len() != 1 {
		return Err(MsgHandleErrInternal::send_err_msg_no_close(
			format!("Unexpected number of RGB assignments: {}", remote_rgb_assignments.len()),
			*temporary_channel_id,
		));
	}
	let remote_rgb_amount = match remote_rgb_assignments[0] {
		Assignment::Fungible(amt) => amt,
		Assignment::NonFungible => 1,
		_ => unreachable!("unsupported schema"),
	};
	let rgb_info = RgbInfo {
		contract_id: consignment.contract_id(),
		schema: AssetSchema::from_schema_id(consignment.schema_id()).unwrap(),
		local_rgb_amount: 0,
		remote_rgb_amount,
	};
	write_rgb_channel_info_kv(kv_store, &temporary_channel_id_str, &rgb_info, true);
	write_rgb_channel_info_kv(kv_store, &temporary_channel_id_str, &rgb_info, false);

	Ok(())
}

/// Update RGB channel amount
pub fn update_rgb_channel_amount(
	channel_id: &str, rgb_offered_htlc: u64, rgb_received_htlc: u64, ldk_data_dir: &Path,
	pending: bool,
) {
	let kv_store = RgbFilesystemKVStore::new(ldk_data_dir.to_path_buf());
	update_rgb_channel_amount_kv(
		&kv_store,
		channel_id,
		rgb_offered_htlc,
		rgb_received_htlc,
		pending,
		None,
	)
}

/// Update pending RGB channel amount
pub(crate) fn update_rgb_channel_amount_pending<K: KVStoreSync>(
	channel_id: &ChannelId, rgb_offered_htlc: u64, rgb_received_htlc: u64, kv_store: &K,
	ldk_data_dir: Option<&Path>,
) {
	update_rgb_channel_amount_kv(
		kv_store,
		&channel_id.0.as_hex().to_string(),
		rgb_offered_htlc,
		rgb_received_htlc,
		true,
		ldk_data_dir,
	)
}

/// Whether the payment is colored
pub(crate) fn is_payment_rgb<K: KVStoreSync>(
	kv_store: &K, payment_hash: &PaymentHash, ldk_data_dir: Option<&Path>,
) -> bool {
	is_payment_rgb_kv(kv_store, payment_hash, ldk_data_dir)
}

/// Detect the contract ID of the payment and then filter hops based on contract ID and amount
pub(crate) fn filter_first_hops<K: KVStoreSync>(
	kv_store: &K, payment_hash: &PaymentHash, first_hops: &mut Vec<ChannelDetails>,
	ldk_data_dir: Option<&Path>,
) -> (ContractId, u64) {
	filter_first_hops_kv(kv_store, payment_hash, first_hops, ldk_data_dir)
}
