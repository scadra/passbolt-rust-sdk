// Passbolt ~ Open source password manager for teams
// Copyright (c) Passbolt SA (https://www.passbolt.com)
//
// Licensed under GNU Affero General Public License version 3 of the or any later version.
// For full copyright and license information, please see the LICENSE
// Redistributions of files must retain the above copyright notice.
//
// @copyright     Copyright (c) Passbolt SA (https://www.passbolt.com)
// @license       https://opensource.org/licenses/AGPL-3.0 AGPL License
// @link          https://www.passbolt.com Passbolt(tm)
// @since         0.1.0

//! KDBX 3.1 and 4.x reader: AES-KDF or Argon2, AES-256-CBC or `ChaCha20`, Salsa20 or
//! `ChaCha20` protected values, as the browser extension reads them. A file may be locked by
//! a password, a key file, both or neither.

use std::io::Read;

use aes::cipher::{generic_array::GenericArray, KeyIvInit, StreamCipher};
use aes::Aes256;
use anyhow::{bail, ensure, Context, Result};
use base64::{engine::general_purpose::STANDARD as BASE64, Engine};
use cbc::cipher::{block_padding::Pkcs7, BlockDecryptMut};
use chacha20::ChaCha20;
use hmac::{Hmac, Mac};
use salsa20::Salsa20;
use sha2::{Digest, Sha256, Sha512};
use xml::reader::{EventReader, XmlEvent};
use zeroize::Zeroizing;

use super::kdbx3::{aes_kdf, sha256};

const SIGNATURE: [u8; 8] = [0x03, 0xD9, 0xA2, 0x9A, 0x67, 0xFB, 0x4B, 0xB5];
const AES256_CIPHER: [u8; 16] = [
    0x31, 0xC1, 0xF2, 0xE6, 0xBF, 0x71, 0x43, 0x50, 0xBE, 0x58, 0x05, 0x21, 0x6A, 0xFC, 0x5A, 0xFF,
];
const CHACHA20_CIPHER: [u8; 16] = [
    0xD6, 0x03, 0x8A, 0x2B, 0x8B, 0x6F, 0x4C, 0xB5, 0xA5, 0x24, 0x33, 0x9A, 0x31, 0xDB, 0xB5, 0x9A,
];
const AES_KDF: [u8; 16] = [
    0xC9, 0xD9, 0xF3, 0x9A, 0x62, 0x8A, 0x44, 0x60, 0xBF, 0x74, 0x0D, 0x08, 0xC1, 0x8A, 0x4F, 0xEA,
];
const ARGON2D_KDF: [u8; 16] = [
    0xEF, 0x63, 0x6D, 0xDF, 0x8C, 0x29, 0x44, 0x4B, 0x91, 0xF7, 0xA9, 0xA4, 0x03, 0xE3, 0x0A, 0x0C,
];
const ARGON2ID_KDF: [u8; 16] = [
    0x9E, 0x29, 0x8B, 0x19, 0x56, 0xDB, 0x47, 0x73, 0xB2, 0x3D, 0xFC, 0x3E, 0xC6, 0xF0, 0xA1, 0xE6,
];
const SALSA20_NONCE: [u8; 8] = [0xE8, 0x30, 0x09, 0x4B, 0x97, 0x20, 0x5D, 0x2A];
const SALSA20_INNER_STREAM: u32 = 2;
const CHACHA20_INNER_STREAM: u32 = 3;
const WRONG_KEY: &str = "Cannot open the KDBX file: wrong password or key file";

/// A group and what it holds, in the order of the file.
#[derive(Debug, Default)]
pub struct Group {
    pub name: String,
    pub groups: Vec<Self>,
    pub entries: Vec<Entry>,
}

#[derive(Debug, Default)]
pub struct Entry {
    /// The string fields, in the order of the file.
    pub fields: Vec<Field>,
    pub icon_id: Option<u32>,
    /// `#RRGGBB`, as written in the file.
    pub background_color: Option<String>,
    pub expires: bool,
    pub expiry_time: Option<chrono::NaiveDateTime>,
}

#[derive(Debug)]
pub struct Field {
    pub key: String,
    pub value: Zeroizing<String>,
    pub protected: bool,
}

impl Entry {
    #[must_use]
    pub fn field(&self, key: &str) -> Option<&Field> {
        self.fields.iter().find(|field| field.key == key)
    }
}

/// The root group of the KDBX `file`, opened with its password and key file; an empty password
/// is no password.
pub fn read(file: &[u8], password: Option<&str>, keyfile: Option<&[u8]>) -> Result<Group> {
    let composite_key = composite_key(password.filter(|password| !password.is_empty()), keyfile)?;
    let mut input = file;
    ensure!(take(&mut input, 8)? == SIGNATURE, "This is not a KDBX file");
    let _minor = u16::from_le_bytes(take_array(&mut input)?);
    let major = u16::from_le_bytes(take_array(&mut input)?);
    let (xml, mut inner_stream) = match major {
        3 => read_payload_3(input, &composite_key)?,
        4 => read_payload_4(file, input, &composite_key)?,
        _ => bail!("KDBX {major} files are not supported"),
    };
    let document = parse_xml(&xml, &mut inner_stream)?;
    let root = document
        .child("Root")
        .and_then(|root| root.child("Group"))
        .context("The KDBX file has no root group")?;
    Ok(group(root))
}

/// SHA-256(SHA-256(password) ‖ key file key), of nothing without either.
pub fn composite_key(
    password: Option<&str>,
    keyfile: Option<&[u8]>,
) -> Result<Zeroizing<[u8; 32]>> {
    let mut hasher = Sha256::new();
    if let Some(password) = password {
        hasher.update(sha256(password.as_bytes()));
    }
    if let Some(keyfile) = keyfile {
        hasher.update(keyfile_key(keyfile)?.as_slice());
    }
    Ok(Zeroizing::new(hasher.finalize().into()))
}

/// The key of a key file: the data of an XML key file, 32 bytes as they are, 64 hexadecimal
/// characters decoded, else the SHA-256 of the file.
fn keyfile_key(keyfile: &[u8]) -> Result<Zeroizing<Vec<u8>>> {
    if let Some(key) = xml_keyfile_key(keyfile)? {
        return Ok(key);
    }
    if keyfile.len() == 32 {
        return Ok(Zeroizing::new(keyfile.to_vec()));
    }
    if keyfile.len() == 64 {
        if let Some(key) = std::str::from_utf8(keyfile).ok().and_then(decode_hex) {
            return Ok(key);
        }
    }
    Ok(Zeroizing::new(sha256(keyfile).to_vec()))
}

/// `<KeyFile><Key><Data>`: base64 in version 1.0, hexadecimal in version 2.0.
fn xml_keyfile_key(keyfile: &[u8]) -> Result<Option<Zeroizing<Vec<u8>>>> {
    let Ok(document) = parse_xml(keyfile, &mut InnerStream::None) else {
        return Ok(None);
    };
    if document.name != "KeyFile" {
        return Ok(None);
    }
    let version = document
        .child("Meta")
        .and_then(|meta| meta.child("Version"))
        .map(|version| version.text.trim().to_string())
        .unwrap_or_default();
    let data = document
        .child("Key")
        .and_then(|key| key.child("Data"))
        .context("The key file has no key")?;
    let key = if version.starts_with("2.") {
        decode_hex(&data.text).context("The key file has an invalid key")?
    } else {
        Zeroizing::new(
            BASE64
                .decode(data.text.trim())
                .context("The key file has an invalid key")?,
        )
    };
    Ok(Some(key))
}

fn decode_hex(text: &str) -> Option<Zeroizing<Vec<u8>>> {
    let digits: Vec<u8> = text
        .bytes()
        .filter(|byte| !byte.is_ascii_whitespace())
        .collect();
    if !digits.len().is_multiple_of(2) {
        return None;
    }
    let mut bytes = Zeroizing::new(Vec::with_capacity(digits.len() / 2));
    for pair in digits.chunks(2) {
        let pair = std::str::from_utf8(pair).ok()?;
        bytes.push(u8::from_str_radix(pair, 16).ok()?);
    }
    Some(bytes)
}

// ─── Outer header ────────────────────────────────────────────────────────────

#[derive(Default)]
struct Header {
    cipher: Vec<u8>,
    compressed: bool,
    master_seed: Vec<u8>,
    encryption_iv: Vec<u8>,
    // KDBX 3
    transform_seed: Vec<u8>,
    transform_rounds: u64,
    protected_stream_key: Zeroizing<Vec<u8>>,
    stream_start_bytes: Vec<u8>,
    inner_stream_id: u32,
    // KDBX 4
    kdf_parameters: Vec<u8>,
}

impl Header {
    fn set(&mut self, id: u8, value: &[u8]) -> Result<()> {
        match id {
            2 => self.cipher = value.to_vec(),
            3 => self.compressed = read_u32(value)? == 1,
            4 => self.master_seed = value.to_vec(),
            5 => self.transform_seed = value.to_vec(),
            6 => self.transform_rounds = read_u64(value)?,
            7 => self.encryption_iv = value.to_vec(),
            8 => self.protected_stream_key = Zeroizing::new(value.to_vec()),
            9 => self.stream_start_bytes = value.to_vec(),
            10 => self.inner_stream_id = read_u32(value)?,
            11 => self.kdf_parameters = value.to_vec(),
            _ => {}
        }
        Ok(())
    }

    /// SHA-256(master seed ‖ transformed key): the key of the payload.
    fn cipher_key(&self, transformed_key: &[u8; 32]) -> Result<Zeroizing<[u8; 32]>> {
        ensure!(self.master_seed.len() == 32, "Invalid KDBX master seed");
        let mut hasher = Sha256::new();
        hasher.update(&self.master_seed);
        hasher.update(transformed_key);
        Ok(Zeroizing::new(hasher.finalize().into()))
    }

    fn decrypt(&self, key: &[u8; 32], data: &[u8]) -> Result<Zeroizing<Vec<u8>>> {
        if self.cipher == AES256_CIPHER {
            ensure!(self.encryption_iv.len() == 16, "Invalid KDBX encryption IV");
            cbc::Decryptor::<Aes256>::new(
                GenericArray::from_slice(key),
                GenericArray::from_slice(&self.encryption_iv),
            )
            .decrypt_padded_vec_mut::<Pkcs7>(data)
            .map(Zeroizing::new)
            .map_err(|_| anyhow::anyhow!(WRONG_KEY))
        } else if self.cipher == CHACHA20_CIPHER {
            ensure!(self.encryption_iv.len() == 12, "Invalid KDBX encryption IV");
            let mut decrypted = Zeroizing::new(data.to_vec());
            ChaCha20::new(
                GenericArray::from_slice(key),
                GenericArray::from_slice(&self.encryption_iv),
            )
            .apply_keystream(&mut decrypted);
            Ok(decrypted)
        } else {
            bail!("The cipher of this KDBX file is not supported")
        }
    }

    fn decompress(&self, data: Zeroizing<Vec<u8>>) -> Result<Zeroizing<Vec<u8>>> {
        if !self.compressed {
            return Ok(data);
        }
        let mut decompressed = Zeroizing::new(Vec::new());
        flate2::read::GzDecoder::new(data.as_slice())
            .read_to_end(&mut decompressed)
            .context("Cannot decompress the KDBX file")?;
        Ok(decompressed)
    }
}

// ─── KDBX 3.1 ────────────────────────────────────────────────────────────────

fn read_payload_3(
    mut input: &[u8],
    composite_key: &[u8; 32],
) -> Result<(Zeroizing<Vec<u8>>, InnerStream)> {
    let mut header = Header::default();
    loop {
        let id = take(&mut input, 1)?[0];
        let length = u16::from_le_bytes(take_array(&mut input)?);
        let value = take(&mut input, usize::from(length))?;
        if id == 0 {
            break;
        }
        header.set(id, value)?;
    }
    let seed: [u8; 32] = header
        .transform_seed
        .as_slice()
        .try_into()
        .context("Invalid KDBX transform seed")?;
    let transformed_key = aes_kdf(composite_key, &seed, header.transform_rounds);
    let cipher_key = header.cipher_key(&transformed_key)?;
    let payload = header.decrypt(&cipher_key, input)?;
    let start_length = header.stream_start_bytes.len();
    ensure!(
        payload.len() >= start_length && payload[..start_length] == header.stream_start_bytes,
        WRONG_KEY
    );
    let blocks = read_hashed_blocks(&payload[start_length..])?;
    let xml = header.decompress(blocks)?;
    let inner_stream = InnerStream::new(header.inner_stream_id, &header.protected_stream_key)?;
    Ok((xml, inner_stream))
}

/// Blocks of `(index: u32, SHA-256: [u8; 32], length: u32, data)` up to an empty one.
fn read_hashed_blocks(mut input: &[u8]) -> Result<Zeroizing<Vec<u8>>> {
    let mut data = Zeroizing::new(Vec::new());
    loop {
        let _index = take(&mut input, 4)?;
        let hash = take(&mut input, 32)?.to_vec();
        let length = u32::from_le_bytes(take_array(&mut input)?);
        if length == 0 {
            return Ok(data);
        }
        let block = take(&mut input, usize::try_from(length)?)?;
        ensure!(
            sha256(block) == hash.as_slice(),
            "The KDBX file is corrupted"
        );
        data.extend_from_slice(block);
    }
}

// ─── KDBX 4.x ────────────────────────────────────────────────────────────────

fn read_payload_4(
    file: &[u8],
    mut input: &[u8],
    composite_key: &[u8; 32],
) -> Result<(Zeroizing<Vec<u8>>, InnerStream)> {
    let mut header = Header::default();
    loop {
        let id = take(&mut input, 1)?[0];
        let length = u32::from_le_bytes(take_array(&mut input)?);
        let value = take(&mut input, usize::try_from(length)?)?;
        if id == 0 {
            break;
        }
        header.set(id, value)?;
    }
    let header_bytes = &file[..file.len() - input.len()];
    let header_hash = take(&mut input, 32)?;
    ensure!(
        sha256(header_bytes) == header_hash,
        "The KDBX file is corrupted"
    );
    let header_hmac = take(&mut input, 32)?;

    let transformed_key = kdf_4(&header.kdf_parameters, composite_key)?;
    let cipher_key = header.cipher_key(&transformed_key)?;
    let mut hasher = Sha512::new();
    hasher.update(&header.master_seed);
    hasher.update(transformed_key.as_ref());
    hasher.update([1]);
    let hmac_key = Zeroizing::new(hasher.finalize().to_vec());
    ensure!(
        block_hmac(&hmac_key, u64::MAX, &[header_bytes])
            .verify_slice(header_hmac)
            .is_ok(),
        WRONG_KEY
    );

    let encrypted = read_hmac_blocks(input, &hmac_key)?;
    let decrypted = header.decrypt(&cipher_key, &encrypted)?;
    let inner = header.decompress(decrypted)?;

    let mut input = inner.as_slice();
    let mut inner_stream_id = 0;
    let mut inner_stream_key = Zeroizing::new(Vec::new());
    loop {
        let id = take(&mut input, 1)?[0];
        let length = u32::from_le_bytes(take_array(&mut input)?);
        let value = take(&mut input, usize::try_from(length)?)?;
        match id {
            0 => break,
            1 => inner_stream_id = read_u32(value)?,
            2 => inner_stream_key = Zeroizing::new(value.to_vec()),
            _ => {}
        }
    }
    let inner_stream = InnerStream::new(inner_stream_id, &inner_stream_key)?;
    Ok((Zeroizing::new(input.to_vec()), inner_stream))
}

/// HMAC-SHA-256 keyed by SHA-512(index ‖ HMAC key) over `parts`.
fn block_hmac(hmac_key: &[u8], index: u64, parts: &[&[u8]]) -> Hmac<Sha256> {
    let mut hasher = Sha512::new();
    hasher.update(index.to_le_bytes());
    hasher.update(hmac_key);
    let key = Zeroizing::new(hasher.finalize());
    let mut mac = <Hmac<Sha256> as Mac>::new_from_slice(&key).expect("HMAC takes any key");
    for part in parts {
        mac.update(part);
    }
    mac
}

/// Blocks of `(HMAC: [u8; 32], length: u32, data)` up to an empty one.
fn read_hmac_blocks(mut input: &[u8], hmac_key: &[u8]) -> Result<Zeroizing<Vec<u8>>> {
    let mut data = Zeroizing::new(Vec::new());
    for index in 0u64.. {
        let hmac = take(&mut input, 32)?;
        let length_bytes: [u8; 4] = take_array(&mut input)?;
        let block = take(
            &mut input,
            usize::try_from(u32::from_le_bytes(length_bytes))?,
        )?;
        ensure!(
            block_hmac(
                hmac_key,
                index,
                &[&index.to_le_bytes(), &length_bytes, block]
            )
            .verify_slice(hmac)
            .is_ok(),
            "The KDBX file is corrupted"
        );
        if block.is_empty() {
            break;
        }
        data.extend_from_slice(block);
    }
    Ok(data)
}

/// The transformed key of the KDF parameters, a variant dictionary.
fn kdf_4(parameters: &[u8], composite_key: &[u8; 32]) -> Result<Zeroizing<[u8; 32]>> {
    let parameters = variant_dictionary(parameters)?;
    let parameter = |name: &str| {
        parameters
            .iter()
            .find(|(key, _)| key == name)
            .map(|(_, value)| value.as_slice())
            .with_context(|| format!("The KDBX file has no KDF parameter {name}"))
    };
    let uuid = parameter("$UUID")?;
    if uuid == AES_KDF {
        let seed: [u8; 32] = parameter("S")?
            .try_into()
            .context("Invalid KDBX transform seed")?;
        return Ok(aes_kdf(composite_key, &seed, read_u64(parameter("R")?)?));
    }
    let algorithm = if uuid == ARGON2D_KDF {
        argon2::Algorithm::Argon2d
    } else if uuid == ARGON2ID_KDF {
        argon2::Algorithm::Argon2id
    } else {
        bail!("The key derivation of this KDBX file is not supported")
    };
    let version = match read_u32(parameter("V")?)? {
        0x10 => argon2::Version::V0x10,
        _ => argon2::Version::V0x13,
    };
    let memory_kib = u32::try_from(read_u64(parameter("M")?)? / 1024)?;
    let iterations = u32::try_from(read_u64(parameter("I")?)?)?;
    let parallelism = read_u32(parameter("P")?)?;
    let params = argon2::Params::new(memory_kib, iterations, parallelism, Some(32))
        .map_err(|error| anyhow::anyhow!("Invalid Argon2 parameters: {error}"))?;
    let mut transformed_key = Zeroizing::new([0u8; 32]);
    argon2::Argon2::new(algorithm, version, params)
        .hash_password_into(composite_key, parameter("S")?, transformed_key.as_mut())
        .map_err(|error| anyhow::anyhow!("Cannot derive the KDBX key: {error}"))?;
    Ok(transformed_key)
}

/// `version: u16`, then `(type: u8, name length: u32, name, value length: u32, value)` up to
/// type 0.
fn variant_dictionary(mut input: &[u8]) -> Result<Vec<(String, Vec<u8>)>> {
    let _version = take(&mut input, 2)?;
    let mut entries = Vec::new();
    loop {
        let kind = take(&mut input, 1)?[0];
        if kind == 0 {
            return Ok(entries);
        }
        let name_length = u32::from_le_bytes(take_array(&mut input)?);
        let name = take(&mut input, usize::try_from(name_length)?)?;
        let value_length = u32::from_le_bytes(take_array(&mut input)?);
        let value = take(&mut input, usize::try_from(value_length)?)?;
        entries.push((String::from_utf8_lossy(name).into_owned(), value.to_vec()));
    }
}

// ─── Protected values ────────────────────────────────────────────────────────

enum InnerStream {
    None,
    Salsa20(Box<Salsa20>),
    ChaCha20(Box<ChaCha20>),
}

impl InnerStream {
    fn new(id: u32, key: &[u8]) -> Result<Self> {
        match id {
            SALSA20_INNER_STREAM => {
                let key = Zeroizing::new(sha256(key));
                Ok(Self::Salsa20(Box::new(Salsa20::new(
                    GenericArray::from_slice(key.as_ref()),
                    GenericArray::from_slice(&SALSA20_NONCE),
                ))))
            }
            CHACHA20_INNER_STREAM => {
                let hash = Zeroizing::new(Sha512::digest(key));
                Ok(Self::ChaCha20(Box::new(ChaCha20::new(
                    GenericArray::from_slice(&hash[..32]),
                    GenericArray::from_slice(&hash[32..44]),
                ))))
            }
            0 => Ok(Self::None),
            _ => bail!("The protection of this KDBX file is not supported"),
        }
    }

    fn apply(&mut self, data: &mut [u8]) {
        match self {
            Self::None => {}
            Self::Salsa20(cipher) => cipher.apply_keystream(data),
            Self::ChaCha20(cipher) => cipher.apply_keystream(data),
        }
    }
}

// ─── XML ─────────────────────────────────────────────────────────────────────

/// An XML element; protected values are decrypted in the order of the document.
#[derive(Default)]
struct Element {
    name: String,
    text: Zeroizing<String>,
    protected: bool,
    children: Vec<Self>,
}

impl Element {
    fn child(&self, name: &str) -> Option<&Self> {
        self.children.iter().find(|child| child.name == name)
    }

    fn children<'a>(&'a self, name: &'a str) -> impl Iterator<Item = &'a Self> {
        self.children.iter().filter(move |child| child.name == name)
    }

    fn child_text(&self, name: &str) -> Option<&str> {
        self.child(name)
            .map(|child| child.text.trim())
            .filter(|text| !text.is_empty())
    }
}

fn parse_xml(xml: &[u8], inner_stream: &mut InnerStream) -> Result<Element> {
    let mut stack: Vec<Element> = Vec::new();
    for event in EventReader::new(xml) {
        match event.context("The KDBX file holds invalid XML")? {
            XmlEvent::StartElement {
                name, attributes, ..
            } => stack.push(Element {
                name: name.local_name,
                protected: attributes.iter().any(|attribute| {
                    attribute.name.local_name == "Protected"
                        && attribute.value.eq_ignore_ascii_case("true")
                }),
                ..Element::default()
            }),
            XmlEvent::Characters(text) | XmlEvent::CData(text) | XmlEvent::Whitespace(text) => {
                if let Some(element) = stack.last_mut() {
                    element.text.push_str(&text);
                }
            }
            XmlEvent::EndElement { .. } => {
                let mut element = stack.pop().context("The KDBX file holds invalid XML")?;
                if element.protected {
                    let mut value = Zeroizing::new(
                        BASE64
                            .decode(element.text.trim())
                            .context("The KDBX file holds an invalid protected value")?,
                    );
                    inner_stream.apply(&mut value);
                    element.text = Zeroizing::new(String::from_utf8_lossy(&value).into_owned());
                }
                match stack.last_mut() {
                    Some(parent) => parent.children.push(element),
                    None => return Ok(element),
                }
            }
            _ => {}
        }
    }
    bail!("The KDBX file holds invalid XML")
}

fn group(element: &Element) -> Group {
    Group {
        name: element.child_text("Name").unwrap_or_default().to_string(),
        groups: element.children("Group").map(group).collect(),
        entries: element.children("Entry").map(entry).collect(),
    }
}

fn entry(element: &Element) -> Entry {
    let times = element.child("Times");
    Entry {
        fields: element
            .children("String")
            .filter_map(|string| {
                let key = string.child("Key")?.text.to_string();
                let value = string.child("Value");
                Some(Field {
                    key,
                    value: value.map(|value| value.text.clone()).unwrap_or_default(),
                    protected: value.is_some_and(|value| value.protected),
                })
            })
            .collect(),
        icon_id: element
            .child_text("IconID")
            .and_then(|icon_id| icon_id.parse().ok()),
        background_color: element.child_text("BackgroundColor").map(str::to_string),
        expires: times
            .and_then(|times| times.child_text("Expires"))
            .is_some_and(|expires| expires.eq_ignore_ascii_case("true")),
        expiry_time: times
            .and_then(|times| times.child_text("ExpiryTime"))
            .and_then(parse_time),
    }
}

/// An ISO 8601 time (KDBX 3), or base64 seconds since 0001-01-01 (KDBX 4).
fn parse_time(text: &str) -> Option<chrono::NaiveDateTime> {
    if let Ok(time) = chrono::DateTime::parse_from_rfc3339(text) {
        return Some(time.naive_utc());
    }
    let seconds = i64::from_le_bytes(BASE64.decode(text).ok()?.try_into().ok()?);
    chrono::NaiveDate::from_ymd_opt(1, 1, 1)?
        .and_hms_opt(0, 0, 0)?
        .checked_add_signed(chrono::TimeDelta::try_seconds(seconds)?)
}

// ─── Bytes ───────────────────────────────────────────────────────────────────

fn take<'a>(input: &mut &'a [u8], length: usize) -> Result<&'a [u8]> {
    ensure!(input.len() >= length, "The KDBX file is truncated");
    let (taken, rest) = input.split_at(length);
    *input = rest;
    Ok(taken)
}

fn take_array<const N: usize>(input: &mut &[u8]) -> Result<[u8; N]> {
    Ok(take(input, N)?.try_into()?)
}

fn read_u32(value: &[u8]) -> Result<u32> {
    Ok(u32::from_le_bytes(
        value.try_into().context("Invalid KDBX header")?,
    ))
}

fn read_u64(value: &[u8]) -> Result<u64> {
    Ok(u64::from_le_bytes(
        value.try_into().context("Invalid KDBX header")?,
    ))
}
