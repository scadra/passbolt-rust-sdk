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

//! KDBX 3.1 writer, the format the browser extension writes: AES-KDF, AES-256-CBC, `GZip`, a
//! hashed block stream and Salsa20 protected values, as `KeePass` 2.x writes it.

use aes::cipher::{generic_array::GenericArray, BlockEncrypt, KeyInit, KeyIvInit, StreamCipher};
use aes::Aes256;
use anyhow::{Context, Result};
use base64::{engine::general_purpose::STANDARD as BASE64, Engine};
use cbc::cipher::{block_padding::Pkcs7, BlockEncryptMut};
use rand::{rngs::OsRng, RngCore};
use salsa20::Salsa20;
use sha2::{Digest, Sha256};
use std::io::Write;
use zeroize::Zeroizing;

use super::export::{KeePassEntry, KeePassGroup, DATABASE_NAME};

const SIGNATURE: [u8; 8] = [0x03, 0xD9, 0xA2, 0x9A, 0x67, 0xFB, 0x4B, 0xB5];
const MINOR_VERSION: u16 = 1;
const MAJOR_VERSION: u16 = 3;
const AES256_CIPHER_ID: [u8; 16] = [
    0x31, 0xC1, 0xF2, 0xE6, 0xBF, 0x71, 0x43, 0x50, 0xBE, 0x58, 0x05, 0x21, 0x6A, 0xFC, 0x5A, 0xFF,
];
const GZIP_COMPRESSION: u32 = 1;
const SALSA20_INNER_STREAM: u32 = 2;
const SALSA20_NONCE: [u8; 8] = [0xE8, 0x30, 0x09, 0x4B, 0x97, 0x20, 0x5D, 0x2A];
/// AES-KDF rounds, as the browser extension writes them.
pub const TRANSFORM_ROUNDS: u64 = 300_000;
const BLOCK_SIZE: usize = 1024 * 1024;
const GROUP_ICON: &str = "48";
const NO_UUID: &str = "AAAAAAAAAAAAAAAAAAAAAA==";

#[repr(u8)]
#[derive(Clone, Copy)]
enum HeaderField {
    End = 0,
    CipherId = 2,
    CompressionFlags = 3,
    MasterSeed = 4,
    TransformSeed = 5,
    TransformRounds = 6,
    EncryptionIv = 7,
    ProtectedStreamKey = 8,
    StreamStartBytes = 9,
    InnerRandomStreamId = 10,
}

/// The random values of one file.
pub struct Seeds {
    pub master_seed: [u8; 32],
    pub transform_seed: [u8; 32],
    pub encryption_iv: [u8; 16],
    pub protected_stream_key: Zeroizing<[u8; 32]>,
    pub stream_start_bytes: [u8; 32],
}

impl Seeds {
    fn random() -> Self {
        let mut seeds = Self {
            master_seed: [0; 32],
            transform_seed: [0; 32],
            encryption_iv: [0; 16],
            protected_stream_key: Zeroizing::new([0; 32]),
            stream_start_bytes: [0; 32],
        };
        OsRng.fill_bytes(&mut seeds.master_seed);
        OsRng.fill_bytes(&mut seeds.transform_seed);
        OsRng.fill_bytes(&mut seeds.encryption_iv);
        OsRng.fill_bytes(seeds.protected_stream_key.as_mut());
        OsRng.fill_bytes(&mut seeds.stream_start_bytes);
        seeds
    }
}

/// Write `root` as a KDBX 3.1 database named `passbolt export`, locked by `composite_key`.
pub fn write_kdbx3(
    output: &mut dyn Write,
    composite_key: &[u8; 32],
    root: &KeePassGroup,
) -> Result<()> {
    let seeds = Seeds::random();
    let header = header(&seeds, TRANSFORM_ROUNDS)?;
    let header_hash = sha256(&header);
    let xml = database_xml(root, &header_hash, &seeds.protected_stream_key);

    let mut compressor = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::default());
    compressor
        .write_all(xml.as_bytes())
        .context("Cannot compress the database")?;
    let compressed = Zeroizing::new(
        compressor
            .finish()
            .context("Cannot compress the database")?,
    );

    let mut payload = Zeroizing::new(seeds.stream_start_bytes.to_vec());
    write_hashed_blocks(&mut payload, &compressed)?;

    let master_key = master_key(composite_key, &seeds, TRANSFORM_ROUNDS);
    let encrypted = cbc::Encryptor::<Aes256>::new(
        GenericArray::from_slice(master_key.as_ref()),
        GenericArray::from_slice(&seeds.encryption_iv),
    )
    .encrypt_padded_vec_mut::<Pkcs7>(&payload);

    output
        .write_all(&header)
        .context("Cannot write the header")?;
    output
        .write_all(&encrypted)
        .context("Cannot write the database")?;
    Ok(())
}

/// The outer header, from the signature to the end field included.
pub fn header(seeds: &Seeds, transform_rounds: u64) -> Result<Vec<u8>> {
    let mut header = SIGNATURE.to_vec();
    header.extend_from_slice(&MINOR_VERSION.to_le_bytes());
    header.extend_from_slice(&MAJOR_VERSION.to_le_bytes());
    let fields: [(HeaderField, &[u8]); 10] = [
        (HeaderField::CipherId, &AES256_CIPHER_ID),
        (
            HeaderField::CompressionFlags,
            &GZIP_COMPRESSION.to_le_bytes(),
        ),
        (HeaderField::MasterSeed, &seeds.master_seed),
        (HeaderField::TransformSeed, &seeds.transform_seed),
        (
            HeaderField::TransformRounds,
            &transform_rounds.to_le_bytes(),
        ),
        (HeaderField::EncryptionIv, &seeds.encryption_iv),
        (
            HeaderField::ProtectedStreamKey,
            seeds.protected_stream_key.as_ref(),
        ),
        (HeaderField::StreamStartBytes, &seeds.stream_start_bytes),
        (
            HeaderField::InnerRandomStreamId,
            &SALSA20_INNER_STREAM.to_le_bytes(),
        ),
        (HeaderField::End, b"\r\n\r\n"),
    ];
    for (field, value) in fields {
        let length = u16::try_from(value.len()).context("Header field too long")?;
        header.push(field as u8);
        header.extend_from_slice(&length.to_le_bytes());
        header.extend_from_slice(value);
    }
    Ok(header)
}

/// SHA-256(seed ‖ AES-KDF(composite key)): the key of the payload.
fn master_key(
    composite_key: &[u8; 32],
    seeds: &Seeds,
    transform_rounds: u64,
) -> Zeroizing<[u8; 32]> {
    let transformed_key = aes_kdf(composite_key, &seeds.transform_seed, transform_rounds);

    let mut hasher = Sha256::new();
    hasher.update(seeds.master_seed);
    hasher.update(transformed_key.as_ref());
    Zeroizing::new(hasher.finalize().into())
}

/// SHA-256 of the composite key encrypted `rounds` times with AES-256 keyed by `seed`.
pub fn aes_kdf(composite_key: &[u8; 32], seed: &[u8; 32], rounds: u64) -> Zeroizing<[u8; 32]> {
    let mut transformed = Zeroizing::new(*composite_key);
    let cipher = Aes256::new(GenericArray::from_slice(seed));
    for half in transformed.as_chunks_mut::<16>().0 {
        let block = GenericArray::from_mut_slice(half);
        for _ in 0..rounds {
            cipher.encrypt_block(block);
        }
    }
    Zeroizing::new(sha256(transformed.as_ref()))
}

/// Blocks of `(index: u32, SHA-256: [u8; 32], length: u32, data)`, then an empty block.
fn write_hashed_blocks(output: &mut Vec<u8>, data: &[u8]) -> Result<()> {
    let mut index: u32 = 0;
    for block in data.chunks(BLOCK_SIZE) {
        output.extend_from_slice(&index.to_le_bytes());
        output.extend_from_slice(&sha256(block));
        let length = u32::try_from(block.len()).context("Block too long")?;
        output.extend_from_slice(&length.to_le_bytes());
        output.extend_from_slice(block);
        index = index.checked_add(1).context("Too many blocks")?;
    }
    output.extend_from_slice(&index.to_le_bytes());
    output.extend_from_slice(&[0; 32]);
    output.extend_from_slice(&0u32.to_le_bytes());
    Ok(())
}

pub fn sha256(data: &[u8]) -> [u8; 32] {
    Sha256::digest(data).into()
}

/// The `KeePassFile` XML. Protected values are XOR-ed with the Salsa20 stream in document
/// order, as readers decrypt them.
fn database_xml(
    root: &KeePassGroup,
    header_hash: &[u8; 32],
    protected_stream_key: &[u8; 32],
) -> Zeroizing<String> {
    let stream_key = Zeroizing::new(sha256(protected_stream_key));
    let mut writer = XmlWriter {
        xml: Zeroizing::new(String::new()),
        inner_stream: Salsa20::new(
            GenericArray::from_slice(stream_key.as_ref()),
            GenericArray::from_slice(&SALSA20_NONCE),
        ),
        now: chrono::Utc::now().format("%Y-%m-%dT%H:%M:%SZ").to_string(),
    };
    writer
        .xml
        .push_str("<?xml version=\"1.0\" encoding=\"utf-8\" standalone=\"yes\"?>\n");
    writer.open("KeePassFile");
    writer.meta(header_hash);
    writer.open("Root");
    writer.group(root);
    writer.empty("DeletedObjects");
    writer.close("Root");
    writer.close("KeePassFile");
    writer.xml
}

struct XmlWriter {
    xml: Zeroizing<String>,
    inner_stream: Salsa20,
    now: String,
}

impl XmlWriter {
    fn open(&mut self, tag: &str) {
        self.xml.push('<');
        self.xml.push_str(tag);
        self.xml.push('>');
    }

    fn close(&mut self, tag: &str) {
        self.xml.push_str("</");
        self.xml.push_str(tag);
        self.xml.push('>');
    }

    fn empty(&mut self, tag: &str) {
        self.xml.push('<');
        self.xml.push_str(tag);
        self.xml.push_str("/>");
    }

    fn element(&mut self, tag: &str, text: &str) {
        self.open(tag);
        push_escaped(&mut self.xml, text);
        self.close(tag);
    }

    fn uuid(&mut self) {
        let mut uuid = [0u8; 16];
        OsRng.fill_bytes(&mut uuid);
        let encoded = BASE64.encode(uuid);
        self.element("UUID", &encoded);
    }

    /// The times of a group or an entry; without `expiry`, it never expires.
    fn times(&mut self, expiry: Option<&chrono::DateTime<chrono::Utc>>) {
        let now = self.now.clone();
        self.open("Times");
        for tag in ["CreationTime", "LastModificationTime", "LastAccessTime"] {
            self.element(tag, &now);
        }
        let expiry_time = expiry.map_or_else(
            || now.clone(),
            |expiry| expiry.format("%Y-%m-%dT%H:%M:%SZ").to_string(),
        );
        self.element("ExpiryTime", &expiry_time);
        self.element("Expires", if expiry.is_some() { "True" } else { "False" });
        self.element("UsageCount", "0");
        self.element("LocationChanged", &now);
        self.close("Times");
    }

    fn meta(&mut self, header_hash: &[u8; 32]) {
        let now = self.now.clone();
        self.open("Meta");
        self.element("Generator", "passbolt-cli");
        self.element("HeaderHash", &BASE64.encode(header_hash));
        self.element("DatabaseName", DATABASE_NAME);
        self.element("DatabaseNameChanged", &now);
        self.element("DatabaseDescription", "");
        self.element("DatabaseDescriptionChanged", &now);
        self.element("DefaultUserName", "");
        self.element("DefaultUserNameChanged", &now);
        self.element("MaintenanceHistoryDays", "365");
        self.element("MasterKeyChanged", &now);
        self.element("MasterKeyChangeRec", "-1");
        self.element("MasterKeyChangeForce", "-1");
        self.open("MemoryProtection");
        self.element("ProtectTitle", "False");
        self.element("ProtectUserName", "False");
        self.element("ProtectPassword", "True");
        self.element("ProtectURL", "False");
        self.element("ProtectNotes", "False");
        self.close("MemoryProtection");
        self.element("RecycleBinEnabled", "False");
        self.element("RecycleBinUUID", NO_UUID);
        self.element("RecycleBinChanged", &now);
        self.element("EntryTemplatesGroup", NO_UUID);
        self.element("EntryTemplatesGroupChanged", &now);
        self.element("HistoryMaxItems", "10");
        self.element("HistoryMaxSize", "6291456");
        self.element("LastSelectedGroup", NO_UUID);
        self.element("LastTopVisibleGroup", NO_UUID);
        self.empty("Binaries");
        self.empty("CustomData");
        self.close("Meta");
    }

    fn group(&mut self, group: &KeePassGroup) {
        self.open("Group");
        self.uuid();
        self.element("Name", &group.name);
        self.element("Notes", "");
        self.element("IconID", GROUP_ICON);
        self.times(None);
        self.element("IsExpanded", "True");
        self.element("DefaultAutoTypeSequence", "");
        self.element("EnableAutoType", "null");
        self.element("EnableSearching", "null");
        self.element("LastTopVisibleEntry", NO_UUID);
        for entry in &group.entries {
            self.entry(entry);
        }
        for child in &group.groups {
            self.group(child);
        }
        self.close("Group");
    }

    fn entry(&mut self, entry: &KeePassEntry) {
        self.open("Entry");
        self.uuid();
        self.element("IconID", &entry.icon_id.unwrap_or(0).to_string());
        self.element("ForegroundColor", "");
        self.element(
            "BackgroundColor",
            entry.background_color.as_deref().unwrap_or_default(),
        );
        self.element("OverrideURL", "");
        self.element("Tags", "");
        self.times(entry.expiry.as_ref());
        for field in &entry.fields {
            self.open("String");
            self.element("Key", &field.key);
            if field.protected {
                self.protected_value(&field.value);
            } else {
                self.element("Value", &field.value);
            }
            self.close("String");
        }
        self.open("AutoType");
        self.element("Enabled", "True");
        self.element("DataTransferObfuscation", "0");
        self.close("AutoType");
        self.empty("History");
        self.close("Entry");
    }

    fn protected_value(&mut self, value: &str) {
        let mut encrypted = Zeroizing::new(value.as_bytes().to_vec());
        self.inner_stream.apply_keystream(&mut encrypted);
        self.xml.push_str("<Value Protected=\"True\">");
        self.xml.push_str(&BASE64.encode(encrypted.as_slice()));
        self.close("Value");
    }
}

/// Escape `text` for XML 1.0; the characters XML 1.0 cannot hold are dropped.
fn push_escaped(xml: &mut String, text: &str) {
    for character in text.chars() {
        match character {
            '&' => xml.push_str("&amp;"),
            '<' => xml.push_str("&lt;"),
            '>' => xml.push_str("&gt;"),
            '"' => xml.push_str("&quot;"),
            '\'' => xml.push_str("&apos;"),
            '\r' => xml.push_str("&#13;"),
            '\t' | '\n' | '\u{20}'..='\u{D7FF}' | '\u{E000}'..='\u{FFFD}' | '\u{10000}'.. => {
                xml.push(character);
            }
            _ => {}
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::keepass::export::EntryField;
    use crate::keepass::kdbx::{self, composite_key};
    use keepass::config::{
        CompressionConfig, DatabaseVersion, InnerCipherConfig, KdfConfig, OuterCipherConfig,
    };
    use keepass::db::{Database, Entry, Group, Node, NodeRef, Value};
    use keepass::DatabaseKey;

    fn field(key: &str, value: &str, protected: bool) -> EntryField {
        EntryField {
            key: key.into(),
            value: value.into(),
            protected,
        }
    }

    fn entry(title: &str) -> KeePassEntry {
        KeePassEntry {
            fields: vec![
                field("Title", title, false),
                field("UserName", &format!("{title}-user"), false),
                field("Password", &format!("{title}-password"), true),
                field("URL", &format!("https://{title}.test"), false),
                field("Notes", &format!("{title} notes"), false),
            ],
            ..KeePassEntry::default()
        }
    }

    fn written_with(
        root: &KeePassGroup,
        password: Option<&str>,
        keyfile: Option<&[u8]>,
    ) -> Vec<u8> {
        let mut file = Vec::new();
        write_kdbx3(&mut file, &composite_key(password, keyfile).unwrap(), root).unwrap();
        file
    }

    fn written(root: &KeePassGroup, password: &str) -> Vec<u8> {
        written_with(root, Some(password), None)
    }

    fn opened(root: &KeePassGroup) -> Database {
        Database::parse(
            &written(root, "master"),
            DatabaseKey::new().with_password("master"),
        )
        .unwrap()
    }

    fn entries(group: &Group) -> Vec<&Entry> {
        group
            .children
            .iter()
            .filter_map(|node| match node {
                Node::Entry(entry) => Some(entry),
                Node::Group(_) => None,
            })
            .collect()
    }

    fn groups(group: &Group) -> Vec<&Group> {
        group
            .children
            .iter()
            .filter_map(|node| match node {
                Node::Group(child) => Some(child),
                Node::Entry(_) => None,
            })
            .collect()
    }

    fn fixed_seeds() -> Seeds {
        Seeds {
            master_seed: [1; 32],
            transform_seed: [2; 32],
            encryption_iv: [3; 16],
            protected_stream_key: Zeroizing::new([4; 32]),
            stream_start_bytes: [5; 32],
        }
    }

    #[test]
    fn test_header_is_kdbx_3_1_with_aes_gzip_and_salsa20() {
        let mut expected = vec![0x03, 0xD9, 0xA2, 0x9A, 0x67, 0xFB, 0x4B, 0xB5, 1, 0, 3, 0];
        let mut field = |id: u8, value: &[u8]| {
            expected.push(id);
            expected.extend_from_slice(&u16::try_from(value.len()).unwrap().to_le_bytes());
            expected.extend_from_slice(value);
        };
        field(2, &AES256_CIPHER_ID);
        field(3, &[1, 0, 0, 0]);
        field(4, &[1; 32]);
        field(5, &[2; 32]);
        field(6, &300_000u64.to_le_bytes());
        field(7, &[3; 16]);
        field(8, &[4; 32]);
        field(9, &[5; 32]);
        field(10, &[2, 0, 0, 0]);
        field(0, b"\r\n\r\n");

        assert_eq!(header(&fixed_seeds(), TRANSFORM_ROUNDS).unwrap(), expected);
    }

    #[test]
    fn test_written_file_has_the_browser_extension_v3_settings() {
        let database = opened(&KeePassGroup::named("root"));

        assert_eq!(database.config.version, DatabaseVersion::KDB3(1));
        assert_eq!(
            database.config.outer_cipher_config,
            OuterCipherConfig::AES256
        );
        assert_eq!(database.config.compression_config, CompressionConfig::GZip);
        assert_eq!(
            database.config.inner_cipher_config,
            InnerCipherConfig::Salsa20
        );
        assert_eq!(
            database.config.kdf_config,
            KdfConfig::Aes {
                rounds: TRANSFORM_ROUNDS
            }
        );
    }

    #[test]
    fn test_written_file_is_named_passbolt_export() {
        let database = opened(&KeePassGroup::named("root"));

        assert_eq!(
            database.meta.database_name.as_deref(),
            Some("passbolt export")
        );
        assert_eq!(database.root.name, "root");
    }

    #[test]
    fn test_written_file_holds_the_entry_fields() {
        let mut root = KeePassGroup::named("root");
        root.entries.push(entry("github"));

        let database = opened(&root);

        let exported = entries(&database.root)[0];
        assert_eq!(exported.get_title(), Some("github"));
        assert_eq!(exported.get_username(), Some("github-user"));
        assert_eq!(exported.get_url(), Some("https://github.test"));
        assert_eq!(exported.get("Notes"), Some("github notes"));
        assert_eq!(exported.get_password(), Some("github-password"));
        assert!(matches!(
            exported.fields.get("Password"),
            Some(Value::Protected(_))
        ));
        assert!(matches!(
            exported.fields.get("Title"),
            Some(Value::Unprotected(_))
        ));
    }

    #[test]
    fn test_written_file_protects_the_otp_and_the_custom_fields() {
        let mut root = KeePassGroup::named("root");
        let mut bank = entry("bank");
        bank.fields.extend([
            field("otp", "otpauth://totp/a:b?secret=JBSWY3DP", true),
            field("Account", "42", true),
            field("PIN", "1234", true),
        ]);
        root.entries.push(bank);

        let database = opened(&root);

        let exported = entries(&database.root)[0];
        assert_eq!(
            exported.get("otp"),
            Some("otpauth://totp/a:b?secret=JBSWY3DP")
        );
        assert_eq!(exported.get("Account"), Some("42"));
        assert_eq!(exported.get("PIN"), Some("1234"));
        for key in ["otp", "Account", "PIN"] {
            assert!(
                matches!(exported.fields.get(key), Some(Value::Protected(_))),
                "{key} not protected"
            );
        }
    }

    #[test]
    fn test_written_file_decrypts_every_protected_value_in_order() {
        let mut root = KeePassGroup::named("root");
        let mut folder = KeePassGroup::named("folder");
        root.entries.push(entry("first"));
        folder.entries.push(entry("second"));
        root.groups.push(folder);
        root.entries.push(entry("third"));

        let database = opened(&root);

        let mut passwords: Vec<_> = database
            .root
            .iter()
            .filter_map(|node| match node {
                NodeRef::Entry(entry) => entry.get_password().map(String::from),
                NodeRef::Group(_) => None,
            })
            .collect();
        passwords.sort();
        assert_eq!(
            passwords,
            ["first-password", "second-password", "third-password"]
        );
    }

    #[test]
    fn test_written_file_keeps_the_sub_groups() {
        let mut root = KeePassGroup::named("root");
        let mut parent = KeePassGroup::named("parent");
        let mut child = KeePassGroup::named("child");
        child.entries.push(entry("nested"));
        parent.groups.push(child);
        root.groups.push(parent);

        let database = opened(&root);

        let parent = groups(&database.root)[0];
        let child = groups(parent)[0];
        assert_eq!(
            (parent.name.as_str(), child.name.as_str()),
            ("parent", "child")
        );
        assert_eq!(entries(child)[0].get_title(), Some("nested"));
    }

    #[test]
    fn test_written_file_escapes_the_markup_characters() {
        let mut root = KeePassGroup::named("<root & 'co'>");
        let mut marked = entry("x");
        marked.fields[4].value = "a < b && \"c\" > d\r\nline".into();
        root.entries.push(marked);

        let database = opened(&root);

        assert_eq!(database.root.name, "<root & 'co'>");
        assert_eq!(
            entries(&database.root)[0].get("Notes"),
            Some("a < b && \"c\" > d\r\nline")
        );
    }

    #[test]
    fn test_written_file_spans_several_blocks() {
        let mut root = KeePassGroup::named("root");
        let mut noise = vec![0u8; 1536 * 1024];
        OsRng.fill_bytes(&mut noise);
        let notes = BASE64.encode(noise);
        let mut large = entry("large");
        large.fields[4].value.clone_from(&notes);
        root.entries.push(large);

        let database = opened(&root);

        let exported = entries(&database.root)[0];
        assert_eq!(exported.get("Notes"), Some(notes.as_str()));
        assert_eq!(exported.get_password(), Some("large-password"));
    }

    #[test]
    fn test_written_file_refuses_another_password() {
        let file = written(&KeePassGroup::named("root"), "master");

        assert!(Database::parse(&file, DatabaseKey::new().with_password("other")).is_err());
    }

    #[test]
    fn test_header_hash_is_the_hash_of_the_written_header() {
        let file = written(&KeePassGroup::named("root"), "master");
        let end_field = [0, 4, 0, b'\r', b'\n', b'\r', b'\n'];
        let header_length = file
            .windows(end_field.len())
            .position(|window| window == end_field)
            .unwrap()
            + end_field.len();

        let xml = Database::get_xml(
            &mut file.as_slice(),
            DatabaseKey::new().with_password("master"),
        )
        .unwrap();

        let expected = BASE64.encode(sha256(&file[..header_length]));
        let xml = String::from_utf8(xml).unwrap();
        assert!(
            xml.contains(&format!("<HeaderHash>{expected}</HeaderHash>")),
            "{xml}"
        );
    }

    #[test]
    fn test_written_file_without_credentials_reads_back() {
        let mut root = KeePassGroup::named("root");
        root.entries.push(entry("open"));

        let read = kdbx::read(&written_with(&root, None, None), None, None).unwrap();

        assert_eq!(
            read.entries[0].field("Password").unwrap().value.as_str(),
            "open-password"
        );
    }

    #[test]
    fn test_written_file_with_a_key_file_reads_back() {
        let keyfile = b"any key file content";
        let root = KeePassGroup::named("locked");

        let file = written_with(&root, Some("master"), Some(keyfile));

        assert_eq!(
            kdbx::read(&file, Some("master"), Some(keyfile))
                .unwrap()
                .name,
            "locked"
        );
        assert!(kdbx::read(&file, Some("master"), None).is_err());
    }

    #[test]
    fn test_written_file_keeps_the_expiry_and_the_icon() {
        let mut root = KeePassGroup::named("root");
        let mut expiring = entry("expiring");
        expiring.expiry = chrono::DateTime::parse_from_rfc3339("2030-01-31T12:00:00Z")
            .ok()
            .map(|expiry| expiry.with_timezone(&chrono::Utc));
        expiring.icon_id = Some(4);
        expiring.background_color = Some("#FF0000".into());
        root.entries.push(expiring);
        root.entries.push(entry("plain"));

        let read = kdbx::read(&written(&root, "master"), Some("master"), None).unwrap();

        let (expiring, plain) = (&read.entries[0], &read.entries[1]);
        assert!(expiring.expires);
        assert_eq!(
            expiring.expiry_time.map(|time| time.to_string()),
            Some("2030-01-31 12:00:00".into())
        );
        assert_eq!(expiring.icon_id, Some(4));
        assert_eq!(expiring.background_color.as_deref(), Some("#FF0000"));
        assert!(!plain.expires);
        assert_eq!(plain.background_color, None);
    }

    #[rstest::rstest]
    #[case::markup("<&>\"'", "&lt;&amp;&gt;&quot;&apos;")]
    #[case::carriage_return("a\r\nb", "a&#13;\nb")]
    #[case::control_characters_dropped("a\u{0}\u{8}\u{1F}b\tc", "ab\tc")]
    #[case::non_characters_dropped("a\u{FFFE}\u{FFFF}b", "ab")]
    #[case::unicode_kept("é😀", "é😀")]
    fn test_push_escaped(#[case] text: &str, #[case] expected: &str) {
        let mut xml = String::new();

        push_escaped(&mut xml, text);

        assert_eq!(xml, expected);
    }
}
