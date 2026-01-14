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

//! v5 resource metadata: the shared metadata keys and the decryption of `metadata`.

use std::collections::HashMap;

use pgp::{SignedPublicKey, SignedSecretKey};
use secrecy::{ExposeSecret, SecretString};
use serde::Deserialize;

use crate::crypto::{self, SessionKey, Signer};
use crate::error::{CryptoError, PassboltError};
use crate::types::{MetadataKey, Resource, ResourceMetadata};

const PRIVATE_KEY_OBJECT_TYPE: &str = "PASSBOLT_METADATA_PRIVATE_KEY";
const RESOURCE_METADATA_OBJECT_TYPE: &str = "PASSBOLT_RESOURCE_METADATA";

/// Decrypted `metadata_private_keys[].data`.
#[derive(Deserialize)]
struct MetadataPrivateKeyData {
    object_type: String,
    fingerprint: String,
    armored_key: String,
    passphrase: SecretString,
}

struct MetadataPrivateKey {
    key: SignedSecretKey,
    passphrase: SecretString,
}

/// The shared metadata key new metadata is encrypted with.
struct ActiveMetadataKey {
    id: String,
    public_key: SignedPublicKey,
}

/// Shared metadata private keys the user holds a share of, by metadata key id,
/// and the active key to encrypt new shared metadata.
#[derive(Default)]
pub struct MetadataKeys {
    private_keys: HashMap<String, MetadataPrivateKey>,
    active: Option<ActiveMetadataKey>,
}

/// Encrypted `metadata` and the key it is encrypted for, as resources carry them.
#[derive(Debug, Clone)]
pub struct EncryptedMetadata {
    pub metadata: String,
    pub metadata_key_id: String,
    /// `user_key` or `shared_key`.
    pub metadata_key_type: &'static str,
}

/// Lists the key ids only: the keys are secret.
impl std::fmt::Debug for MetadataKeys {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_set()
            .entries(self.private_keys.keys())
            .finish()
    }
}

impl MetadataKeys {
    /// Decrypt the user's share of every metadata key not deleted.
    ///
    /// A key without a share for the user is skipped: in zero-knowledge mode it has not been shared yet.
    pub fn decrypt(
        keys: &[MetadataKey],
        user_id: &str,
        user_key: &SignedSecretKey,
        user_passphrase: &str,
    ) -> Result<Self, PassboltError> {
        let mut decrypted_keys = HashMap::new();
        for metadata_key in keys.iter().filter(|key| key.deleted.is_none()) {
            let Some(share) = metadata_key
                .metadata_private_keys
                .iter()
                .find(|share| share.user_id.as_deref() == Some(user_id))
            else {
                continue;
            };
            let plaintext = crypto::decrypt_message(&share.data, user_key, user_passphrase)
                .map_err(|error| {
                    CryptoError::Decrypt(format!("metadata key {} share: {error}", metadata_key.id))
                })?;
            let private_key = parse_private_key_data(metadata_key, &plaintext)?;
            decrypted_keys.insert(metadata_key.id.clone(), private_key);
        }
        Ok(Self {
            private_keys: decrypted_keys,
            active: active_key(keys)?,
        })
    }

    /// Encrypt `metadata` for the active shared key, signed by the user and by that key.
    pub fn encrypt(
        &self,
        metadata: &ResourceMetadata,
        user: &Signer<'_>,
    ) -> Result<EncryptedMetadata, PassboltError> {
        let active = self.active.as_ref().ok_or_else(|| {
            CryptoError::Encrypt("the server has no active shared metadata key".into())
        })?;
        let mut signers = vec![Signer {
            key: user.key,
            passphrase: user.passphrase,
        }];
        if let Some(private_key) = self.private_keys.get(&active.id) {
            signers.push(Signer {
                key: &private_key.key,
                passphrase: private_key.passphrase.expose_secret(),
            });
        }
        let plaintext = serde_json::to_string(metadata)?;
        Ok(EncryptedMetadata {
            metadata: crypto::sign_and_encrypt(&plaintext, &signers, &[&active.public_key])?,
            metadata_key_id: active.id.clone(),
            metadata_key_type: "shared_key",
        })
    }

    /// The active key, the one new shared metadata is encrypted for.
    #[must_use]
    pub fn active_public_key(&self) -> Option<&SignedPublicKey> {
        self.active.as_ref().map(|active| &active.public_key)
    }

    /// Fingerprint of the active key, the one new shared metadata is encrypted for.
    #[must_use]
    pub fn active_fingerprint(&self) -> Option<String> {
        use pgp::types::PublicKeyTrait;

        self.active
            .as_ref()
            .map(|active| hex::encode_upper(active.public_key.fingerprint().as_bytes()))
    }

    /// The number of keys the user can decrypt metadata with.
    #[must_use]
    pub fn len(&self) -> usize {
        self.private_keys.len()
    }

    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.private_keys.is_empty()
    }
}

/// The latest created key neither expired nor deleted: the server accepts only that one.
fn active_key(keys: &[MetadataKey]) -> Result<Option<ActiveMetadataKey>, PassboltError> {
    let Some(metadata_key) = keys
        .iter()
        .filter(|key| key.deleted.is_none() && key.expired.is_none())
        .max_by_key(|key| key.created)
    else {
        return Ok(None);
    };
    let armored_key = metadata_key.armored_key.as_deref().ok_or_else(|| {
        CryptoError::KeyParse(format!(
            "metadata key {} has no public key",
            metadata_key.id
        ))
    })?;
    Ok(Some(ActiveMetadataKey {
        id: metadata_key.id.clone(),
        public_key: crypto::parse_public_key(armored_key)?,
    }))
}

/// Encrypt `metadata` for the user's own key, signed by the user.
///
/// `gpgkey_id` is the id of the user's key on the server, sent as `metadata_key_id`.
pub fn encrypt_for_user(
    metadata: &ResourceMetadata,
    user: &Signer<'_>,
    user_public_key: &SignedPublicKey,
    gpgkey_id: &str,
) -> Result<EncryptedMetadata, PassboltError> {
    let plaintext = serde_json::to_string(metadata)?;
    Ok(EncryptedMetadata {
        metadata: crypto::sign_and_encrypt(
            &plaintext,
            std::slice::from_ref(user),
            &[user_public_key],
        )?,
        metadata_key_id: gpgkey_id.to_string(),
        metadata_key_type: "user_key",
    })
}

/// The share must hold the private part of the metadata key it is attached to.
fn parse_private_key_data(
    metadata_key: &MetadataKey,
    plaintext: &[u8],
) -> Result<MetadataPrivateKey, PassboltError> {
    let invalid = |reason: String| {
        CryptoError::KeyParse(format!("metadata key {} share: {reason}", metadata_key.id))
    };
    let data: MetadataPrivateKeyData = serde_json::from_slice(plaintext)
        .map_err(|error| invalid(format!("not a metadata private key: {error}")))?;
    if data.object_type != PRIVATE_KEY_OBJECT_TYPE {
        return Err(invalid(format!("unexpected object_type {}", data.object_type)).into());
    }
    let private_key = crypto::parse_private_key(&data.armored_key)?;
    let fingerprints_match = private_key
        .fingerprint
        .eq_ignore_ascii_case(&data.fingerprint)
        && metadata_key
            .fingerprint
            .as_deref()
            .is_none_or(|fingerprint| fingerprint.eq_ignore_ascii_case(&data.fingerprint));
    if !fingerprints_match {
        return Err(invalid("fingerprint mismatch".into()).into());
    }
    Ok(MetadataPrivateKey {
        key: private_key.key.clone(),
        passphrase: data.passphrase,
    })
}

/// Decrypt the `metadata` of a v5 resource; `None` for a v4 resource.
///
/// `user_key` metadata is encrypted for the user, `shared_key` metadata for `metadata_key_id`.
pub fn decrypt_resource_metadata(
    resource: &Resource,
    user_key: &SignedSecretKey,
    user_passphrase: &str,
    shared_keys: &MetadataKeys,
) -> Result<Option<ResourceMetadata>, PassboltError> {
    let decrypted = decrypt_resource_metadata_with_session_keys(
        resource,
        user_key,
        user_passphrase,
        shared_keys,
        &SessionKeys::default(),
    )?;
    Ok(decrypted.map(|(metadata, _)| metadata))
}

/// Like [`decrypt_resource_metadata`], with the session key of the resource when the user has it.
///
/// Much faster than a public key decryption. Also gives the session key of the metadata
/// when it was not known, to save it.
pub fn decrypt_resource_metadata_with_session_keys(
    resource: &Resource,
    user_key: &SignedSecretKey,
    user_passphrase: &str,
    shared_keys: &MetadataKeys,
    session_keys: &SessionKeys,
) -> Result<Option<(ResourceMetadata, Option<SessionKey>)>, PassboltError> {
    let Some(armored) = resource.armored_metadata() else {
        return Ok(None);
    };
    let failure = |reason: String| {
        CryptoError::Decrypt(format!("resource {} metadata: {reason}", resource.id))
    };
    // A stale session key (the metadata changed since) falls back to the keys.
    let known = session_keys
        .get(&resource.id)
        .and_then(|session_key| crypto::decrypt_with_session_key(armored, session_key).ok());
    let (plaintext, new_session_key) = if let Some(plaintext) = known {
        (plaintext, None)
    } else {
        let (key, passphrase) = if resource.metadata_key_type.as_deref() == Some("user_key") {
            (user_key, user_passphrase)
        } else {
            let key_id = resource.metadata_key_id.as_deref().unwrap_or_default();
            let metadata_key = shared_keys.private_keys.get(key_id).ok_or_else(|| {
                failure(format!("the metadata key {key_id} is not shared with you"))
            })?;
            (&metadata_key.key, metadata_key.passphrase.expose_secret())
        };
        let (plaintext, session_key) =
            crypto::decrypt_message_keeping_session_key(armored, key, passphrase)
                .map_err(|error| failure(error.to_string()))?;
        (plaintext, Some(session_key))
    };

    let metadata: ResourceMetadata = serde_json::from_slice(&plaintext)
        .map_err(|error| failure(format!("invalid JSON: {error}")))?;
    if metadata.object_type.as_deref() != Some(RESOURCE_METADATA_OBJECT_TYPE) {
        return Err(failure(format!("unexpected object_type {:?}", metadata.object_type)).into());
    }
    Ok(Some((metadata, new_session_key)))
}

const SESSION_KEYS_OBJECT_TYPE: &str = "PASSBOLT_SESSION_KEYS";

/// One session key of a bundle, as the browser extension writes it.
#[derive(Clone, serde::Serialize, Deserialize)]
struct SessionKeyEntry {
    foreign_model: String,
    foreign_id: String,
    session_key: String,
    #[serde(default)]
    modified: Option<String>,
}

#[derive(serde::Serialize, Deserialize)]
struct SessionKeysBundleData {
    object_type: String,
    session_keys: Vec<SessionKeyEntry>,
}

/// A `/metadata/session-keys.json` bundle: session keys encrypted for the user.
#[derive(Debug, Clone, Deserialize)]
pub struct SessionKeysBundle {
    pub id: String,
    pub data: String,
    #[serde(default)]
    pub modified: Option<String>,
}

/// The session key of a resource's metadata, with the resource's `modified` it is valid for.
pub struct ResourceSessionKey {
    pub resource_id: String,
    pub session_key: SessionKey,
    pub modified: Option<String>,
}

/// The user's session keys of resource metadata, by resource id, and the bundles they came
/// from, to update the latest and delete the others.
#[derive(Default, Clone)]
pub struct SessionKeys {
    keys: HashMap<String, (SessionKey, Option<String>)>,
    /// Entries of other models (folders…), kept as they are when the bundle is rewritten.
    other_entries: Vec<SessionKeyEntry>,
    /// `(id, modified)` of the latest bundle, the one to update.
    bundle: Option<(String, String)>,
    /// Ids of the older bundles, replaced by the latest one.
    older_bundle_ids: Vec<String>,
}

/// Lists the resource ids only: the keys are secret.
impl std::fmt::Debug for SessionKeys {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.debug_set().entries(self.keys.keys()).finish()
    }
}

impl SessionKeys {
    /// Read the bundles, the latest last; one that cannot be read is skipped: session keys are
    /// a cache.
    #[must_use]
    pub fn decrypt(
        bundles: &[SessionKeysBundle],
        user_key: &SignedSecretKey,
        user_passphrase: &str,
    ) -> Self {
        let mut session_keys = Self::default();
        let mut by_date = bundles.iter().collect::<Vec<_>>();
        by_date.sort_by(|first, second| first.modified.cmp(&second.modified));
        for bundle in by_date {
            if let Some((older_id, _)) = session_keys.bundle.take() {
                session_keys.older_bundle_ids.push(older_id);
            }
            session_keys.bundle = Some((
                bundle.id.clone(),
                bundle.modified.clone().unwrap_or_default(),
            ));
            let Ok(plaintext) = crypto::decrypt_message(&bundle.data, user_key, user_passphrase)
            else {
                continue;
            };
            let Ok(data) = serde_json::from_slice::<SessionKeysBundleData>(&plaintext) else {
                continue;
            };
            if data.object_type != SESSION_KEYS_OBJECT_TYPE {
                continue;
            }
            for entry in data.session_keys {
                if entry.foreign_model != "Resource" {
                    session_keys.other_entries.retain(|other| {
                        (&other.foreign_model, &other.foreign_id)
                            != (&entry.foreign_model, &entry.foreign_id)
                    });
                    session_keys.other_entries.push(entry);
                } else if let Ok(session_key) = SessionKey::parse(&entry.session_key) {
                    session_keys
                        .keys
                        .insert(entry.foreign_id, (session_key, entry.modified));
                }
            }
        }
        session_keys
    }

    #[must_use]
    pub fn get(&self, resource_id: &str) -> Option<&SessionKey> {
        self.keys
            .get(resource_id)
            .map(|(session_key, _)| session_key)
    }

    #[must_use]
    pub fn len(&self) -> usize {
        self.keys.len()
    }

    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.keys.is_empty()
    }

    /// `(id, modified)` of the bundle to update; `None` to create one.
    #[must_use]
    pub const fn bundle(&self) -> Option<&(String, String)> {
        self.bundle.as_ref()
    }

    /// Ids of the bundles older than [`Self::bundle`], to delete once it is saved.
    #[must_use]
    pub fn older_bundle_ids(&self) -> &[String] {
        &self.older_bundle_ids
    }

    /// These session keys with `new` ones added or replaced.
    #[must_use]
    pub fn with(&self, new: &[ResourceSessionKey]) -> Self {
        let mut merged = self.clone();
        for resource_session_key in new {
            merged.keys.insert(
                resource_session_key.resource_id.clone(),
                (
                    resource_session_key.session_key.clone(),
                    resource_session_key.modified.clone(),
                ),
            );
        }
        merged
    }

    /// The same session keys, now stored in the bundle `id` at `modified` alone.
    #[must_use]
    pub fn saved_in(mut self, id: String, modified: String) -> Self {
        self.bundle = Some((id, modified));
        self.older_bundle_ids.clear();
        self
    }

    /// The bundle content: every session key, of resources and of other models.
    pub fn bundle_data(&self) -> Result<String, PassboltError> {
        let mut entries: Vec<SessionKeyEntry> = self
            .keys
            .iter()
            .map(|(resource_id, (session_key, modified))| SessionKeyEntry {
                foreign_model: "Resource".into(),
                foreign_id: resource_id.clone(),
                session_key: session_key.to_passbolt_string(),
                modified: modified.clone(),
            })
            .collect();
        entries.extend(self.other_entries.iter().cloned());
        let data = SessionKeysBundleData {
            object_type: SESSION_KEYS_OBJECT_TYPE.into(),
            session_keys: entries,
        };
        Ok(serde_json::to_string(&data)?)
    }
}
