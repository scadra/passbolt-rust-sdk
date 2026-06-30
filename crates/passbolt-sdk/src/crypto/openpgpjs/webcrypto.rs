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

//! The `WebCrypto` primitives OpenPGP.js has no JavaScript fallback for, or runs too slowly in
//! JavaScript: digests, AES-GCM, AES-CBC, AES-CTR and HKDF. `webcrypto.js` exposes them as
//! `crypto.subtle`; what is missing there makes OpenPGP.js use its own implementation.

use aes::cipher::{BlockDecryptMut, BlockEncryptMut, KeyInit, KeyIvInit, StreamCipher};
use aes_gcm::aead::{Aead, Payload};
use rquickjs::{ArrayBuffer, Ctx, Function, Object, Result, TypedArray};
use sha2::Digest;

/// The bytes of a `Uint8Array`, copied before any JavaScript runs again.
#[allow(unsafe_code)]
pub fn bytes(array: &TypedArray<'_, u8>) -> Vec<u8> {
    // SAFETY: the slice is copied at once, while no JavaScript runs that could detach or
    // write into the buffer.
    unsafe { array.as_slice() }.to_vec()
}

fn buffer<'js>(ctx: &Ctx<'js>, data: Option<Vec<u8>>) -> Result<Option<ArrayBuffer<'js>>> {
    data.map(|data| ArrayBuffer::new(ctx.clone(), data))
        .transpose()
}

fn digest(name: &str, data: &[u8]) -> Option<Vec<u8>> {
    Some(match name {
        "SHA-1" => sha1::Sha1::digest(data).to_vec(),
        "SHA-256" => sha2::Sha256::digest(data).to_vec(),
        "SHA-384" => sha2::Sha384::digest(data).to_vec(),
        "SHA-512" => sha2::Sha512::digest(data).to_vec(),
        _ => return None,
    })
}

/// AES-GCM with a 16 bytes tag and a 12 bytes nonce, as `OpenPGP` uses it; `None` when the
/// tag does not match.
fn aes_gcm(encrypt: bool, key: &[u8], iv: &[u8], aad: &[u8], data: &[u8]) -> Option<Vec<u8>> {
    use aes_gcm::{Aes128Gcm, Aes256Gcm, Nonce};

    if iv.len() != 12 {
        return None;
    }
    let nonce = Nonce::from_slice(iv);
    let payload = Payload { msg: data, aad };
    match key.len() {
        16 => {
            let cipher = Aes128Gcm::new_from_slice(key).ok()?;
            if encrypt {
                cipher.encrypt(nonce, payload)
            } else {
                cipher.decrypt(nonce, payload)
            }
        }
        32 => {
            let cipher = Aes256Gcm::new_from_slice(key).ok()?;
            if encrypt {
                cipher.encrypt(nonce, payload)
            } else {
                cipher.decrypt(nonce, payload)
            }
        }
        _ => return None,
    }
    .ok()
}

/// AES-CBC with PKCS#7 padding, as `WebCrypto` has it.
fn aes_cbc(encrypt: bool, key: &[u8], iv: &[u8], data: &[u8]) -> Option<Vec<u8>> {
    use aes::cipher::block_padding::Pkcs7;

    macro_rules! run {
        ($aes:ty) => {
            if encrypt {
                Some(
                    cbc::Encryptor::<$aes>::new_from_slices(key, iv)
                        .ok()?
                        .encrypt_padded_vec_mut::<Pkcs7>(data),
                )
            } else {
                cbc::Decryptor::<$aes>::new_from_slices(key, iv)
                    .ok()?
                    .decrypt_padded_vec_mut::<Pkcs7>(data)
                    .ok()
            }
        };
    }
    match key.len() {
        16 => run!(aes::Aes128),
        24 => run!(aes::Aes192),
        32 => run!(aes::Aes256),
        _ => None,
    }
}

/// AES-CTR over a big-endian counter of the last `length` bits of `counter`.
fn aes_ctr(key: &[u8], counter: &[u8], length: u32, data: &[u8]) -> Option<Vec<u8>> {
    macro_rules! run {
        ($aes:ty) => {
            match length {
                128 => apply::<ctr::Ctr128BE<$aes>>(key, counter, data),
                64 => apply::<ctr::Ctr64BE<$aes>>(key, counter, data),
                32 => apply::<ctr::Ctr32BE<$aes>>(key, counter, data),
                _ => None,
            }
        };
    }
    fn apply<C: KeyIvInit + StreamCipher>(key: &[u8], iv: &[u8], data: &[u8]) -> Option<Vec<u8>> {
        let mut output = data.to_vec();
        C::new_from_slices(key, iv)
            .ok()?
            .try_apply_keystream(&mut output)
            .ok()?;
        Some(output)
    }
    match key.len() {
        16 => run!(aes::Aes128),
        24 => run!(aes::Aes192),
        32 => run!(aes::Aes256),
        _ => None,
    }
}

fn hkdf(hash: &str, key: &[u8], salt: &[u8], info: &[u8], bits: usize) -> Option<Vec<u8>> {
    let mut output = vec![0; bits / 8];
    match hash {
        "SHA-256" => hkdf::Hkdf::<sha2::Sha256>::new(Some(salt), key)
            .expand(info, &mut output)
            .ok()?,
        "SHA-384" => hkdf::Hkdf::<sha2::Sha384>::new(Some(salt), key)
            .expand(info, &mut output)
            .ok()?,
        "SHA-512" => hkdf::Hkdf::<sha2::Sha512>::new(Some(salt), key)
            .expand(info, &mut output)
            .ok()?,
        _ => return None,
    }
    Some(output)
}

/// Install the primitives on `native`, each giving an `ArrayBuffer`, `undefined` when it
/// cannot run the operation.
pub fn install<'js>(ctx: &Ctx<'js>, native: &Object<'js>) -> Result<()> {
    native.set(
        "random",
        Function::new(ctx.clone(), |ctx: Ctx<'js>, length: usize| {
            let mut data = vec![0; length];
            rand::RngCore::fill_bytes(&mut rand::thread_rng(), &mut data);
            ArrayBuffer::new(ctx, data)
        }),
    )?;
    native.set(
        "digest",
        Function::new(
            ctx.clone(),
            |ctx: Ctx<'js>, name: String, data: TypedArray<'js, u8>| {
                buffer(&ctx, digest(&name, &bytes(&data)))
            },
        ),
    )?;
    native.set(
        "aesGcm",
        Function::new(
            ctx.clone(),
            |ctx: Ctx<'js>,
             encrypt: bool,
             key: TypedArray<'js, u8>,
             iv: TypedArray<'js, u8>,
             aad: TypedArray<'js, u8>,
             data: TypedArray<'js, u8>| {
                let output = aes_gcm(
                    encrypt,
                    &bytes(&key),
                    &bytes(&iv),
                    &bytes(&aad),
                    &bytes(&data),
                );
                buffer(&ctx, output)
            },
        ),
    )?;
    native.set(
        "aesCbc",
        Function::new(
            ctx.clone(),
            |ctx: Ctx<'js>,
             encrypt: bool,
             key: TypedArray<'js, u8>,
             iv: TypedArray<'js, u8>,
             data: TypedArray<'js, u8>| {
                buffer(
                    &ctx,
                    aes_cbc(encrypt, &bytes(&key), &bytes(&iv), &bytes(&data)),
                )
            },
        ),
    )?;
    native.set(
        "aesCtr",
        Function::new(
            ctx.clone(),
            |ctx: Ctx<'js>,
             key: TypedArray<'js, u8>,
             counter: TypedArray<'js, u8>,
             length: u32,
             data: TypedArray<'js, u8>| {
                buffer(
                    &ctx,
                    aes_ctr(&bytes(&key), &bytes(&counter), length, &bytes(&data)),
                )
            },
        ),
    )?;
    native.set(
        "hkdf",
        Function::new(
            ctx.clone(),
            |ctx: Ctx<'js>,
             hash: String,
             key: TypedArray<'js, u8>,
             salt: TypedArray<'js, u8>,
             info: TypedArray<'js, u8>,
             bits: usize| {
                buffer(
                    &ctx,
                    hkdf(&hash, &bytes(&key), &bytes(&salt), &bytes(&info), bits),
                )
            },
        ),
    )?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// NIST SP 800-38A F.5.1, CTR-AES128.Encrypt, first block.
    #[test]
    fn test_aes_ctr_follows_nist() {
        let key = hex::decode("2b7e151628aed2a6abf7158809cf4f3c").unwrap();
        let counter = hex::decode("f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff").unwrap();
        let plaintext = hex::decode("6bc1bee22e409f96e93d7e117393172a").unwrap();

        let ciphertext = aes_ctr(&key, &counter, 128, &plaintext).unwrap();

        assert_eq!(hex::encode(ciphertext), "874d6191b620e3261bef6864990db6ce");
    }

    #[test]
    fn test_aes_gcm_refuses_a_wrong_tag() {
        let key = [7; 32];
        let iv = [1; 12];
        let mut sealed = aes_gcm(true, &key, &iv, b"aad", b"secret").unwrap();
        sealed[0] ^= 1;

        assert!(aes_gcm(false, &key, &iv, b"aad", &sealed).is_none());
    }

    #[test]
    fn test_aes_cbc_round_trips() {
        let key = [3; 24];
        let iv = [9; 16];

        let sealed = aes_cbc(true, &key, &iv, b"seventeen bytes!!").unwrap();

        assert_eq!(sealed.len(), 32);
        assert_eq!(
            aes_cbc(false, &key, &iv, &sealed).unwrap(),
            b"seventeen bytes!!"
        );
    }

    /// RFC 5869 A.1.
    #[test]
    fn test_hkdf_follows_rfc_5869() {
        let key = [0x0b; 22];
        let salt = hex::decode("000102030405060708090a0b0c").unwrap();
        let info = hex::decode("f0f1f2f3f4f5f6f7f8f9").unwrap();

        let output = hkdf("SHA-256", &key, &salt, &info, 42 * 8).unwrap();

        assert_eq!(
            hex::encode(output),
            "3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf34007208d5b887185865"
        );
    }

    #[test]
    fn test_an_unknown_digest_is_not_run() {
        assert!(digest("MD5", b"").is_none());
    }
}
