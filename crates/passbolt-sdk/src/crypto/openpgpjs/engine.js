/**
 * Passbolt ~ Open source password manager for teams
 * Copyright (c) Passbolt SA (https://www.passbolt.com)
 *
 * Licensed under GNU Affero General Public License version 3 of the or any later version.
 * For full copyright and license information, please see the LICENSE
 * Redistributions of files must retain the above copyright notice.
 *
 * @copyright     Copyright (c) Passbolt SA (https://www.passbolt.com)
 * @license       https://opensource.org/licenses/AGPL-3.0 AGPL License
 * @link          https://www.passbolt.com Passbolt(tm)
 * @since         0.1.0
 */

/*
 * The operations of the OpenPGP.js engine, called from `mod.rs`, as the browser extension
 * runs them. Keys stay here, by id; a private key is decrypted once per passphrase.
 */

// As the browser extension: some secrets were encrypted for RSA keys not flagged for encryption.
openpgp.config.allowInsecureDecryptionWithSigningKeys = true;

const keys = new Map();
const unlockedKeys = new Map();
let lastKeyId = 0;

function hold(key) {
  keys.set(++lastKeyId, key);
  return { id: lastKeyId, fingerprint: key.getFingerprint().toUpperCase() };
}

function keyOf(id) {
  const key = keys.get(id);
  if (!key) {
    throw new Error("unknown key");
  }
  return key;
}

const passphraseDigest = (passphrase) => new Uint8Array(native.digest("SHA-256", new TextEncoder().encode(passphrase))).join();

async function readPrivateKey(armoredKey) {
  return hold(await openpgp.readPrivateKey({ armoredKey }));
}

async function readPublicKey(armoredKey) {
  const key = await openpgp.readKey({ armoredKey });
  if (key.isPrivate()) {
    throw new Error("a private key, not a public key");
  }
  return hold(key);
}

function forget(id) {
  keys.delete(id);
  unlockedKeys.delete(id);
}

async function unlock(id, passphrase) {
  const digest = passphraseDigest(passphrase);
  const unlocked = unlockedKeys.get(id);
  if (unlocked?.digest === digest) {
    return unlocked.key;
  }
  const key = keyOf(id);
  const decrypted = key.isDecrypted() ? key : await openpgp.decryptKey({ privateKey: key, passphrase });
  unlockedKeys.set(id, { digest, key: decrypted });
  return decrypted;
}

/** The literal content of `decrypted`: text with LF line endings, binary data as it is. */
function content(decrypted) {
  const literal = decrypted.unwrapCompressed().packets.findPacket(openpgp.enums.packet.literalData);
  if (!literal) {
    throw new Error("no literal data");
  }
  return literal.format === openpgp.enums.literal.binary ? literal.getBytes() : new TextEncoder().encode(literal.getText());
}

/** The symmetric algorithm of `message`, for the session keys without one (SEIPD v2). */
function cipherOf(message) {
  const encrypted = message.packets.findPacket(openpgp.enums.packet.symEncryptedIntegrityProtectedData)
    ?? message.packets.findPacket(openpgp.enums.packet.aeadEncryptedData);
  return encrypted?.cipherAlgorithm;
}

async function decrypt(armoredMessage, id, passphrase) {
  const message = await openpgp.readMessage({ armoredMessage });
  return content(await message.decrypt([await unlock(id, passphrase)]));
}

async function decryptKeepingSessionKey(armoredMessage, id, passphrase) {
  const message = await openpgp.readMessage({ armoredMessage });
  const [sessionKey] = await openpgp.decryptSessionKeys({ message, decryptionKeys: await unlock(id, passphrase) });
  const algorithm = sessionKey.algorithm
    ? openpgp.enums.write(openpgp.enums.symmetric, sessionKey.algorithm)
    : cipherOf(message);
  return {
    data: content(await message.decrypt(undefined, undefined, [sessionKey])),
    algorithm,
    key: sessionKey.data,
  };
}

async function decryptWithSessionKey(armoredMessage, algorithm, key) {
  const message = await openpgp.readMessage({ armoredMessage });
  const sessionKey = { data: key, algorithm: openpgp.enums.read(openpgp.enums.symmetric, algorithm) };
  return content(await message.decrypt(undefined, undefined, [sessionKey]));
}

function encrypt(binary, recipientIds) {
  return openpgp.createMessage({ binary })
    .then((message) => openpgp.encrypt({ message, encryptionKeys: recipientIds.map(keyOf) }));
}

async function signAndEncrypt(text, signers, recipientIds) {
  const signingKeys = [];
  for (const { id, passphrase } of signers) {
    signingKeys.push(await unlock(id, passphrase));
  }
  const message = await openpgp.createMessage({ text, format: "utf8" });
  return openpgp.encrypt({ message, encryptionKeys: recipientIds.map(keyOf), signingKeys });
}
