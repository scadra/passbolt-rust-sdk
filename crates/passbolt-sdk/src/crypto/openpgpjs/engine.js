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
 * The operations of the OpenPGP.js engine, as the browser extension runs them, on the OpenPGP.js
 * of QuickJS (`mod.rs`) or of the page (`page.rs`). Keys are named by their armored text and
 * read once; a private key is decrypted once per passphrase, until it is forgotten.
 */

/**
 * @param {object} openpgp The OpenPGP.js module.
 */
export function createEngine(openpgp) {
  // As the browser extension: some secrets were encrypted for RSA keys not flagged for encryption.
  openpgp.config.allowInsecureDecryptionWithSigningKeys = true;

  const privateKeys = new Map();
  const publicKeys = new Map();
  const unlockedKeys = new Map();

  const digestOf = async(passphrase) => new Uint8Array(
    await crypto.subtle.digest("SHA-256", new TextEncoder().encode(passphrase))
  ).join();

  async function privateKey(armoredKey) {
    if (!privateKeys.has(armoredKey)) {
      privateKeys.set(armoredKey, await openpgp.readPrivateKey({ armoredKey }));
    }
    return privateKeys.get(armoredKey);
  }

  async function publicKey(armoredKey) {
    if (!publicKeys.has(armoredKey)) {
      const key = await openpgp.readKey({ armoredKey });
      if (key.isPrivate()) {
        throw new Error("a private key, not a public key");
      }
      publicKeys.set(armoredKey, key);
    }
    return publicKeys.get(armoredKey);
  }

  async function unlock(armoredKey, passphrase) {
    const digest = await digestOf(passphrase);
    const unlocked = unlockedKeys.get(armoredKey);
    if (unlocked?.digest === digest) {
      return unlocked.key;
    }
    const key = await privateKey(armoredKey);
    const decrypted = key.isDecrypted() ? key : await openpgp.decryptKey({ privateKey: key, passphrase });
    unlockedKeys.set(armoredKey, { digest, key: decrypted });
    return decrypted;
  }

  /** The literal content of `decrypted`: text with LF line endings, binary data as it is. */
  function content(decrypted) {
    const literal = decrypted.unwrapCompressed().packets.findPacket(openpgp.enums.packet.literalData);
    if (!literal) {
      throw new Error("no literal data");
    }
    return literal.format === openpgp.enums.literal.binary
      ? literal.getBytes()
      : new TextEncoder().encode(literal.getText());
  }

  /** The symmetric algorithm of `message`, for the session keys without one (SEIPD v2). */
  function cipherOf(message) {
    const encrypted = message.packets.findPacket(openpgp.enums.packet.symEncryptedIntegrityProtectedData)
      ?? message.packets.findPacket(openpgp.enums.packet.aeadEncryptedData);
    return encrypted?.cipherAlgorithm;
  }

  const fingerprintOf = (key) => key.getFingerprint().toUpperCase();
  const recipientKeys = (armoredKeys) => Promise.all(armoredKeys.map(publicKey));

  return {
    readPrivateKey: async(armoredKey) => fingerprintOf(await privateKey(armoredKey)),

    readPublicKey: async(armoredKey) => fingerprintOf(await publicKey(armoredKey)),

    forget(armoredKey) {
      privateKeys.delete(armoredKey);
      publicKeys.delete(armoredKey);
      unlockedKeys.delete(armoredKey);
    },

    async decrypt(armoredMessage, armoredKey, passphrase) {
      const message = await openpgp.readMessage({ armoredMessage });
      return content(await message.decrypt([await unlock(armoredKey, passphrase)]));
    },

    async decryptKeepingSessionKey(armoredMessage, armoredKey, passphrase) {
      const message = await openpgp.readMessage({ armoredMessage });
      const decryptionKeys = await unlock(armoredKey, passphrase);
      const [sessionKey] = await openpgp.decryptSessionKeys({ message, decryptionKeys });
      const algorithm = sessionKey.algorithm
        ? openpgp.enums.write(openpgp.enums.symmetric, sessionKey.algorithm)
        : cipherOf(message);
      return {
        data: content(await message.decrypt(undefined, undefined, [sessionKey])),
        algorithm,
        key: sessionKey.data,
      };
    },

    async decryptWithSessionKey(armoredMessage, algorithm, key) {
      const message = await openpgp.readMessage({ armoredMessage });
      const sessionKey = { data: key, algorithm: openpgp.enums.read(openpgp.enums.symmetric, algorithm) };
      return content(await message.decrypt(undefined, undefined, [sessionKey]));
    },

    async encrypt(binary, armoredRecipients) {
      const message = await openpgp.createMessage({ binary });
      return openpgp.encrypt({ message, encryptionKeys: await recipientKeys(armoredRecipients) });
    },

    async signAndEncrypt(text, signers, armoredRecipients) {
      const signingKeys = [];
      for (const { key, passphrase } of signers) {
        signingKeys.push(await unlock(key, passphrase));
      }
      const message = await openpgp.createMessage({ text, format: "utf8" });
      return openpgp.encrypt({ message, encryptionKeys: await recipientKeys(armoredRecipients), signingKeys });
    },
  };
}
