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
 * The browser APIs OpenPGP.js runs on, over the primitives of `webcrypto.rs` (`native`).
 * An operation `crypto.subtle` does not have fails with `NotSupportedError`: OpenPGP.js then
 * runs its own implementation.
 */

globalThis.self = globalThis;
globalThis.navigator = { userAgent: "passbolt" };

const failure = (name, message) => Object.assign(new Error(message), { name });
const notSupported = (operation) => Promise.reject(failure("NotSupportedError", `${operation} is not supported`));
const bytesOf = (data) => {
  if (data instanceof Uint8Array) {
    return data;
  }
  return ArrayBuffer.isView(data)
    ? new Uint8Array(data.buffer, data.byteOffset, data.byteLength)
    : new Uint8Array(data);
};
const nameOf = (algorithm) => (typeof algorithm === "string" ? algorithm : algorithm.name).toUpperCase();
/** The result of a native primitive, `OperationError` when it could not run. */
const ran = (operation, result) => (result === undefined
  ? Promise.reject(failure("OperationError", `${operation} failed`))
  : Promise.resolve(result));

/** The secret keys `importKey` gives: their raw bytes. */
const RAW_KEY_ALGORITHMS = ["AES-GCM", "AES-CBC", "AES-CTR", "HKDF"];

const subtle = {
  digest(algorithm, data) {
    const name = nameOf(algorithm);
    const digest = native.digest(name, bytesOf(data));
    return digest === undefined ? notSupported(`digest ${name}`) : Promise.resolve(digest);
  },

  importKey(format, keyData, algorithm) {
    const name = nameOf(algorithm);
    if (format !== "raw" || !RAW_KEY_ALGORITHMS.includes(name)) {
      return notSupported(`importKey ${format} ${name}`);
    }
    return Promise.resolve({ type: "secret", algorithm: { name }, raw: bytesOf(keyData).slice() });
  },

  exportKey(format, key) {
    return format === "raw" ? Promise.resolve(key.raw.slice().buffer) : notSupported(`exportKey ${format}`);
  },

  encrypt(parameters, key, data) {
    return cipher(true, parameters, key, data);
  },

  decrypt(parameters, key, data) {
    return cipher(false, parameters, key, data);
  },

  deriveBits(parameters, key, length) {
    if (nameOf(parameters) !== "HKDF") {
      return notSupported(`deriveBits ${nameOf(parameters)}`);
    }
    const hash = nameOf(parameters.hash);
    return ran("HKDF", native.hkdf(hash, key.raw, bytesOf(parameters.salt), bytesOf(parameters.info), length));
  },
};

function cipher(encrypt, parameters, key, data) {
  const name = nameOf(parameters);
  switch (name) {
    case "AES-GCM":
      if ((parameters.tagLength ?? 128) !== 128) {
        return notSupported(`AES-GCM tag of ${parameters.tagLength} bits`);
      }
      return ran(name, native.aesGcm(encrypt, key.raw, bytesOf(parameters.iv), bytesOf(parameters.additionalData ?? []), bytesOf(data)));
    case "AES-CBC":
      return ran(name, native.aesCbc(encrypt, key.raw, bytesOf(parameters.iv), bytesOf(data)));
    case "AES-CTR":
      return ran(name, native.aesCtr(key.raw, bytesOf(parameters.counter), parameters.length, bytesOf(data)));
    default:
      return notSupported(`${encrypt ? "encrypt" : "decrypt"} ${name}`);
  }
}

globalThis.crypto = {
  subtle: new Proxy(subtle, {
    get: (target, operation) => target[operation] ?? (() => notSupported(String(operation))),
  }),
  getRandomValues(array) {
    bytesOf(array).set(new Uint8Array(native.random(array.byteLength)));
    return array;
  },
};

globalThis.TextEncoder = class TextEncoder {
  encode(text = "") {
    const binary = unescape(encodeURIComponent(text));
    const bytes = new Uint8Array(binary.length);
    for (let index = 0; index < binary.length; index++) {
      bytes[index] = binary.charCodeAt(index);
    }
    return bytes;
  }
};

globalThis.TextDecoder = class TextDecoder {
  constructor(label = "utf-8", options = {}) {
    this.fatal = Boolean(options.fatal);
  }

  decode(data) {
    if (data === undefined) {
      return "";
    }
    const bytes = bytesOf(data);
    let binary = "";
    for (let index = 0; index < bytes.length; index += 0x8000) {
      binary += String.fromCharCode.apply(null, bytes.subarray(index, index + 0x8000));
    }
    try {
      return decodeURIComponent(escape(binary));
    } catch (error) {
      if (this.fatal) {
        throw new TypeError("The data is not valid UTF-8");
      }
      return binary;
    }
  }
};
