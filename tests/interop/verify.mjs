// Decrypt an OpenPGP message with OpenPGP.js, the library of the browser extension, and check
// its signatures. Input (stdin, JSON): message, then decryption_key (+ passphrase) or session_key
// ("9:HEX"), and verification_keys. Output (stdout, JSON): text and each signature's key and result.
import * as openpgp from "openpgp";

const chunks = [];
for await (const chunk of process.stdin) {
  chunks.push(chunk);
}
const input = JSON.parse(Buffer.concat(chunks).toString("utf8"));

const message = await openpgp.readMessage({ armoredMessage: input.message });
const options = {
  message,
  verificationKeys: await Promise.all(
    input.verification_keys.map((armoredKey) => openpgp.readKey({ armoredKey })),
  ),
};
if (input.session_key) {
  const [algorithm, hex] = input.session_key.split(":");
  if (algorithm !== "9") {
    throw new Error(`unsupported session key algorithm ${algorithm}`);
  }
  options.sessionKeys = { data: Uint8Array.from(Buffer.from(hex, "hex")), algorithm: "aes256" };
} else {
  let key = await openpgp.readPrivateKey({ armoredKey: input.decryption_key });
  if (!key.isDecrypted()) {
    key = await openpgp.decryptKey({ privateKey: key, passphrase: input.passphrase });
  }
  options.decryptionKeys = key;
}

const { data, signatures } = await openpgp.decrypt(options);
const results = [];
for (const signature of signatures) {
  try {
    await signature.verified;
    results.push({ key_id: signature.keyID.toHex(), valid: true });
  } catch (error) {
    results.push({ key_id: signature.keyID.toHex(), valid: false, error: error.message });
  }
}
process.stdout.write(JSON.stringify({ text: data, signatures: results }));
