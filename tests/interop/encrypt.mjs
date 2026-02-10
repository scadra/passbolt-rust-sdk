// Encrypt a text with OpenPGP.js in an AEAD container. Input (stdin, JSON): text, the recipient's
// private_key and passphrase, and container: "seipd_v2" (RFC 9580, written by OpenPGP.js for keys
// that ask for it) or "gnupg_aead" (the OCB packet GnuPG writes). Output (stdout, JSON): message.
import * as openpgp from "openpgp";

const chunks = [];
for await (const chunk of process.stdin) {
  chunks.push(chunk);
}
const input = JSON.parse(Buffer.concat(chunks).toString("utf8"));

let privateKey = await openpgp.readPrivateKey({ armoredKey: input.private_key });
if (!privateKey.isDecrypted()) {
  privateKey = await openpgp.decryptKey({ privateKey, passphrase: input.passphrase });
}
const text = await openpgp.createMessage({ text: input.text });

async function seipdV2() {
  // The same key, with preferences asking for SEIPD v2.
  const { publicKey } = await openpgp.reformatKey({
    privateKey,
    userIDs: privateKey.users.map((user) => user.userID),
    format: "object",
    config: { aeadProtect: true },
  });
  return openpgp.encrypt({ message: text, encryptionKeys: publicKey, config: { aeadProtect: true } });
}

async function gnupgAead() {
  const sessionKey = await openpgp.generateSessionKey({ encryptionKeys: privateKey.toPublic() });
  const encryptedKeys = await openpgp.encryptSessionKey({
    ...sessionKey,
    encryptionKeys: privateKey.toPublic(),
    format: "object",
  });
  const data = new openpgp.AEADEncryptedDataPacket();
  data.aeadAlgorithm = openpgp.enums.aead.ocb;
  data.packets = text.packets;
  await data.encrypt(openpgp.enums.symmetric[sessionKey.algorithm], sessionKey.data);
  const packets = new openpgp.PacketList();
  packets.push(...encryptedKeys.packets, data);
  // The packet encrypts as a stream: read it to the end.
  const armored = new openpgp.Message(packets).armor();
  return armored.readToEnd((parts) => parts.join(""));
}

const containers = { seipd_v2: seipdV2, gnupg_aead: gnupgAead };
process.stdout.write(JSON.stringify({ message: await containers[input.container]() }));
