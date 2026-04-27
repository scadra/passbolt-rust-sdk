// The installed npm package loads its WebAssembly module and maps Rust errors to JS errors.
const { getKeyFingerprint, PassboltSession } = require("@switch-case/passbolt-sdk");

if (typeof PassboltSession !== "function") {
  throw new Error("PassboltSession is not exported");
}
try {
  getKeyFingerprint("not a key");
} catch (error) {
  console.log(`ok: ${error}`);
  process.exit(0);
}
throw new Error("expected a crypto error");
