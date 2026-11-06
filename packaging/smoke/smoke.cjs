// The installed npm package loads its WebAssembly module, with `require` and with `import`, and
// throws a `PassboltError` with a `code`.
const assert = require("node:assert/strict");
const { getKeyFingerprint, isPassboltError, PassboltSession } = require("@switch-case/passbolt-sdk");

assert.equal(typeof PassboltSession.login, "function", "PassboltSession is not exported");
assert.throws(
  () => getKeyFingerprint("not a key"),
  (error) =>
    error instanceof Error &&
    isPassboltError(error) &&
    error.name === "PassboltError" &&
    error.code === "INVALID_KEY",
);
assert.equal(isPassboltError(new Error("other")), false);

import("@switch-case/passbolt-sdk").then((esm) => {
  assert.equal(esm.PassboltSession, PassboltSession, "import and require give other modules");
  console.log("ok");
});
