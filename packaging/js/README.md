# @passbolt/sdk

JavaScript and TypeScript bindings of the Passbolt Rust SDK, compiled to WebAssembly.
Bundlers (webpack, Vite, …) use `bundler/`, Node.js uses `node/`; both ship the same
TypeScript declarations.

```ts
import { PassboltSession, getKeyFingerprint } from "@passbolt/sdk";
```

The session relies on `fetch` with cookie credentials, as in a browser or an extension.
