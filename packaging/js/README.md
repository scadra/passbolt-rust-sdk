# @switch-case/passbolt-sdk

JavaScript and TypeScript bindings of the Passbolt Rust SDK, compiled to WebAssembly.
Bundlers (webpack, Vite, …) use `bundler/`, Node.js uses `node/`; both ship the same
TypeScript declarations.

```ts
import { PassboltSession, getKeyFingerprint } from "@switch-case/passbolt-sdk";
```

The session relies on `fetch`. A browser or an extension keeps the session cookies; give
`login` a `csrfTokenProvider` there, e.g. with `browser.cookies.get`. Node (20+), Deno and
Bun keep none: the session keeps the cookies the server sets and sends them back.

```js
const { PassboltSession } = require("@switch-case/passbolt-sdk");

const session = await PassboltSession.login(serverUrl, privateKey, passphrase);
const resources = await session.listResourceViews(undefined, false);
await session.logout();
```
