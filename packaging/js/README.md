# @switch-case/passbolt-sdk

JavaScript and TypeScript bindings of the Passbolt Rust SDK, compiled to WebAssembly. Node.js
(20.19+), Deno and Bun load the `node/` build, `import` and `require` alike; bundlers (webpack,
Vite, …) the `bundler/` build. Both ship the same TypeScript declarations.

```ts
import { PassboltSession, isPassboltError } from "@switch-case/passbolt-sdk";

const session = await PassboltSession.login(serverUrl, privateKeyArmored, passphrase);
try {
  const views = await session.listResourceViews({ search: "github" });
  for (const view of views) console.log(view.id, view.name, view.username);
} catch (error) {
  if (isPassboltError(error) && error.code === "SESSION_EXPIRED") {
    // log in again
  }
  throw error;
} finally {
  await session.logout();
}
```

Every session method returns a promise; errors are `Error`s named `PassboltError`, with a
`code`. Node, Deno and Bun keep no cookies: the session keeps the cookies the server sets and
sends them back. A browser or an extension keeps them; give `login` a `csrfTokenProvider` there,
e.g. with `browser.cookies.get`.

Documentation: https://github.com/scadra/passbolt-rust-sdk/blob/master/docs/sdk/javascript.md
