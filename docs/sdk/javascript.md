---
title: JavaScript and TypeScript
sidebar_position: 3
---

# JavaScript and TypeScript

Use `@switch-case/passbolt-sdk` to log in to Passbolt and read, write and share secrets from
Node.js, Deno, Bun, browsers and extensions.

## Installation

The package is on npm as `@switch-case/passbolt-sdk`: the SDK compiled to WebAssembly, with its
TypeScript declarations.

```bash
npm install @switch-case/passbolt-sdk
```

```bash
yarn add @switch-case/passbolt-sdk
```

```bash
pnpm add @switch-case/passbolt-sdk
```

- Node.js 20.19 or later, Deno and Bun load its `node/` build, with `import` or `require`.
- Bundlers (webpack, Vite…) load its `bundler/` build.

Every session method returns a promise.

## Initialize

Log in with `PassboltSession.login`, then call `logout()` when you are done.

### Node.js, Deno and Bun

These runtimes keep no cookies: the session keeps those the server sets and sends them back, with
nothing to configure.

```ts
import { PassboltSession } from "@switch-case/passbolt-sdk";

const session = await PassboltSession.login(serverUrl, privateKeyArmored, passphrase);
try {
  const views = await session.listResourceViews({ search: "github" });
  for (const view of views) console.log(view.id, view.name, view.username);
} finally {
  await session.logout();
}
```

CommonJS takes the same exports: `const { PassboltSession } = require("@switch-case/passbolt-sdk");`.

### Browsers and extensions

The browser keeps the session cookie. The session needs the `csrfToken` cookie, which `fetch`
cannot read: a page served by Passbolt reads it from `document.cookie`, and an extension gives a
provider.

```ts
import { PassboltSession } from "@switch-case/passbolt-sdk";

const session = await PassboltSession.login(serverUrl, privateKeyArmored, passphrase, {
  csrfTokenProvider: async () =>
    (await browser.cookies.get({ name: "csrfToken", url: serverUrl }))?.value,
});
```

Each session has its own provider, so two sessions can talk to two servers.

### Free the session

`logout()` ends the session on the server. The session object also holds WebAssembly memory,
released when it is garbage collected, or at once with `free()`. With TypeScript 5.2 or later,
`using` frees it at the end of the block:

```ts
import { PassboltSession } from "@switch-case/passbolt-sdk";

{
  using session = await PassboltSession.login(serverUrl, privateKeyArmored, passphrase);
  console.log(session.userId, session.baseUrl);
  await session.logout();
}
```

## Login options

`login` takes an options object as its fourth argument.

| Option | Type | Description |
|---|---|---|
| `csrfTokenProvider` | Function | Returns the `csrfToken` cookie, or a promise of it. |
| `fetch` | `FetchFunction` | Sends the requests in place of the global `fetch`. See [TLS and proxies](#tls-and-proxies). |
| `totpCode` | `string` | The TOTP code answering the MFA challenge. |
| `serverPublicKey` | `string` | The armored server key pinned with `PassboltSession.fetchServerKey(serverUrl)`. |
| `metadataKeyFingerprint` | `string` | The shared metadata key pinned with `session.metadataKeyFingerprint()`. |
| `openpgp` | `object` | The OpenPGP.js module (`import * as openpgp from "openpgp"`) to read and write messages with, for example the one of a browser extension. Default: the OpenPGP.js 6.1.1 the SDK bundles. |

### Pin the server key and answer MFA

```ts
import { PassboltSession } from "@switch-case/passbolt-sdk";

const { fingerprint, armoredKey } = await PassboltSession.fetchServerKey(serverUrl);
console.log(`Check this fingerprint with your administrator: ${fingerprint}`);
const session = await PassboltSession.login(serverUrl, privateKeyArmored, passphrase, {
  serverPublicKey: armoredKey,
  totpCode: "123456",
});
```

## TLS and proxies

The session sends its requests with the global `fetch`. A browser applies its own certificates
and proxy settings. Node's `fetch` takes neither a proxy nor a TLS setting: give `login` a `fetch`
that does, and give the same one to `fetchServerKey`.

```ts
import { Agent, ProxyAgent, fetch as undiciFetch } from "undici";
import { PassboltSession, type FetchFunction } from "@switch-case/passbolt-sdk";

// A server with a certificate of an internal authority:
const dispatcher = new Agent({ connect: { ca: internalCaPem } });
// or through a proxy: new ProxyAgent("http://proxy.example.com:3128")
const fetch: FetchFunction = (url, init) => undiciFetch(url, { ...init, dispatcher });

const { armoredKey } = await PassboltSession.fetchServerKey(serverUrl, { fetch });
const session = await PassboltSession.login(serverUrl, privateKeyArmored, passphrase, {
  fetch,
  serverPublicKey: armoredKey,
});
```

The SDK calls the function as `fetch(url, init)`:

- `init` holds plain values only: `method`, `headers` as an object, `body` as an `ArrayBuffer`.
  Any `fetch` takes it: the global one, undici's, node-fetch, or the request helper of a host
  application.
- The SDK reads `status`, `headers` and `arrayBuffer()` of what it returns.
- A rejection is a `NETWORK` error, with the cause Node gives: `fetch failed: self-signed
  certificate`.

Without changing the code, Node also trusts the certificates of `NODE_EXTRA_CA_CERTS`, a PEM file
read at start-up:

```bash
NODE_EXTRA_CA_CERTS=/etc/ssl/internal-ca.pem node app.js
```

:::caution
Skipping the check (`rejectUnauthorized: false`) leaves the session open to whoever answers at the
address. Pin the server key with `serverPublicKey` at least.
:::

## Read resources

`getResourceView` and `listResourceViews` decrypt the name, username, URIs and, on request, the
secret. Methods with optional arguments take an options object.

### Read a resource and search your resources

```ts
const view = await session.getResourceView(id); // name, username, uris, password, secret…
const withSecrets = await session.listResourceViews({ search: "github", withSecrets: true });
const favorites = await session.listResources({ favoritesOnly: true });
```

## Create and share resources

`createResource` takes the fields of the resource, `updateResource` only the fields to change.
Permission types are `1` read, `7` update, `15` owner, `-1` to revoke.

### Create, update, share and move a resource

```ts
const created = await session.createResource({ name: "GitHub", username: "ada", password: "s3cret" });
await session.updateResource(created.id, { password: "new" });
await session.shareResource(created.id, { userIds: [userId], permissionType: 7 });
await session.moveResource(created.id, folderId);
```

### Manage folders, users and groups

```ts
const folder = await session.createFolder("Ops");
await session.shareFolder(folder.id, { groupIds: [groupId], permissionType: 1, withContent: true });

const betty = await session.createUser({ username: "betty@example.com", firstName: "Betty", lastName: "Holberton" });
const group = await session.createGroup({ name: "Ops", managerIds: [session.userId], memberIds: [betty.id] });
await session.updateGroup(group.id, { name: "Infra", removeMemberIds: [betty.id] });
```

## Generate a password

Generate passwords from character sets, passphrases of words of the EFF list, and PIN codes, as
the browser extension does. Start from the password policies of the organization or from settings
of your own.

The settings have the shape of the API, the `PasswordPoliciesDto` of the extension: the fields you
leave out keep the defaults of Passbolt. The functions need no session.

### Generate secrets and rate them

```ts
import {
  generatePassphrase,
  generatePassword,
  generatePinCode,
  generateSecret,
  secretEntropy,
  secretStrength,
} from "@switch-case/passbolt-sdk";

const policies = await session.getPasswordPolicies(); // the organization's
const secret = generateSecret(policies);

const password = generatePassword({ length: 24, mask_emoji: true });
const passphrase = generatePassphrase({ words: 6, word_separator: "-", word_case: "camelcase" });
const pinCode = generatePinCode(6);

secretStrength(password); // "very-strong", the ids of the extension
secretEntropy(password); // in bits
```

## Handle errors

Every failure rejects the promise, or throws for the synchronous helpers, with an `Error` named
`PassboltError`. Its `code` says what failed; an API error also has the HTTP `status` and the
`validationErrors` of the server. `isPassboltError` narrows an unknown error to it.

### Handle a missing resource and an expired session

```ts
import { isPassboltError } from "@switch-case/passbolt-sdk";

try {
  await session.getResource(id);
} catch (error) {
  if (!isPassboltError(error)) throw error;
  switch (error.code) {
    case "NOT_FOUND":
      console.log("No such resource");
      break;
    case "SESSION_EXPIRED":
      console.log("Log in again");
      break;
    default:
      console.error(error.code, error.status, error.message);
  }
}
```

| `code` | Description |
|---|---|
| `NETWORK`, `TIMEOUT` | The server could not be reached. |
| `LOGIN_FAILED`, `SESSION_EXPIRED` | The login failed, or the session ended. |
| `MFA_REQUIRED`, `MFA_FAILED`, `MFA_UNSUPPORTED`, `MFA_LOCKED_OUT` | The MFA challenge: no `totpCode`, a wrong one, no TOTP provider, too many attempts. |
| `SERVER_IDENTITY_MISMATCH`, `UNTRUSTED_METADATA_KEY` | A pinned key does not match. |
| `INVALID_KEY`, `DECRYPTION_FAILED`, `ENCRYPTION_FAILED`, `CRYPTO` | OpenPGP. |
| `NOT_FOUND` | No such item (an API 404 too). |
| `API` | Another API error, with its `status`. |
| `INVALID_ARGUMENT` | An argument, or an option, the SDK refuses before any request. |
| `INVALID_RESPONSE`, `CONFIG`, `UNKNOWN` | Anything else. |

## Encrypt and decrypt messages

The stateless helpers work outside a session: `encryptMessage(plaintext, publicKeysArmored)`,
`decryptMessage(armoredMessage, privateKeyArmored, passphrase)` and
`getKeyFingerprint(privateKeyArmored)`.

### Encrypt a message and decrypt it

```ts
import { decryptMessage, encryptMessage } from "@switch-case/passbolt-sdk";

const armored = await encryptMessage(new TextEncoder().encode("hello"), [publicKeyArmored]);
const plaintext = new TextDecoder().decode(await decryptMessage(armored, privateKeyArmored, passphrase));
```

## Methods

| Area | Methods |
|---|---|
| Session | `login`, `fetchServerKey` (static), `logout`, `keepAlive`, `checkAuth`, `metadataKeyFingerprint`, `userId`, `baseUrl`, `free` |
| Resources | `listResources({ search?, favoritesOnly?, ownedByMe? })`, `getResource`, `getResourcesByIds`, `getResourceView`, `listResourceViews({ search?, withSecrets? })`, `decryptResourceSecret`, `createResource`, `updateResource`, `deleteResource`, `deleteResources`, `shareResource(id, { userIds?, groupIds?, permissionType })`, `moveResource(id, folderId?)`, `getResourcePermissions` |
| Folders | `listFolders({ search? })`, `getFolder`, `getFolderTree`, `createFolder(name, parentId?)`, `renameFolder`, `deleteFolder`, `deleteFolderWithContent`, `shareFolder(id, { userIds?, groupIds?, permissionType, withContent? })`, `moveFolder(id, folderId?)`, `getFolderPermissions` |
| Users | `listUsers({ search?, groupId?, adminOnly? })`, `getMe`, `getUser`, `createUser({ username, firstName, lastName, role? })`, `updateUser(id, { firstName?, lastName?, role? })`, `deleteUser`, `deleteUserDryRun`, `userDeleteBlockers`, `deleteUserWithTransfer(id, successorId)` |
| Groups | `listGroups`, `getGroup`, `createGroup({ name, memberIds?, managerIds? })`, `updateGroup(id, { name?, addMemberIds?, addManagerIds?, removeMemberIds? })`, `deleteGroup`, `deleteGroupDryRun`, `groupDeleteBlockers`, `deleteGroupWithTransfer(id, successorId)` |
| Tags, comments, favorites | `getTags`, `addTagToResource`, `setResourceTags`, `renameTag`, `deleteTag`, `getComments`, `createComment(resourceId, content, parentId?)`, `deleteComment`, `addFavorite`, `removeFavorite` |
| Settings | `getPasswordPolicies`, `savePasswordPolicies`, `getPasswordExpirySettings`, `savePasswordExpirySettings`, `deletePasswordExpirySettings`, `listResourceTypes`, `getMetadataTypesSettings`, `saveMetadataTypesSettings`, `getMetadataKeysSettings`, `saveMetadataKeysSettings` |
| Other | `searchAros`, `checkPasswordPwned` (a `number`) |

The functions outside a session: `encryptMessage`, `decryptMessage`, `getKeyFingerprint`,
`isPassboltError`, and the generator: `generatePassword`, `generatePassphrase`, `generateSecret`,
`generatePinCode`, `secretEntropy`, `secretStrength`.

## Types

The declarations type what each method takes and returns.

- The options of the methods are camelCase.
- The objects of the Passbolt API keep its field names (`folder_parent_id`, `groups_users`…), with
  `null` for an absent value and dates as RFC 3339 strings.

### Type a login and its results

```ts
import { PassboltSession } from "@switch-case/passbolt-sdk";
import type { LoginOptions, NewResource, Resource, ResourceView } from "@switch-case/passbolt-sdk";

const options: LoginOptions = { totpCode: "123456" };
const session = await PassboltSession.login(serverUrl, privateKeyArmored, passphrase, options);
const views: ResourceView[] = await session.listResourceViews();
const created: Resource = await session.createResource({ name: "GitHub" } satisfies NewResource);
console.log(views.length, created.folder_parent_id);
```

The main types:

- Records: `Resource`, `ResourceView`, `SecretData`, `NewResource`, `ResourceChanges`, `Folder`,
  `FolderTreeNode`, `User`, `Group`, `Permission`, `DeleteBlockers`, `Tag`, `Comment`, `Favorite`,
  `Aro`, `ResourceType`.
- Generator and settings: `PasswordPolicies`, `PasswordGeneratorSettings`,
  `PassphraseGeneratorSettings`, `Strength`, `PasswordExpirySettings`, `MetadataTypesSettings`,
  `MetadataKeysSettings`.
- Login and transport: `LoginOptions`, `FetchServerKeyOptions`, `FetchFunction`, `FetchInit`,
  `FetchResponse`, `ServerKey`.
- Errors: `PassboltError`, `PassboltErrorCode`.
- Options: `ResourceFilter`, `ResourceViewFilter`, `FolderFilter`, `UserFilter`, `Share`,
  `FolderShare`, `NewUser`, `UserChanges`, `NewGroup`, `GroupChanges`.

## Related

- [Overview](README.md): the concepts shared by every language.
- [API reference](api.md#javascript): how the JavaScript API differs from the other bindings.
- [Upgrading](upgrading.md): the breaking changes since the 0.1.1 packages.
