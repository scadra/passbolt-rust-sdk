---
title: JavaScript and TypeScript
sidebar_position: 3
---

# JavaScript and TypeScript

```bash
npm install @switch-case/passbolt-sdk
```

The SDK compiled to WebAssembly, with its TypeScript declarations. Node.js (20.19 or later), Deno
and Bun load its `node/` build, with `import` or `require`; bundlers (webpack, Vite…) its
`bundler/` build. Every session method returns a promise.

## Node.js, Deno, Bun

These runtimes keep no cookies: the session keeps those the server sets and sends them back,
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

## Browsers and extensions

The browser keeps the session cookie; the session needs the `csrfToken` cookie, which `fetch`
cannot read. A page served by Passbolt reads it from `document.cookie`; an extension gives a
provider:

```ts
import { PassboltSession } from "@switch-case/passbolt-sdk";

const session = await PassboltSession.login(serverUrl, privateKeyArmored, passphrase, {
  csrfTokenProvider: async () =>
    (await browser.cookies.get({ name: "csrfToken", url: serverUrl }))?.value,
});
```

Each session has its own provider: two sessions can talk to two servers.

## Login options

| Option | |
|---|---|
| `csrfTokenProvider` | Function returning the `csrfToken` cookie, or a promise of it |
| `totpCode` | The TOTP code answering the MFA challenge |
| `serverPublicKey` | The armored server key pinned with `PassboltSession.fetchServerKey(serverUrl)` |
| `metadataKeyFingerprint` | The shared metadata key pinned with `session.metadataKeyFingerprint()` |
| `openpgp` | The OpenPGP.js module (`import * as openpgp from "openpgp"`) to read and write messages with; default: the SDK's own |

TLS and proxies are the browser's or the runtime's business.

```ts
import { PassboltSession } from "@switch-case/passbolt-sdk";

const { fingerprint, armoredKey } = await PassboltSession.fetchServerKey(serverUrl);
console.log(`Check this fingerprint with your administrator: ${fingerprint}`);
const session = await PassboltSession.login(serverUrl, privateKeyArmored, passphrase, {
  serverPublicKey: armoredKey,
  totpCode: "123456",
});
```

## Reading and writing

Methods with optional arguments take an options object.

```ts
const view = await session.getResourceView(id); // name, username, uris, password, secret…
const withSecrets = await session.listResourceViews({ search: "github", withSecrets: true });
const favorites = await session.listResources({ favoritesOnly: true });

const created = await session.createResource({ name: "GitHub", username: "ada", password: "s3cret" });
await session.updateResource(created.id, { password: "new" });
await session.shareResource(created.id, { userIds: [userId], permissionType: 7 });
await session.moveResource(created.id, folderId);

const folder = await session.createFolder("Ops");
await session.shareFolder(folder.id, { groupIds: [groupId], permissionType: 1, withContent: true });

const betty = await session.createUser({ username: "betty@example.com", firstName: "Betty", lastName: "Holberton" });
const group = await session.createGroup({ name: "Ops", managerIds: [session.userId], memberIds: [betty.id] });
await session.updateGroup(group.id, { name: "Infra", removeMemberIds: [betty.id] });
```

Permission types are `1` read, `7` update, `15` owner, `-1` to revoke.

## Errors

Every failure rejects the promise (or throws, for the synchronous helpers) with an `Error` named
`PassboltError`, whose `code` says what failed; an API error also has the HTTP `status` and the
`validationErrors` of the server. `isPassboltError` narrows an unknown error to it:

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

| `code` | |
|---|---|
| `NETWORK`, `TIMEOUT` | The server could not be reached |
| `LOGIN_FAILED`, `SESSION_EXPIRED` | The login failed, or the session ended |
| `MFA_REQUIRED`, `MFA_FAILED`, `MFA_UNSUPPORTED`, `MFA_LOCKED_OUT` | The MFA challenge: no `totpCode`, a wrong one, no TOTP provider, too many attempts |
| `SERVER_IDENTITY_MISMATCH`, `UNTRUSTED_METADATA_KEY` | A pinned key does not match |
| `INVALID_KEY`, `DECRYPTION_FAILED`, `ENCRYPTION_FAILED`, `CRYPTO` | OpenPGP |
| `NOT_FOUND` | No such item (an API 404 too) |
| `API` | Another API error, with its `status` |
| `INVALID_ARGUMENT` | An argument, or an option, the SDK refuses before any request |
| `INVALID_RESPONSE`, `CONFIG`, `UNKNOWN` | Anything else |

## Session lifetime

`logout()` ends the session on the server. The session object also holds WebAssembly memory,
released when it is garbage collected, or at once with `free()`; with TypeScript 5.2+, `using`
frees it at the end of the block:

```ts
import { PassboltSession } from "@switch-case/passbolt-sdk";

{
  using session = await PassboltSession.login(serverUrl, privateKeyArmored, passphrase);
  console.log(session.userId, session.baseUrl);
  await session.logout();
}
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
| Settings | `getPasswordExpirySettings`, `savePasswordExpirySettings`, `deletePasswordExpirySettings`, `listResourceTypes`, `getMetadataTypesSettings`, `saveMetadataTypesSettings`, `getMetadataKeysSettings`, `saveMetadataKeysSettings` |
| Other | `searchAros`, `checkPasswordPwned` (a `number`) |

Stateless helpers, outside a session: `encryptMessage(plaintext, publicKeysArmored)`,
`decryptMessage(armoredMessage, privateKeyArmored, passphrase)`,
`getKeyFingerprint(privateKeyArmored)`, `isPassboltError(error)`.

```ts
import { decryptMessage, encryptMessage } from "@switch-case/passbolt-sdk";

const armored = await encryptMessage(new TextEncoder().encode("hello"), [publicKeyArmored]);
const plaintext = new TextDecoder().decode(await decryptMessage(armored, privateKeyArmored, passphrase));
```

## Types

The declarations type what each method takes and returns. The options of the methods are
camelCase; the objects of the Passbolt API keep its field names (`folder_parent_id`,
`groups_users`…), with `null` for an absent value and dates as RFC 3339 strings:

```ts
import { PassboltSession } from "@switch-case/passbolt-sdk";
import type { LoginOptions, NewResource, Resource, ResourceView } from "@switch-case/passbolt-sdk";

const options: LoginOptions = { totpCode: "123456" };
const session = await PassboltSession.login(serverUrl, privateKeyArmored, passphrase, options);
const views: ResourceView[] = await session.listResourceViews();
const created: Resource = await session.createResource({ name: "GitHub" } satisfies NewResource);
console.log(views.length, created.folder_parent_id);
```

Main types: `Resource`, `ResourceView`, `SecretData`, `NewResource`, `ResourceChanges`, `Folder`,
`FolderTreeNode`, `User`, `Group`, `Permission`, `DeleteBlockers`, `Tag`, `Comment`, `Favorite`,
`Aro`, `ResourceType`, `PasswordExpirySettings`, `MetadataTypesSettings`, `MetadataKeysSettings`,
`LoginOptions`, `ServerKey`, `PassboltError`, `PassboltErrorCode`; the options `ResourceFilter`,
`ResourceViewFilter`, `FolderFilter`, `UserFilter`, `Share`, `FolderShare`, `NewUser`,
`UserChanges`, `NewGroup`, `GroupChanges`.
