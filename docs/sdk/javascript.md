---
title: JavaScript and TypeScript
sidebar_position: 3
---

# JavaScript and TypeScript

```bash
npm install @switch-case/passbolt-sdk
```

The SDK compiled to WebAssembly. Bundlers (webpack, Vite…) take its `bundler/` build, Node.js its
`node/` build; both ship TypeScript declarations. Every session method returns a promise.

## Node.js, Deno, Bun

Node 20 or later. These runtimes keep no cookies: the session keeps those the server sets and
sends them back, nothing to configure.

```js
const { PassboltSession } = require("@switch-case/passbolt-sdk");

const session = await PassboltSession.login(serverUrl, privateKeyArmored, passphrase);
const views = await session.listResourceViews("github", false);
for (const view of views) console.log(view.id, view.name, view.username);
await session.logout();
```

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

## Login options

| Option | |
|---|---|
| `csrfTokenProvider` | Function returning the `csrfToken` cookie, or a promise of it |
| `totpCode` | The TOTP code answering the MFA challenge |
| `serverPublicKey` | The armored server key pinned with `PassboltSession.fetchServerKey(serverUrl)` |
| `metadataKeyFingerprint` | The shared metadata key pinned with `session.metadataKeyFingerprint()` |

TLS and proxies are the browser's or the runtime's business.

## Reading and writing

```js
const view = await session.getResourceView(id);          // name, username, uris, password, secret…
const created = await session.createResource({ name: "GitHub", username: "ada", password: "…" });
await session.updateResource(created.id, { password: "new" });
await session.shareResource(created.id, [userId], [], 7);
await session.moveResource(created.id, folderId);
```

Errors are thrown as `Error` with the message of the SDK.

## Methods

| Area | Methods |
|---|---|
| Session | `login`, `fetchServerKey` (static), `logout`, `keepAlive`, `checkAuth`, `metadataKeyFingerprint`, `userId`, `baseUrl` |
| Resources | `listResources(search?, favoritesOnly?, ownedByMe?)`, `getResource`, `getResourcesByIds`, `getResourceView`, `listResourceViews(search?, withSecrets)`, `decryptResourceSecret`, `createResource`, `updateResource`, `deleteResource`, `deleteResources`, `shareResource`, `moveResource`, `getResourcePermissions` |
| Folders | `listFolders(search?)`, `getFolder`, `getFolderTree`, `createFolder`, `renameFolder`, `deleteFolder`, `deleteFolderWithContent`, `shareFolder`, `moveFolder`, `getFolderPermissions` |
| Users | `listUsers(search?, groupId?, adminOnly?)`, `getMe`, `getUser`, `createUser`, `updateUser`, `deleteUser`, `deleteUserDryRun`, `userDeleteBlockers`, `deleteUserWithTransfer` |
| Groups | `listGroups`, `getGroup`, `createGroup`, `updateGroup`, `deleteGroup`, `deleteGroupDryRun`, `groupDeleteBlockers`, `deleteGroupWithTransfer` |
| Tags, comments, favorites | `getTags`, `addTagToResource`, `setResourceTags`, `renameTag`, `deleteTag`, `getComments`, `createComment`, `deleteComment`, `addFavorite`, `removeFavorite` |
| Settings | `getPasswordExpirySettings`, `savePasswordExpirySettings`, `deletePasswordExpirySettings`, `listResourceTypes`, `getMetadataTypesSettings`, `saveMetadataTypesSettings`, `getMetadataKeysSettings`, `saveMetadataKeysSettings` |
| Other | `searchAros`, `checkPasswordPwned` |

Stateless helpers, outside a session: `encryptMessage(plaintext, publicKeys)`,
`decryptMessage(armored, privateKey, passphrase)`, `getKeyFingerprint(privateKey)`.

## Types

The declarations type what each method takes and returns, with the field names of the Passbolt
API (`folder_parent_id`, `groups_users`…), `null` for an absent value and dates as RFC 3339
strings:

```ts
import { PassboltSession } from "@switch-case/passbolt-sdk";
import type { LoginOptions, NewResource, Resource, ResourceView } from "@switch-case/passbolt-sdk";

const options: LoginOptions = { totpCode: "123456" };
const session = await PassboltSession.login(serverUrl, privateKey, passphrase, options);
const views: ResourceView[] = await session.listResourceViews(undefined, false);
const created: Resource = await session.createResource({ name: "GitHub" } satisfies NewResource);
```

Main types: `Resource`, `ResourceView`, `SecretData`, `NewResource`, `ResourceChanges`, `Folder`,
`FolderTreeNode`, `User`, `Group`, `Permission`, `DeleteBlockers`, `Tag`, `Comment`, `Favorite`,
`Aro`, `ResourceType`, `PasswordExpirySettings`, `MetadataTypesSettings`, `MetadataKeysSettings`,
`LoginOptions`, `ServerKey`.
