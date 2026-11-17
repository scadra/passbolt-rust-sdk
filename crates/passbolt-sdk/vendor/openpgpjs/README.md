# OpenPGP.js

`openpgp.min.js` and `openpgp.min.mjs` are `dist/openpgp.min.js` and `dist/openpgp.min.mjs` of
the npm package `openpgp` 6.1.1, the version of the browser extension, unmodified. They are
licensed under the GNU Lesser General Public License 3.0 or later (`LICENSE`); the `openpgpjs`
feature of the SDK embeds the first in QuickJS, and bundles the second in WebAssembly.

| File             | SHA-256                                                            |
|------------------|--------------------------------------------------------------------|
| `openpgp.min.js` | `e7a4e4b2e0cfd864aa50b2cb0a7bb50052cc41b0b9a845843de9a6f2dbec386a` |
| `openpgp.min.mjs` | `ad672805c04de594bafaab94a333c54b0d3bac353abf4c291179e32b8321783e` |

To check it against the registry:

```sh
npm pack openpgp@6.1.1 && tar xzf openpgp-6.1.1.tgz
sha256sum package/dist/openpgp.min.js package/dist/openpgp.min.mjs
```
