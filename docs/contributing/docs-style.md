---
title: Writing the docs
sidebar_position: 6
---

# Writing the docs

Write each page so that a reader can find the answer, copy a working example and move on. The
pages follow the shape of the [Supabase docs](https://supabase.com/docs): a summary, then
steps or a reference, then where to go next.

## Every page

- Start with the `# Title`, then one sentence saying what the page lets you do.
- Address the reader as "you" and use the imperative for actions: "Install the CLI", "Run
  `passbolt verify`".
- Keep paragraphs to one to three sentences. Put lists of facts in bullets or tables.
- Use task-oriented headings: "Pin the server's identity", "Use a proxy". Avoid "Misc" or
  "Notes".
- End with `## Next steps` (a page you follow) or `## Related` (a reference page): a few links,
  one line each.
- Use **bold** for what you click or press, and `code` for commands, flags, files, fields and
  values.

## Steps

Number the steps of a quickstart or a guide in their headings, one action each:

```md
## 1. Install the CLI

## 2. Save your settings
```

List what you need first, under `## Prerequisites`, when there is something.

## Callouts

Use Docusaurus admonitions, sparingly: one or two per page.

```md
:::note
Background the reader may need, or another way to do the same thing.
:::

:::tip
A shortcut.
:::

:::caution
What can break, or leak a secret.
:::
```

## Code

- Give each block its language. Name the file when the block is a file:
  ` ```toml title="~/.config/passbolt/config.toml" `.
- Make every example runnable as written: placeholders in capitals (`<UUID>`,
  `https://passbolt.example.com`), the same ones across the page.
- Show what a command prints in a separate ` ```text ` block, under the command.
- Draw diagrams as ` ```mermaid ` blocks: GitHub and the site both render them.

## CLI reference

Each command has the same sections:

````md
## create group

Create a group with its managers and members.

```bash
passbolt create group --name <NAME> --manager <UUID> [flags]
```

### Flags

| Flag | Required | Description |
|---|---|---|
| `-n, --name <NAME>` | Yes | Name of the group. |
| `-m, --manager <UUID>` | Yes | Manager of the group. Repeat it for several. |

### Examples

#### Create a group with two members

```bash
passbolt create group --name "DevOps" --manager <UUID> --user <UUID> --user <UUID>
```
````

Give the default of a flag in its description: "Default: `name`." Global flags are on
[configuration](../cli/configuration.md), not repeated on each command.

## SDK reference

Each function or method has a one-line summary, its parameters, what it returns, and titled
examples:

````md
### listResources

List the resources you can read.

| Parameter | Type | Required | Description |
|---|---|---|---|
| `filter` | `ResourceFilter` | No | `search`, `favoritesOnly`, `ownedByMe`. |

Returns `Promise<Resource[]>`.

#### List your favorites

```ts
const favorites = await session.listResources({ favoritesOnly: true });
```
````

## Layout

Each page starts with a front matter (`title`, `sidebar_position`). Each folder has a `README.md`,
its index. Links between pages use the relative `.md` path, which works on GitHub and on the site.
The site reads the pages as CommonMark, not MDX: no JSX, no tabs.
