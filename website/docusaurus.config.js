// The documentation site: the pages of ../docs, the sidebar from their folders and front matter.
// `npm ci && npm run build` writes it to build/; `npm start` serves it while editing.
const { themes } = require("prism-react-renderer");

const repository = process.env.GITHUB_REPOSITORY ?? "scadra/passbolt-rust-sdk";
const [owner, name] = repository.split("/");

/** @type {import('@docusaurus/types').Config} */
module.exports = {
  title: "passbolt-rust",
  tagline: "A command-line client and an SDK for Passbolt, written in Rust",
  url: `https://${owner}.github.io`,
  baseUrl: `/${name}/`,
  organizationName: owner,
  projectName: name,
  trailingSlash: false,
  onBrokenLinks: "throw",
  onBrokenAnchors: "throw",
  markdown: {
    // Plain Markdown: `<UUID>` and `{…}` in the pages are text, not JSX.
    format: "detect",
    hooks: { onBrokenMarkdownLinks: "throw" },
  },
  i18n: { defaultLocale: "en", locales: ["en"] },
  presets: [
    [
      "classic",
      /** @type {import('@docusaurus/preset-classic').Options} */
      ({
        docs: {
          path: "../docs",
          routeBasePath: "/",
          sidebarPath: require.resolve("./sidebars.js"),
          editUrl: `https://github.com/${repository}/edit/master/`,
        },
        blog: false,
        pages: false,
        theme: {},
      }),
    ],
  ],
  themeConfig:
    /** @type {import('@docusaurus/preset-classic').ThemeConfig} */
    ({
      navbar: {
        title: "passbolt-rust",
        items: [
          { to: "/getting-started/installation", label: "Install", position: "left" },
          { to: "/cli", label: "CLI", position: "left" },
          { to: "/sdk", label: "SDK", position: "left" },
          { href: `https://github.com/${repository}`, label: "GitHub", position: "right" },
        ],
      },
      footer: {
        style: "dark",
        copyright: "AGPL-3.0-or-later. Passbolt is a registered trademark of Passbolt SA.",
      },
      prism: {
        theme: themes.github,
        darkTheme: themes.dracula,
        additionalLanguages: ["bash", "toml", "rust", "kotlin", "swift", "csharp", "ruby", "go", "java"],
      },
    }),
};
