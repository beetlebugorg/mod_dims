// @ts-check
import {themes as prismThemes} from 'prism-react-renderer';

/** @type {import('@docusaurus/types').Config} */
const config = {
  title: 'mod_dims',
  tagline: 'Dynamic image manipulation for Apache httpd',
  favicon: 'img/favicon.ico',

  url: 'https://beetlebugorg.github.io',
  baseUrl: '/mod_dims/',

  organizationName: 'beetlebugorg',
  projectName: 'mod_dims',

  onBrokenLinks: 'throw',

  markdown: {
    hooks: {onBrokenMarkdownLinks: 'throw'},
  },

  i18n: {defaultLocale: 'en', locales: ['en']},

  presets: [
    [
      'classic',
      /** @type {import('@docusaurus/preset-classic').Options} */
      ({
        docs: {
          routeBasePath: '/',
          sidebarPath: './sidebars.js',
          editUrl: 'https://github.com/beetlebugorg/mod_dims/tree/main/docs/',
        },
        blog: false,
        theme: {customCss: './src/css/custom.css'},
      }),
    ],
  ],

  themeConfig:
    /** @type {import('@docusaurus/preset-classic').ThemeConfig} */
    ({
      navbar: {
        title: 'mod_dims',
        items: [
          {type: 'docSidebar', sidebarId: 'docs', position: 'left', label: 'Documentation'},
          {href: 'https://github.com/beetlebugorg/mod_dims', label: 'GitHub', position: 'right'},
        ],
      },
      footer: {
        style: 'dark',
        links: [
          {
            title: 'Documentation',
            items: [
              {label: 'Installation', to: '/installation'},
              {label: 'Endpoints', to: '/endpoints/'},
              {label: 'Operations', to: '/operations/'},
              {label: 'Configuration', to: '/configuration/'},
            ],
          },
          {
            title: 'More',
            items: [
              {label: 'GitHub', href: 'https://github.com/beetlebugorg/mod_dims'},
            ],
          },
        ],
        copyright: `Copyright 2009 AOL LLC. Apache License 2.0.`,
      },
      prism: {
        theme: prismThemes.github,
        darkTheme: prismThemes.dracula,
        additionalLanguages: ['apacheconf', 'bash'],
      },
    }),
};

export default config;
