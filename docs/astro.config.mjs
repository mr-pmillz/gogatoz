// @ts-check
import { defineConfig } from 'astro/config';
import starlight from '@astrojs/starlight';

// https://astro.build/config
export default defineConfig({
	// Served at the ROOT of a GitHub Pages randomly-generated domain
	// (e.g. https://<random>.pages.github.io/), so there is no `base` subpath
	// and all asset/link URLs stay root-relative. Once the final Pages URL is
	// known, set `site` to it to enable accurate canonical URLs and an absolute
	// sitemap, e.g.:
	//   site: 'https://<random>.pages.github.io',
	integrations: [
		starlight({
			title: 'GoGatoZ',
			customCss: ['./src/styles/custom.css'],
			social: [
				{ icon: 'x.com', label: 'X/Twitter', href: 'https://x.com/ProOfConcept9' },
				{ icon: 'linkedin', label: 'LinkedIn', href: 'https://www.linkedin.com/in/phillip-miller1992/' },
				{ icon: 'discord', label: 'Discord', href: 'https://discord.com/invite/BHIS' },
			],
			editLink: {
				baseUrl: 'https://github.com/mr-pmillz/gogatoz/edit/main/docs/',
			},
			sidebar: [
				{ label: 'Quick Start', slug: 'quick-start' },
				{
					label: 'User Guide',
					items: [
						{ label: 'Installation', slug: 'user-guide/installation' },
						{
							label: 'Command Reference',
							items: [
								{ label: 'Overview', slug: 'user-guide/command-reference' },
								{ label: 'Search', slug: 'user-guide/command-reference/search' },
								{ label: 'Enumerate', slug: 'user-guide/command-reference/enumerate' },
								{ label: 'Attack', slug: 'user-guide/command-reference/attack' },
								{ label: 'Pivot', slug: 'user-guide/command-reference/pivot' },
							{ label: 'Persistence', slug: 'user-guide/command-reference/persistence' },
							],
						},
						{ label: 'API Server', slug: 'user-guide/api-server' },
						{
							label: 'Use Cases',
							items: [
								{ label: 'Overview', slug: 'user-guide/use-cases' },
								{ label: 'Scanning', slug: 'user-guide/use-cases/scanning' },
								{ label: 'Runner Takeover', slug: 'user-guide/use-cases/runner-takeover' },
								{ label: 'Post-Compromise', slug: 'user-guide/use-cases/post-compromise' },
							{ label: 'Persistence', slug: 'user-guide/use-cases/persistence' },
								{ label: 'Lateral Movement', slug: 'user-guide/use-cases/lateral-movement' },
								{ label: 'Supply Chain Attacks', slug: 'user-guide/use-cases/supply-chain' },
								{ label: 'Reporting', slug: 'user-guide/use-cases/reporting' },
								{ label: 'MCP Capstone Lab', slug: 'user-guide/use-cases/mcp-lab' },
							],
						},
						{
							label: 'Advanced',
							items: [
								{ label: 'Overview', slug: 'user-guide/advanced' },
								{ label: 'Vulnerabilities', slug: 'user-guide/advanced/vulnerabilities' },
								{ label: 'Complex Attacks', slug: 'user-guide/advanced/complex-attacks' },
								{ label: 'Continuous Scanning', slug: 'user-guide/advanced/continuous-scanning' },
								{ label: 'Networking & Proxy', slug: 'user-guide/advanced/networking' },
							],
						},
						{
							label: 'Concepts',
							items: [
								{ label: 'GitLab PATs', slug: 'user-guide/concepts/gitlab-pats' },
								{ label: 'Callback Server', slug: 'user-guide/concepts/webhook-server' },
							],
						},
					],
				},
				{ label: 'CLI Reference', slug: 'reference/cli' },
			],
		}),
	],
});
