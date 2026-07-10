// @ts-check
import { defineConfig } from 'astro/config';
import starlight from '@astrojs/starlight';
import mermaid from 'astro-mermaid';

// https://astro.build/config
export default defineConfig({
	// Served at https://mr-pmillz.github.io/gogatoz/ (project Pages, not user Pages),
	// so base must match the repo name to keep asset/link URLs correct.
	site: 'https://mr-pmillz.github.io/gogatoz',
	base: '/gogatoz',
	integrations: [
		mermaid({ autoTheme: true }),
		starlight({
			title: 'GoGatoZ',
			favicon: '/favicon-32x32.png',
			head: [
				{
					tag: 'link',
					attrs: {
						rel: 'icon',
						href: '/gogatoz/favicon.ico',
						sizes: '32x32',
					},
				},
				{
					tag: 'link',
					attrs: {
						rel: 'icon',
						type: 'image/png',
						href: '/gogatoz/favicon-16x16.png',
						sizes: '16x16',
					},
				},
			],
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
								{ label: 'Explain', slug: 'user-guide/command-reference/explain' },
								{ label: 'PBOM', slug: 'user-guide/command-reference/pbom' },
								{ label: 'Query', slug: 'user-guide/command-reference/query' },
								{ label: 'Secretscan', slug: 'user-guide/command-reference/secretscan' },
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
								{ label: 'Advanced Supply Chain', slug: 'user-guide/use-cases/advanced-supply-chain' },
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
				{
						label: 'Contributing',
						items: [
							{ label: 'Release Process', slug: 'contributing/release-process' },
						],
					},
					{ label: 'CLI Reference', slug: 'reference/cli' },
			],
		}),
	],
});
