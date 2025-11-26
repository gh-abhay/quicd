// @ts-check
import { defineConfig } from 'astro/config';
import starlight from '@astrojs/starlight';
import sitemap from '@astrojs/sitemap';
import mermaid from 'astro-mermaid';

// https://astro.build/config
export default defineConfig({
	site: 'https://quicd.com',
	integrations: [
		mermaid(),
		starlight({
			title: 'QuicD',
			description: 'High-performance QUIC server for building modern internet applications',
			social: [
				{ icon: 'github', label: 'GitHub', href: 'https://github.com/gh-abhay/quicd' }
			],
			customCss: [
				'./src/styles/custom.css',
			],
			head: [
				// Google Tag Manager
				{
					tag: 'script',
					attrs: {
						async: true,
						src: 'https://www.googletagmanager.com/gtag/js?id=G-6N9LKSJFW4',
					},
				},
				{
					tag: 'script',
					content: `
						window.dataLayer = window.dataLayer || [];
						function gtag(){dataLayer.push(arguments);}
						gtag('js', new Date());
						gtag('config', 'G-6N9LKSJFW4');
					`,
				},
				{
					tag: 'meta',
					attrs: {
						property: 'og:type',
						content: 'website',
					},
				},
				{
					tag: 'meta',
					attrs: {
						property: 'og:image',
						content: 'https://quicd.com/og-image.png',
					},
				},
				{
					tag: 'meta',
					attrs: {
						name: 'twitter:card',
						content: 'summary_large_image',
					},
				},
				{
					tag: 'meta',
					attrs: {
						name: 'twitter:image',
						content: 'https://quicd.com/og-image.png',
					},
				},
				{
					tag: 'link',
					attrs: {
						rel: 'sitemap',
						href: '/sitemap-index.xml',
					},
				},
			],
			editLink: {
				baseUrl: 'https://github.com/gh-abhay/quicd/edit/main/website/src/content/',
			},
			lastUpdated: true,
			favicon: '/favicon.svg',
			components: {
				// Use custom components if needed
			},
			expressiveCode: {
				themes: ['github-dark', 'github-light'],
			},
			sidebar: [
				{
					label: 'Introduction',
					link: '/introduction/',
				},
				{
					label: 'Architecture',
					link: '/architecture/',
				},
				{
					label: 'Core Concepts',
					link: '/concepts/',
				},
				{
					label: 'Getting Started',
					items: [
						{ label: 'Installation', link: '/getting-started/installation/' },
						{ label: 'Configuration', link: '/getting-started/configuration/' },
					],
				},
				{
					label: 'Usage',
					items: [
						{ label: 'HTTP/3 Server', link: '/usage/http3/' },
						{ label: 'Media over QUIC', link: '/usage/moq/' },
						{ label: 'Custom Applications', link: '/usage/custom/' },
					],
				},
				{
					label: 'Building Apps',
					items: [
						{ label: 'Application Interface', link: '/building-apps/interface/' },
						{ label: 'HTTP/3 Apps', link: '/building-apps/http3/' },
						{ label: 'Examples', link: '/building-apps/examples/' },
					],
				},
				{
					label: 'Reference',
					items: [
						{ label: 'API Reference', link: '/reference/api/' },
						{ label: 'Configuration', link: '/reference/configuration/' },
						{ label: 'Error Codes', link: '/reference/errors/' },
						{ label: 'Performance Tuning', link: '/reference/performance/' },
						{ label: 'Glossary', link: '/reference/glossary/' },
					],
				},
				{
					label: 'Community',
					items: [
						{ label: 'Contributing', link: '/community/contributing/' },
						{ label: 'FAQ', link: '/community/faq/' },
						{ label: 'Roadmap', link: '/community/roadmap/' },
						{ label: 'Changelog', link: '/community/changelog/' },
					],
				},
			],
		}),
		sitemap(),
	],
});
