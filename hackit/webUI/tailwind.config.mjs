/** @type {import('tailwindcss').Config} */
export default {
	content: ['./src/**/*.{astro,html,js,jsx,md,mdx,svelte,ts,tsx,vue}'],
	theme: {
		extend: {
			colors: {
				cyan: {
					400: '#22d3ee',
					500: '#06b6d4',
				},
				magenta: {
					500: '#d946ef',
				}
			},
			fontFamily: {
				mono: ['JetBrains Mono', 'monospace'],
			},
		},
	},
	plugins: [],
};
