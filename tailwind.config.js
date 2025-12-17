/** @type {import('tailwindcss').Config} */
module.exports = {
	content: ['./src/utils/templates/**/*.ts'],
	darkMode: 'media',
	theme: {
		extend: {
			fontFamily: {
				sans: [
					'ui-sans-serif',
					'system-ui',
					'sans-serif',
					'"Apple Color Emoji"',
					'"Segoe UI Emoji"',
					'"Segoe UI Symbol"',
					'"Noto Color Emoji"',
				],
			},
		},
	},
	plugins: [],
};
