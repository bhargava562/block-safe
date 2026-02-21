/** @type {import('tailwindcss').Config} */
export default {
    content: [
        "./index.html",
        "./src/**/*.{js,ts,jsx,tsx}",
    ],
    theme: {
        extend: {
            colors: {
                background: '#09090b',
                card: '#18181b',
                border: '#27272a',
                primary: {
                    DEFAULT: '#3b82f6',
                    dark: '#2563eb',
                },
                scam: '#ef4444',
                safe: '#22c55e',
            }
        },
    },
    plugins: [],
}
