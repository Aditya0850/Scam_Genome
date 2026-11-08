/** @type {import('tailwindcss').Config} */
export default {
  darkMode: ["class"],
  content: ["./index.html", "./src/**/*.{js,ts,jsx,tsx}", "./components/**/*.{js,ts,jsx,tsx}"],
  theme: { extend: { colors: { background: "#080d16", foreground: "#e8f0fb", primary: "#62e5ef" } } },
  plugins: [],
}
