/** @type {import('tailwindcss').Config} */
module.exports = {
  content: ["./src/**/*.{js,ts,jsx,tsx}"],
  theme: {
    extend: {
      colors: {
        bg: "#0A0D12",
        surface: "#11151C",
        surface2: "#161B24",
        border: "#232935",
        wire: "#2A3441",
        text: "#E7EBF0",
        text2: "#8B95A5",
        accent: "#4FD1C5",   // signal teal — the "connection is alive" color
        accent2: "#7C9CFF",  // secondary wire color
        ok: "#57C785",
        warn: "#E0A83E",
        crit: "#E0575C",
      },
      fontFamily: {
        display: ["'IBM Plex Sans'", "system-ui", "sans-serif"],
        mono: ["'IBM Plex Mono'", "ui-monospace", "SFMono-Regular", "monospace"],
      },
      boxShadow: {
        glow: "0 0 0 1px rgba(79,209,197,0.25), 0 0 24px -4px rgba(79,209,197,0.35)",
      },
    },
  },
  plugins: [],
};
