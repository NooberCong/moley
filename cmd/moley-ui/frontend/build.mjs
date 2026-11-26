// Copies the static files next to the compiled scripts, plus the display
// font (Oxanium, OFL-1.1): dist/ is what the app embeds.
import { cpSync, mkdirSync } from "node:fs";
cpSync("static", "dist", { recursive: true });
mkdirSync("dist/fonts", { recursive: true });
cpSync("node_modules/@fontsource-variable/oxanium/files/oxanium-latin-wght-normal.woff2", "dist/fonts/oxanium.woff2");
cpSync("node_modules/@fontsource-variable/oxanium/LICENSE", "dist/fonts/OFL.txt");
