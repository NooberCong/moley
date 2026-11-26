// Copies the static files next to the compiled scripts: dist/ is the unpacked extension.
import { cpSync } from "node:fs";
cpSync("static", "dist", { recursive: true });
cpSync("icons", "dist/icons", { recursive: true });
