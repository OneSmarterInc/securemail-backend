import { build } from "vite";
import { resolve } from "node:path";
import { fileURLToPath } from "node:url";

const root = fileURLToPath(new URL(".", import.meta.url));
await build({ root, configFile: false, build: { emptyOutDir: false, outDir: resolve(root, "../../backend/keyservice/static"), lib: { entry: resolve(root, "custodian-qr.js"), name: "CustodianQr", formats: ["iife"], fileName: () => "custodian-qr.js" }, minify: true, sourcemap: false } });
