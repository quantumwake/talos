import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";

// The portal talks to the FastAPI backend (default http://127.0.0.1:58789).
// Override with VITE_API_URL at build/dev time. Uncommon ports so we don't collide
// with the dozen other dev servers that all squat on 5173 / 3000 / 8080.
export default defineConfig({
  plugins: [react()],
  server: { port: 58790, strictPort: true },
});
