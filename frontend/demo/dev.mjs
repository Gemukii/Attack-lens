// Starts `nuxt dev` with demo mode on. Used by `npm run dev:demo`.
// A script rather than an inline variable, so that it works the same on Windows, macOS and Linux.
import { spawn } from 'node:child_process'
import { fileURLToPath } from 'node:url'

const nuxt = fileURLToPath(new URL('../node_modules/nuxt/bin/nuxt.mjs', import.meta.url))

const child = spawn(process.execPath, [nuxt, 'dev', ...process.argv.slice(2)], {
  stdio: 'inherit',
  env: { ...process.env, ATTACKLENS_DEMO: '1' },
})

child.on('exit', (code) => process.exit(code ?? 0))
