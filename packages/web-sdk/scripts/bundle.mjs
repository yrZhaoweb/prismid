import fs from 'node:fs'
import path from 'node:path'
import { fileURLToPath } from 'node:url'

const __dirname = path.dirname(fileURLToPath(import.meta.url))
const distDir = path.resolve(__dirname, '../dist')

const filesInOrder = [
  'crypto/aead.js',
  'probes/storageBeacon.js',
  'probes/webgl.js',
  'probes/workerLie.js',
  'probes/audio.js',
  'probes/fontsCanvas.js',
  'probes/lieDetector.js',
  'index.js',
]

let bundle = `// PrismID Web SDK (prismid-js) Standalone ES Module Bundle\n`
for (const rel of filesInOrder) {
  const fullPath = path.join(distDir, rel)
  let code = fs.readFileSync(fullPath, 'utf8')
  // Strip local relative imports and re-exports since all modules are inlined in topological order
  code = code.replace(/^\s*import\s+\{[\s\S]*?\}\s+from\s+['"]\..*?['"];?\s*$/gm, '')
  code = code.replace(/^\s*export\s+\{[\s\S]*?\}\s+from\s+['"]\..*?['"];?\s*$/gm, '')
  if (rel === 'index.js') {
    // Remove duplicate export block of already-exported symbols
    code = code.replace(/export\s+\{[\s\S]*?\};?/m, '')
  }
  bundle += `\n// --- ${rel} ---\n` + code.trim() + '\n'
}

const outBundle = path.join(distDir, 'prismid.bundle.js')
fs.writeFileSync(outBundle, bundle, 'utf8')

const goStaticDir = path.resolve(__dirname, '../../../server/go/cmd/prismid-server/static')
fs.mkdirSync(goStaticDir, { recursive: true })
fs.writeFileSync(path.join(goStaticDir, 'prismid.bundle.js'), bundle, 'utf8')
console.log('Generated standalone ESM bundle:', outBundle)
