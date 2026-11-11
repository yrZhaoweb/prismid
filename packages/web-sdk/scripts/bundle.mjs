import fs from 'node:fs'
import path from 'node:path'
import { fileURLToPath } from 'node:url'
import ts from 'typescript'

const __dirname = path.dirname(fileURLToPath(import.meta.url))
const distDir = path.resolve(__dirname, '../dist')

const filesInOrder = [
  'crypto/aead.js',
  'crypto/deviceKey.js',
  'probes/storageBeacon.js',
  'probes/webgl.js',
  'probes/workerLie.js',
  'probes/audio.js',
  'probes/fontsCanvas.js',
  'probes/lieDetector.js',
  'index.js',
]

function stripRelativeModuleSyntaxWithAST(relPath, code) {
  const sf = ts.createSourceFile(relPath, code, ts.ScriptTarget.ES2022, true, ts.ScriptKind.JS)
  const skipRanges = []

  for (const stmt of sf.statements) {
    if (ts.isImportDeclaration(stmt)) {
      const spec =
        stmt.moduleSpecifier && ts.isStringLiteral(stmt.moduleSpecifier)
          ? stmt.moduleSpecifier.text
          : ''
      if (!spec.startsWith('.')) {
        throw new Error(`External runtime import "${spec}" is not allowed in zero-dependency prismid-js (${relPath})`)
      }
      skipRanges.push([stmt.getFullStart(), stmt.getEnd()])
      continue
    }

    if (ts.isExportDeclaration(stmt)) {
      if (stmt.moduleSpecifier) {
        const spec = ts.isStringLiteral(stmt.moduleSpecifier) ? stmt.moduleSpecifier.text : ''
        if (!spec.startsWith('.')) {
          throw new Error(`External re-export "${spec}" is not allowed in prismid-js (${relPath})`)
        }
        skipRanges.push([stmt.getFullStart(), stmt.getEnd()])
        continue
      }
      // In index.js, named re-exports (`export { AEAD_KEY_DOMAIN_PREFIX, ... }`) refer to symbols
      // that are already `export const` / `export function` in their inlined source modules.
      if (relPath === 'index.js') {
        skipRanges.push([stmt.getFullStart(), stmt.getEnd()])
      }
    }
  }

  if (skipRanges.length === 0) {
    return code.trim()
  }

  skipRanges.sort((a, b) => a[0] - b[0])
  let out = ''
  let cursor = 0
  for (const [start, end] of skipRanges) {
    out += code.slice(cursor, start)
    cursor = end
  }
  out += code.slice(cursor)
  return out.trim()
}

let bundle = `// PrismID Web SDK (prismid-js v1.1.0) Standalone ES Module Bundle\n`
for (const rel of filesInOrder) {
  const fullPath = path.join(distDir, rel)
  const code = fs.readFileSync(fullPath, 'utf8')
  const stripped = stripRelativeModuleSyntaxWithAST(rel, code)
  bundle += `\n// --- ${rel} ---\n${stripped}\n`
}

// Validate final ESM bundle syntax & top-level statements via TypeScript AST parser (S3-54)
const validatedSf = ts.createSourceFile(
  'prismid.bundle.js',
  bundle,
  ts.ScriptTarget.ES2022,
  true,
  ts.ScriptKind.JS
)
if (Array.isArray(validatedSf.parseDiagnostics) && validatedSf.parseDiagnostics.length > 0) {
  const msg = validatedSf.parseDiagnostics
    .map((d) => ts.flattenDiagnosticMessageText(d.messageText, '\n'))
    .join('; ')
  throw new Error(`Bundled ESM failed AST syntax validation: ${msg}`)
}
for (const stmt of validatedSf.statements) {
  if (ts.isImportDeclaration(stmt)) {
    throw new Error('Bundled ESM still contains an unresolved import declaration')
  }
}

const outBundle = path.join(distDir, 'prismid.bundle.js')
fs.writeFileSync(outBundle, bundle, 'utf8')

const goStaticDir = path.resolve(__dirname, '../../../server/go/cmd/prismid-server/static')
fs.mkdirSync(goStaticDir, { recursive: true })
fs.writeFileSync(path.join(goStaticDir, 'prismid.bundle.js'), bundle, 'utf8')
console.log('Generated & AST-verified standalone ESM bundle:', outBundle)
