import Parser from 'web-tree-sitter';
import { Finding } from '../../types';

let parserInitialized = false;

export async function initAstParser(): Promise<void> {
  if (parserInitialized) return;
  try {
    // @ts-ignore
    await Parser.init();
    parserInitialized = true;
  } catch (error) {
    console.warn('AST Parser initialization failed:', error);
  }
}

// Maps file extensions to their corresponding tree-sitter wasm paths
// We will resolve this at runtime when loading the grammar
export const LANG_WASM_MAP: Record<string, string> = {
  '.ts': 'tree-sitter-typescript.wasm',
  '.js': 'tree-sitter-javascript.wasm',
  '.py': 'tree-sitter-python.wasm',
  '.java': 'tree-sitter-java.wasm',
  '.go': 'tree-sitter-go.wasm',
  '.cs': 'tree-sitter-c_sharp.wasm',
};

const grammarCache = new Map<string, Parser.Language>();

// We define a set of cryptographic APIs we want to look for in the AST
const CRYPTO_API_PATTERNS = {
  javascript: [
    'crypto', 'createHash', 'createCipheriv', 'createSign', 'crypto.subtle'
  ],
  python: [
    'hashlib', 'cryptography', 'Crypto.Cipher', 'AES', 'RSA', 'pycryptodome'
  ],
  java: [
    'javax.crypto', 'Cipher.getInstance', 'MessageDigest.getInstance', 'java.security'
  ]
};

export async function enrichWithAst(
  path: string,
  content: string,
  findings: Finding[]
): Promise<void> {
  if (!parserInitialized) return;

  const ext = path.slice(path.lastIndexOf('.')).toLowerCase();
  const wasmFile = LANG_WASM_MAP[ext];
  if (!wasmFile) return;

  try {
    let language = grammarCache.get(wasmFile);
    if (!language) {
      // Depending on the environment, we might need a physical path or a URL
      // For Node.js (our primary backend target for this), we can point to the node_modules directory
      let wasmPath = '';
      if (typeof process !== 'undefined' && process.env) {
        // Node environment
        wasmPath = require('path').resolve(process.cwd(), 'node_modules/tree-sitter-wasms/out', wasmFile);
      } else {
        // Browser fallback (if we hosted them) - for now just skip if no path
        return;
      }

      // @ts-ignore
      language = await Parser.Language.load(wasmPath);
      grammarCache.set(wasmFile, language);
    }

    // @ts-ignore
    const parser = new Parser();
    parser.setLanguage(language);
    const tree = parser.parse(content);

    // Now, cross-reference existing findings with AST nodes to add evidence and boost confidence
    for (const finding of findings) {
      if (finding.file === path) {
        // Simple AST walk to find the node containing the finding's line
        let relevantNode: any = null;
        const walk = (node: any) => {
          if (node.startPosition.row <= (finding.line - 1) && node.endPosition.row >= (finding.line - 1)) {
            relevantNode = node;
            for (const child of node.children) walk(child);
          }
        };
        walk(tree.rootNode);

        if (relevantNode) {
          const nodeType = relevantNode.type;
          const nodeText = relevantNode.text;
          
          finding.evidence = {
            detectionLayers: ['regex', 'ast'],
            matchedText: finding.detectedPattern,
            astContext: {
              type: nodeType,
              text: nodeText,
              start: relevantNode.startPosition,
              end: relevantNode.endPosition
            },
            confidenceDerivation: 'Regex matched; AST confirms presence within a valid code node.'
          };
          
          // Boost confidence since AST confirms it's not just inside a random string or comment
          // (assuming tree-sitter distinguishes comments/strings, which it does)
          if (nodeType !== 'comment' && nodeType !== 'string') {
            finding.confidence = Math.min(0.98, finding.confidence + 0.15);
          } else {
            // It's in a comment or string. Might be a false positive or just documentation.
            finding.confidence = Math.max(0.1, finding.confidence - 0.3);
            finding.remediationStatus = 'accepted-risk'; // Fallback mapping since false-positive wasn't in type
          }
        }
      }
    }
  } catch (error) {
    console.warn(`AST Enrichment failed for ${path}:`, error);
  }
}
