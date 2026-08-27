// ============================================================
// QuantumGuard AI — AST Detection Layer (P0-7: Revived)
// Uses web-tree-sitter for semantic analysis of source code.
// Works in both Node.js (server) and browser environments.
// Gracefully degrades if tree-sitter is not available.
// ============================================================

import type { Finding } from '../../types';

// Lazy-loaded parser and Language class to avoid import errors at build time
let Parser: any = null;
let Language: any = null;
let parserInitialized = false;
let initFailed = false;
// Resolved path to tree-sitter-wasms/out/ directory
let WASMS_DIR = '';

/**
 * Initialize the AST parser. Uses dynamic import to avoid
 * build-time failures when web-tree-sitter is not available.
 */
export async function initAstParser(): Promise<boolean> {
  if (parserInitialized) return true;
  if (initFailed) return false;

  try {
    // Dynamic import to handle both Node.js and browser environments
    const mod = await import('web-tree-sitter');
    // web-tree-sitter exports Parser and Language as named exports.
    // The ES module build has no default export; the CJS build wraps them.
    const P = (mod as any).Parser || (mod as any).default?.Parser || (mod as any).default;
    const L = (mod as any).Language || (mod as any).default?.Language;
    if (!P || typeof P.init !== 'function') {
      throw new Error('Could not find Parser.init — web-tree-sitter module structure unexpected');
    }
    Parser = P;
    Language = L; // may be null — we have a fallback
    await Parser.init();
    // Also try to get Language from Parser if the standalone import failed
    if (!Language && Parser.Language) {
      Language = Parser.Language;
    }

    // Resolve the tree-sitter-wasms directory
    const pathMod = await import('path');
    const fsMod = await import('fs');
    const candidates: string[] = [];

    // Method 1: require.resolve (works in CJS and Vitest CJS mode)
    try {
      const wtsFile = require.resolve('web-tree-sitter');
      candidates.push(pathMod.default.join(pathMod.default.dirname(wtsFile), '..', 'tree-sitter-wasms', 'out'));
    } catch { /* not available */ }

    // Method 2: Walk up from the package.json directory
    try {
      // Find project root by walking up to find package.json
      let dir = process.cwd();
      for (let i = 0; i < 6; i++) {
        if (fsMod.default.existsSync(pathMod.default.join(dir, 'package.json'))) {
          candidates.push(pathMod.default.join(dir, 'node_modules', 'tree-sitter-wasms', 'out'));
          break;
        }
        dir = pathMod.default.dirname(dir);
      }
    } catch { /* not available */ }

    // Method 3: Walk up from process.cwd()
    let d = process.cwd();
    for (let i = 0; i < 5; i++) {
      candidates.push(pathMod.default.join(d, 'node_modules', 'tree-sitter-wasms', 'out'));
      d = pathMod.default.dirname(d);
    }

    for (const c of candidates) {
      try {
        const testFile = pathMod.default.join(c, 'tree-sitter-javascript.wasm');
        if (fsMod.default.existsSync(testFile)) {
          WASMS_DIR = c;
          break;
        }
      } catch { /* ignore */ }
    }

    if (!WASMS_DIR) {
      console.warn('tree-sitter-wasms directory not found — AST language loading will fail');
    }
    parserInitialized = true;
    return true;
  } catch (error) {
    console.warn('AST Parser initialization failed (AST enrichment disabled):', error);
    initFailed = true;
    return false;
  }
}

/**
 * Check if AST parser is available and initialized.
 */
export function isAstAvailable(): boolean {
  return parserInitialized && Parser !== null;
}

// Maps file extensions to their corresponding tree-sitter wasm paths
export const LANG_WASM_MAP: Record<string, string> = {
  '.ts': 'tree-sitter-typescript.wasm',
  '.tsx': 'tree-sitter-typescript.wasm',
  '.js': 'tree-sitter-javascript.wasm',
  '.jsx': 'tree-sitter-javascript.wasm',
  '.py': 'tree-sitter-python.wasm',
  '.java': 'tree-sitter-java.wasm',
  '.go': 'tree-sitter-go.wasm',
  '.cs': 'tree-sitter-c_sharp.wasm',
};

// Cache loaded languages to avoid reloading wasm files
const grammarCache = new Map<string, any>();

/**
 * Resolve the path to a wasm file for the given language.
 * Handles both Node.js (file system) and browser (URL) environments.
 */
async function loadLanguage(wasmFile: string): Promise<any> {
  const cached = grammarCache.get(wasmFile);
  if (cached) return cached;

  try {
    let wasmPath: string;

    // Determine runtime: prefer Node.js (file system) over browser (URL).
    // In jsdom/Vitest, typeof window is 'object' but we still have Node.js fs.
    const isNode = typeof process !== 'undefined' && typeof process.versions?.node === 'string';
    if (isNode && WASMS_DIR) {
      // Node.js environment — use pre-resolved WASM dir from init
      const pathMod = await import('path');
      wasmPath = pathMod.default.join(WASMS_DIR, wasmFile);
    } else {
      // Browser fallback — the WASM files must be served statically
      wasmPath = `/node_modules/tree-sitter-wasms/out/${wasmFile}`;
    }

    // Resolve Language.load — the class may be on the module or on Parser
    const LangLoad = Language?.load || Parser?.Language?.load;
    if (!LangLoad) {
      throw new Error('Language.load not available — cannot load WASM grammar');
    }
    const language = await LangLoad(wasmPath);
    grammarCache.set(wasmFile, language);
    return language;
  } catch (error) {
    console.warn(`Failed to load language ${wasmFile}:`, error);
    return null;
  }
}

/**
 * Extract call expression arguments from AST nodes.
 * This provides semantic information about how crypto APIs are called.
 */
function extractCallArguments(node: any): string[] {
  const args: string[] = [];
  
  if (node.type === 'call_expression' || node.type === 'function_call') {
    // Get the arguments node
    const argsNode = node.children?.find((child: any) => 
      child.type === 'arguments' || child.type === 'argument_list'
    );
    
    if (argsNode) {
      for (const arg of argsNode.children || []) {
        if (arg.type !== ',' && arg.type !== '(' && arg.type !== ')') {
          args.push(arg.text || '');
        }
      }
    }
  }
  
  return args;
}

/**
 * Determine if a node is inside a comment or string literal.
 */
function isInCommentOrString(node: any): boolean {
  if (!node) return false;
  
  const nodeType = node.type?.toLowerCase() || '';
  return (
    nodeType.includes('comment') ||
    nodeType.includes('string') ||
    nodeType.includes('docstring') ||
    nodeType.includes('template')
  );
}

/**
 * Get the context type of a node (function, class, module-level, etc.)
 */
function getNodeContext(node: any): string {
  if (!node) return 'unknown';
  
  const nodeType = node.type?.toLowerCase() || '';
  
  if (nodeType.includes('function') || nodeType.includes('method')) return 'function';
  if (nodeType.includes('class')) return 'class';
  if (nodeType.includes('module') || nodeType.includes('program')) return 'module';
  if (nodeType.includes('arrow')) return 'arrow-function';
  
  return 'other';
}

/**
 * Enrich findings with AST-based evidence.
 * 
 * This function:
 * 1. Parses the file using tree-sitter
 * 2. Finds AST nodes corresponding to each finding's line
 * 3. Adds AST context to the finding's evidence
 * 4. Adjusts confidence based on whether the match is in code vs comments/strings
 * 5. Extracts call arguments for additional context
 */
export async function enrichWithAst(
  path: string,
  content: string,
  findings: Finding[]
): Promise<void> {
  // Skip if AST is not available
  if (!parserInitialized || !Parser) {
    return;
  }

  // Determine language from file extension
  const ext = path.slice(path.lastIndexOf('.')).toLowerCase();
  const wasmFile = LANG_WASM_MAP[ext];
  if (!wasmFile) {
    return; // No grammar available for this language
  }

  try {
    // Load the language grammar
    const language = await loadLanguage(wasmFile);
    if (!language) {
      return; // Failed to load grammar
    }

    // Parse the file
    // @ts-ignore - Parser constructor exists but types may not expose it
    const parser = new Parser();
    parser.setLanguage(language);
    const tree = parser.parse(content);

    // Cross-reference findings with AST nodes
    for (const finding of findings) {
      if (finding.file !== path) continue;
      if (!finding.line) continue;

      // Find the AST node at the finding's line
      let relevantNode: any = null;
      let parentContext: any = null;

      const findNode = (node: any, parent?: any) => {
        const startRow = node.startPosition?.row ?? -1;
        const endRow = node.endPosition?.row ?? -1;
        
        if (startRow <= (finding.line! - 1) && endRow >= (finding.line! - 1)) {
          relevantNode = node;
          parentContext = parent;
          // Continue searching for more specific (inner) nodes
          for (const child of node.children || []) {
            findNode(child, node);
          }
        }
      };

      findNode(tree.rootNode);

      if (!relevantNode) {
        continue; // No node found at this line
      }

      const nodeType = relevantNode.type || 'unknown';
      const nodeText = (relevantNode.text || '').slice(0, 200);
      const inComment = isInCommentOrString(relevantNode);
      const contextType = getNodeContext(parentContext);
      
      // Extract call arguments if this is a function call
      const callArgs = extractCallArguments(relevantNode);

      // Update evidence with AST context
      finding.evidence = {
        detectionLayers: [...(finding.evidence?.detectionLayers || []), 'ast'],
        matchedText: finding.detectedPattern,
        astContext: {
          type: nodeType,
          text: nodeText,
          start: relevantNode.startPosition,
          end: relevantNode.endPosition,
          inComment,
          contextType,
          callArguments: callArgs.length > 0 ? callArgs : undefined,
          parentNodeType: parentContext?.type,
        },
        confidenceDerivation: finding.evidence?.confidenceDerivation || 
          'AST confirms presence within a valid code node.',
      };

      // Adjust confidence based on AST evidence
      if (inComment) {
        // Match is inside a comment or string - likely documentation, not usage
        finding.confidence = Math.max(0.1, finding.confidence - 0.3);
        finding.evidence.confidenceDerivation += 
          ` -0.30 (match in ${relevantNode.type})`;
        // Mark as accepted risk since it's likely documentation
        if (finding.remediationStatus === 'open') {
          finding.remediationStatus = 'accepted-risk';
        }
      } else if (nodeType === 'call_expression' || nodeType === 'function_call') {
        // Match is in a function call - high confidence it's real usage
        finding.confidence = Math.min(0.98, finding.confidence + 0.15);
        finding.evidence.confidenceDerivation += 
          ' +0.15 (AST confirms call expression)';
      } else if (nodeType === 'assignment' || nodeType === 'variable_declarator') {
        // Match is in an assignment - likely real usage
        finding.confidence = Math.min(0.95, finding.confidence + 0.10);
        finding.evidence.confidenceDerivation += 
          ' +0.10 (AST confirms assignment)';
      }

      // Store additional AST-derived metadata
      if (callArgs.length > 0) {
        // We could extract key sizes, modes, etc. from call arguments
        // For now, store them as additional context
        if (!finding.tags) finding.tags = [];
        finding.tags.push('ast-analyzed');
      }
    }
  } catch (error) {
    // Log but don't fail - AST enrichment is optional
    console.warn(`AST enrichment failed for ${path}:`, error);
  }
}

/**
 * Get AST analysis statistics for a set of findings.
 * Useful for debugging and showing AST coverage.
 */
export function getAstStats(findings: Finding[]): {
  totalFindings: number;
  astAnalyzed: number;
  inComments: number;
  inCode: number;
} {
  const astFindings = findings.filter(f => 
    f.evidence?.detectionLayers?.includes('ast')
  );
  
  return {
    totalFindings: findings.length,
    astAnalyzed: astFindings.length,
    inComments: astFindings.filter(f => 
      (f.evidence?.astContext as any)?.inComment === true
    ).length,
    inCode: astFindings.filter(f => 
      (f.evidence?.astContext as any)?.inComment === false
    ).length,
  };
}
