// ============================================================
// Qrypto — Detector: Binary Crypto Artifact Discovery (v2)
//
// Implements STRUCTURAL static binary parsing for ELF and PE.
// Rather than running regexes over a raw string dump, this parser
// reads the actual binary format headers and extracts:
//
//   PE (Windows EXE/DLL):
//     - DOS Header → PE Header (NT Headers)
//     - Import Directory Table → DLL names + imported function names
//     → Finds: bcrypt.dll, crypt32.dll, ncrypt.dll, libcrypto-3-x64.dll
//
//   ELF (Linux/WASM):
//     - ELF64/ELF32 Header → Section Headers → .dynsym + .dynstr
//     - Dynamic segment → DT_NEEDED (required shared libraries)
//     → Finds: libssl.so, libcrypto.so, libgnutls.so
//
// Fallback: ASCII string extraction for unrecognized binary formats.
//
// SAFETY RULES (absolute):
//   - NEVER execute the binary
//   - NEVER call eval() on any content
//   - All reads are bounds-checked
//   - Treat all input as hostile
// ============================================================

import type { Finding, Severity } from '../../types';
import { computeRiskScore } from '../riskEngine';
import { deriveAlgorithmSeverity, deriveEffectiveSeverity } from '../severity';

// ─── Safety Limits ──────────────────────────────────────────
const MAX_BINARY_SIZE = 500 * 1024 * 1024; // 500 MB
const MAX_STRINGS_SCANNED = 5000;
const MAX_STRING_LENGTH = 200;
const MIN_STRING_LENGTH = 4;

// ─── Crypto Library Signatures ──────────────────────────────

interface LibSignature {
  pattern: RegExp;
  algorithm: string;
  usage: string;
  severity: Severity;
  confidence: number;
  quantumStatus: Finding['quantumStatus'];
  classicalStatus: Finding['classicalStatus'];
}

const CRYPTO_LIB_SIGNATURES: LibSignature[] = [
  // --- Shared Libraries (ELF DT_NEEDED / PE IAT) ---
  { pattern: /libcrypto[.-]?\d*(?:\.so|\.dll|\.dylib)/i, algorithm: 'OpenSSL/libcrypto', usage: 'Linked against OpenSSL crypto library', severity: 'medium', confidence: 0.95, quantumStatus: 'vulnerable', classicalStatus: 'adequate' },
  { pattern: /libssl[.-]?\d*(?:\.so|\.dll|\.dylib)/i, algorithm: 'OpenSSL/libssl', usage: 'Linked against OpenSSL TLS library', severity: 'medium', confidence: 0.95, quantumStatus: 'vulnerable', classicalStatus: 'adequate' },
  { pattern: /bcrypt\.dll/i, algorithm: 'Windows BCrypt', usage: 'Imported Windows BCrypt.dll (Windows crypto primitives)', severity: 'info', confidence: 0.97, quantumStatus: 'adequate', classicalStatus: 'strong' },
  { pattern: /ncrypt\.dll/i, algorithm: 'Windows NCrypt', usage: 'Imported Windows NCrypt.dll (CNG next-gen crypto)', severity: 'info', confidence: 0.97, quantumStatus: 'adequate', classicalStatus: 'strong' },
  { pattern: /crypt32\.dll/i, algorithm: 'Windows Crypt32', usage: 'Imported Crypt32.dll (certificate & message functions)', severity: 'low', confidence: 0.96, quantumStatus: 'adequate', classicalStatus: 'adequate' },
  { pattern: /libgnutls[.-]?\d*(?:\.so|\.dll|\.dylib)/i, algorithm: 'GnuTLS', usage: 'Linked against GnuTLS library', severity: 'low', confidence: 0.93, quantumStatus: 'adequate', classicalStatus: 'adequate' },
  { pattern: /libnss3?(?:\.so|\.dll|\.dylib)/i, algorithm: 'Mozilla NSS', usage: 'Linked against Mozilla NSS crypto library', severity: 'low', confidence: 0.93, quantumStatus: 'adequate', classicalStatus: 'adequate' },
  { pattern: /libmbedcrypto(?:\.so|\.dll|\.dylib)/i, algorithm: 'Mbed TLS', usage: 'Linked against Arm Mbed TLS crypto library', severity: 'low', confidence: 0.92, quantumStatus: 'adequate', classicalStatus: 'adequate' },
  // --- Imported Function Symbols ---
  { pattern: /EVP_(?:Encrypt|Decrypt|Sign|Verify|Digest)(?:Init|Update|Final)/i, algorithm: 'OpenSSL EVP', usage: 'OpenSSL EVP high-level crypto API imported', severity: 'info', confidence: 0.92, quantumStatus: 'adequate', classicalStatus: 'adequate' },
  { pattern: /RSA_(?:public_encrypt|private_decrypt|sign|verify)/i, algorithm: 'RSA', usage: 'OpenSSL RSA API imported in binary', severity: 'high', confidence: 0.93, quantumStatus: 'vulnerable', classicalStatus: 'adequate' },
  { pattern: /EC_KEY_new|ECDSA_sign|ECDH_compute_key/i, algorithm: 'ECC/ECDSA', usage: 'OpenSSL ECC API imported in binary', severity: 'high', confidence: 0.93, quantumStatus: 'vulnerable', classicalStatus: 'strong' },
  { pattern: /BCryptOpenAlgorithmProvider|BCryptGenerateKeyPair|BCryptSignHash/i, algorithm: 'Windows BCrypt API', usage: 'Windows CNG BCrypt API imported', severity: 'info', confidence: 0.95, quantumStatus: 'adequate', classicalStatus: 'strong' },
  { pattern: /CryptImportKey|CryptEncrypt|CryptSignMessage/i, algorithm: 'Windows CryptoAPI (CAPI)', usage: 'Legacy Windows CAPI (wincrypt.h) imported — deprecated in favour of CNG', severity: 'medium', confidence: 0.90, quantumStatus: 'adequate', classicalStatus: 'weak' },
  // --- Algorithm name strings (fallback) ---
  { pattern: /AES(?:_|-)?(?:128|192|256)(?:_|-)?(?:CBC|GCM|CTR|ECB|CCM|CFB|OFB)?/i, algorithm: 'AES', usage: 'AES algorithm string in binary', severity: 'info', confidence: 0.80, quantumStatus: 'adequate', classicalStatus: 'strong' },
  { pattern: /RSA(?:_|-)?(?:1024|2048|3072|4096)/i, algorithm: 'RSA', usage: 'RSA key-size string in binary', severity: 'high', confidence: 0.85, quantumStatus: 'vulnerable', classicalStatus: 'adequate' },
  { pattern: /TLSv1\.[0-3]|SSLv[23]/i, algorithm: 'TLS Protocol', usage: 'TLS version string in binary', severity: 'medium', confidence: 0.82, quantumStatus: 'adequate', classicalStatus: 'adequate' },
  { pattern: /sha1_?(?:digest|init|update|final)/i, algorithm: 'SHA-1', usage: 'SHA-1 API in binary', severity: 'high', confidence: 0.88, quantumStatus: 'classical-weak', classicalStatus: 'weak' },
  { pattern: /md5_?(?:digest|init|update|final)/i, algorithm: 'MD5', usage: 'MD5 API in binary', severity: 'critical', confidence: 0.92, quantumStatus: 'classical-weak', classicalStatus: 'broken' },
];

// ─── Utility: Safe DataView Reader ──────────────────────────

class SafeReader {
  private view: DataView;
  readonly size: number;

  constructor(buffer: ArrayBuffer) {
    this.view = new DataView(buffer);
    this.size = buffer.byteLength;
  }

  ok(offset: number, bytes: number): boolean {
    return offset >= 0 && offset + bytes <= this.size;
  }

  u8(offset: number): number {
    return this.ok(offset, 1) ? this.view.getUint8(offset) : 0;
  }

  u16le(offset: number): number {
    return this.ok(offset, 2) ? this.view.getUint16(offset, true) : 0;
  }

  u32le(offset: number): number {
    return this.ok(offset, 4) ? this.view.getUint32(offset, true) : 0;
  }

  u64le(offset: number): number {
    // Return as JS number (safe for addresses up to 2^53)
    if (!this.ok(offset, 8)) return 0;
    return this.view.getUint32(offset, true) + this.view.getUint32(offset + 4, true) * 0x100000000;
  }

  cstr(offset: number, maxLen: number = 256): string {
    const chars: number[] = [];
    for (let i = 0; i < maxLen; i++) {
      if (!this.ok(offset + i, 1)) break;
      const c = this.view.getUint8(offset + i);
      if (c === 0) break;
      if (c >= 0x20 && c < 0x7F) chars.push(c);
    }
    return String.fromCharCode(...chars);
  }

  magic4(offset: number): string {
    if (!this.ok(offset, 4)) return '';
    return [0, 1, 2, 3].map(i => String.fromCharCode(this.u8(offset + i))).join('');
  }
}

// ─── PE Parser ──────────────────────────────────────────────
// Walks the Import Directory Table to extract DLL names and
// imported function names relevant to cryptography.

interface PeImport {
  dll: string;
  functions: string[];
}

function parsePeImports(r: SafeReader): PeImport[] {
  const imports: PeImport[] = [];

  // DOS header: magic = 'MZ'
  if (r.u8(0) !== 0x4D || r.u8(1) !== 0x5A) return imports;

  // e_lfanew at offset 0x3C
  const peOffset = r.u32le(0x3C);
  if (!r.ok(peOffset, 24)) return imports;

  // NT Signature: 'PE\0\0'
  if (r.magic4(peOffset) !== 'PE\0\0') return imports;

  const machine = r.u16le(peOffset + 4);
  const optHeaderOffset = peOffset + 24;
  const magic = r.u16le(optHeaderOffset);

  // Determine PE32 vs PE32+
  const is64 = magic === 0x20B;
  const importDirOffset = is64 ? optHeaderOffset + 104 : optHeaderOffset + 92;
  if (!r.ok(importDirOffset, 8)) return imports;

  let importRva = r.u32le(importDirOffset);
  const importSize = r.u32le(importDirOffset + 4);
  if (importRva === 0 || importSize === 0) return imports;

  // We need to convert RVA → file offset via section headers.
  // Section table starts after the optional header.
  const numSections = r.u16le(peOffset + 6);
  const optHeaderSize = r.u16le(peOffset + 20);
  const sectionTableOffset = optHeaderOffset + optHeaderSize;

  function rvaToOffset(rva: number): number {
    for (let i = 0; i < numSections; i++) {
      const soff = sectionTableOffset + i * 40;
      if (!r.ok(soff, 40)) break;
      const vaddr = r.u32le(soff + 12);
      const vsize = r.u32le(soff + 16);
      const rawoff = r.u32le(soff + 20);
      if (rva >= vaddr && rva < vaddr + vsize) {
        return rawoff + (rva - vaddr);
      }
    }
    return -1;
  }

  let idtOffset = rvaToOffset(importRva);
  if (idtOffset < 0) return imports;

  // Each Import Directory Entry is 20 bytes; table ends with all-zeros entry
  for (let entryIdx = 0; entryIdx < 200; entryIdx++) {
    const entryBase = idtOffset + entryIdx * 20;
    if (!r.ok(entryBase, 20)) break;

    const nameRva = r.u32le(entryBase + 12);
    const iltRva = r.u32le(entryBase + 0); // Import Lookup Table RVA
    if (nameRva === 0 && iltRva === 0) break; // end sentinel

    const nameOffset = rvaToOffset(nameRva);
    if (nameOffset < 0) continue;
    const dllName = r.cstr(nameOffset, 128).toLowerCase();
    if (!dllName) continue;

    const functions: string[] = [];
    let iltOffset = rvaToOffset(iltRva || r.u32le(entryBase + 16));
    if (iltOffset >= 0) {
      const entrySize = is64 ? 8 : 4;
      for (let fnIdx = 0; fnIdx < 1000; fnIdx++) {
        const thunkOffset = iltOffset + fnIdx * entrySize;
        if (!r.ok(thunkOffset, entrySize)) break;
        const thunkVal = is64 ? r.u64le(thunkOffset) : r.u32le(thunkOffset);
        if (thunkVal === 0) break;
        const msb = is64 ? (thunkVal > 0x7FFFFFFFFFFFFFFF) : (thunkVal > 0x7FFFFFFF);
        if (msb) continue; // ordinal import — skip name lookup
        const hintNameRva = thunkVal & (is64 ? 0x7FFFFFFFFFFFFFFF : 0x7FFFFFFF);
        const hintNameOffset = rvaToOffset(Number(hintNameRva));
        if (hintNameOffset < 0) continue;
        // Hint is 2 bytes, then null-terminated function name
        const fnName = r.cstr(hintNameOffset + 2, 128);
        if (fnName) functions.push(fnName);
      }
    }

    imports.push({ dll: dllName, functions });
  }

  return imports;
}

// ─── ELF Parser ─────────────────────────────────────────────
// Walks the Dynamic segment (DT_NEEDED) and .dynsym table.

interface ElfAnalysis {
  needed: string[];   // DT_NEEDED shared libraries
  symbols: string[];  // exported/imported function names in .dynsym
}

function parseElfAnalysis(r: SafeReader): ElfAnalysis {
  const result: ElfAnalysis = { needed: [], symbols: [] };

  // ELF magic: 0x7F 'E' 'L' 'F'
  if (r.u8(0) !== 0x7F || r.u8(1) !== 0x45 || r.u8(2) !== 0x4C || r.u8(3) !== 0x46) {
    return result;
  }

  const elfClass = r.u8(4); // 1=32bit, 2=64bit
  const is64 = elfClass === 2;

  // ELF header fields differ by class
  const shoffOffset = is64 ? 40 : 32;
  const shentsizeOffset = is64 ? 58 : 46;
  const shnumOffset = is64 ? 60 : 48;
  const shstrndxOffset = is64 ? 62 : 50;

  const shoff = is64 ? r.u64le(shoffOffset) : r.u32le(shoffOffset);
  const shentsize = r.u16le(shentsizeOffset);
  const shnum = r.u16le(shnumOffset);
  const shstrndx = r.u16le(shstrndxOffset);

  if (shoff === 0 || shnum === 0 || shentsize === 0) return result;

  // Read section name string table (shstrtab)
  function getSectionName(nameOffset: number, strtabOffset: number): string {
    return r.cstr(strtabOffset + nameOffset, 64);
  }

  // Get the shstrtab section offset
  const shstrSecBase = shoff + shstrndx * shentsize;
  const shstrDataOff = is64 ? r.u64le(shstrSecBase + 24) : r.u32le(shstrSecBase + 16);

  interface SectionInfo { nameOffset: number; type: number; offset: number; size: number; link: number; entsize: number; }
  const sections: SectionInfo[] = [];

  for (let i = 0; i < shnum && i < 200; i++) {
    const base = shoff + i * shentsize;
    if (!r.ok(base, shentsize)) break;
    sections.push({
      nameOffset: r.u32le(base),
      type: r.u32le(base + 4),
      offset: is64 ? Number(r.u64le(base + 24)) : r.u32le(base + 16),
      size:   is64 ? Number(r.u64le(base + 32)) : r.u32le(base + 20),
      link:   r.u32le(base + (is64 ? 40 : 24)),
      entsize: is64 ? Number(r.u64le(base + 56)) : r.u32le(base + 36),
    });
  }

  // Process .dynsym (type=11) and .dynamic (type=6) sections
  for (const sec of sections) {
    const secName = getSectionName(sec.nameOffset, Number(shstrDataOff));

    // SHT_DYNSYM (11) — dynamic symbol table
    if (sec.type === 11 && sec.entsize > 0) {
      // Linked section is .dynstr
      const strSec = sections[sec.link];
      if (!strSec) continue;
      const symEntSize = is64 ? 24 : 16;
      const numSyms = Math.floor(sec.size / symEntSize);
      for (let s = 0; s < numSyms && s < 2000; s++) {
        const symBase = sec.offset + s * symEntSize;
        const nameIdx = r.u32le(symBase); // st_name
        const symName = r.cstr(strSec.offset + nameIdx, 128);
        if (symName) result.symbols.push(symName);
      }
    }

    // SHT_DYNAMIC (6) — dynamic segment (DT_NEEDED = tag 1)
    if (sec.type === 6) {
      // Locate .dynstr section for this dynamic segment
      const dynstrSec = sections.find(s => getSectionName(s.nameOffset, Number(shstrDataOff)) === '.dynstr');
      if (!dynstrSec) continue;
      const dynEntSize = is64 ? 16 : 8;
      const numEntries = Math.floor(sec.size / dynEntSize);
      for (let e = 0; e < numEntries && e < 500; e++) {
        const base = sec.offset + e * dynEntSize;
        const tag = is64 ? Number(r.u64le(base)) : r.u32le(base);
        const val = is64 ? Number(r.u64le(base + 8)) : r.u32le(base + 4);
        if (tag === 0) break; // DT_NULL
        if (tag === 1) { // DT_NEEDED
          const libName = r.cstr(dynstrSec.offset + val, 128);
          if (libName) result.needed.push(libName);
        }
      }
    }
  }

  return result;
}

// ─── String Extractor (Fallback) ────────────────────────────

function extractStrings(buffer: ArrayBuffer, maxStrings = MAX_STRINGS_SCANNED): string[] {
  const bytes = new Uint8Array(buffer);
  const strings: string[] = [];
  let current: number[] = [];

  for (let i = 0; i < bytes.length && strings.length < maxStrings; i++) {
    const b = bytes[i];
    if (b >= 0x20 && b < 0x7F && current.length < MAX_STRING_LENGTH) {
      current.push(b);
    } else {
      if (current.length >= MIN_STRING_LENGTH) {
        strings.push(String.fromCharCode(...current));
      }
      current = [];
    }
  }
  if (current.length >= MIN_STRING_LENGTH) strings.push(String.fromCharCode(...current));
  return strings;
}

// ─── Finding Builder ────────────────────────────────────────

function buildFinding(
  filePath: string, repository: string, project: string,
  sig: LibSignature, detectedPattern: string, lineApprox: number,
  detectionLayer: string, evidence: string,
): Finding {
  const now = new Date().toISOString();

  const riskBreakdown = computeRiskScore({
    quantumStatus: sig.quantumStatus,
    baseSeverity: sig.severity,
    internetFacing: false,
    dataSensitivity: 'medium',
    dataLifetimeYears: 5,
    isHardcoded: false,
    service: 'Binary Artifact',
  });

  const algorithmSeverity = deriveAlgorithmSeverity({
    algorithm: sig.algorithm,
    quantumStatus: sig.quantumStatus,
    baseSeverity: sig.severity,
    category: 'binary-artifact',
  });

  const effective = deriveEffectiveSeverity({
    algorithmSeverity: algorithmSeverity.severity,
    quantumStatus: sig.quantumStatus,
    contextualRisk: riskBreakdown.totalScore,
  });

  return {
    id: `bin-${Math.random().toString(36).substr(2, 9)}`,
    file: filePath,
    line: lineApprox,
    repository,
    project,
    service: 'Binary Artifact',
    language: 'unknown',
    algorithm: sig.algorithm,
    category: 'binary-artifact',
    usage: sig.usage,
    detectedPattern: detectedPattern.slice(0, 100),
    confidence: sig.confidence,
    quantumStatus: sig.quantumStatus,
    classicalStatus: sig.classicalStatus,
    algorithmSeverity: algorithmSeverity.severity,
    severity: effective.severity,
    severityRationale: `${algorithmSeverity.rationale}. ${effective.rationale}. Detection via ${detectionLayer}.`,
    internetFacing: false,
    dataSensitivity: 'medium',
    dataLifetimeYears: 5,
    isCryptoAgile: false,
    isHardcoded: false,
    contextSource: 'UNKNOWN',
    riskScore: riskBreakdown.totalScore,
    riskBreakdown,
    remediationStatus: 'open',
    migrationPriority: 0,
    recommendedAlgorithm: sig.quantumStatus === 'vulnerable'
      ? 'Identify source and replace with post-quantum algorithm'
      : 'Binary contains well-known crypto library; verify version and update regularly',
    migrationStrategy: 'Identify source code, perform source-level scan, then apply library migration.',
    tags: ['binary', 'static-analysis', detectionLayer],
    detectedAt: now,
    firstSeen: now,
    lastSeen: now,
    evidence: {
      detectionLayers: ['binary-structural-parse', detectionLayer],
      matchedText: evidence.slice(0, 300),
      confidenceDerivation: `${detectionLayer}: pattern "${sig.pattern.source}" matched "${detectedPattern.slice(0, 60)}".`,
    },
  };
}

// ─── Main Detector ──────────────────────────────────────────

export function detectBinaryArtifacts(
  filePath: string,
  rawContent: string,
  repository: string,
  project: string,
): Finding[] {
  const findings: Finding[] = [];
  if (rawContent.length > MAX_BINARY_SIZE) return findings;

  // Convert string to ArrayBuffer (latin-1 / byte-accurate)
  const buf = new ArrayBuffer(rawContent.length);
  const u8 = new Uint8Array(buf);
  for (let i = 0; i < rawContent.length; i++) {
    u8[i] = rawContent.charCodeAt(i) & 0xFF;
  }

  const r = new SafeReader(buf);
  const seen = new Set<string>();

  function addFinding(sig: LibSignature, pattern: string, line: number, layer: string, evidence: string) {
    const key = `${sig.algorithm}:${pattern}`;
    if (seen.has(key)) return;
    seen.add(key);
    findings.push(buildFinding(filePath, repository, project, sig, pattern, line, layer, evidence));
  }

  // ── Detect binary format ─────────────────────────────────
  const isPE = r.u8(0) === 0x4D && r.u8(1) === 0x5A;
  const isELF = r.u8(0) === 0x7F && r.u8(1) === 0x45 && r.u8(2) === 0x4C && r.u8(3) === 0x46;
  const hasNullBytes = (rawContent.match(/\0/g) || []).length > rawContent.length * 0.05;

  if (!isPE && !isELF && !hasNullBytes) return findings; // not binary

  // ── PE: Walk Import Directory Table ─────────────────────
  if (isPE) {
    try {
      const peImports = parsePeImports(r);
      for (const imp of peImports) {
        for (const sig of CRYPTO_LIB_SIGNATURES) {
          if (sig.pattern.test(imp.dll)) {
            addFinding(sig, imp.dll, 1, 'PE-import-table', `DLL: ${imp.dll}`);
          }
        }
        for (const fn of imp.functions) {
          for (const sig of CRYPTO_LIB_SIGNATURES) {
            if (sig.pattern.test(fn)) {
              addFinding(sig, fn, 1, 'PE-IAT-symbol', `${imp.dll}::${fn}`);
            }
          }
        }
      }
    } catch (_) { /* fallthrough to string scan */ }
  }

  // ── ELF: Walk .dynsym and DT_NEEDED ─────────────────────
  if (isELF) {
    try {
      const elf = parseElfAnalysis(r);
      for (const lib of elf.needed) {
        for (const sig of CRYPTO_LIB_SIGNATURES) {
          if (sig.pattern.test(lib)) {
            addFinding(sig, lib, 1, 'ELF-DT_NEEDED', `DT_NEEDED: ${lib}`);
          }
        }
      }
      for (const sym of elf.symbols) {
        for (const sig of CRYPTO_LIB_SIGNATURES) {
          if (sig.pattern.test(sym)) {
            addFinding(sig, sym, 1, 'ELF-dynsym', `.dynsym: ${sym}`);
          }
        }
      }
    } catch (_) { /* fallthrough to string scan */ }
  }

  // ── Fallback: ASCII string scan (WASM / unknown binary) ─
  // Always run for any binary so we don't miss opaque formats
  if (hasNullBytes || isPE || isELF) {
    const strings = extractStrings(buf);
    let stringIdx = 0;
    for (const str of strings) {
      for (const sig of CRYPTO_LIB_SIGNATURES) {
        sig.pattern.lastIndex = 0;
        if (sig.pattern.test(str)) {
          addFinding(sig, str.slice(0, 80), stringIdx, 'binary-string-scan', str);
        }
      }
      stringIdx++;
    }
  }

  return findings;
}
