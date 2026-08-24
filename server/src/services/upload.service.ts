import multer from 'multer';
import path from 'path';
import fs from 'fs';
import AdmZip from 'adm-zip';
import { v4 as uuidv4 } from 'uuid';

const UPLOAD_DIR = path.join(__dirname, '../../uploads');

if (!fs.existsSync(UPLOAD_DIR)) {
  fs.mkdirSync(UPLOAD_DIR, { recursive: true });
}

// Multer config for zip files
const storage = multer.diskStorage({
  destination: (req, file, cb) => cb(null, UPLOAD_DIR),
  filename: (req, file, cb) => cb(null, `${uuidv4()}.zip`),
});

export const upload = multer({
  storage,
  limits: { fileSize: 50 * 1024 * 1024 }, // 50MB limit
  fileFilter: (req, file, cb) => {
    if (file.mimetype === 'application/zip' || file.mimetype === 'application/x-zip-compressed') {
      cb(null, true);
    } else {
      cb(new Error('Only zip files are allowed'));
    }
  },
});

export const extractZipSecurely = (zipPath: string, extractToDir: string): string[] => {
  const zip = new AdmZip(zipPath);
  const zipEntries = zip.getEntries();

  if (zipEntries.length > 10000) {
    throw new Error('Too many files in zip (max 10000)');
  }

  const extractedFiles: string[] = [];

  for (const entry of zipEntries) {
    if (entry.isDirectory) continue;

    // Security: Path traversal prevention
    const entryName = entry.entryName.replace(/\\/g, '/');
    if (entryName.includes('../') || entryName.startsWith('/')) {
      throw new Error(`Invalid file path detected: ${entryName}`);
    }

    // Security: Zip bomb prevention (ratio check)
    const compressionRatio = entry.header.size === 0 ? 1 : entry.header.size / entry.header.compressedSize;
    if (compressionRatio > 100) {
      throw new Error(`Suspicious compression ratio detected in file: ${entryName}`);
    }

    // Optional: filter extensions here
    const ext = path.extname(entryName).toLowerCase();
    const allowedExts = ['.ts', '.js', '.jsx', '.tsx', '.py', '.java', '.go', '.rs', '.c', '.cpp', '.h', '.hpp', '.cs', '.pem', '.der', '.crt', '.key', '.yaml', '.yml', '.json', '.toml', '.xml'];
    if (!allowedExts.includes(ext) && ext !== '') {
        continue;
    }

    // Extract file
    zip.extractEntryTo(entry.entryName, extractToDir, true, true);
    extractedFiles.push(path.join(extractToDir, entry.entryName));
  }

  return extractedFiles;
};
