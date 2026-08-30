import { collection, addDoc, getDocs, query, orderBy, limit, serverTimestamp, doc, setDoc, getDoc, updateDoc } from 'firebase/firestore';
import { db } from './firebase';
import type { Assessment } from '../types';

export interface AuditLogEntry {
  id?: string;
  action: string;
  targetId: string | null;
  metadata: Record<string, unknown> | null;
  timestamp: string;
  userId: string;
  userEmail: string;
}

export const firebaseDb = {
  // ── Scans ──
  async saveScan(assessment: Assessment, userId: string): Promise<void> {
    const docRef = doc(db, 'scans', assessment.id);
    
    // 1. Separate the heavy fields from the lightweight metadata
    const { findings, services, migrationTasks, hndlAssessments, ...metadata } = assessment;
    
    // Save metadata to the parent document (clean of undefined)
    const cleanMetadata = JSON.parse(JSON.stringify(metadata));
    await setDoc(docRef, {
      ...cleanMetadata,
      userId,
      createdAt: serverTimestamp(),
    });

    // 2. Package heavy fields, stringify, and chunk into 900KB pieces to bypass 1MB limit
    const heavyPayload = { findings, services, migrationTasks, hndlAssessments };
    const cleanPayloadStr = JSON.stringify(heavyPayload);
    const CHUNK_SIZE = 900 * 1024; // 900 KB per chunk

    const chunksCol = collection(docRef, 'payloads');
    
    for (let i = 0; i < cleanPayloadStr.length; i += CHUNK_SIZE) {
      const chunkStr = cleanPayloadStr.slice(i, i + CHUNK_SIZE);
      const chunkRef = doc(chunksCol, `chunk_${i}`);
      await setDoc(chunkRef, { index: i, data: chunkStr });
    }
  },

  async getScans(userId: string): Promise<Assessment[]> {
    // Currently fetching all and filtering in-memory to avoid requiring composite indexes immediately.
    // For a production app, we would use `where('userId', '==', userId)` and create an index.
    const scansCol = collection(db, 'scans');
    const q = query(scansCol, orderBy('createdAt', 'desc'));
    const snapshot = await getDocs(q);
    
    return snapshot.docs
      .map(doc => ({ id: doc.id, ...doc.data() } as Assessment))
      .filter(scan => (scan as any).userId === userId);
  },

  async getScan(scanId: string): Promise<Assessment | null> {
    const docRef = doc(db, 'scans', scanId);
    const snapshot = await getDoc(docRef);
    if (!snapshot.exists()) return null;

    const metadata = snapshot.data() as Partial<Assessment>;
    
    // Fetch all payload chunks
    const chunksCol = collection(docRef, 'payloads');
    const chunksQuery = query(chunksCol, orderBy('index', 'asc'));
    const chunksSnap = await getDocs(chunksQuery);

    let heavyPayload = { findings: [], services: [], migrationTasks: [], hndlAssessments: [] };

    if (!chunksSnap.empty) {
      // Reassemble the 900KB string chunks
      let fullStr = '';
      chunksSnap.forEach(doc => {
        fullStr += doc.data().data;
      });
      try {
        heavyPayload = JSON.parse(fullStr);
      } catch (err) {
        console.error("Failed to parse reconstructed scan payload", err);
      }
    }

    return { 
      id: snapshot.id, 
      ...metadata,
      ...heavyPayload 
    } as Assessment;
  },
  
  async updateScan(scanId: string, updates: Partial<Assessment>): Promise<void> {
    // Note: To fully support partial updates of heavy fields (e.g. findings), 
    // we would need to read, merge, and rewrite chunks. 
    // For now, updateFindingStatus in assessmentStore passes { findings: [...] }.
    // If findings are provided, we rewrite the chunks.
    const docRef = doc(db, 'scans', scanId);
    
    const { findings, services, migrationTasks, hndlAssessments, ...metadataUpdates } = updates;
    
    if (Object.keys(metadataUpdates).length > 0) {
      const cleanUpdates = JSON.parse(JSON.stringify(metadataUpdates));
      await updateDoc(docRef, cleanUpdates);
    }

    // If findings are being updated, we must fetch the existing heavy fields, merge, and rewrite chunks
    if (findings || services || migrationTasks || hndlAssessments) {
      const currentFull = await firebaseDb.getScan(scanId);
      if (currentFull) {
        const newHeavyPayload = {
          findings: findings || currentFull.findings,
          services: services || currentFull.services,
          migrationTasks: migrationTasks || currentFull.migrationTasks,
          hndlAssessments: hndlAssessments || currentFull.hndlAssessments,
        };

        const cleanPayloadStr = JSON.stringify(newHeavyPayload);
        const CHUNK_SIZE = 900 * 1024;
        const chunksCol = collection(docRef, 'payloads');
        
        // Rewrite chunks
        for (let i = 0; i < cleanPayloadStr.length; i += CHUNK_SIZE) {
          const chunkStr = cleanPayloadStr.slice(i, i + CHUNK_SIZE);
          const chunkRef = doc(chunksCol, `chunk_${i}`);
          await setDoc(chunkRef, { index: i, data: chunkStr });
        }
      }
    }
  },

  // ── Audit Logs ──
  async logAudit(entry: Omit<AuditLogEntry, 'timestamp'>): Promise<void> {
    const logsCol = collection(db, 'auditLogs');
    const cleanEntry = JSON.parse(JSON.stringify(entry));
    await addDoc(logsCol, {
      ...cleanEntry,
      timestamp: new Date().toISOString(), // store ISO string for easy client sorting
      serverTime: serverTimestamp()
    });
  },

  async getAuditLogs(userId: string): Promise<AuditLogEntry[]> {
    const logsCol = collection(db, 'auditLogs');
    const q = query(logsCol, orderBy('serverTime', 'desc'), limit(100));
    const snapshot = await getDocs(q);
    
    return snapshot.docs
      .map(doc => ({ id: doc.id, ...doc.data() } as AuditLogEntry))
      .filter(log => log.userId === userId);
  }
};
