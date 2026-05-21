export interface PhaseField {
  k: string;
  l: string;
  mono?: boolean;
  full?: boolean;
}

export interface Phase {
  id: string;
  name: string;
  short: string;
  desc: string;
  fields: PhaseField[];
}

export interface AuditEntry {
  id: string;
  ts: number;
  [key: string]: any; // dynamic fields like host, ports, status etc.
}

export interface Project {
  id: string;
  userId?: string;
  name: string;
  scope: string;
  auditor: string;
  date: string;
  desc: string;

  status: 'pending' | 'active' | 'done' | 'archived';
  createdAt: number;
  updatedAt: number;
  entries: {
    [phaseId: string]: AuditEntry[];
  };
  phaseStatus: {
    [phaseId: string]: 'pending' | 'progress' | 'done';
  };
}
