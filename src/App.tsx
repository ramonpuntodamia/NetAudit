import { useState, useEffect } from 'react';
import { motion, AnimatePresence } from 'motion/react';
import {
  Shield,
  Plus,
  ArrowLeft,
  Pencil,
  BookOpen,
  Download,
  Trash2,
  ChevronDown,
  User,
  Calendar,
  FileText,
  Copy,
  Check,
  Search,
  CheckCircle2,
  ListTodo,
  Terminal,
  Activity,
  AlertTriangle,
  FolderLock,
  Cloud,
  CloudUpload,
  LogOut,
  LogIn,
  Database,
  RefreshCw
} from 'lucide-react';
import { Project, Phase, AuditEntry } from './types';
import { auth, db, handleFirestoreError, OperationType } from './firebase';
import { onAuthStateChanged, signInWithPopup, GoogleAuthProvider, signOut, User as FirebaseUser } from 'firebase/auth';
import { collection, query, where, onSnapshot, doc, setDoc, deleteDoc } from 'firebase/firestore';

// Static phases matching user definitions perfectly
const PHASES: Phase[] = [
  {
    id: 'recon',
    name: 'Reconocimiento (OSINT)',
    short: 'Reconocimiento',
    desc: 'Recolección de información pública y OSINT',
    fields: [
      { k: 'objetivo', l: 'Objetivo / Dominio' },
      { k: 'herramienta', l: 'Herramienta utilizada' },
      { k: 'hallazgo', l: 'Hallazgo principal', full: true },
      { k: 'comando', l: 'Comando / Query', mono: true, full: true },
      { k: 'output', l: 'Salida del Comando / Tool Output', mono: true, full: true },
      { k: 'notas', l: 'Notas', mono: true, full: true }
    ]
  },
  {
    id: 'scan',
    name: 'Escaneo y Enumeración',
    short: 'Escaneo',
    desc: 'Descubrimiento de hosts, puertos y servicios',
    fields: [
      { k: 'host', l: 'Host / IP' },
      { k: 'puertos', l: 'Puertos abiertos' },
      { k: 'servicios', l: 'Servicios' },
      { k: 'version', l: 'Versión / Banner' },
      { k: 'comando', l: 'Comando ejecutado', mono: true, full: true },
      { k: 'output', l: 'Salida del Comando / Output relevante', mono: true, full: true }
    ]
  },
  {
    id: 'vuln',
    name: 'Análisis de Vulnerabilidades',
    short: 'Vulnerabilidades',
    desc: 'Identificación y clasificación de vulnerabilidades',
    fields: [
      { k: 'cve', l: 'CVE / ID' },
      { k: 'severidad', l: 'Severidad (CVSS)' },
      { k: 'servicio', l: 'Servicio afectado' },
      { k: 'descripcion', l: 'Descripción', full: true },
      { k: 'comando', l: 'Comando de verificación', mono: true, full: true },
      { k: 'output', l: 'Salida / Output de la verificación', mono: true, full: true },
      { k: 'evidencia', l: 'Evidencia / PoC', mono: true, full: true }
    ]
  },
  {
    id: 'exploit',
    name: 'Explotación',
    short: 'Explotación',
    desc: 'Ejecución de exploits y acceso obtenido',
    fields: [
      { k: 'vuln', l: 'Vulnerabilidad explotada' },
      { k: 'vector', l: 'Vector de ataque' },
      { k: 'payload', l: 'Payload / Exploit', mono: true, full: true },
      { k: 'comando', l: 'Comando ejecutado (Exploit)', mono: true, full: true },
      { k: 'output', l: 'Salida del Exploit / Acceso obtenido', mono: true, full: true },
      { k: 'resultado', l: 'Resultado obtenido', full: true },
      { k: 'evidencia', l: 'Path de evidencia', full: true }
    ]
  },
  {
    id: 'post',
    name: 'Post-Explotación',
    short: 'Post-Exploit',
    desc: 'Persistencia, pivoting y escalada de privilegios',
    fields: [
      { k: 'tecnica', l: 'Técnica' },
      { k: 'acceso', l: 'Nivel de acceso' },
      { k: 'artefacto', l: 'Artefactos' },
      { k: 'comando', l: 'Comandos ejecutados', mono: true, full: true },
      { k: 'output', l: 'Salida del Comando / Terminal Output', mono: true, full: true },
      { k: 'notas', l: 'Notas', mono: true, full: true }
    ]
  },
  {
    id: 'report',
    name: 'Reporte y Mitigación',
    short: 'Mitigación',
    desc: 'Recomendaciones y estado de remediación',
    fields: [
      { k: 'hallazgo', l: 'Hallazgo crítico' },
      { k: 'impacto', l: 'Impacto' },
      { k: 'prioridad', l: 'Prioridad' },
      { k: 'estado', l: 'Estado remediación' },
      { k: 'comando', l: 'Comando para verificar corrección', mono: true, full: true },
      { k: 'output', l: 'Salida esperada (Post-Mitigación)', mono: true, full: true },
      { k: 'mitigacion', l: 'Recomendación', mono: true, full: true }
    ]
  }
];

export default function App() {
  // Database store logic
  const loadProjectsFromLocalStorage = () => {
    const saved = localStorage.getItem('netaudit_db');
    if (saved) {
      try {
        const parsed = JSON.parse(saved);
        if (parsed && Array.isArray(parsed.projects)) {
          return parsed.projects;
        }
      } catch (e) {
        console.error("No se pudo cargar la base de datos de auditorías anteriores.", e);
      }
    }
    return [];
  };

  const [projects, setProjects] = useState<Project[]>(loadProjectsFromLocalStorage);
  const [user, setUser] = useState<FirebaseUser | null>(null);
  const [isCloudLoading, setIsCloudLoading] = useState(false);
  const [isAuthLoading, setIsAuthLoading] = useState(true);
  const [isMigrating, setIsMigrating] = useState(false);

  const handleGoogleLogin = async () => {
    const provider = new GoogleAuthProvider();
    try {
      await signInWithPopup(auth, provider);
    } catch (e) {
      console.error("Error signing in with Google:", e);
    }
  };

  const handleGoogleLogout = async () => {
    try {
      await signOut(auth);
      setActiveProjectId(null);
    } catch (e) {
      console.error("Error signing out:", e);
    }
  };

  const handleMigrateLocalProjects = async () => {
    if (!user) return;
    setIsMigrating(true);
    const localProjs = loadProjectsFromLocalStorage();
    for (const p of localProjs) {
      const copy = { ...p, userId: user.uid, updatedAt: Date.now() };
      try {
        await setDoc(doc(db, 'projects', copy.id), copy);
      } catch (error) {
        console.error("Error migrating project:", error);
      }
    }
    localStorage.removeItem('netaudit_db');
    setIsMigrating(false);
  };

  // Authentication Listener
  useEffect(() => {
    const unsubscribe = onAuthStateChanged(auth, (usr) => {
      setUser(usr);
      setIsAuthLoading(false);
      if (!usr) {
        // Sign out restores local storage projects
        setProjects(loadProjectsFromLocalStorage());
      }
    });
    return () => unsubscribe();
  }, []);

  // Firestore Sync Listener
  useEffect(() => {
    if (!user) return;
    setIsCloudLoading(true);
    const q = query(collection(db, 'projects'), where('userId', '==', user.uid));
    const unsubscribe = onSnapshot(q, (snapshot) => {
      const cloudProjects: Project[] = [];
      snapshot.forEach((docSnap) => {
        cloudProjects.push(docSnap.data() as Project);
      });
      // Sort on client side to optimize and avoid indexing errors
      cloudProjects.sort((a, b) => b.createdAt - a.createdAt);
      setProjects(cloudProjects);
      setIsCloudLoading(false);
    }, (error) => {
      handleFirestoreError(error, OperationType.LIST, 'projects');
      setIsCloudLoading(false);
    });
    return () => unsubscribe();
  }, [user]);

  // Navigation and active project state
  const [activeProjectId, setActiveProjectId] = useState<string | null>(null);
  const [activePhaseId, setActivePhaseId] = useState<string>('recon');
  const [viewMode, setViewMode] = useState<'phase' | 'report'>('phase');

  // Search/Filter state (Highly intuitive UX addition)
  const [prjSearchTerm, setPrjSearchTerm] = useState('');
  const [reportSearchQuery, setReportSearchQuery] = useState('');

  // Expandable list items
  const [expandedEntries, setExpandedEntries] = useState<Record<string, boolean>>({});

  // Modals visibility
  const [showProjectModal, setShowProjectModal] = useState(false);
  const [editingProjectMode, setEditingProjectMode] = useState(false);

  // Form states
  const [prjForm, setPrjForm] = useState({
    name: '',
    scope: '',
    auditor: '',
    date: '',
    status: 'pending' as Project['status'],
    desc: ''
  });

  // Phase Entry Form states
  const [isFormOpen, setIsFormOpen] = useState(false);
  const [editingEntryId, setEditingEntryId] = useState<string | null>(null);
  const [nfValues, setNfValues] = useState<Record<string, string>>({});

  // Clipboard notice state
  const [copiedId, setCopiedId] = useState<string | null>(null);

  // Custom inline confirmations and validation alerts
  const [deleteConfirmId, setDeleteConfirmId] = useState<string | null>(null);
  const [confirmDeleteProject, setConfirmDeleteProject] = useState(false);
  const [prjFormError, setPrjFormError] = useState<string | null>(null);

  // Sync state with localStorage
  useEffect(() => {
    if (!user) {
      localStorage.setItem('netaudit_db', JSON.stringify({ projects }));
    }
  }, [projects, user]);

  const activeProject = projects.find((p) => p.id === activeProjectId);

  // Helpers
  const saveProject = async (updatedPrj: Project) => {
    if (user) {
      const copy = { ...updatedPrj, userId: user.uid };
      try {
        await setDoc(doc(db, 'projects', copy.id), copy);
      } catch (error) {
        handleFirestoreError(error, OperationType.WRITE, `projects/${copy.id}`);
      }
    } else {
      setProjects((prev) => {
        const index = prev.findIndex((p) => p.id === updatedPrj.id);
        if (index >= 0) {
          const next = [...prev];
          next[index] = updatedPrj;
          return next;
        } else {
          return [updatedPrj, ...prev];
        }
      });
    }
  };

  const handleLoadDemo = async () => {
    const demoId = `demo_${Date.now()}`;
    const newDemoProject: Project = {
      id: demoId,
      userId: user?.uid || '',
      name: 'Auditoría Demo: Pentest Externo Perimetral',
      scope: 'empresa-ejemplo.com (203.0.113.85 & 192.168.10.0/24)',
      auditor: 'Ramón López',
      date: new Date().toISOString().split('T')[0],
      status: 'active',
      desc: 'Simulación de auditoría de seguridad perimetral de caja negra (Black-box Network Audit) para descubrir puertos expuestos, enumerar servicios desactualizados, verificar ejecución remota de código (RCE) mediante payloads seguros y documentar la mitigación.',
      createdAt: Date.now(),
      updatedAt: Date.now(),
      phaseStatus: {
        recon: 'done',
        scan: 'done',
        vuln: 'done',
        exploit: 'done',
        post: 'done',
        report: 'progress'
      },
      entries: {
        recon: [
          {
            id: `e_rec_${Date.now()}`,
            ts: Date.now() - 36000000,
            objetivo: 'empresa-ejemplo.com',
            herramienta: 'Subfinder & Amass',
            hallazgo: 'Descubiertos subdominios activos expuestos, incluyendo un portal de desarrollo dev.empresa-ejemplo.com.',
            comando: 'subfinder -d empresa-ejemplo.com -o subdomains.txt',
            output: '[subfinder] dev.empresa-ejemplo.com\n[subfinder] smtp.empresa-ejemplo.com\n[subfinder] www.empresa-ejemplo.com\n[subfinder] mail.empresa-ejemplo.com',
            notas: 'El host de desarrollo apunta a una IP poco documentada expuesta a internet.'
          }
        ],
        scan: [
          {
            id: `e_sca_${Date.now()}`,
            ts: Date.now() - 32000000,
            host: 'dev.empresa-ejemplo.com (203.0.113.85)',
            puertos: '22, 80, 443, 8080',
            servicios: 'SSH, HTTP, HTTPS, Apache Tomcat (WebSockets)',
            version: 'Apache Tomcat 9.0.37',
            comando: 'nmap -sS -sV -p 22,80,443,8080 -T4 203.0.113.85',
            output: 'PORT     STATE SERVICE VERSION\n22/tcp   open  ssh     OpenSSH 8.2p1 Ubuntu\n80/tcp   open  http    Apache httpd 2.4.41\n443/tcp  open  ssl/http Apache httpd 2.4.41\n8080/tcp open  http    Apache Tomcat 9.0.37',
            notas: 'El puerto 8080 de Tomcat tiene soporte de WebSockets activado.'
          }
        ],
        vuln: [
          {
            id: `e_vul_${Date.now()}`,
            ts: Date.now() - 28000000,
            cve: 'CVE-2020-13935',
            severidad: 'Crítica (9.8 CVSS)',
            servicio: 'Apache Tomcat WebSocket Engine',
            descripcion: 'Vulnerabilidad de flujo de entrada de WebSockets que permite ejecución remota de código (RCE) no autenticada.',
            comando: 'npx nuclei -t cves/2020/CVE-2020-13935.yaml -u http://203.0.113.85:8080',
            output: '[CVE-2020-13935] [http] [critical] http://203.0.113.85:8080/websocket - Vulnerability Verified Successfully',
            evidencia: 'Nuclei confirmó que el socket responde a desbordamiento de búfer perimetral.'
          }
        ],
        exploit: [
          {
            id: `e_exp_${Date.now()}`,
            ts: Date.now() - 24000000,
            vuln: 'CVE-2020-13935 Remote Code Execution',
            vector: 'Petición WebSockets HTTP maliciosa',
            payload: 'ws_sploit.py --target http://203.0.113.85:8080/websocket --cmd "whoami; id"',
            comando: 'python3 ws_sploit.py --target http://203.0.113.85:8080/websocket --cmd "whoami; id; hostname"',
            output: 'tomcat9\nuid=1001(tomcat9) gid=1001(tomcat9) groups=1001(tomcat9)\ndev-tomcat-backend',
            resultado: 'Acceso inicial obtenido de manera remota como usuario tomcat9 sin privilegios administrativos.',
            evidencia: '/var/log/tomcat/tomcat9_access.log'
          }
        ],
        post: [
          {
            id: `e_pos_${Date.now()}`,
            ts: Date.now() - 20000000,
            tecnica: 'Sudo baron-samedit (CVE-2021-3156)',
            acceso: 'Root / System Admin',
            artefacto: '/tmp/.pk_sys',
            comando: 'sudo -l\nsudo-pkexec-sploit',
            output: 'Matching Defaults entries for tomcat9:\n    env_keep+=SSH_AUTH_SOCK\n\n[+] Exploiting Baron Samedit...\n[+] Success! Root shell spawned.\n# whoami\nroot',
            notas: 'Se identificó falta de parches de seguridad a nivel del kernel de Linux.'
          }
        ],
        report: [
          {
            id: `e_rep_${Date.now()}`,
            ts: Date.now() - 16000000,
            hallazgo: 'Ejecución Remota de Código (Tomcat WebSockets) y Escalada Local',
            impacto: 'Control absoluto del servidor comprometido y potencial filtración de credenciales internas.',
            prioridad: 'Inmediata (Crítica)',
            estado: 'Pendiente de verificar solución contratada',
            comando: 'npa-validator --check 203.0.113.85',
            output: 'Apache Tomcat version is now 9.0.86\n[+] CVE-2020-13935: SECURE\n[+] Non-authorized WebSockets disabled.',
            mitigacion: 'Actualizar Apache Tomcat a la versión estable 9.0.86 o superior de forma inmediata. Implementar regla perimetral que deniegue el acceso al puerto 8080 desde internet.'
          }
        ]
      }
    };

    await saveProject(newDemoProject);
    setActiveProjectId(demoId);
  };

  const handleCopyText = (text: string, id: string) => {
    navigator.clipboard.writeText(text);
    setCopiedId(id);
    setTimeout(() => {
      setCopiedId(null);
    }, 1500);
  };

  const getPhaseDoneCount = (p: Project) => {
    return PHASES.filter(ph => p.phaseStatus[ph.id] === 'done').length;
  };

  const getTotalEntriesCount = (p: Project) => {
    return PHASES.reduce((acc, ph) => acc + (p.entries[ph.id] || []).length, 0);
  };

  // Create or Update project handlers
  const handleOpenNewProjectModal = () => {
    setEditingProjectMode(false);
    setPrjFormError(null);
    setConfirmDeleteProject(false);
    setPrjForm({
      name: '',
      scope: '',
      auditor: user?.displayName || '',
      date: new Date().toISOString().split('T')[0],
      status: 'pending',
      desc: ''
    });
    setShowProjectModal(true);
  };

  const handleOpenEditProjectModal = () => {
    if (!activeProject) return;
    setEditingProjectMode(true);
    setPrjFormError(null);
    setConfirmDeleteProject(false);
    setPrjForm({
      name: activeProject.name,
      scope: activeProject.scope || '',
      auditor: activeProject.auditor || '',
      date: activeProject.date || '',
      status: activeProject.status || 'pending',
      desc: activeProject.desc || ''
    });
    setShowProjectModal(true);
  };

  const handleSaveProject = async () => {
    if (!prjForm.name.trim()) {
      setPrjFormError('El nombre de la auditoría es obligatorio.');
      return;
    }

    if (editingProjectMode && activeProjectId && activeProject) {
      const updated = {
        ...activeProject,
        name: prjForm.name.trim(),
        scope: prjForm.scope.trim(),
        auditor: prjForm.auditor.trim(),
        date: prjForm.date,
        status: prjForm.status,
        desc: prjForm.desc.trim(),
        updatedAt: Date.now()
      };
      await saveProject(updated);
      setShowProjectModal(false);
    } else {
      const newId = 'p_' + Date.now();
      const initialPhaseStatus: Record<string, 'pending' | 'progress' | 'done'> = {};
      const initialEntries: Record<string, AuditEntry[]> = {};

      PHASES.forEach((ph) => {
        initialPhaseStatus[ph.id] = 'pending';
        initialEntries[ph.id] = [];
      });

      const newPrj: Project = {
        id: newId,
        userId: user?.uid || '',
        name: prjForm.name.trim(),
        scope: prjForm.scope.trim(),
        auditor: prjForm.auditor.trim(),
        date: prjForm.date,
        status: prjForm.status,
        desc: prjForm.desc.trim(),
        createdAt: Date.now(),
        updatedAt: Date.now(),
        entries: initialEntries,
        phaseStatus: initialPhaseStatus
      };

      await saveProject(newPrj);
      setShowProjectModal(false);
      // Automatically open the new project
      setActiveProjectId(newId);
      setActivePhaseId(PHASES[0].id);
      setViewMode('phase');
      setIsFormOpen(false);
      setEditingEntryId(null);
    }
  };

  const handleDeleteProject = async () => {
    if (!activeProjectId) return;
    if (user) {
      try {
        await deleteDoc(doc(db, 'projects', activeProjectId));
      } catch (error) {
        handleFirestoreError(error, OperationType.DELETE, `projects/${activeProjectId}`);
      }
    } else {
      setProjects((prev) => prev.filter((p) => p.id !== activeProjectId));
    }
    setShowProjectModal(false);
    setActiveProjectId(null);
    setConfirmDeleteProject(false);
  };

  const setProjectStatus = async (status: Project['status']) => {
    if (!activeProject) return;
    const updated = { ...activeProject, status, updatedAt: Date.now() };
    await saveProject(updated);
  };

  const updatePhaseStatus = async (phaseId: string, status: 'pending' | 'progress' | 'done') => {
    if (!activeProject) return;
    const updated = {
      ...activeProject,
      phaseStatus: { ...activeProject.phaseStatus, [phaseId]: status },
      updatedAt: Date.now()
    };
    await saveProject(updated);
  };

  // Phase item entries management
  const handleOpenAddEntry = (phaseId: string) => {
    setEditingEntryId(null);
    const initialVals: Record<string, string> = {};
    const ph = PHASES.find((x) => x.id === phaseId);
    if (ph) {
      ph.fields.forEach((f) => {
        initialVals[f.k] = '';
      });
    }
    setNfValues(initialVals);
    setIsFormOpen(true);
  };

  const handleOpenEditEntry = (phaseId: string, entry: AuditEntry) => {
    setEditingEntryId(entry.id);
    const initialVals: Record<string, string> = {};
    const ph = PHASES.find((x) => x.id === phaseId);
    if (ph) {
      ph.fields.forEach((f) => {
        initialVals[f.k] = entry[f.k] || '';
      });
    }
    setNfValues(initialVals);
    setIsFormOpen(true);
  };

  const handleSaveEntry = async (phaseId: string) => {
    if (!activeProject) return;

    const phaseEntries = activeProject.entries[phaseId] || [];
    let updatedEntries = [...phaseEntries];

    if (editingEntryId) {
      // Edit existing
      updatedEntries = updatedEntries.map((e) => {
        if (e.id === editingEntryId) {
          return { ...e, ...nfValues, ts: Date.now() };
        }
        return e;
      });
    } else {
      // Create new
      const newEntry: AuditEntry = {
        id: 'e_' + Date.now(),
        ts: Date.now(),
        ...nfValues
      };
      updatedEntries.push(newEntry);
    }

    const updated = {
      ...activeProject,
      entries: {
        ...activeProject.entries,
        [phaseId]: updatedEntries
      },
      updatedAt: Date.now()
    };

    await saveProject(updated);
    setIsFormOpen(false);
    setEditingEntryId(null);
    setNfValues({});
  };

  const handleDeleteEntry = async (phaseId: string, entryId: string) => {
    if (!activeProject) return;
    const updatedEntries = (activeProject.entries[phaseId] || []).filter((e) => e.id !== entryId);
    const updated = {
      ...activeProject,
      entries: {
        ...activeProject.entries,
        [phaseId]: updatedEntries
      },
      updatedAt: Date.now()
    };
    await saveProject(updated);
  };


  const toggleEntryAccordion = (entryId: string) => {
    setExpandedEntries((prev) => ({
      ...prev,
      [entryId]: !prev[entryId]
    }));
  };

  // Stats for dashboard
  const totalAuditsCount = projects.length;
  const activeAuditsCount = projects.filter((p) => p.status === 'active').length;
  const doneAuditsCount = projects.filter((p) => p.status === 'done').length;
  const pendingAuditsCount = projects.filter((p) => p.status === 'pending').length;
  const archivedAuditsCount = projects.filter((p) => p.status === 'archived').length;

  const filteredProjects = projects.filter((p) => {
    const q = prjSearchTerm.toLowerCase();
    return (
      p.name.toLowerCase().includes(q) ||
      (p.scope && p.scope.toLowerCase().includes(q)) ||
      (p.auditor && p.auditor.toLowerCase().includes(q)) ||
      (p.desc && p.desc.toLowerCase().includes(q))
    );
  });

  const getFilteredByStatus = (status: Project['status']) => {
    return filteredProjects.filter((p) => p.status === status);
  };

  const activeList = getFilteredByStatus('active');
  const doneList = getFilteredByStatus('done');
  const pendingList = getFilteredByStatus('pending');
  const archivedList = getFilteredByStatus('archived');

  // Text/Log Report Exporter
  const exportTxt = () => {
    if (!activeProject) return;
    const nowStr = new Date().toLocaleString('es-AR');
    let txt = '='.repeat(60) + '\nNETAUDIT LOGBOOK — BITÁCORA DE AUDITORÍA DE RED\n' + '='.repeat(60) + '\n\n';
    txt += `Auditoría       : ${activeProject.name}\n`;
    if (activeProject.scope) txt += `Scope / Target  : ${activeProject.scope}\n`;
    if (activeProject.auditor) txt += `Auditor         : ${activeProject.auditor}\n`;
    if (activeProject.date) txt += `Fecha de inicio : ${activeProject.date}\n`;
    const statusLabels = { pending: 'Pendiente', active: 'En curso', done: 'Completada', archived: 'Archivada' };
    txt += `Estado General  : ${statusLabels[activeProject.status] || activeProject.status}\n`;
    txt += `Exportado el    : ${nowStr}\n`;
    if (activeProject.desc) txt += `\nDescripción / Notas iniciales:\n${activeProject.desc}\n`;

    PHASES.forEach((ph, i) => {
      const s = activeProject.phaseStatus[ph.id] || 'pending';
      const pEntries = activeProject.entries[ph.id] || [];
      const statusLabelsPhase = { pending: 'Pendiente', progress: 'En curso', done: 'Completada' };

      txt += '\n' + '-'.repeat(60) + '\n';
      txt += `${i + 1}. ${ph.name.toUpperCase()}\n`;
      txt += `Estado de la fase: ${statusLabelsPhase[s]}\n`;
      txt += '-'.repeat(60) + '\n\n';

      if (!pEntries.length) {
        txt += 'Sin registros anotados en esta fase.\n';
        return;
      }

      pEntries.forEach((e, j) => {
        txt += `Registro #${j + 1} (${new Date(e.ts).toLocaleDateString('es-AR')}):\n`;
        ph.fields.forEach((f) => {
          if (e[f.k]) {
            txt += `  ${f.l}:\n    ${e[f.k].replace(/\n/g, '\n    ')}\n`;
          }
        });
        txt += '\n';
      });
    });

    const blob = new Blob([txt], { type: 'text/plain;charset=utf-8' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `bitacora_auditoria_${activeProject.name.replace(/\s+/g, '_')}_${Date.now()}.txt`;
    a.click();
    URL.revokeObjectURL(url);
  };

  return (
    <div className="min-h-screen bg-slate-950 text-slate-100 flex flex-col selection:bg-blue-600 selection:text-white">
      {/* ============================= DASHBOARD SCREEN ============================= */}
      {!activeProjectId && (
        <motion.div
          id="screen-dashboard"
          initial={{ opacity: 0, y: 15 }}
          animate={{ opacity: 1, y: 0 }}
          exit={{ opacity: 0 }}
          className="flex flex-col flex-1"
        >
          <div className="dash-header">
            <div className="dash-logo">
              <div className="logo-icon">
                <Shield className="text-blue-400 w-6 h-6" />
              </div>
              <div>
                <div className="app-name">NetAudit Logbook</div>
                <div className="app-version">Bitácora de auditorías de red</div>
              </div>
            </div>

            <div className="flex items-center gap-3">
              {/* Cloud Synchronization Info/Control */}
              {isAuthLoading ? (
                <div className="flex items-center gap-1.5 text-xs text-slate-500 font-medium bg-slate-900/50 border border-slate-800/60 px-3 py-2 rounded-lg">
                  <RefreshCw className="w-3.5 h-3.5 animate-spin text-blue-500" />
                  <span>Conectando...</span>
                </div>
              ) : user ? (
                <div className="flex items-center gap-2 bg-slate-900 border border-slate-800 px-3 py-2 rounded-lg text-xs">
                  <Database className="w-3.5 h-3.5 text-emerald-400 shrink-0" />
                  <span className="text-slate-300 font-medium max-w-[120px] truncate" title={user.email || ''}>
                    {user.displayName || 'Auditor'}
                  </span>
                  <div className="w-1.5 h-1.5 rounded-full bg-emerald-400 animate-pulse ml-0.5 shrink-0" title="Sincronizado en tiempo real" />
                  <button
                    type="button"
                    onClick={handleGoogleLogout}
                    className="ml-2 text-slate-400 hover:text-red-400 transition-colors cursor-pointer shrink-0"
                    title="Cerrar sesión"
                  >
                    <LogOut className="w-3.5 h-3.5" />
                  </button>
                </div>
              ) : (
                <button
                  type="button"
                  onClick={handleGoogleLogin}
                  className="flex items-center gap-1.5 bg-slate-900 hover:bg-slate-800 border border-slate-800 text-blue-400 hover:text-blue-300 px-3 py-2 rounded-lg text-xs font-semibold transition-all cursor-pointer"
                  title="Conectarse a la nube (Google Login) para resguardo y sincronización en tiempo real"
                >
                  <LogIn className="w-3.5 h-3.5" />
                  <span>Conectar Nube</span>
                </button>
              )}

              <button
                type="button"
                className="btn text-xs font-semibold flex items-center gap-1.5 bg-slate-900 border border-slate-800 hover:bg-slate-800 text-blue-400 transition-colors cursor-pointer py-2 px-3 rounded-lg"
                onClick={handleLoadDemo}
                title="Cargar simulación de auditoría completa para evaluación de reportes"
              >
                <Activity className="w-3.5 h-3.5" />
                Cargar Auditoría Demo
              </button>
              <button className="btn primary font-semibold" onClick={handleOpenNewProjectModal}>
                <Plus className="w-4 h-4 text-blue-100" />
                Nueva auditoría
              </button>
            </div>
          </div>

          <div className="dash-body max-w-7xl mx-auto w-full px-6 py-8">
            {/* Migration Banner */}
            {(() => {
              const localProjectsToSyncCount = loadProjectsFromLocalStorage().filter((p) => !p.userId).length;
              if (user && localProjectsToSyncCount > 0) {
                return (
                  <div className="bg-blue-950/30 border border-blue-900/50 rounded-xl p-4 mb-8 flex flex-col sm:flex-row items-start sm:items-center justify-between gap-4">
                    <div className="flex items-start gap-3">
                      <CloudUpload className="w-5 h-5 text-blue-400 shrink-0 mt-0.5 animate-bounce" />
                      <div>
                        <h4 className="text-sm font-semibold text-slate-200">¿Respaldar auditorías locales en tu cuenta?</h4>
                        <p className="text-xs text-slate-400 mt-0.5">
                          Tienes {localProjectsToSyncCount} {localProjectsToSyncCount === 1 ? 'auditoría' : 'auditorías'} en tu almacenamiento local que no están guardadas en la nube. Conéctalas a tu cuenta de Firebase.
                        </p>
                      </div>
                    </div>
                    <button
                      type="button"
                      disabled={isMigrating}
                      onClick={handleMigrateLocalProjects}
                      className="flex items-center gap-1.5 bg-blue-600 hover:bg-blue-500 disabled:bg-blue-800 text-white px-3.5 py-1.5 rounded-lg text-xs font-semibold transition-colors shrink-0 cursor-pointer shadow-md"
                    >
                      {isMigrating ? (
                        <>
                          <RefreshCw className="w-3.5 h-3.5 animate-spin" />
                          <span>Sincronizando...</span>
                        </>
                      ) : (
                        <>
                          <CloudUpload className="w-3.5 h-3.5" />
                          <span>Respaldar en la Nube</span>
                        </>
                      )}
                    </button>
                  </div>
                );
              }
              return null;
            })()}

            {/* Quick stats board */}
            <div className="stats-row mb-8">
              <div className="stat-card">
                <div className="stat-num text-blue-400">{totalAuditsCount}</div>
                <div className="stat-label">Total auditorías</div>
              </div>
              <div className="stat-card">
                <div className="stat-num text-amber-500">{activeAuditsCount}</div>
                <div className="stat-label">En curso</div>
              </div>
              <div className="stat-card">
                <div className="stat-num text-emerald-400">{doneAuditsCount}</div>
                <div className="stat-label">Completadas</div>
              </div>
              <div className="stat-card">
                <div className="stat-num text-slate-400">{pendingAuditsCount}</div>
                <div className="stat-label">Pendientes</div>
              </div>
            </div>

            {/* Smart Search Bar */}
            <div className="bg-slate-900 border border-slate-800 rounded-xl px-4 py-3 mb-8 flex items-center justify-between gap-3 shadow-lg">
              <div className="flex items-center gap-3 flex-1">
                <Search className="w-4 h-4 text-slate-400 shrink-0" />
                <input
                  type="text"
                  placeholder="Buscar auditoría por nombre, target, auditor, apuntes..."
                  className="bg-transparent border-none text-slate-200 placeholder-slate-500 text-sm focus:outline-none w-full"
                  value={prjSearchTerm}
                  onChange={(e) => setPrjSearchTerm(e.target.value)}
                />
              </div>
              {prjSearchTerm && (
                <button
                  type="button"
                  className="text-xs text-slate-400 hover:text-slate-200 transition-colors bg-slate-800 px-2.5 py-1 rounded-md"
                  onClick={() => setPrjSearchTerm('')}
                >
                  Limpiar
                </button>
              )}
            </div>

            {/* In Progress Row */}
            <div className="section-title">
              <span>Auditorías en curso</span>
              <span className="text-xs text-slate-400">
                {activeList.length} {activeList.length === 1 ? 'proyecto' : 'proyectos'}
              </span>
            </div>
            <div className="projects-grid">
              {activeList.length > 0 ? (
                activeList.map((p) => {
                  const donePh = getPhaseDoneCount(p);
                  const entCount = getTotalEntriesCount(p);
                  const pct = Math.round((donePh / PHASES.length) * 100);
                  const dateStr = p.date ? p.date : new Date(p.createdAt).toLocaleDateString('es-AR');

                  return (
                    <motion.div
                      key={p.id}
                      whileHover={{ y: -3 }}
                      className="project-card bg-slate-900/50"
                      onClick={() => {
                        setActiveProjectId(p.id);
                        setActivePhaseId(PHASES[0].id);
                        setViewMode('phase');
                        setIsFormOpen(false);
                      }}
                    >
                      <div className="project-card-top">
                        <div className="flex justify-between items-start gap-4 mb-2">
                          <h3 className="project-card-name text-slate-100 font-semibold">{p.name}</h3>
                          <span className="card-status-badge badge-active text-xs">En curso</span>
                        </div>
                        <p className="project-card-scope text-xs text-slate-400">{p.scope || 'Sin target definido'}</p>
                        {p.auditor && (
                          <div className="text-xs text-slate-400 flex items-center gap-1.5 mt-2.5">
                            <User className="w-3.5 h-3.5 text-slate-500" />
                            <span>{p.auditor}</span>
                          </div>
                        )}
                      </div>
                      <div className="project-card-bottom bg-slate-900/80">
                        <div className="mini-progress">
                          <div
                            className="mini-progress-bar bg-blue-500"
                            style={{ width: `${pct}%` }}
                          />
                        </div>
                        <div className="card-meta text-xs">
                          {pct}% &nbsp;·&nbsp; {entCount} registros
                        </div>
                      </div>
                      <div className="px-[18px] pb-3 flex justify-between text-xs text-slate-500 bg-slate-900/80">
                        <span className="flex items-center gap-1">
                          <Calendar className="w-3 h-3" />
                          {dateStr}
                        </span>
                        <span>{donePh}/6 fases listadas</span>
                      </div>
                    </motion.div>
                  );
                })
              ) : (
                <div className="text-sm text-slate-500 italic py-2 col-span-full">Sin proyectos activos en esta vista.</div>
              )}
            </div>

            {/* Completadas Row */}
            <div className="section-title mt-4">
              <span>Auditorías Completadas</span>
              <span className="text-xs text-slate-400">
                {doneList.length} {doneList.length === 1 ? 'proyecto' : 'proyectos'}
              </span>
            </div>
            <div className="projects-grid">
              {doneList.length > 0 ? (
                doneList.map((p) => {
                  const donePh = getPhaseDoneCount(p);
                  const entCount = getTotalEntriesCount(p);
                  const pct = Math.round((donePh / PHASES.length) * 100);
                  const dateStr = p.date ? p.date : new Date(p.createdAt).toLocaleDateString('es-AR');

                  return (
                    <motion.div
                      key={p.id}
                      whileHover={{ y: -3 }}
                      className="project-card bg-slate-900/50"
                      onClick={() => {
                        setActiveProjectId(p.id);
                        setActivePhaseId(PHASES[0].id);
                        setViewMode('phase');
                        setIsFormOpen(false);
                      }}
                    >
                      <div className="project-card-top">
                        <div className="flex justify-between items-start gap-4 mb-2">
                          <h3 className="project-card-name text-slate-100 font-semibold">{p.name}</h3>
                          <span className="card-status-badge badge-done text-xs">Completada</span>
                        </div>
                        <p className="project-card-scope text-xs text-slate-400">{p.scope || 'Sin target definido'}</p>
                        {p.auditor && (
                          <div className="text-xs text-slate-400 flex items-center gap-1.5 mt-2.5">
                            <User className="w-3.5 h-3.5 text-slate-500" />
                            <span>{p.auditor}</span>
                          </div>
                        )}
                      </div>
                      <div className="project-card-bottom bg-slate-900/80">
                        <div className="mini-progress">
                          <div
                            className="mini-progress-bar bg-emerald-500"
                            style={{ width: `${pct}%` }}
                          />
                        </div>
                        <div className="card-meta text-xs">
                          {pct}% &nbsp;·&nbsp; {entCount} registros
                        </div>
                      </div>
                      <div className="px-[18px] pb-3 flex justify-between text-xs text-slate-500 bg-slate-900/80">
                        <span className="flex items-center gap-1">
                          <Calendar className="w-3 h-3" />
                          {dateStr}
                        </span>
                        <span>{donePh}/6 fases listadas</span>
                      </div>
                    </motion.div>
                  );
                })
              ) : (
                <div className="text-sm text-slate-500 italic py-2 col-span-full">Sin proyectos completados.</div>
              )}
            </div>

            {/* Pendientes Row */}
            <div className="section-title mt-4">
              <span>Pendientes / Sin iniciar</span>
              <span className="text-xs text-slate-400">
                {pendingList.length} {pendingList.length === 1 ? 'proyecto' : 'proyectos'}
              </span>
            </div>
            <div className="projects-grid">
              {pendingList.length > 0 ? (
                pendingList.map((p) => {
                  const donePh = getPhaseDoneCount(p);
                  const entCount = getTotalEntriesCount(p);
                  const pct = Math.round((donePh / PHASES.length) * 100);
                  const dateStr = p.date ? p.date : new Date(p.createdAt).toLocaleDateString('es-AR');

                  return (
                    <motion.div
                      key={p.id}
                      whileHover={{ y: -3 }}
                      className="project-card bg-slate-900/50"
                      onClick={() => {
                        setActiveProjectId(p.id);
                        setActivePhaseId(PHASES[0].id);
                        setViewMode('phase');
                        setIsFormOpen(false);
                      }}
                    >
                      <div className="project-card-top">
                        <div className="flex justify-between items-start gap-4 mb-2">
                          <h3 className="project-card-name text-slate-100 font-semibold">{p.name}</h3>
                          <span className="card-status-badge badge-pending text-xs">Pendiente</span>
                        </div>
                        <p className="project-card-scope text-xs text-slate-400">{p.scope || 'Sin target definido'}</p>
                        {p.auditor && (
                          <div className="text-xs text-slate-400 flex items-center gap-1.5 mt-2.5">
                            <User className="w-3.5 h-3.5 text-slate-500" />
                            <span>{p.auditor}</span>
                          </div>
                        )}
                      </div>
                      <div className="project-card-bottom bg-slate-900/80">
                        <div className="mini-progress">
                          <div
                            className="mini-progress-bar bg-slate-500"
                            style={{ width: `${pct}%` }}
                          />
                        </div>
                        <div className="card-meta text-xs">
                          {pct}% &nbsp;·&nbsp; {entCount} registros
                        </div>
                      </div>
                      <div className="px-[18px] pb-3 flex justify-between text-xs text-slate-500 bg-slate-900/80">
                        <span className="flex items-center gap-1">
                          <Calendar className="w-3 h-3" />
                          {dateStr}
                        </span>
                        <span>{donePh}/6 fases listadas</span>
                      </div>
                    </motion.div>
                  );
                })
              ) : (
                <div className="text-sm text-slate-500 italic py-2 col-span-full">Sin proyectos pendientes.</div>
              )}
            </div>

            {/* Archivados Row */}
            <div className="section-title mt-4">
              <span>Archivadas / Descartadas</span>
              <span className="text-xs text-slate-400">
                {archivedList.length} {archivedList.length === 1 ? 'proyecto' : 'proyectos'}
              </span>
            </div>
            <div className="projects-grid">
              {archivedList.length > 0 ? (
                archivedList.map((p) => {
                  const donePh = getPhaseDoneCount(p);
                  const entCount = getTotalEntriesCount(p);
                  const pct = Math.round((donePh / PHASES.length) * 100);
                  const dateStr = p.date ? p.date : new Date(p.createdAt).toLocaleDateString('es-AR');

                  return (
                    <motion.div
                      key={p.id}
                      whileHover={{ y: -3 }}
                      className="project-card bg-slate-900/50"
                      onClick={() => {
                        setActiveProjectId(p.id);
                        setActivePhaseId(PHASES[0].id);
                        setViewMode('phase');
                        setIsFormOpen(false);
                      }}
                    >
                      <div className="project-card-top">
                        <div className="flex justify-between items-start gap-4 mb-2">
                          <h3 className="project-card-name text-slate-100 font-semibold">{p.name}</h3>
                          <span className="card-status-badge badge-archived text-xs">Archivada</span>
                        </div>
                        <p className="project-card-scope text-xs text-slate-400">{p.scope || 'Sin target definido'}</p>
                        {p.auditor && (
                          <div className="text-xs text-slate-400 flex items-center gap-1.5 mt-2.5">
                            <User className="w-3.5 h-3.5 text-slate-500" />
                            <span>{p.auditor}</span>
                          </div>
                        )}
                      </div>
                      <div className="project-card-bottom bg-slate-900/80">
                        <div className="mini-progress">
                          <div
                            className="mini-progress-bar bg-purple-500"
                            style={{ width: `${pct}%` }}
                          />
                        </div>
                        <div className="card-meta text-xs">
                          {pct}% &nbsp;·&nbsp; {entCount} registros
                        </div>
                      </div>
                      <div className="px-[18px] pb-3 flex justify-between text-xs text-slate-500 bg-slate-900/80">
                        <span className="flex items-center gap-1">
                          <Calendar className="w-3 h-3" />
                          {dateStr}
                        </span>
                        <span>{donePh}/6 fases listadas</span>
                      </div>
                    </motion.div>
                  );
                })
              ) : (
                <div className="text-sm text-slate-500 italic py-2 col-span-full">Sin proyectos archivados.</div>
              )}
            </div>

            {/* Zero Projects State */}
            {projects.length === 0 && (
              <div className="empty-dash py-16 flex flex-col items-center select-none">
                <Shield className="w-16 h-16 text-slate-700 mb-4 stroke-[1.5]" />
                <h3 className="text-lg font-semibold text-slate-300">NetAudit Logbook</h3>
                <p className="text-slate-500 max-w-sm text-sm mt-1 mb-6 text-center">
                  Aún no has creado ninguna auditoría de red. Empieza pulsando el botón superior.
                </p>
                <button className="btn primary" onClick={handleOpenNewProjectModal}>
                  <Plus className="w-4 h-4" />
                  Crear mi primera auditoría
                </button>
              </div>
            )}
          </div>
        </motion.div>
      )}

      {/* ============================= ACTIVE AUDIT VIEW SCREEN ============================= */}
      {activeProjectId && activeProject && (
        <div id="screen-audit" className="flex flex-col flex-1" style={{ display: 'flex' }}>
          <div className="app-header bg-slate-900 border-b border-slate-800">
            <div className="app-header-left">
              <button className="back-btn cursor-pointer" onClick={() => setActiveProjectId(null)} title="Volver al dashboard">
                <ArrowLeft className="w-4 h-4 text-slate-300" />
              </button>
              <div className="project-info">
                <div className="flex items-center gap-2 flex-wrap">
                  <div className="pname text-slate-200 font-semibold">{activeProject.name}</div>
                  {user ? (
                    <span className="flex items-center gap-1 bg-emerald-950/40 text-emerald-400 border border-emerald-900/30 px-1.5 py-0.5 rounded text-[10px] font-medium shrink-0" title="Sincronizado con la nube en vivo">
                      <Cloud className="w-3 h-3 shrink-0" />
                      <span>Nube</span>
                    </span>
                  ) : (
                    <span className="flex items-center gap-1 bg-slate-800/80 text-slate-400 border border-slate-700/60 px-1.5 py-0.5 rounded text-[10px] font-medium shrink-0" title="Guardado localmente en este navegador">
                      <RefreshCw className="w-3 h-3 shrink-0" />
                      <span>Local</span>
                    </span>
                  )}
                </div>
                <div className="pscope text-slate-400">
                  {[activeProject.scope, activeProject.auditor, activeProject.date].filter(Boolean).join(' · ') || 'Sin target definido'}
                </div>
              </div>
            </div>


            <div className="flex gap-2 items-center flex-wrap">
              <button className="btn" onClick={handleOpenEditProjectModal} title="Editar metadatos de la auditoría">
                <Pencil className="w-3.5 h-3.5 text-slate-400 mr-1" />
                Editar
              </button>
              <button
                className={`btn ${viewMode === 'report' ? 'primary' : ''}`}
                onClick={() => setViewMode(viewMode === 'report' ? 'phase' : 'report')}
                title="Ver reporte con todos los registros"
              >
                <BookOpen className="w-3.5 h-3.5 text-slate-400 mr-1" />
                Reporte
              </button>
              <button className="btn green" onClick={exportTxt} title="Exportar reporte de texto estructurado">
                <Download className="w-3.5 h-3.5 text-emerald-400 mr-1" />
                Exportar TXT
              </button>
            </div>
          </div>

          <div className="app-layout flex-1 flex flex-col md:flex-row">
            {/* Nav sidebar of stages */}
            <aside className="sidebar border-r border-slate-800 shrink-0 w-full md:w-[240px] bg-slate-900/40">
              <div className="sidebar-label text-slate-500 font-bold tracking-wider text-[10px]">Fases de Pentesting</div>
              <div id="sidebar-phases" className="space-y-1 my-2">
                {PHASES.map((ph, idx) => {
                  const recordsCount = (activeProject.entries[ph.id] || []).length;
                  const st = activeProject.phaseStatus[ph.id] || 'pending';
                  const isSelected = activePhaseId === ph.id && viewMode === 'phase';

                  return (
                    <div
                      key={ph.id}
                      onClick={() => {
                        setActivePhaseId(ph.id);
                        setViewMode('phase');
                        setIsFormOpen(false);
                      }}
                      className={`phase-item flex items-center justify-between py-2.5 px-4 cursor-pointer transition-all ${
                        isSelected ? 'active bg-slate-800 text-slate-100 border-r-2 border-blue-500' : 'text-slate-400 hover:bg-slate-900/60'
                      }`}
                    >
                      <div className="flex items-center gap-2.5 min-w-0">
                        <span className={`phase-num text-[11px] font-bold ${isSelected ? 'bg-blue-600 border-blue-500 text-white' : 'bg-slate-800 border-slate-700 text-slate-400'}`}>
                          {idx + 1}
                        </span>
                        <span className="truncate text-sm">{ph.short}</span>
                      </div>
                      <div className="flex items-center gap-2">
                        {recordsCount > 0 && (
                          <span className="phase-count bg-slate-950 border border-slate-800 px-2 py-0.5 rounded-full text-[10px] text-slate-400">
                            {recordsCount}
                          </span>
                        )}
                        <span className={`status-dot dot-${st}`} />
                      </div>
                    </div>
                  );
                })}
              </div>

              {/* Progress Panel */}
              <div className="sidebar-progress p-4 border-t border-slate-800">
                <div className="flex justify-between items-center text-xs text-slate-400 mb-1.5">
                  <span className="font-semibold text-slate-400">Completadas</span>
                  <span className="font-mono text-xs">{getPhaseDoneCount(activeProject)}/{PHASES.length}</span>
                </div>
                <div className="prog-bar-outer bg-slate-800">
                  <div
                    className="prog-bar-inner bg-blue-500"
                    style={{ width: `${(getPhaseDoneCount(activeProject) / PHASES.length) * 100}%` }}
                  />
                </div>
              </div>

              {/* General Project Status picker */}
              <div className="p-4 border-t border-slate-800 bg-slate-900/30">
                <div className="text-[11px] text-slate-500 uppercase tracking-wider font-bold mb-2">Estado auditoría</div>
                <select
                  className="status-sel w-full bg-slate-950 border border-slate-800 text-sm text-slate-300"
                  value={activeProject.status}
                  onChange={(e) => setProjectStatus(e.target.value as Project['status'])}
                >
                  <option value="pending">Pendiente</option>
                  <option value="active">En curso</option>
                  <option value="done">Completada</option>
                  <option value="archived">Archivada</option>
                </select>
              </div>
            </aside>

            {/* Main content body */}
            <main className="main-content flex-1 p-6 md:p-8 overflow-y-auto">
              {/* PHASE LOG VIEW */}
              {viewMode === 'phase' && (
                <div>
                  {(() => {
                    const currentPhase = PHASES.find((x) => x.id === activePhaseId)!;
                    const phaseState = activeProject.phaseStatus[currentPhase.id] || 'pending';
                    const phaseEntries = activeProject.entries[currentPhase.id] || [];

                    // Badges matching their stylesheet perfectly
                    const statusClassMap = { pending: 'sb-pending', progress: 'sb-progress', done: 'sb-done' };
                    const statusLabelMap = { pending: 'Pendiente', progress: 'En curso', done: 'Completada' };

                    return (
                      <div className="space-y-6">
                        <div className="phase-header flex justify-between items-start gap-4">
                          <div>
                            <h2 className="phase-name text-slate-100 tracking-tight">{currentPhase.name}</h2>
                            <p className="phase-desc text-slate-400 mt-1">{currentPhase.desc}</p>
                          </div>
                          <div className="phase-controls shrink-0">
                            <span className={`status-badge ${statusClassMap[phaseState]}`}>
                              {statusLabelMap[phaseState]}
                            </span>
                            <select
                              className="status-sel bg-slate-900 border border-slate-800 text-slate-300"
                              value={phaseState}
                              onChange={(e) => updatePhaseStatus(currentPhase.id, e.target.value as any)}
                            >
                              <option value="pending">Pendiente</option>
                              <option value="progress">En curso</option>
                              <option value="done">Completada</option>
                            </select>
                          </div>
                        </div>

                        {/* Record creation form inside phase layout */}
                        {isFormOpen && (
                          <motion.div
                            initial={{ opacity: 0, height: 0 }}
                            animate={{ opacity: 1, height: 'auto' }}
                            className={`add-form bg-slate-900/60 border ${editingEntryId ? 'border-amber-600 edit-mode shadow-amber-950/20 shadow-md' : 'border-slate-700 shadow-md'} rounded-lg p-5`}
                          >
                            <h4 className="add-form-title flex items-center gap-1.5 text-slate-100 font-semibold mb-3">
                              <Terminal className="w-4 h-4 text-blue-400" />
                              {editingEntryId ? 'Editar registro de auditoría' : 'Anotar nuevo registro en bitácora'}
                            </h4>

                            <div className="form-grid">
                              {currentPhase.fields.map((f) => (
                                <div key={f.k} className={`form-group ${f.full ? 'full font-sans' : ''}`}>
                                  <label className="text-slate-400 font-bold text-[10px] tracking-wider">{f.l}</label>
                                  {f.mono ? (
                                    <textarea
                                      id={`nf_${f.k}`}
                                      placeholder={`${f.l}... (admite texto multilínea)`}
                                      value={nfValues[f.k] || ''}
                                      className="bg-slate-950 text-slate-100 border border-slate-800 font-mono text-xs focus:ring-1 focus:ring-blue-500 rounded-md p-2.5 min-h-[90px]"
                                      onChange={(e) => setNfValues((prev) => ({ ...prev, [f.k]: e.target.value }))}
                                    />
                                  ) : (
                                    <input
                                      type="text"
                                      id={`nf_${f.k}`}
                                      placeholder={`${f.l}...`}
                                      value={nfValues[f.k] || ''}
                                      className="bg-slate-950 text-slate-100 border border-slate-800 focus:ring-1 focus:ring-blue-500 rounded-md p-2"
                                      onChange={(e) => setNfValues((prev) => ({ ...prev, [f.k]: e.target.value }))}
                                    />
                                  )}
                                </div>
                              ))}
                            </div>

                            <div className="form-actions mt-4 flex gap-2">
                              <button className="btn primary" onClick={() => handleSaveEntry(currentPhase.id)}>
                                <CheckCircle2 className="w-3.5 h-3.5 mr-1" />
                                {editingEntryId ? 'Guardar cambios' : 'Añadir registro'}
                              </button>
                              <button
                                className="btn"
                                onClick={() => {
                                  setIsFormOpen(false);
                                  setEditingEntryId(null);
                                }}
                              >
                                Cancelar
                              </button>
                            </div>
                          </motion.div>
                        )}

                        {/* "Write a record" trigger button */}
                        {!isFormOpen && (
                          <button className="btn primary py-2 bg-blue-950/30 text-blue-400" onClick={() => handleOpenAddEntry(currentPhase.id)}>
                            <Plus className="w-4 h-4 mr-1.5" />
                            Añadir registro
                          </button>
                        )}

                        {/* Phase records listing with custom Accordions */}
                        <div className="entries space-y-3">
                          {phaseEntries.length > 0 ? (
                            phaseEntries.map((e) => {
                              const headerTitle = e[currentPhase.fields[0].k] || 'Registro sin título';
                              const rawDate = new Date(e.ts);
                              const formattedTs = rawDate.toLocaleDateString('es-AR') + ' ' + rawDate.toLocaleTimeString('es-AR', { hour: '2-digit', minute: '2-digit' });
                              const isExpanded = !!expandedEntries[e.id];

                              return (
                                <div key={e.id} className="entry-card bg-slate-900 border border-slate-800 rounded-lg overflow-hidden">
                                  <div
                                    className="entry-head hover:bg-slate-800/50 p-4 flex items-center justify-between cursor-pointer"
                                    onClick={() => toggleEntryAccordion(e.id)}
                                  >
                                    <div className="entry-left">
                                      <div className="entry-icon bg-slate-950 border border-slate-800">
                                        <FileText className="w-3.5 h-3.5 text-slate-400" />
                                      </div>
                                      <div>
                                        <div className="entry-title font-medium text-slate-200">{headerTitle}</div>
                                        <div className="entry-ts text-slate-500 font-mono text-[10px] mt-0.5">{formattedTs}</div>
                                      </div>
                                    </div>

                                    <div className="entry-right" onClick={(ev) => ev.stopPropagation()}>
                                      {deleteConfirmId === e.id ? (
                                        <div className="flex items-center gap-1.5 bg-slate-950 px-2.5 py-1 rounded border border-red-900/60 shadow-lg animate-fade-in">
                                          <span className="text-[10px] text-red-400 font-bold uppercase tracking-wider mr-1">¿Eliminar?</span>
                                          <button
                                            type="button"
                                            onClick={() => {
                                              handleDeleteEntry(currentPhase.id, e.id);
                                              setDeleteConfirmId(null);
                                            }}
                                            className="px-2 py-0.5 bg-red-950 text-red-400 hover:bg-red-900 hover:text-white rounded text-[10px] font-bold border border-red-800 uppercase tracking-wide transition-colors cursor-pointer"
                                          >
                                            Sí
                                          </button>
                                          <button
                                            type="button"
                                            onClick={() => setDeleteConfirmId(null)}
                                            className="px-2 py-0.5 bg-slate-800 text-slate-300 hover:bg-slate-700 hover:text-white rounded text-[10px] font-semibold border border-slate-700 transition-colors cursor-pointer"
                                          >
                                            No
                                          </button>
                                        </div>
                                      ) : (
                                        <>
                                          <button
                                            type="button"
                                            className="icon-btn"
                                            title="Editar este registro"
                                            onClick={() => handleOpenEditEntry(currentPhase.id, e)}
                                          >
                                            <Pencil className="w-3.5 h-3.5 text-slate-400" />
                                          </button>
                                          <button
                                            type="button"
                                            className="icon-btn del"
                                            title="Eliminar registro"
                                            onClick={() => setDeleteConfirmId(e.id)}
                                          >
                                            <Trash2 className="w-3.5 h-3.5" />
                                          </button>
                                        </>
                                      )}
                                      <ChevronDown
                                        className={`chevron text-slate-400 w-4 h-4 ml-1 transition-transform duration-200 ${isExpanded ? 'open rotate-180 text-blue-500' : ''}`}
                                      />
                                    </div>
                                  </div>

                                  {/* Expandable Accordion Block */}
                                  <AnimatePresence initial={false}>
                                    {isExpanded && (
                                      <motion.div
                                        initial={{ height: 0, opacity: 0 }}
                                        animate={{ height: 'auto', opacity: 1 }}
                                        exit={{ height: 0, opacity: 0 }}
                                        transition={{ duration: 0.15 }}
                                        className="entry-body open bg-slate-950 p-4 border-t border-slate-800/80"
                                      >
                                        <div className="entry-fields grid grid-cols-1 md:grid-cols-2 gap-4">
                                          {currentPhase.fields.map((f) => {
                                            if (!e[f.k]?.trim()) return null;

                                            return (
                                              <div key={f.k} className={`field-block ${f.full ? 'full' : ''}`}>
                                                <div className="flex justify-between items-center mb-1.5">
                                                  <span className="field-label text-slate-500 text-[10px] tracking-wide font-black uppercase">
                                                    {f.l}
                                                  </span>
                                                  {f.mono && (
                                                    <button
                                                      type="button"
                                                      onClick={() => handleCopyText(e[f.k], `${e.id}_${f.k}`)}
                                                      className="text-slate-500 hover:text-blue-400 text-[10px] flex items-center gap-1 bg-slate-900 border border-slate-800 px-1.5 py-0.5 rounded cursor-pointer transition-colors"
                                                    >
                                                      {copiedId === `${e.id}_${f.k}` ? (
                                                        <>
                                                          <Check className="w-3 h-3 text-emerald-400" />
                                                          <span className="text-emerald-400">Copiado</span>
                                                        </>
                                                      ) : (
                                                        <>
                                                          <Copy className="w-3 h-3" />
                                                          <span>Copiar</span>
                                                        </>
                                                      )}
                                                    </button>
                                                  )}
                                                </div>
                                                <div className={`field-val ${f.mono ? 'field-val mono bg-slate-900 border border-slate-800 text-blue-300 font-mono text-sm leading-relaxed p-3 rounded-md shadow-inner select-all' : 'text-sm text-slate-200'}`}>
                                                  {e[f.k]}
                                                </div>
                                              </div>
                                            );
                                          })}
                                        </div>
                                      </motion.div>
                                    )}
                                  </AnimatePresence>
                                </div>
                              );
                            })
                          ) : (
                            <div className="empty-state py-12 text-center text-slate-500 bg-slate-900/10 border border-dashed border-slate-800 rounded-lg">
                              <ListTodo className="w-10 h-10 text-slate-700 mx-auto mb-3" />
                              <p>No se encontraron registros de auditoría en esta fase.</p>
                              <p className="text-xs text-slate-600 mt-1">Inserta un nuevo registro para comenzar.</p>
                            </div>
                          )}
                        </div>
                      </div>
                    );
                  })()}
                </div>
              )}

              {/* CONSOLIDATED REPORT VIEW */}
              {viewMode === 'report' && (
                <motion.div
                  initial={{ opacity: 0 }}
                  animate={{ opacity: 1 }}
                  id="audit-view-report"
                  className="space-y-6"
                >
                  <div className="flex items-center justify-between border-b border-slate-800 pb-3">
                    <div className="font-semibold text-lg text-slate-200 flex items-center gap-1.5">
                      <FileText className="w-5 h-5 text-blue-500" />
                      Reporte consolidado
                    </div>
                    <button className="btn text-xs" onClick={() => setViewMode('phase')}>
                      ← Volver a bitácora por fase
                    </button>
                  </div>

                  <div className="report-header-card bg-slate-900 border border-slate-800 rounded-xl p-6 shadow-md">
                    <h1 className="report-title text-2xl font-bold text-slate-100 tracking-tight">{activeProject.name}</h1>
                    <div className="report-meta-line text-sm text-slate-400 mt-1.5 flex flex-wrap gap-x-4 gap-y-1">
                      {activeProject.scope && <span><strong>Target Scope:</strong> {activeProject.scope}</span>}
                      {activeProject.auditor && <span><strong>Auditor:</strong> {activeProject.auditor}</span>}
                      {activeProject.date && <span><strong>Inicio:</strong> {activeProject.date}</span>}
                      <span><strong>Generado:</strong> {new Date().toLocaleDateString('es-AR')}</span>
                    </div>

                    <div className="text-xs text-slate-500 mt-3 font-mono">
                      {getPhaseDoneCount(activeProject)}/{PHASES.length} fases completadas &nbsp;·&nbsp; {getTotalEntriesCount(activeProject)} registros totales
                    </div>

                    {activeProject.desc && (
                      <div className="text-slate-300 text-xs border-t border-slate-800/80 pt-4 mt-4 leading-relaxed bg-slate-950/40 p-4 rounded-md">
                        <strong className="text-slate-400 block text-[10px] tracking-wider uppercase mb-1">Descripción / Notas generales</strong>
                        {activeProject.desc}
                      </div>
                    )}

                    <div className="report-badges flex flex-wrap gap-2 mt-4 pt-2">
                      {PHASES.map((ph) => {
                        const s = activeProject.phaseStatus[ph.id] || 'pending';
                        let bg = 'bg-slate-800 text-slate-400';
                        let label = '○ Sin iniciar';

                        if (s === 'done') {
                          bg = 'bg-emerald-950/60 text-emerald-400';
                          label = '✓ Completada';
                        } else if (s === 'progress') {
                          bg = 'bg-amber-950/60 text-amber-400';
                          label = '⟳ En curso';
                        }

                        return (
                          <span key={ph.id} className={`text-[10px] px-3 py-1 rounded-full font-semibold ${bg}`}>
                            {ph.short}: {label}
                          </span>
                        );
                      })}
                    </div>
                  </div>

                  {/* Report Search Engine and Filtering */}
                  <div className="report-search-bar bg-slate-900 border border-slate-800 rounded-xl px-4 py-3 flex items-center justify-between gap-3 shadow-md">
                    <div className="flex items-center gap-3 flex-1">
                      <Search className="w-4 h-4 text-blue-500 shrink-0" />
                      <input
                        type="text"
                        placeholder="Filtrar reporte por comando, cve, severidad, herramientas, hallazgo..."
                        className="bg-transparent border-none text-slate-200 placeholder-slate-500 text-sm focus:outline-none w-full"
                        value={reportSearchQuery}
                        onChange={(e) => setReportSearchQuery(e.target.value)}
                      />
                    </div>
                    {reportSearchQuery && (
                      <button
                        type="button"
                        className="text-xs text-slate-400 hover:text-slate-200 transition-colors bg-slate-800 px-2.5 py-1 rounded-md"
                        onClick={() => setReportSearchQuery('')}
                      >
                        Ver todo
                      </button>
                    )}
                  </div>

                  {/* Phases rendering inside the consolidated report */}
                  <div className="space-y-4">
                    {(() => {
                      let totalMatches = 0;
                      const renderedBlocks = PHASES.map((ph) => {
                        const pEntries = activeProject.entries[ph.id] || [];
                        const filteredEntries = pEntries.filter((e) => {
                          if (!reportSearchQuery.trim()) return true;
                          const q = reportSearchQuery.toLowerCase();
                          // Search across all dynamic key-value fields in this entry
                          return ph.fields.some((f) => e[f.k] && String(e[f.k]).toLowerCase().includes(q));
                        });

                        if (reportSearchQuery.trim() && filteredEntries.length === 0) return null;
                        totalMatches += filteredEntries.length;

                        const st = activeProject.phaseStatus[ph.id] || 'pending';

                        // Status line indicator styling
                        let borderCol = 'border-l-slate-700';
                        if (st === 'done') borderCol = 'border-l-emerald-500';
                        if (st === 'progress') borderCol = 'border-l-amber-500';

                        return (
                          <div key={ph.id} className="report-phase-block bg-slate-900 border border-slate-800/80 rounded-xl overflow-hidden shadow-sm">
                            <div className="report-phase-head p-4 bg-slate-900/80 flex items-center justify-between border-b border-slate-800">
                              <span className={`report-phase-name text-sm font-semibold tracking-tight ${borderCol} border-l-[3px] pl-3 text-slate-200`}>
                                {ph.name}
                              </span>
                              <span className="text-xs text-slate-500">
                                {filteredEntries.length} {filteredEntries.length === 1 ? 'registro' : 'registros'}
                              </span>
                            </div>

                            <div className="report-phase-body p-4 bg-slate-950/20">
                              {filteredEntries.length > 0 ? (
                                <div className="space-y-4">
                                  {filteredEntries.map((e, idx) => {
                                    const mainKey = ph.fields[0].k;
                                    return (
                                      <div key={e.id} className="report-entry pl-4 border-l-2 border-slate-800 py-1">
                                        <h4 className="report-entry-title text-sm font-semibold text-slate-100 flex items-center gap-1.5">
                                          <span className="text-slate-600 font-mono text-xs">{idx + 1}.</span>
                                          {e[mainKey] || 'Sin título'}
                                        </h4>

                                        {ph.fields.slice(1).map((f) => {
                                          if (!e[f.k]?.trim()) return null;

                                          return (
                                            <div key={f.k} className="report-entry-row text-xs text-slate-400 mt-1.5 leading-relaxed">
                                              <strong className="text-slate-300 font-semibold">{f.l}:</strong>{' '}
                                              {f.mono ? (
                                                <pre className="bg-slate-950/60 p-2 border border-slate-900/60 text-blue-300 font-mono rounded mt-1 overflow-x-auto text-[11px] select-all leading-normal whitespace-pre-wrap">
                                                  {e[f.k]}
                                                </pre>
                                              ) : (
                                                <span>{e[f.k]}</span>
                                              )}
                                            </div>
                                          );
                                        })}
                                      </div>
                                    );
                                  })}
                                </div>
                              ) : (
                                <div className="text-xs text-slate-500 font-medium italic">No se han anotado registros en esta sección.</div>
                              )}
                            </div>
                          </div>
                        );
                      });

                      if (reportSearchQuery.trim() && totalMatches === 0) {
                        return (
                          <div className="text-center py-10 bg-slate-900 border border-slate-800 rounded-xl space-y-2">
                            <Search className="w-8 h-8 text-slate-600 mx-auto" />
                            <p className="text-sm text-slate-400 font-medium">No se encontraron hallazgos que coincidan con la búsqueda.</p>
                            <button
                              type="button"
                              className="text-xs text-blue-400 hover:underline"
                              onClick={() => setReportSearchQuery('')}
                            >
                              Restablecer búsqueda
                            </button>
                          </div>
                        );
                      }

                      return renderedBlocks;
                    })()}
                  </div>
                </motion.div>
              )}
            </main>
          </div>
        </div>
      )}

      {/* ============================= MODAL: NEW / EDIT PROJECT DIALOG ============================= */}
      <AnimatePresence>
        {showProjectModal && (
          <div className="modal-overlay" style={{ display: 'flex' }}>
            <motion.div
              initial={{ scale: 0.95, opacity: 0 }}
              animate={{ scale: 1, opacity: 1 }}
              exit={{ scale: 0.95, opacity: 0 }}
              transition={{ duration: 0.12 }}
              className="modal select-none bg-slate-900 border border-slate-800 rounded-xl"
            >
              <div className="modal-title flex items-center gap-2 text-slate-100 font-bold">
                <Shield className="w-5 h-5 text-blue-500" />
                <span>{editingProjectMode ? 'Editar auditoría de red' : 'Programar nueva auditoría'}</span>
              </div>

              <div className="form-grid gap-4 mt-3">
                <div className="form-group full">
                  <label className="text-[10px] font-bold text-slate-400 tracking-wider">Nombre de la auditoría / Cliente *</label>
                  <input
                    type="text"
                    placeholder="Ej: Pentest Interno Q2-2026"
                    value={prjForm.name}
                    className="bg-slate-950 text-slate-100 border border-slate-800"
                    onChange={(e) => {
                      setPrjForm({ ...prjForm, name: e.target.value });
                      if (e.target.value.trim()) setPrjFormError(null);
                    }}
                  />
                  {prjFormError && (
                    <div className="flex items-center gap-1 mt-1.5 text-red-400 text-xs font-semibold animate-fade-in">
                      <AlertTriangle className="w-3.5 h-3.5" />
                      <span>{prjFormError}</span>
                    </div>
                  )}
                </div>

                <div className="form-group">
                  <label className="text-[10px] font-bold text-slate-400 tracking-wider">Scope / Target de red</label>
                  <input
                    type="text"
                    placeholder="Ej: 192.168.1.0/24 o *.target.com"
                    value={prjForm.scope}
                    className="bg-slate-950 text-slate-100 border border-slate-800"
                    onChange={(e) => setPrjForm({ ...prjForm, scope: e.target.value })}
                  />
                </div>

                <div className="form-group">
                  <label className="text-[10px] font-bold text-slate-400 tracking-wider">Auditor a cargo</label>
                  <input
                    type="text"
                    placeholder="Ej: Ramón G."
                    value={prjForm.auditor}
                    className="bg-slate-950 text-slate-100 border border-slate-800"
                    onChange={(e) => setPrjForm({ ...prjForm, auditor: e.target.value })}
                  />
                </div>

                <div className="form-group">
                  <label className="text-[10px] font-bold text-slate-400 tracking-wider">Fecha de inicio</label>
                  <input
                    type="date"
                    value={prjForm.date}
                    className="bg-slate-950 text-slate-100 border border-slate-800"
                    onChange={(e) => setPrjForm({ ...prjForm, date: e.target.value })}
                  />
                </div>

                <div className="form-group">
                  <label className="text-[10px] font-bold text-slate-400 tracking-wider">Estado inicial</label>
                  <select
                    className="bg-slate-950 border border-slate-800 text-slate-300"
                    value={prjForm.status}
                    onChange={(e) => setPrjForm({ ...prjForm, status: e.target.value as Project['status'] })}
                  >
                    <option value="pending">Pendiente / Agendada</option>
                    <option value="active">En curso</option>
                    <option value="done">Completada</option>
                    <option value="archived">Archivada</option>
                  </select>
                </div>

                <div className="form-group full">
                  <label className="text-[10px] font-bold text-slate-400 tracking-wider">Descripción / Notas preliminares</label>
                  <textarea
                    placeholder="Ingresa el objetivo general del engagement de pentesting, alcance acordado, o notas cruciales..."
                    value={prjForm.desc}
                    className="bg-slate-950 text-slate-100 border border-slate-800 min-h-[90px]"
                    onChange={(e) => setPrjForm({ ...prjForm, desc: e.target.value })}
                  />
                </div>
              </div>

              <div className="modal-actions mt-6 flex justify-end gap-2.5">
                {editingProjectMode && (
                  confirmDeleteProject ? (
                    <div className="flex items-center gap-2 bg-red-950/20 border border-red-900/60 p-2 rounded-lg mr-auto animate-fade-in">
                      <span className="text-[10px] text-red-400 font-bold uppercase tracking-wide">¿Confirmar eliminación absoluta?</span>
                      <button
                        className="px-2.5 py-1 bg-red-800 hover:bg-red-700 text-white text-xs rounded border border-red-650 font-bold uppercase tracking-wider transition-colors cursor-pointer"
                        onClick={handleDeleteProject}
                      >
                        Sí, eliminar
                      </button>
                      <button
                        className="px-2.5 py-1 bg-slate-800 hover:bg-slate-700 text-slate-300 text-xs rounded border border-slate-700 font-semibold transition-colors cursor-pointer"
                        onClick={() => setConfirmDeleteProject(false)}
                      >
                        No
                      </button>
                    </div>
                  ) : (
                    <button className="btn danger flex items-center mr-auto transition-colors cursor-pointer" onClick={() => setConfirmDeleteProject(true)}>
                      <Trash2 className="w-3.5 h-3.5 mr-1" />
                      Eliminar auditoría
                    </button>
                  )
                )}
                <button className="btn text-xs font-semibold" onClick={() => setShowProjectModal(false)}>
                  Cancelar
                </button>
                <button className="btn primary text-xs" onClick={handleSaveProject}>
                  <CheckCircle2 className="w-3.5 h-3.5 mr-1" />
                  <span>Guardar</span>
                </button>
              </div>
            </motion.div>
          </div>
        )}
      </AnimatePresence>
    </div>
  );
}
