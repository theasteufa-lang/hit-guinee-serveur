import 'dotenv/config';
import express from 'express';
import session from 'express-session';
import connectPgSimple from 'connect-pg-simple';
import { PrismaClient } from '@prisma/client';
import bcrypt from 'bcryptjs';
import helmet from 'helmet';
import cors from 'cors';
import rateLimit from 'express-rate-limit';
import { z } from 'zod';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const prisma = new PrismaClient();
const app = express();
const PgSession = connectPgSimple(session);
const __dirname = path.dirname(fileURLToPath(import.meta.url));
const isProd = process.env.NODE_ENV === 'production';
const origin = process.env.FRONTEND_ORIGIN || 'http://localhost:3000';

if (!process.env.SESSION_SECRET || process.env.SESSION_SECRET.length < 32) {
  throw new Error('SESSION_SECRET doit contenir au moins 32 caractères.');
}
if (!process.env.DATABASE_URL) throw new Error('DATABASE_URL manquant.');

app.set('trust proxy', isProd ? 1 : false);
app.use(helmet({ contentSecurityPolicy: false }));
app.use(cors({ origin, credentials: true }));
app.use(express.json({ limit: '1mb' }));
app.use(session({
  store: new PgSession({ conString: process.env.DATABASE_URL, tableName: 'user_sessions', createTableIfMissing: true }),
  name: 'hit.sid',
  secret: process.env.SESSION_SECRET,
  resave: false,
  saveUninitialized: false,
  cookie: { httpOnly: true, secure: isProd, sameSite: 'lax', maxAge: 1000 * 60 * 60 * 8 }
}));

const loginLimiter = rateLimit({ windowMs: 15 * 60 * 1000, limit: 8, standardHeaders: 'draft-7', legacyHeaders: false });
const asyncRoute = fn => (req, res, next) => Promise.resolve(fn(req, res, next)).catch(next);

async function audit(req, action, detail = '') {
  await prisma.auditLog.create({
    data: { userId: req.session.userId || null, action, detail: String(detail).slice(0, 500),
      ipAddress: req.ip?.slice(0, 80) || null }
  });
}
function requireAuth(req, res, next) {
  if (!req.session.userId) return res.status(401).json({ error: 'Connexion requise.' });
  next();
}
const requireAdmin = asyncRoute(async (req, res, next) => {
  if (!req.session.userId) return res.status(401).json({ error: 'Connexion requise.' });
  const user = await prisma.user.findUnique({ where: { id: req.session.userId }, select: { id: true, role: true, active: true } });
  if (!user || !user.active || user.role !== 'ADMIN') return res.status(403).json({ error: 'Accès administrateur refusé.' });
  req.currentUser = user;
  next();
});

app.get('/api/health', (_req, res) => res.json({ ok: true, service: 'HIT GUINÉE API' }));

app.post('/api/auth/login', loginLimiter, asyncRoute(async (req, res) => {
  const parsed = z.object({ email: z.string().email().max(254), password: z.string().min(1).max(200) }).safeParse(req.body);
  if (!parsed.success) return res.status(400).json({ error: 'Identifiants invalides.' });
  const email = parsed.data.email.toLowerCase().trim();
  const user = await prisma.user.findUnique({ where: { email } });
  const valid = user && user.active && await bcrypt.compare(parsed.data.password, user.passwordHash);
  if (!valid) {
    await audit(req, 'LOGIN_FAILED', `Tentative de connexion pour ${email}`);
    return res.status(401).json({ error: 'E-mail ou mot de passe incorrect.' });
  }
  await new Promise((resolve, reject) => req.session.regenerate(err => err ? reject(err) : resolve()));
  req.session.userId = user.id;
  await audit(req, 'LOGIN_SUCCESS', `Rôle ${user.role}`);
  res.json({ user: { id: user.id, email: user.email, firstName: user.firstName, lastName: user.lastName, role: user.role } });
}));

app.post('/api/auth/logout', requireAuth, asyncRoute(async (req, res) => {
  await audit(req, 'LOGOUT');
  req.session.destroy(() => res.clearCookie('hit.sid').json({ ok: true }));
}));

app.get('/api/auth/me', requireAuth, asyncRoute(async (req, res) => {
  const user = await prisma.user.findUnique({ where: { id: req.session.userId },
    select: { id: true, email: true, phone: true, firstName: true, lastName: true, role: true, active: true } });
  if (!user || !user.active) return res.status(401).json({ error: 'Session invalide.' });
  res.json({ user });
}));

app.get('/api/admin/overview', requireAdmin, asyncRoute(async (_req, res) => {
  const [users, artists, tasks, contracts, recentLogs] = await Promise.all([
    prisma.user.count(), prisma.user.count({ where: { role: 'ARTIST' } }),
    prisma.adminTask.count({ where: { status: { not: 'DONE' } } }),
    prisma.artistContract.count(),
    prisma.auditLog.findMany({ take: 20, orderBy: { createdAt: 'desc' }, include: { user: { select: { email: true, role: true } } } })
  ]);
  res.json({ users, artists, openTasks: tasks, contracts, recentLogs });
}));

app.get('/api/admin/tasks', requireAdmin, asyncRoute(async (_req, res) => {
  res.json(await prisma.adminTask.findMany({ orderBy: [{ status: 'asc' }, { createdAt: 'asc' }] }));
}));
app.patch('/api/admin/tasks/:id', requireAdmin, asyncRoute(async (req, res) => {
  const parsed = z.object({ status: z.enum(['TODO','IN_PROGRESS','BLOCKED','DONE']), ownerNote: z.string().max(1000).optional() }).safeParse(req.body);
  if (!parsed.success) return res.status(400).json({ error: 'Modification invalide.' });
  const task = await prisma.adminTask.update({ where: { id: req.params.id }, data: parsed.data });
  await audit(req, 'ADMIN_TASK_UPDATED', `${task.title}: ${task.status}`);
  res.json(task);
}));
app.get('/api/admin/contracts', requireAdmin, asyncRoute(async (_req, res) => {
  res.json(await prisma.artistContract.findMany({ orderBy: { createdAt: 'desc' } }));
}));
app.post('/api/admin/contracts', requireAdmin, asyncRoute(async (req, res) => {
  const parsed = z.object({
    artistName: z.string().min(2).max(120), artistEmail: z.string().email().optional().or(z.literal('')),
    terms: z.string().min(20).max(12000)
  }).safeParse(req.body);
  if (!parsed.success) return res.status(400).json({ error: 'Informations du contrat incomplètes.' });
  const contract = await prisma.artistContract.create({ data: {
    artistName: parsed.data.artistName, artistEmail: parsed.data.artistEmail || null, terms: parsed.data.terms
  }});
  await audit(req, 'ARTIST_CONTRACT_DRAFT_CREATED', parsed.data.artistName);
  res.status(201).json(contract);
}));
app.get('/api/admin/audit', requireAdmin, asyncRoute(async (_req, res) => {
  res.json(await prisma.auditLog.findMany({ take: 100, orderBy: { createdAt: 'desc' }, include: { user: { select: { email: true, role: true } } } }));
}));

// Le serveur sert l'écran web de démarrage sur la même origine.
app.use(express.static(path.resolve(__dirname, '../../web')));
app.get('*path', (_req, res) => res.sendFile(path.resolve(__dirname, '../../web/index.html')));

app.use((err, _req, res, _next) => {
  console.error(err);
  res.status(500).json({ error: 'Erreur serveur. Consulte les journaux techniques.' });
});

const port = Number(process.env.PORT || 3000);
app.listen(port, () => console.log(`HIT GUINÉE serveur prêt sur le port ${port}`));
