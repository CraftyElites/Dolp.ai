/**
 * Dolphine – HTML → APK / AAB / IPA
 * Minimal, robust, JSON-DB, Expo + GitHub Actions ready
 *
 * Local build: tries EAS local when EXPO_TOKEN is set; on failure falls back to
 * expo prebuild + Gradle (assembleRelease / bundleRelease).
 */
const path = require('path');
const fs = require('fs');

// Load secrets from .env (no extra dependency)
(function loadEnv() {
  const envPath = path.join(__dirname, '.env');
  if (!fs.existsSync(envPath)) return;
  const lines = fs.readFileSync(envPath, 'utf8').split(/\r?\n/);
  for (const line of lines) {
    const trimmed = line.trim();
    if (!trimmed || trimmed.startsWith('#')) continue;
    const eq = trimmed.indexOf('=');
    if (eq === -1) continue;
    const key = trimmed.slice(0, eq).trim();
    let val = trimmed.slice(eq + 1).trim();
    if ((val.startsWith('"') && val.endsWith('"')) || (val.startsWith("'") && val.endsWith("'"))) {
      val = val.slice(1, -1);
    }
    if (!(key in process.env)) process.env[key] = val;
  }
})();

const express = require('express');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const multer = require('multer');
const AdmZip = require('adm-zip');
const { v4: uuidv4 } = require('uuid');
const cors = require('cors');

const app = express();
const PORT = process.env.PORT || 3847;
const JWT_SECRET = process.env.JWT_SECRET || 'dolphine-secret-change-me-in-prod';
const DATA_DIR = path.join(__dirname, 'data');
const USERS_DIR = path.join(DATA_DIR, 'users');
const DB_FILE = path.join(DATA_DIR, 'db.json');
const BUILDS_DIR = path.join(DATA_DIR, 'builds');

// Ensure dirs
[DATA_DIR, USERS_DIR, BUILDS_DIR].forEach(d => {
  if (!fs.existsSync(d)) fs.mkdirSync(d, { recursive: true });
});

// ---------- JSON DB ----------
function loadDB() {
  if (!fs.existsSync(DB_FILE)) {
    const init = { users: [], projects: [], builds: [] };
    fs.writeFileSync(DB_FILE, JSON.stringify(init, null, 2));
    return init;
  }
  return JSON.parse(fs.readFileSync(DB_FILE, 'utf8'));
}
function saveDB(db) {
  fs.writeFileSync(DB_FILE, JSON.stringify(db, null, 2));
}

// ---------- Middleware ----------
app.use(cors());
app.use(express.json({ limit: '10mb' }));
app.use(express.urlencoded({ extended: true }));
app.use(express.static(path.join(__dirname, 'public')));

// Auth middleware
function auth(req, res, next) {
  const header = req.headers.authorization;
  if (!header || !header.startsWith('Bearer ')) {
    return res.status(401).json({ error: 'Unauthorized' });
  }
  try {
    const token = header.slice(7);
    req.user = jwt.verify(token, JWT_SECRET);
    next();
  } catch {
    return res.status(401).json({ error: 'Invalid token' });
  }
}

// Multer for file uploads
const storage = multer.diskStorage({
  destination: (req, file, cb) => {
    const tmp = path.join(DATA_DIR, 'tmp');
    if (!fs.existsSync(tmp)) fs.mkdirSync(tmp, { recursive: true });
    cb(null, tmp);
  },
  filename: (req, file, cb) => cb(null, `${Date.now()}-${file.originalname}`)
});
const upload = multer({
  storage,
  limits: { fileSize: 50 * 1024 * 1024 } // 50MB
});

// ---------- Auth Routes ----------
app.post('/api/register', async (req, res) => {
  try {
    const { email, password, name } = req.body;
    if (!email || !password || password.length < 6) {
      return res.status(400).json({ error: 'Email and password (min 6) required' });
    }
    const db = loadDB();
    if (db.users.find(u => u.email.toLowerCase() === email.toLowerCase())) {
      return res.status(400).json({ error: 'Email already registered' });
    }
    const id = uuidv4();
    const hash = await bcrypt.hash(password, 10);
    const user = {
      id,
      email: email.toLowerCase(),
      name: name || email.split('@')[0],
      password: hash,
      createdAt: new Date().toISOString()
    };
    db.users.push(user);
    saveDB(db);

    // Create user project root
    const userDir = path.join(USERS_DIR, id);
    fs.mkdirSync(userDir, { recursive: true });

    const token = jwt.sign({ id: user.id, email: user.email }, JWT_SECRET, { expiresIn: '7d' });
    res.json({
      token,
      user: { id: user.id, email: user.email, name: user.name }
    });
  } catch (e) {
    console.error(e);
    res.status(500).json({ error: 'Registration failed' });
  }
});

app.post('/api/login', async (req, res) => {
  try {
    const { email, password } = req.body;
    const db = loadDB();
    const user = db.users.find(u => u.email.toLowerCase() === (email || '').toLowerCase());
    if (!user || !(await bcrypt.compare(password || '', user.password))) {
      return res.status(401).json({ error: 'Invalid credentials' });
    }
    const token = jwt.sign({ id: user.id, email: user.email }, JWT_SECRET, { expiresIn: '7d' });
    res.json({
      token,
      user: { id: user.id, email: user.email, name: user.name }
    });
  } catch (e) {
    res.status(500).json({ error: 'Login failed' });
  }
});

app.get('/api/me', auth, (req, res) => {
  const db = loadDB();
  const user = db.users.find(u => u.id === req.user.id);
  if (!user) return res.status(404).json({ error: 'User not found' });
  res.json({ id: user.id, email: user.email, name: user.name });
});

// ---------- Project Routes ----------
app.get('/api/projects', auth, (req, res) => {
  const db = loadDB();
  const projects = db.projects.filter(p => p.userId === req.user.id);
  res.json(projects);
});

app.post('/api/projects', auth, (req, res) => {
  try {
    const { name, description } = req.body;
    if (!name || !name.trim()) return res.status(400).json({ error: 'Name required' });
    const db = loadDB();
    const id = uuidv4();
    const projectDir = path.join(USERS_DIR, req.user.id, id);
    fs.mkdirSync(projectDir, { recursive: true });

    const project = {
      id,
      userId: req.user.id,
      name: name.trim(),
      description: description || '',
      config: {
        name: name.trim(),
        slug: name.trim().toLowerCase().replace(/[^a-z0-9]+/g, '-').replace(/^-|-$/g, ''),
        version: '1.0.0',
        orientation: 'portrait',
        icon: 'logo.png',
        splash: { image: 'logo.png', resizeMode: 'contain', backgroundColor: '#0f172a' },
        android: { package: `com.dolphine.${id.slice(0, 8)}`, versionCode: 1 },
        ios: { bundleIdentifier: `com.dolphine.${id.slice(0, 8)}`, buildNumber: '1' },
        web: { bundler: 'metro' },
        extra: {}
      },
      files: [],
      createdAt: new Date().toISOString(),
      updatedAt: new Date().toISOString()
    };
    db.projects.push(project);
    saveDB(db);
    res.json(project);
  } catch (e) {
    console.error(e);
    res.status(500).json({ error: 'Create project failed' });
  }
});

app.get('/api/projects/:id', auth, (req, res) => {
  const db = loadDB();
  const project = db.projects.find(p => p.id === req.params.id && p.userId === req.user.id);
  if (!project) return res.status(404).json({ error: 'Project not found' });
  res.json(project);
});

app.put('/api/projects/:id', auth, (req, res) => {
  const db = loadDB();
  const idx = db.projects.findIndex(p => p.id === req.params.id && p.userId === req.user.id);
  if (idx === -1) return res.status(404).json({ error: 'Project not found' });
  const { name, description, config } = req.body;
  if (name) db.projects[idx].name = name;
  if (description !== undefined) db.projects[idx].description = description;
  if (config) db.projects[idx].config = { ...db.projects[idx].config, ...config };
  db.projects[idx].updatedAt = new Date().toISOString();
  saveDB(db);
  res.json(db.projects[idx]);
});

app.delete('/api/projects/:id', auth, (req, res) => {
  const db = loadDB();
  const idx = db.projects.findIndex(p => p.id === req.params.id && p.userId === req.user.id);
  if (idx === -1) return res.status(404).json({ error: 'Project not found' });
  const projectDir = path.join(USERS_DIR, req.user.id, req.params.id);
  if (fs.existsSync(projectDir)) fs.rmSync(projectDir, { recursive: true, force: true });
  db.projects.splice(idx, 1);
  // Also clean builds
  db.builds = db.builds.filter(b => b.projectId !== req.params.id);
  saveDB(db);
  res.json({ ok: true });
});

// ---------- File Upload (ZIP or single) ----------
app.post('/api/projects/:id/upload', auth, (req, res, next) => {
  upload.single('file')(req, res, (err) => {
    if (err) {
      console.error('Multer error:', err);
      return res.status(400).json({ error: 'Upload error: ' + (err.message || 'file rejected') });
    }
    next();
  });
}, (req, res) => {
  try {
    const db = loadDB();
    const project = db.projects.find(p => p.id === req.params.id && p.userId === req.user.id);
    if (!project) return res.status(404).json({ error: 'Project not found' });

    const projectDir = path.join(USERS_DIR, req.user.id, project.id);
    if (!fs.existsSync(projectDir)) fs.mkdirSync(projectDir, { recursive: true });

    const file = req.file;
    if (!file) return res.status(400).json({ error: 'No file uploaded' });

    const isZip = file.originalname.toLowerCase().endsWith('.zip') ||
                  file.mimetype === 'application/zip' ||
                  file.mimetype === 'application/x-zip-compressed';

    if (isZip) {
      const zip = new AdmZip(file.path);
      const entries = zip.getEntries();
      entries.forEach(entry => {
        if (entry.isDirectory) return;
        const safeName = path.normalize(entry.entryName).replace(/^(\.\.[/\\])+/, '');
        if (safeName.includes('..')) return;
        const dest = path.join(projectDir, safeName);
        const destDir = path.dirname(dest);
        if (!fs.existsSync(destDir)) fs.mkdirSync(destDir, { recursive: true });
        fs.writeFileSync(dest, entry.getData());
      });
      project.files = listFiles(projectDir);
    } else {
      const dest = path.join(projectDir, file.originalname);
      fs.renameSync(file.path, dest);
      project.files = listFiles(projectDir);
    }

    // Cleanup tmp
    try { if (fs.existsSync(file.path)) fs.unlinkSync(file.path); } catch (_) {}

    project.updatedAt = new Date().toISOString();
    saveDB(db);
    res.json({ ok: true, files: project.files, project });
  } catch (e) {
    console.error('Upload handler error:', e);
    res.status(500).json({ error: 'Upload failed: ' + e.message });
  }
});

function listFiles(dir, base = '') {
  let results = [];
  if (!fs.existsSync(dir)) return results;
  const items = fs.readdirSync(dir);
  for (const item of items) {
    const full = path.join(dir, item);
    const rel = path.join(base, item).replace(/\\/g, '/');
    if (fs.statSync(full).isDirectory()) {
      results = results.concat(listFiles(full, rel));
    } else {
      results.push(rel);
    }
  }
  return results;
}

// Serve project files (for preview)
app.get('/api/projects/:id/files/*', auth, (req, res) => {
  const db = loadDB();
  const project = db.projects.find(p => p.id === req.params.id && p.userId === req.user.id);
  if (!project) return res.status(404).json({ error: 'Not found' });
  const rel = req.params[0];
  const filePath = path.join(USERS_DIR, req.user.id, project.id, rel);
  if (!filePath.startsWith(path.join(USERS_DIR, req.user.id, project.id))) {
    return res.status(403).json({ error: 'Forbidden' });
  }
  if (!fs.existsSync(filePath) || fs.statSync(filePath).isDirectory()) {
    return res.status(404).json({ error: 'File not found' });
  }
  res.sendFile(filePath);
});

// Rename a file inside a project
app.post('/api/projects/:id/rename', auth, (req, res) => {
  try {
    const { from, to } = req.body;
    if (!from || !to) return res.status(400).json({ error: 'from and to required' });
    const db = loadDB();
    const project = db.projects.find(p => p.id === req.params.id && p.userId === req.user.id);
    if (!project) return res.status(404).json({ error: 'Project not found' });

    const projectDir = path.join(USERS_DIR, req.user.id, project.id);
    const src = path.join(projectDir, from);
    const dest = path.join(projectDir, to);

    // Security
    if (!src.startsWith(projectDir) || !dest.startsWith(projectDir)) {
      return res.status(403).json({ error: 'Forbidden path' });
    }
    if (!fs.existsSync(src)) return res.status(404).json({ error: 'Source file not found' });
    if (fs.existsSync(dest)) return res.status(400).json({ error: 'Target already exists' });

    const destDir = path.dirname(dest);
    if (!fs.existsSync(destDir)) fs.mkdirSync(destDir, { recursive: true });
    fs.renameSync(src, dest);

    project.files = listFiles(projectDir);
    project.updatedAt = new Date().toISOString();
    saveDB(db);
    res.json({ ok: true, files: project.files, project });
  } catch (e) {
    console.error(e);
    res.status(500).json({ error: 'Rename failed: ' + e.message });
  }
});

// Delete a file inside a project
app.post('/api/projects/:id/delete-file', auth, (req, res) => {
  try {
    const { path: relPath } = req.body;
    if (!relPath) return res.status(400).json({ error: 'path required' });
    const db = loadDB();
    const project = db.projects.find(p => p.id === req.params.id && p.userId === req.user.id);
    if (!project) return res.status(404).json({ error: 'Project not found' });

    const projectDir = path.join(USERS_DIR, req.user.id, project.id);
    const target = path.join(projectDir, relPath);
    if (!target.startsWith(projectDir)) return res.status(403).json({ error: 'Forbidden' });
    if (!fs.existsSync(target)) return res.status(404).json({ error: 'File not found' });

    fs.unlinkSync(target);
    project.files = listFiles(projectDir);
    project.updatedAt = new Date().toISOString();
    saveDB(db);
    res.json({ ok: true, files: project.files, project });
  } catch (e) {
    res.status(500).json({ error: 'Delete failed: ' + e.message });
  }
});

// ---------- Build helpers ----------
function appendLog(buildId, line) {
  const db = loadDB();
  const b = db.builds.find(x => x.id === buildId);
  if (!b) return;
  if (!b.logs) b.logs = [];
  const entry = `[${new Date().toISOString().slice(11, 19)}] ${line}`;
  b.logs.push(entry);
  // Keep last 400 lines
  if (b.logs.length > 400) b.logs = b.logs.slice(-400);
  b.message = line;
  saveDB(db);
}

function updateBuild(buildId, patch) {
  const db = loadDB();
  const idx = db.builds.findIndex(x => x.id === buildId);
  if (idx === -1) return null;
  db.builds[idx] = { ...db.builds[idx], ...patch, updatedAt: new Date().toISOString() };
  saveDB(db);
  return db.builds[idx];
}

const { exec } = require('child_process');
const { promisify } = require('util');
const execAsync = promisify(exec);

function sleep(ms) {
  return new Promise(r => setTimeout(r, ms));
}

// Find a Java 17 (or 11/21) JDK on this machine, since Gradle for RN/Expo
// builds chokes on very new JDKs (e.g. "Unsupported class file major version 69" = JDK 25).
// Codespaces / Ubuntu images commonly install Temurin under /usr/lib/jvm.
function findCompatibleJavaHome() {
  if (process.env.GRADLE_JAVA_HOME && fs.existsSync(process.env.GRADLE_JAVA_HOME)) {
    return process.env.GRADLE_JAVA_HOME;
  }
  const candidates = [
    // Preferred order: 17 first (Expo/RN default target), then 11, then 21
    '/usr/lib/jvm/temurin-17-jdk-amd64',
    '/usr/lib/jvm/java-17-openjdk-amd64',
    '/usr/lib/jvm/temurin-11-jdk-amd64',
    '/usr/lib/jvm/java-11-openjdk-amd64',
    '/usr/lib/jvm/temurin-21-jdk-amd64',
    '/usr/lib/jvm/java-21-openjdk-amd64'
  ];
  for (const dir of candidates) {
    if (fs.existsSync(path.join(dir, 'bin', 'java'))) return dir;
  }
  // Fallback: scan /usr/lib/jvm for anything named 17/11/21
  try {
    const jvmRoot = '/usr/lib/jvm';
    if (fs.existsSync(jvmRoot)) {
      const entries = fs.readdirSync(jvmRoot);
      const preferred = ['17', '11', '21'];
      for (const ver of preferred) {
        const match = entries.find(e => e.includes(`-${ver}-`) || e.includes(`${ver}.0`));
        if (match && fs.existsSync(path.join(jvmRoot, match, 'bin', 'java'))) {
          return path.join(jvmRoot, match);
        }
      }
    }
  } catch (_) {}
  return null; // none found — caller should warn and fall back to system default
}

// Find the Android SDK, checking env vars first, then common install
// locations — so builds don't silently break just because ANDROID_HOME
// wasn't exported into the process that's running the Node server
// (e.g. server started before .bashrc was sourced, or from a different shell/session).
function findAndroidSdkHome() {
  const envCandidates = [process.env.ANDROID_HOME, process.env.ANDROID_SDK_ROOT].filter(Boolean);
  for (const dir of envCandidates) {
    if (fs.existsSync(dir)) return dir;
  }
  const pathCandidates = [
    path.join(process.env.HOME || '', 'android-sdk'),      // setup-android-sdk.sh default
    path.join(process.env.HOME || '', 'Android', 'Sdk'),   // Android Studio default on Linux
    '/usr/local/lib/android/sdk',                            // common devcontainer feature default
    '/opt/android-sdk'
  ];
  for (const dir of pathCandidates) {
    if (dir && fs.existsSync(dir) && fs.existsSync(path.join(dir, 'platform-tools'))) {
      return dir;
    }
  }
  return null;
}

async function runCmd(buildId, cmd, cwd, env = {}) {
  appendLog(buildId, `$ ${cmd}`);
  try {
    const { stdout, stderr } = await execAsync(cmd, {
      cwd,
      env: { ...process.env, ...env },
      maxBuffer: 10 * 1024 * 1024,
      timeout: 15 * 60 * 1000
    });
    const out = (stdout || '').trim();
    const err = (stderr || '').trim();
    if (out) out.split('\n').slice(-30).forEach(l => appendLog(buildId, l));
    if (err) err.split('\n').slice(-15).forEach(l => appendLog(buildId, l));
    return { stdout: out, stderr: err };
  } catch (e) {
    const out = (e.stdout || '').toString().trim();
    const err = (e.stderr || '').toString().trim();
    if (out) out.split('\n').slice(-20).forEach(l => appendLog(buildId, l));
    if (err) err.split('\n').slice(-20).forEach(l => appendLog(buildId, l));
    throw e;
  }
}

// Poll Expo GraphQL for build status (using EXPO_TOKEN)
// NOTE: Expo's schema has no root `builds(filter:)` list — a single build is
// fetched via `builds { byId(buildId: $id) }`. The old query silently returned
// { data: { builds: null }, errors: [...] }, which made every poll look like
// "still queued" until the deadline expired.
async function pollExpoBuild(buildId, expoBuildId, expoToken, maxMinutes = 25) {
  const deadline = Date.now() + maxMinutes * 60 * 1000;
  appendLog(buildId, `Polling Expo build ${expoBuildId}…`);

  let lastStatus = null;
  let graphqlBroken = false;

  const pickUrl = (b) =>
    b?.artifacts?.applicationArchiveUrl ||
    b?.artifacts?.buildUrl ||
    b?.artifacts?.url ||
    null;

  // Fallback: ask eas-cli directly. Slower, but immune to schema drift.
  async function viaCli() {
    try {
      const { stdout } = await execAsync(
        `npx --yes eas-cli@latest build:view ${expoBuildId} --json --non-interactive`,
        { env: { ...process.env, EXPO_TOKEN: expoToken }, maxBuffer: 1024 * 1024 * 20 }
      );
      const match = stdout.match(/\{[\s\S]*\}/);
      return match ? JSON.parse(match[0]) : null;
    } catch (e) {
      appendLog(buildId, 'build:view failed: ' + (e.message || String(e)).slice(0, 160));
      return null;
    }
  }

  while (Date.now() < deadline) {
    let b = null;

    if (!graphqlBroken) {
      try {
        const res = await fetch('https://api.expo.dev/graphql', {
          method: 'POST',
          headers: {
            'Content-Type': 'application/json',
            Authorization: `Bearer ${expoToken}`
          },
          body: JSON.stringify({
            query: `query($id: ID!) {
              builds {
                byId(buildId: $id) {
                  id
                  status
                  platform
                  artifacts { buildUrl applicationArchiveUrl }
                  app { name }
                }
              }
            }`,
            variables: { id: expoBuildId }
          })
        });
        const json = await res.json();
        if (json?.errors?.length) {
          appendLog(
            buildId,
            'Expo GraphQL error: ' + String(json.errors[0].message || '').slice(0, 200)
          );
          graphqlBroken = true;
          appendLog(buildId, 'Falling back to eas-cli build:view for status.');
        }
        b = json?.data?.builds?.byId || null;
      } catch (e) {
        appendLog(buildId, 'Poll error: ' + (e.message || String(e)).slice(0, 120));
      }
    }

    if (!b) b = await viaCli();

    if (!b) {
      appendLog(buildId, 'Waiting for Expo build…');
    } else {
      const status = String(b.status || '').toUpperCase();
      if (status !== lastStatus) {
        appendLog(buildId, `Expo status: ${status}`);
        lastStatus = status;
      }
      if (status === 'FINISHED') {
        const url = pickUrl(b);
        if (!url) appendLog(buildId, 'Build finished but no artifact URL was returned.');
        return { status: 'success', url, raw: b };
      }
      if (status === 'ERRORED' || status === 'CANCELED') {
        return { status: 'failed', url: null, raw: b };
      }
    }

    await sleep(20000);
  }
  appendLog(buildId, `Stopped polling after ${maxMinutes} min — check the Expo build page.`);
  return { status: 'timeout', url: null };
}

// Find APK/AAB produced by a local build
function findLocalBinaries(dir) {
  const found = [];
  function walk(d) {
    if (!fs.existsSync(d)) return;
    for (const name of fs.readdirSync(d)) {
      const full = path.join(d, name);
      let st;
      try { st = fs.statSync(full); } catch { continue; }
      if (st.isDirectory()) {
        if (name === 'node_modules' || name === '.git') continue;
        walk(full);
      } else if (/\.(apk|aab)$/i.test(name)) {
        found.push(full);
      }
    }
  }
  walk(dir);
  return found;
}

/**
 * Local Gradle path: expo prebuild → write local.properties → assemble/bundleRelease.
 * Hardened for low-RAM (Codespaces): --no-daemon, capped JVM heap, NODE_ENV=production.
 */
async function runLocalGradleBuild(buildId, buildDir, profile) {
  appendLog(buildId, 'Using expo prebuild + Gradle…');
  await runCmd(buildId, 'npx --yes expo prebuild --platform android --no-install', buildDir, {
    EAS_NO_VCS: '1',
    CI: '1',
    NODE_ENV: 'production'
  });

  // Copy www into Android assets so file:///android_asset/www works as a fallback path
  try {
    const srcWww = path.join(buildDir, 'assets', 'www');
    const destWww = path.join(buildDir, 'android', 'app', 'src', 'main', 'assets', 'www');
    if (fs.existsSync(srcWww)) {
      fs.mkdirSync(path.dirname(destWww), { recursive: true });
      copyDir(srcWww, destWww);
      appendLog(buildId, 'Copied www → android/app/src/main/assets/www');
    }
  } catch (copyErr) {
    appendLog(buildId, 'www→android assets copy note: ' + (copyErr.message || '').slice(0, 120));
  }

  const androidDir = path.join(buildDir, 'android');
  if (!fs.existsSync(androidDir)) {
    throw new Error('android/ folder missing after prebuild');
  }

  const gradlew = path.join(androidDir, 'gradlew');
  if (fs.existsSync(gradlew)) {
    try { fs.chmodSync(gradlew, 0o755); } catch (_) {}
  }

  const androidHome = findAndroidSdkHome();
  if (androidHome && fs.existsSync(androidHome)) {
    fs.writeFileSync(
      path.join(androidDir, 'local.properties'),
      `sdk.dir=${androidHome.replace(/\\/g, '/')}\n`
    );
    appendLog(buildId, `Using Android SDK at ${androidHome}.`);
  } else {
    appendLog(buildId, '❌ No Android SDK found (ANDROID_HOME/ANDROID_SDK_ROOT not set or path missing). Run setup-android-sdk.sh once, then retry.');
    throw new Error('Android SDK not configured (ANDROID_HOME/ANDROID_SDK_ROOT missing).');
  }

  // Cap Gradle memory + disable daemon — prevents "daemon disappeared" OOM on Codespaces.
  const gradlePropsPath = path.join(androidDir, 'gradle.properties');
  let gradleProps = '';
  try {
    if (fs.existsSync(gradlePropsPath)) gradleProps = fs.readFileSync(gradlePropsPath, 'utf8');
  } catch (_) {}
  if (!gradleProps.includes('org.gradle.daemon=false')) {
    fs.writeFileSync(
      gradlePropsPath,
      gradleProps.trimEnd() +
        '\n\n# Dolphine local-build (low-RAM safe)\n' +
        'org.gradle.daemon=false\n' +
        'org.gradle.jvmargs=-Xmx1536m -XX:MaxMetaspaceSize=384m -XX:+HeapDumpOnOutOfMemoryError -Dfile.encoding=UTF-8\n' +
        'org.gradle.parallel=false\n' +
        'org.gradle.workers.max=1\n' +
        // org.gradle.daemon=false only kills the *main* Gradle daemon. The Kotlin
        // compiler and R8/dex still spawn their own separate JVMs by default,
        // which is what actually gets OOM-killed on low-RAM machines (Gradle then
        // misreports it as "daemon disappeared"). Forcing Kotlin in-process avoids
        // spawning that extra JVM.
        'kotlin.compiler.execution.strategy=in-process\n' +
        'kotlin.incremental=false\n'
    );
    appendLog(buildId, 'Wrote low-RAM Gradle settings (no-daemon, 1.5g heap).');
  }

  const gradleCmd = profile === 'production'
    ? './gradlew app:bundleRelease --no-daemon --stacktrace'
    : './gradlew app:assembleRelease --no-daemon --stacktrace';

  const javaHome = findCompatibleJavaHome();
  const gradleEnv = {
    ANDROID_HOME: androidHome,
    ANDROID_SDK_ROOT: androidHome,
    NODE_ENV: 'production',
    GRADLE_OPTS: '-Dorg.gradle.daemon=false'
  };
  if (javaHome) {
    appendLog(buildId, `Using JDK at ${javaHome} for Gradle (avoids "Unsupported class file" errors on newer default JDKs).`);
    gradleEnv.JAVA_HOME = javaHome;
    gradleEnv.PATH = `${javaHome}/bin:${androidHome}/platform-tools:${process.env.PATH || ''}`;
  } else {
    appendLog(buildId, '⚠️ No JDK 17/11/21 found under /usr/lib/jvm — using system default Java. If the build fails with "Unsupported class file major version", install JDK 17 (setup-jdk17.sh) and re-run.');
  }

  appendLog(buildId, `Running ${gradleCmd}…`);
  await runCmd(buildId, gradleCmd, androidDir, gradleEnv);
}

// Background build runner (survives page leave)
async function runBuildPipeline(buildId) {
  const db = loadDB();
  const build = db.builds.find(b => b.id === buildId);
  if (!build) return;

  try {
    updateBuild(buildId, { status: 'queued' });
    appendLog(buildId, 'Build queued…');
    await sleep(400);
    updateBuild(buildId, { status: 'building' });
    appendLog(buildId, 'Preparing Expo project…');

    const projectDir = path.join(USERS_DIR, build.userId, build.projectId);
    const buildDir = path.join(BUILDS_DIR, buildId);

    if (!fs.existsSync(path.join(buildDir, 'package.json'))) {
      const project = db.projects.find(p => p.id === build.projectId);
      await generateExpoProject(buildDir, project, projectDir);
    }
    appendLog(buildId, 'Expo project ready (WebView + assets).');

    const zipPath = path.join(BUILDS_DIR, `${buildId}-bundle.zip`);
    const zip = new AdmZip();
    zip.addLocalFolder(buildDir);
    zip.writeZip(zipPath);

    const ghToken = (process.env.GITHUB_TOKEN || '').trim();
    // GITHUB_REPO must be "owner/repo" — never put the token here (common misconfig).
    let ghRepo = (process.env.GITHUB_REPO || '').replace(/^https?:\/\/github\.com\//, '').replace(/\.git$/, '').trim();
    if (ghRepo.startsWith('ghp_') || ghRepo.startsWith('github_pat_') || ghRepo.includes('@')) {
      appendLog(buildId, '⚠️ GITHUB_REPO looks like a token — ignoring. Set GITHUB_REPO=owner/repo (e.g. webever_studio/my-app).');
      ghRepo = '';
    }
    const expoToken = process.env.EXPO_TOKEN;
    const platform = build.platform || 'android';
    const profile = build.profile || 'preview';
    const mode = build.mode || 'cloud';
    const artifacts = [{ type: 'expo-bundle', name: 'expo-project.zip', path: zipPath }];

    appendLog(buildId, `Mode: ${mode} · Platform: ${platform} · Profile: ${profile}`);

    // ===================== LOCAL ANDROID BUILD =====================
    if (mode === 'local') {
      if (platform === 'ios') {
        updateBuild(buildId, { status: 'failed', message: 'Local iOS requires macOS + Xcode', artifacts });
        appendLog(buildId, '❌ Local iOS builds only work on macOS with Xcode. Use Cloud mode.');
        return;
      }

      appendLog(buildId, 'Local mode: Android build on this machine…');
      appendLog(buildId, 'Requires: Node, Java, Android SDK (ANDROID_HOME).');

      try {
        appendLog(buildId, 'Installing npm dependencies…');
        await runCmd(buildId, 'npm install --no-audit --no-fund', buildDir);

        let usedGradleFallback = false;

        // EAS --local often breaks on nested paths (data/builds/<id>) with
        // "package.json does not exist". Default to Gradle; set PREFER_GRADLE_LOCAL=0 to try EAS local.
        const preferGradle = process.env.PREFER_GRADLE_LOCAL !== '0';
        if (expoToken && !preferGradle) {
          appendLog(buildId, 'EXPO_TOKEN found — trying EAS local build…');
          try {
            const easAccount = (process.env.EAS_ACCOUNT || process.env.EXPO_ACCOUNT || '').trim();
            try {
              appendLog(buildId, 'Ensuring EAS project is configured (eas init)…');
              const initCmd = easAccount
                ? `npx --yes eas-cli@latest init --account ${easAccount} --non-interactive`
                : 'npx --yes eas-cli@latest init --non-interactive';
              await runCmd(buildId, initCmd, buildDir, {
                EXPO_TOKEN: expoToken,
                EAS_NO_VCS: '1',
                EAS_PROJECT_ROOT: buildDir
              });
            } catch (initErr) {
              appendLog(buildId, 'eas init note: ' + (initErr.message || String(initErr)).slice(0, 200));
              if (!easAccount) {
                appendLog(buildId, 'Tip: set EAS_ACCOUNT=webever_studio (or www.eazywok.com) in .env for multi-account tokens.');
              }
              appendLog(buildId, 'Continuing — project may already be linked.');
            }

            const easLocal = `npx --yes eas-cli@latest build --platform android --profile ${profile} --local --non-interactive`;
            await runCmd(buildId, easLocal, buildDir, {
              EXPO_TOKEN: expoToken,
              EAS_NO_VCS: '1',
              EAS_PROJECT_ROOT: buildDir
            });
          } catch (easErr) {
            appendLog(buildId, 'EAS local build failed: ' + (easErr.message || String(easErr)).slice(0, 300));
            appendLog(buildId, 'Falling back to expo prebuild + Gradle…');
            usedGradleFallback = true;
            await runLocalGradleBuild(buildId, buildDir, profile);
          }
        } else {
          if (expoToken) {
            appendLog(buildId, 'Skipping EAS local (nested path / low RAM) — using expo prebuild + Gradle…');
          } else {
            appendLog(buildId, 'No EXPO_TOKEN — using expo prebuild + Gradle…');
          }
          usedGradleFallback = true;
          await runLocalGradleBuild(buildId, buildDir, profile);
        }

        const binaries = findLocalBinaries(buildDir);
        if (binaries.length) {
          for (const bin of binaries) {
            const base = path.basename(bin);
            const dest = path.join(BUILDS_DIR, `${buildId}-${base}`);
            fs.copyFileSync(bin, dest);
            artifacts.push({ type: 'app-binary', name: base, path: dest });
            appendLog(buildId, `Found binary: ${base}`);
          }
          updateBuild(buildId, {
            status: 'success',
            message: usedGradleFallback
              ? 'Local Gradle build finished — download APK/AAB below.'
              : 'Local EAS build finished — download APK/AAB below.',
            artifacts,
            hasApk: true,
            binaryName: path.basename(binaries[0])
          });
          appendLog(buildId, '✅ Local build complete.');
          return;
        }

        appendLog(buildId, 'No APK/AAB found after local build. Check Android SDK / logs.');
        updateBuild(buildId, {
          status: 'failed',
          message: 'Local build ran but no APK/AAB was produced.',
          artifacts
        });
        return;
      } catch (e) {
        appendLog(buildId, 'Local build error: ' + (e.message || String(e)).slice(0, 400));
        appendLog(buildId, 'Tip: install Android Studio / set ANDROID_HOME (or run setup-android-sdk.sh), install JDK 17 (setup-jdk17.sh), or use Cloud mode.');
        updateBuild(buildId, {
          status: 'failed',
          message: 'Local build failed: ' + (e.message || '').slice(0, 120),
          artifacts
        });
        return;
      }
    }

    // ===================== CLOUD (EAS + optional GitHub Action) =====================
    appendLog(buildId, 'Cloud mode: EAS / GitHub Action…');

    if (expoToken) {
      appendLog(buildId, 'EXPO_TOKEN found — starting EAS cloud build…');
      try {
        appendLog(buildId, 'Installing dependencies…');
        await runCmd(buildId, 'npm install --no-audit --no-fund', buildDir);

        // With EAS_NO_VCS=1, EAS CLI still falls back to the nearest .gitignore
        // for the upload archive when no .easignore is present. Since buildDir
        // lives under data/builds/<id> — likely excluded by the server repo's
        // own .gitignore — that fallback can silently drop package.json (and
        // everything else) from the uploaded tarball, causing the EAS worker
        // to report "package.json does not exist". Writing an explicit
        // .easignore here bypasses that fallback entirely.
        fs.writeFileSync(path.join(buildDir, '.easignore'), 'node_modules\n.git\n');

        // Non-interactive EAS requires the project to be linked. Multi-account tokens need --account.
        const easAccount = (process.env.EAS_ACCOUNT || process.env.EXPO_ACCOUNT || '').trim();
        try {
          appendLog(buildId, 'Ensuring EAS project is configured (eas init)…');
          const initCmd = easAccount
            ? `npx --yes eas-cli@latest init --account ${easAccount} --non-interactive`
            : 'npx --yes eas-cli@latest init --non-interactive';
          await runCmd(buildId, initCmd, buildDir, {
            EXPO_TOKEN: expoToken,
            EAS_NO_VCS: '1',
            EAS_PROJECT_ROOT: buildDir
          });
        } catch (initErr) {
          appendLog(buildId, 'eas init note: ' + (initErr.message || String(initErr)).slice(0, 200));
          if (!easAccount) {
            appendLog(buildId, 'Tip: set EAS_ACCOUNT=webever_studio (or www.eazywok.com) in .env for multi-account tokens.');
          }
        }

        appendLog(buildId, `Running: eas build -p ${platform} --profile ${profile}`);
        const easCmd = `npx --yes eas-cli@latest build --platform ${platform === 'all' ? 'all' : platform} --profile ${profile} --non-interactive --no-wait --json`;
        const { stdout } = await runCmd(buildId, easCmd, buildDir, {
          EXPO_TOKEN: expoToken,
          EAS_NO_VCS: '1',
          EAS_PROJECT_ROOT: buildDir
        });

        let expoBuildId = null;
        let buildPageUrl = null;
        try {
          const parsed = JSON.parse(stdout);
          const first = Array.isArray(parsed) ? parsed[0] : parsed;
          expoBuildId = first?.id || first?.buildId || null;
          buildPageUrl = first?.buildDetailsPageUrl || first?.url || null;
        } catch (_) {
          const m = stdout.match(/builds\/([a-f0-9-]{20,})/i);
          if (m) expoBuildId = m[1];
          const u = stdout.match(/https:\/\/expo\.dev\/[^\s]+/i);
          if (u) buildPageUrl = u[0];
        }

        if (buildPageUrl) {
          appendLog(buildId, `Build page: ${buildPageUrl}`);
          artifacts.push({ type: 'expo-page', name: 'Expo build page', url: buildPageUrl });
        }

        if (expoBuildId) {
          appendLog(buildId, `EAS build queued: ${expoBuildId}`);
          appendLog(buildId, 'Waiting for cloud build (often 5–20 min)…');
          const result = await pollExpoBuild(buildId, expoBuildId, expoToken);
          if (result.status === 'success' && result.url) {
            artifacts.push({ type: 'app-binary', name: 'App binary (APK/AAB/IPA)', url: result.url });
            updateBuild(buildId, {
              status: 'success',
              message: 'EAS cloud build finished — download your APK/AAB below.',
              artifacts,
              expoBuildId,
              binaryUrl: result.url
            });
            appendLog(buildId, '✅ Final app binary ready.');
            appendLog(buildId, result.url);
            return;
          }
          if (result.status === 'success') {
            updateBuild(buildId, {
              status: 'success',
              message: 'EAS build finished. Open Expo dashboard for the download.',
              artifacts,
              expoBuildId
            });
            appendLog(buildId, '✅ EAS build finished. Check Expo dashboard for APK/AAB.');
            return;
          }
          appendLog(buildId, 'Cloud build timed out or failed — see logs / Expo dashboard.');
        } else {
          appendLog(buildId, 'Could not parse EAS build id. Check https://expo.dev');
        }
      } catch (e) {
        appendLog(buildId, 'EAS cloud error: ' + (e.message || String(e)).slice(0, 300));
      }
    } else {
      appendLog(buildId, 'No EXPO_TOKEN in .env — trying GitHub Action only…');
    }

    if (ghToken && ghRepo) {
      appendLog(buildId, `Triggering GitHub Action on ${ghRepo}…`);
      try {
        const res = await fetch(`https://api.github.com/repos/${ghRepo}/actions/workflows/eas-build.yml/dispatches`, {
          method: 'POST',
          headers: {
            Authorization: `Bearer ${ghToken}`,
            Accept: 'application/vnd.github+json',
            'X-GitHub-Api-Version': '2022-11-28'
          },
          body: JSON.stringify({
            ref: 'main',
            inputs: {
              platform: platform === 'all' ? 'all' : platform,
              profile
            }
          })
        });
        if (res.ok || res.status === 204) {
          appendLog(buildId, 'GitHub Action dispatched (uses repo secret EXPO_TOKEN).');
          appendLog(buildId, `Watch: https://github.com/${ghRepo}/actions`);
          artifacts.push({
            type: 'github-actions',
            name: 'GitHub Actions',
            url: `https://github.com/${ghRepo}/actions`
          });
        } else {
          const txt = await res.text();
          appendLog(buildId, `GitHub dispatch: ${res.status} ${txt.slice(0, 250)}`);
          appendLog(buildId, 'Ensure .github/workflows/eas-build.yml exists on main.');
        }
      } catch (e) {
        appendLog(buildId, 'GitHub trigger error: ' + e.message);
      }
    } else if (!expoToken) {
      appendLog(buildId, 'No EXPO_TOKEN and no GITHUB_TOKEN/GITHUB_REPO — cannot start cloud build.');
      appendLog(buildId, 'Add tokens to .env or use Local mode on a machine with Android SDK.');
    }

    updateBuild(buildId, {
      status: 'success',
      message: expoToken || (ghToken && ghRepo)
        ? 'Cloud pipeline started. Check Expo / GitHub Actions for APK.'
        : 'Expo project prepared. Configure tokens or use Local mode.',
      artifacts
    });
    appendLog(buildId, '✅ Cloud pipeline step complete.');
  } catch (e) {
    console.error('Build pipeline error', e);
    updateBuild(buildId, { status: 'failed', message: e.message });
    appendLog(buildId, '❌ Build failed: ' + e.message);
  }
}

// ---------- Build routes ----------
app.post('/api/projects/:id/build', auth, async (req, res) => {
  try {
    const { platform = 'android', profile = 'preview', mode = 'cloud' } = req.body;
    const buildMode = mode === 'local' ? 'local' : 'cloud';
    const db = loadDB();
    const project = db.projects.find(p => p.id === req.params.id && p.userId === req.user.id);
    if (!project) return res.status(404).json({ error: 'Project not found' });

    const projectDir = path.join(USERS_DIR, req.user.id, project.id);
    if (!fs.existsSync(path.join(projectDir, 'index.html'))) {
      return res.status(400).json({ error: 'index.html required at project root' });
    }

    if (buildMode === 'local' && platform === 'ios') {
      return res.status(400).json({ error: 'Local iOS builds require macOS + Xcode. Use Cloud or Android.' });
    }

    const buildId = uuidv4();
    const buildDir = path.join(BUILDS_DIR, buildId);
    fs.mkdirSync(buildDir, { recursive: true });

    await generateExpoProject(buildDir, project, projectDir);

    const buildRecord = {
      id: buildId,
      projectId: project.id,
      userId: req.user.id,
      platform,
      profile,
      mode: buildMode,
      status: 'prepared',
      createdAt: new Date().toISOString(),
      updatedAt: new Date().toISOString(),
      message: buildMode === 'local'
        ? 'Local Android build starting…'
        : 'Cloud build starting…',
      logs: [`[${new Date().toISOString().slice(11, 19)}] Expo project generated (${buildMode}).`],
      artifacts: []
    };
    db.builds.push(buildRecord);
    saveDB(db);

    setImmediate(() => runBuildPipeline(buildId));

    res.json({ ok: true, build: buildRecord });
  } catch (e) {
    console.error(e);
    res.status(500).json({ error: 'Build start failed: ' + e.message });
  }
});

app.get('/api/builds', auth, (req, res) => {
  const db = loadDB();
  const builds = db.builds
    .filter(b => b.userId === req.user.id)
    .sort((a, b) => new Date(b.createdAt) - new Date(a.createdAt))
    .map(b => ({
      ...b,
      logs: undefined // list without heavy logs
    }));
  res.json(builds);
});

app.get('/api/builds/:id', auth, (req, res) => {
  const db = loadDB();
  const build = db.builds.find(b => b.id === req.params.id && b.userId === req.user.id);
  if (!build) return res.status(404).json({ error: 'Build not found' });
  res.json(build);
});

app.delete('/api/builds/:id', auth, (req, res) => {
  const db = loadDB();
  const idx = db.builds.findIndex(b => b.id === req.params.id && b.userId === req.user.id);
  if (idx === -1) return res.status(404).json({ error: 'Build not found' });
  const build = db.builds[idx];

  // Clean up any artifact files on disk (binaries copied into BUILDS_DIR,
  // the working build dir, and any generated project-zip bundle).
  try {
    (build.artifacts || []).forEach(a => {
      if (a.path && fs.existsSync(a.path)) fs.rmSync(a.path, { force: true });
    });
    const buildDir = path.join(BUILDS_DIR, build.id);
    if (fs.existsSync(buildDir)) fs.rmSync(buildDir, { recursive: true, force: true });
    const zipPath = path.join(BUILDS_DIR, `${build.id}-bundle.zip`);
    if (fs.existsSync(zipPath)) fs.rmSync(zipPath, { force: true });
  } catch (e) {
    console.error('Build cleanup error:', e);
  }

  db.builds.splice(idx, 1);
  saveDB(db);
  res.json({ ok: true });
});

// Realtime-ish logs
app.get('/api/builds/:id/logs', auth, (req, res) => {
  const db = loadDB();
  const build = db.builds.find(b => b.id === req.params.id && b.userId === req.user.id);
  if (!build) return res.status(404).json({ error: 'Build not found' });
  res.json({
    id: build.id,
    status: build.status,
    message: build.message,
    logs: build.logs || [],
    artifacts: build.artifacts || []
  });
});

// Download APK/AAB (preferred) or Expo project ZIP
app.get('/api/builds/:id/download', auth, (req, res) => {
  const db = loadDB();
  const build = db.builds.find(b => b.id === req.params.id && b.userId === req.user.id);
  if (!build) return res.status(404).json({ error: 'Build not found' });

  const forceZip = String(req.query.zip || '') === '1' || String(req.query.type || '') === 'zip';

  function sendBinary(filePath, name) {
    if (!filePath || !fs.existsSync(filePath)) return false;
    const fname = name || path.basename(filePath);
    const lower = fname.toLowerCase();
    const ctype = lower.endsWith('.aab')
      ? 'application/octet-stream'
      : lower.endsWith('.apk')
        ? 'application/vnd.android.package-archive'
        : 'application/octet-stream';
    res.setHeader('Content-Type', ctype);
    res.setHeader('Content-Disposition', `attachment; filename="${fname}"`);
    res.setHeader('Cache-Control', 'no-store');
    res.sendFile(path.resolve(filePath), (err) => {
      if (err && !res.headersSent) {
        console.error('sendFile error', err);
        res.status(500).json({ error: 'Failed to stream binary' });
      }
    });
    return true;
  }

  if (!forceZip) {
    // 1) Artifact with valid path
    const binaryArt = (build.artifacts || []).find(
      a => a.type === 'app-binary' && a.path && fs.existsSync(a.path)
    );
    if (binaryArt && sendBinary(binaryArt.path, binaryArt.name)) return;

    // 2) Disk scan: <buildId>-*.apk / *.aab in BUILDS_DIR (survives artifact path drift)
    try {
      const files = fs.readdirSync(BUILDS_DIR);
      const match = files.find(f =>
        f.startsWith(build.id) && /\.(apk|aab)$/i.test(f)
      );
      if (match) {
        const full = path.join(BUILDS_DIR, match);
        if (sendBinary(full, match.replace(build.id + '-', ''))) return;
      }
    } catch (_) {}

    // 3) Inside build working dir
    try {
      const found = findLocalBinaries(path.join(BUILDS_DIR, build.id));
      if (found.length) {
        const bin = found[0];
        if (sendBinary(bin, path.basename(bin))) return;
      }
    } catch (_) {}

    // 4) Remote cloud URL
    if (build.binaryUrl) {
      return res.redirect(build.binaryUrl);
    }
    const remoteBinary = (build.artifacts || []).find(a => a.type === 'app-binary' && a.url);
    if (remoteBinary) {
      return res.redirect(remoteBinary.url);
    }
  }

  // Fallback: Expo project ZIP
  const zipPath = path.join(BUILDS_DIR, `${build.id}-bundle.zip`);
  if (!fs.existsSync(zipPath)) {
    const buildDir = path.join(BUILDS_DIR, build.id);
    if (!fs.existsSync(buildDir)) return res.status(404).json({ error: 'No APK/AAB or build folder found. Re-run the build.' });
    const zip = new AdmZip();
    zip.addLocalFolder(buildDir);
    zip.writeZip(zipPath);
  }

  res.setHeader('Content-Type', 'application/zip');
  res.setHeader('Content-Disposition', `attachment; filename="dolphine-${build.id.slice(0, 8)}-expo.zip"`);
  res.sendFile(path.resolve(zipPath));
});

// Explicit APK-only endpoint (UI uses this for the primary download button)
app.get('/api/builds/:id/apk', auth, (req, res) => {
  req.url = `/api/builds/${req.params.id}/download`;
  // Re-use download logic via internal redirect of query
  const db = loadDB();
  const build = db.builds.find(b => b.id === req.params.id && b.userId === req.user.id);
  if (!build) return res.status(404).json({ error: 'Build not found' });

  const trySend = (filePath, name) => {
    if (!filePath || !fs.existsSync(filePath)) return false;
    const fname = name || path.basename(filePath);
    const lower = fname.toLowerCase();
    if (!/\.(apk|aab)$/i.test(lower)) return false;
    res.setHeader(
      'Content-Type',
      lower.endsWith('.aab') ? 'application/octet-stream' : 'application/vnd.android.package-archive'
    );
    res.setHeader('Content-Disposition', `attachment; filename="${fname}"`);
    res.setHeader('Cache-Control', 'no-store');
    res.sendFile(path.resolve(filePath));
    return true;
  };

  const binaryArt = (build.artifacts || []).find(
    a => a.type === 'app-binary' && a.path && fs.existsSync(a.path)
  );
  if (binaryArt && trySend(binaryArt.path, binaryArt.name)) return;

  try {
    const files = fs.readdirSync(BUILDS_DIR);
    const match = files.find(f => f.startsWith(build.id) && /\.(apk|aab)$/i.test(f));
    if (match && trySend(path.join(BUILDS_DIR, match), match.replace(build.id + '-', ''))) return;
  } catch (_) {}

  try {
    const found = findLocalBinaries(path.join(BUILDS_DIR, build.id));
    if (found.length && trySend(found[0], path.basename(found[0]))) return;
  } catch (_) {}

  if (build.binaryUrl) return res.redirect(build.binaryUrl);
  const remote = (build.artifacts || []).find(a => a.type === 'app-binary' && a.url);
  if (remote) return res.redirect(remote.url);

  return res.status(404).json({
    error: 'APK/AAB not found on server. Re-run a Local build, or open the Expo link for a Cloud build.'
  });
});

// ---------- Generate Expo project ----------
async function generateExpoProject(targetDir, project, sourceDir) {
  const cfg = project.config || {};
  const name = cfg.name || project.name;
  const slug = cfg.slug || name.toLowerCase().replace(/[^a-z0-9]+/g, '-');
  const packageName = (cfg.android && cfg.android.package) || `com.dolphine.${project.id.slice(0, 8)}`;
  const bundleId = (cfg.ios && cfg.ios.bundleIdentifier) || packageName;

  // package.json — use classic App.js entry (NOT expo-router; we don't install it)
  // Wrong main: 'expo-router/entry' without the package causes Gradle path='' failures.
  fs.writeFileSync(path.join(targetDir, 'package.json'), JSON.stringify({
    name: slug,
    version: cfg.version || '1.0.0',
    main: 'node_modules/expo/AppEntry.js',
    scripts: {
      start: 'expo start',
      android: 'expo start --android',
      ios: 'expo start --ios',
      web: 'expo start --web'
    },
    dependencies: {
      expo: '~52.0.0',
      'expo-status-bar': '~2.0.0',
      react: '18.3.1',
      'react-native': '0.76.3',
      'react-native-webview': '13.12.5',
      'expo-asset': '~11.0.0',
      'expo-file-system': '~18.0.0',
      'expo-constants': '~17.0.0',
      jszip: '^3.10.1',
      '@expo/config-plugins': '~9.0.0',
      'expo-build-properties': '~0.13.0'
    },
    devDependencies: {
      '@babel/core': '^7.25.0'
    },
    private: true
  }, null, 2));

  // Optional EAS account / projectId from env (fixes multi-account non-interactive init)
  const easAccount = (process.env.EAS_ACCOUNT || process.env.EXPO_ACCOUNT || '').trim();
  const easProjectId = (process.env.EAS_PROJECT_ID || '').trim();

  // app.json
  const appJson = {
    expo: {
      name,
      slug,
      version: cfg.version || '1.0.0',
      orientation: cfg.orientation || 'portrait',
      icon: './assets/icon.png',
      userInterfaceStyle: 'automatic',
      splash: {
        image: './assets/splash.png',
        resizeMode: (cfg.splash && cfg.splash.resizeMode) || 'contain',
        backgroundColor: (cfg.splash && cfg.splash.backgroundColor) || '#0f172a'
      },
      assetBundlePatterns: ['**/*'],
      ios: {
        supportsTablet: true,
        bundleIdentifier: bundleId,
        buildNumber: (cfg.ios && cfg.ios.buildNumber) || '1'
      },
      android: {
        adaptiveIcon: {
          foregroundImage: './assets/adaptive-icon.png',
          backgroundColor: '#0f172a'
        },
        package: packageName,
        versionCode: (cfg.android && cfg.android.versionCode) || 1
      },
      web: {
        bundler: 'metro',
        favicon: './assets/favicon.png'
      },
      // owner + projectId make non-interactive EAS work with multi-account tokens
      ...(easAccount ? { owner: easAccount } : {}),
      extra: {
        ...(cfg.extra || {}),
        ...(easProjectId ? { eas: { projectId: easProjectId } } : {})
      },
      // Travels with the project, so it applies to EAS cloud builds and local
      // prebuild + Gradle alike. 1.9.25 is binary-compatible with 1.9.24.
      plugins: [
        ['expo-build-properties', {
          android: {
            kotlinVersion: '1.9.25'
          }
        }]
      ]
    }
  };
  fs.writeFileSync(path.join(targetDir, 'app.json'), JSON.stringify(appJson, null, 2));

  // eas.json
  fs.writeFileSync(path.join(targetDir, 'eas.json'), JSON.stringify({
    cli: { version: '>= 12.0.0', appVersionSource: 'remote' },
    build: {
      development: {
        developmentClient: true,
        distribution: 'internal'
      },
      preview: {
        distribution: 'internal',
        android: { buildType: 'apk' }
      },
      production: {
        android: { buildType: 'app-bundle' }
      }
    },
    submit: { production: {} }
  }, null, 2));

  // GitHub Action workflow
  const workflowDir = path.join(targetDir, '.github', 'workflows');
  fs.mkdirSync(workflowDir, { recursive: true });
  fs.writeFileSync(path.join(workflowDir, 'eas-build.yml'), `name: EAS Build (Dolphine)
on:
  workflow_dispatch:
    inputs:
      platform:
        description: 'Platform'
        required: true
        default: 'android'
        type: choice
        options:
          - android
          - ios
          - all
      profile:
        description: 'Build profile'
        required: true
        default: 'preview'
        type: choice
        options:
          - development
          - preview
          - production

jobs:
  build:
    name: Install & Build
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-node@v4
        with:
          node-version: 20
          cache: npm
      - name: Setup Expo & EAS
        uses: expo/expo-github-action@v8
        with:
          eas-version: latest
          token: \${{ secrets.EXPO_TOKEN }}
      - name: Install dependencies
        run: npm ci
      - name: Build on EAS
        run: eas build --platform \${{ github.event.inputs.platform || 'android' }} --profile \${{ github.event.inputs.profile || 'preview' }} --non-interactive --no-wait
`);

  // Assets
  const assetsDir = path.join(targetDir, 'assets');
  fs.mkdirSync(assetsDir, { recursive: true });

  // Copy logo if exists, else create placeholder
  const logoSrc = path.join(sourceDir, 'logo.png');
  const iconDest = path.join(assetsDir, 'icon.png');
  const splashDest = path.join(assetsDir, 'splash.png');
  const adaptiveDest = path.join(assetsDir, 'adaptive-icon.png');
  const faviconDest = path.join(assetsDir, 'favicon.png');

  if (fs.existsSync(logoSrc)) {
    fs.copyFileSync(logoSrc, iconDest);
    fs.copyFileSync(logoSrc, splashDest);
    fs.copyFileSync(logoSrc, adaptiveDest);
    fs.copyFileSync(logoSrc, faviconDest);
  } else {
    // Minimal 1x1 transparent PNG as placeholder
    const png = Buffer.from(
      'iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJAAAADUlEQVR42mP8z8BQDwAEhQGAhKmMIQAAAABJRU5ErkJggg==',
      'base64'
    );
    [iconDest, splashDest, adaptiveDest, faviconDest].forEach(p => fs.writeFileSync(p, png));
  }

  // Copy project files into assets/www + pack www.zip for runtime unpack fallback
  const wwwDir = path.join(targetDir, 'assets', 'www');
  fs.mkdirSync(wwwDir, { recursive: true });
  copyDir(sourceDir, wwwDir);

  const wwwZipPath = path.join(targetDir, 'assets', 'www.zip');
  try {
    const wwwZip = new AdmZip();
    wwwZip.addLocalFolder(wwwDir);
    wwwZip.writeZip(wwwZipPath);
  } catch (zipErr) {
    console.warn('www.zip pack failed', zipErr.message);
  }

  // Expo config plugin: copy www → android assets on every prebuild (local + EAS cloud)
  const pluginsDir = path.join(targetDir, 'plugins');
  fs.mkdirSync(pluginsDir, { recursive: true });
  fs.writeFileSync(path.join(pluginsDir, 'withWwwAssets.js'), `const {
  withDangerousMod,
  createRunOncePlugin
} = require('@expo/config-plugins');
const fs = require('fs');
const path = require('path');

function copyRecursive(src, dest) {
  if (!fs.existsSync(src)) return;
  fs.mkdirSync(dest, { recursive: true });
  for (const name of fs.readdirSync(src)) {
    const s = path.join(src, name);
    const d = path.join(dest, name);
    if (fs.statSync(s).isDirectory()) copyRecursive(s, d);
    else fs.copyFileSync(s, d);
  }
}

const withWwwAssets = (config) => {
  return withDangerousMod(config, [
    'android',
    async (cfg) => {
      const projectRoot = cfg.modRequest.projectRoot;
      const platformRoot = cfg.modRequest.platformProjectRoot;
      const src = path.join(projectRoot, 'assets', 'www');
      const dest = path.join(platformRoot, 'app', 'src', 'main', 'assets', 'www');
      if (fs.existsSync(src)) {
        copyRecursive(src, dest);
      }
      return cfg;
    }
  ]);
};

module.exports = createRunOncePlugin(withWwwAssets, 'with-dolphine-www', '1.0.0');
`);

  // Ensure plugin is registered in app.json we already wrote — patch it
  try {
    const appJsonPath = path.join(targetDir, 'app.json');
    const appJson = JSON.parse(fs.readFileSync(appJsonPath, 'utf8'));
    const plugins = appJson.expo.plugins || [];
    if (!plugins.some(p => (Array.isArray(p) ? p[0] : p) === './plugins/withWwwAssets')) {
      plugins.push('./plugins/withWwwAssets');
    }
    appJson.expo.plugins = plugins;
    // Keep splash visible longer feeling: background matches boot screen
    if (!appJson.expo.splash) appJson.expo.splash = {};
    appJson.expo.splash.image = './assets/splash.png';
    appJson.expo.splash.resizeMode = (cfg.splash && cfg.splash.resizeMode) || 'contain';
    appJson.expo.splash.backgroundColor = (cfg.splash && cfg.splash.backgroundColor) || '#0f172a';
    fs.writeFileSync(appJsonPath, JSON.stringify(appJson, null, 2));
  } catch (_) {}

  // App.js — splash screen, android_asset primary, JSZip base64 fallback, ErrorBoundary
  const splashBg = (cfg.splash && cfg.splash.backgroundColor) || '#0f172a';
  fs.writeFileSync(path.join(targetDir, 'App.js'), `import React, { Component } from 'react';
import {
  StyleSheet,
  View,
  StatusBar,
  Text,
  Platform,
  Image,
  Dimensions
} from 'react-native';
import { WebView } from 'react-native-webview';
import { Asset } from 'expo-asset';
import * as FileSystem from 'expo-file-system';
import { registerRootComponent } from 'expo';
import JSZip from 'jszip';

const SPLASH_BG = '${splashBg}';
const ANDROID_ASSET_URI = 'file:///android_asset/www/index.html';

const FALLBACK_HTML = \`<!DOCTYPE html>
<html><head>
<meta name="viewport" content="width=device-width,initial-scale=1,maximum-scale=1,user-scalable=no">
<style>
  body{margin:0;font-family:system-ui,-apple-system,sans-serif;background:${splashBg};color:#f1f5f9;
       display:flex;align-items:center;justify-content:center;min-height:100vh;text-align:center;padding:24px}
  h1{font-size:1.4rem;margin-bottom:8px} p{opacity:.8;line-height:1.55;max-width:320px;margin:0 auto 8px}
  code{background:#1e293b;padding:2px 6px;border-radius:4px;font-size:0.85em}
</style></head><body>
<div>
  <h1>Could not load content</h1>
  <p>Re-upload <code>index.html</code> at the project root and build again.</p>
</div>
</body></html>\`;

class ErrorBoundary extends Component {
  constructor(props) {
    super(props);
    this.state = { error: null };
  }
  static getDerivedStateFromError(error) {
    return { error: error && error.message ? error.message : String(error) };
  }
  componentDidCatch(error, info) {
    console.warn('App ErrorBoundary', error, info);
  }
  render() {
    if (this.state.error) {
      return (
        <View style={styles.boot}>
          <StatusBar barStyle="light-content" backgroundColor={SPLASH_BG} />
          <Image source={require('./assets/splash.png')} style={styles.splashLogo} resizeMode="contain" />
          <Text style={styles.bootTitle}>Something went wrong</Text>
          <Text style={styles.bootText}>{this.state.error}</Text>
        </View>
      );
    }
    return this.props.children;
  }
}

async function unpackWwwFromZip() {
  const root = FileSystem.documentDirectory + 'dolphine-www/';
  const marker = root + '.ready';
  // Reuse previous unpack if present (faster subsequent launches)
  try {
    const m = await FileSystem.getInfoAsync(marker);
    const idx = await FileSystem.getInfoAsync(root + 'index.html');
    if (m.exists && idx.exists) {
      const p = root + 'index.html';
      return p.startsWith('file://') ? p : 'file://' + p;
    }
  } catch (_) {}

  try {
    const info = await FileSystem.getInfoAsync(root);
    if (info.exists) await FileSystem.deleteAsync(root, { idempotent: true });
  } catch (_) {}
  await FileSystem.makeDirectoryAsync(root, { intermediates: true });

  const asset = Asset.fromModule(require('./assets/www.zip'));
  await asset.downloadAsync();
  const uri = asset.localUri || asset.uri;
  if (!uri) throw new Error('www.zip asset missing from bundle');

  // Load zip as base64 — Hermes-safe (no binary string)
  const b64 = await FileSystem.readAsStringAsync(uri, {
    encoding: FileSystem.EncodingType.Base64
  });
  const zip = await JSZip.loadAsync(b64, { base64: true });
  const names = Object.keys(zip.files);
  for (const name of names) {
    const entry = zip.files[name];
    if (!entry || entry.dir) continue;
    const rel = String(name).replace(/^[/\\\\]+/, '').replace(/\\\\/g, '/');
    if (!rel || rel.includes('..')) continue;
    const dest = root + rel;
    const dir = dest.substring(0, dest.lastIndexOf('/'));
    if (dir) {
      try { await FileSystem.makeDirectoryAsync(dir, { intermediates: true }); } catch (_) {}
    }
    const content = await entry.async('base64');
    await FileSystem.writeAsStringAsync(dest, content, {
      encoding: FileSystem.EncodingType.Base64
    });
  }

  const indexPath = root + 'index.html';
  const indexInfo = await FileSystem.getInfoAsync(indexPath);
  if (!indexInfo.exists) throw new Error('index.html missing after unpack');
  try {
    await FileSystem.writeAsStringAsync(marker, String(Date.now()));
  } catch (_) {}
  return indexPath.startsWith('file://') ? indexPath : 'file://' + indexPath;
}

async function resolveWwwUri() {
  // 1) Android assets (copied by withWwwAssets plugin / local prebuild) — most reliable
  if (Platform.OS === 'android') {
    return ANDROID_ASSET_URI;
  }
  // 2) Unpack zip into document directory (iOS + Android fallback)
  return unpackWwwFromZip();
}

function Splash() {
  return (
    <View style={styles.boot}>
      <StatusBar barStyle="light-content" backgroundColor={SPLASH_BG} />
      <Image
        source={require('./assets/splash.png')}
        style={styles.splashLogo}
        resizeMode="contain"
      />
      <Text style={styles.bootBrand}>Loading…</Text>
    </View>
  );
}

function AppInner() {
  const [uri, setUri] = React.useState(null);
  const [error, setError] = React.useState(null);
  const [ready, setReady] = React.useState(false);
  const [webLoaded, setWebLoaded] = React.useState(false);

  React.useEffect(() => {
    let cancelled = false;
    (async () => {
      try {
        // On Android prefer asset path; still try zip unpack if asset fails later
        let fileUri = null;
        if (Platform.OS === 'android') {
          fileUri = ANDROID_ASSET_URI;
          // Also warm-up unpack in background as silent fallback
          unpackWwwFromZip().catch(() => {});
        } else {
          fileUri = await unpackWwwFromZip();
        }
        if (!cancelled) {
          setUri(fileUri);
          setReady(true);
        }
      } catch (e) {
        console.warn('Dolphine www setup failed', e);
        if (!cancelled) {
          // Last resort: try the other strategy
          try {
            const alt = Platform.OS === 'android'
              ? await unpackWwwFromZip()
              : ANDROID_ASSET_URI;
            if (!cancelled) {
              setUri(alt);
              setReady(true);
              return;
            }
          } catch (e2) {
            if (!cancelled) {
              setError(String((e && e.message) || e));
              setReady(true);
            }
          }
        }
      }
    })();
    return () => { cancelled = true; };
  }, []);

  if (!ready) {
    return <Splash />;
  }

  return (
    <View style={styles.container}>
      <StatusBar barStyle="light-content" backgroundColor={SPLASH_BG} />
      {!webLoaded && <View style={StyleSheet.absoluteFill} pointerEvents="none"><Splash /></View>}
      <WebView
        originWhitelist={['*']}
        source={
          uri
            ? { uri }
            : { html: FALLBACK_HTML + (error ? '<p style="color:#f87171">' + error + '</p>' : '') }
        }
        style={[styles.webview, !webLoaded && { opacity: 0 }]}
        javaScriptEnabled={true}
        domStorageEnabled={true}
        allowFileAccess={true}
        allowFileAccessFromFileURLs={true}
        allowUniversalAccessFromFileURLs={true}
        mixedContentMode="always"
        startInLoadingState={false}
        scalesPageToFit={true}
        setSupportMultipleWindows={false}
        androidLayerType="hardware"
        onLoadEnd={() => setWebLoaded(true)}
        onError={(synEvt) => {
          const e = synEvt.nativeEvent;
          console.warn('WebView error', e);
          // If android_asset failed, fall back to unpacked zip
          if (uri === ANDROID_ASSET_URI) {
            unpackWwwFromZip()
              .then((alt) => {
                setUri(alt);
                setWebLoaded(false);
              })
              .catch((err) => {
                setError((e && e.description) || String(err && err.message) || 'WebView failed');
                setWebLoaded(true);
              });
          } else {
            setError((e && e.description) || 'WebView failed to load');
            setWebLoaded(true);
          }
        }}
        onHttpError={(synEvt) => {
          console.warn('WebView HTTP error', synEvt.nativeEvent);
        }}
      />
    </View>
  );
}

function App() {
  return (
    <ErrorBoundary>
      <AppInner />
    </ErrorBoundary>
  );
}

export default App;

const { width: W } = Dimensions.get('window');
const styles = StyleSheet.create({
  container: { flex: 1, backgroundColor: SPLASH_BG },
  webview: { flex: 1, backgroundColor: 'transparent' },
  boot: {
    flex: 1,
    backgroundColor: SPLASH_BG,
    alignItems: 'center',
    justifyContent: 'center',
    padding: 24
  },
  splashLogo: {
    width: Math.min(W * 0.42, 160),
    height: Math.min(W * 0.42, 160),
    marginBottom: 20
  },
  bootBrand: {
    color: '#94a3b8',
    fontSize: 15,
    fontWeight: '500',
    letterSpacing: 0.3
  },
  bootTitle: {
    color: '#f1f5f9',
    fontSize: 17,
    fontWeight: '700',
    marginBottom: 8,
    textAlign: 'center'
  },
  bootText: {
    color: '#94a3b8',
    fontSize: 13,
    textAlign: 'center',
    lineHeight: 18,
    maxWidth: 280
  }
});

`);

  // babel.config.js
  fs.writeFileSync(path.join(targetDir, 'babel.config.js'), `module.exports = function (api) {
  api.cache(true);
  return {
    presets: ['babel-preset-expo'],
  };
};
`);

  // metro.config.js — zip is an asset; html kept for optional direct requires
  fs.writeFileSync(path.join(targetDir, 'metro.config.js'), `const { getDefaultConfig } = require('expo/metro-config');
const config = getDefaultConfig(__dirname);
for (const ext of ['zip', 'html', 'htm']) {
  if (!config.resolver.assetExts.includes(ext)) config.resolver.assetExts.push(ext);
}
module.exports = config;
`);

  // README for the generated project
  fs.writeFileSync(path.join(targetDir, 'README.md'), `# ${name} – Generated by Dolphine

This Expo project wraps your HTML (\`assets/www\`) inside a React Native WebView.

## Quick start (local)

\`\`\`bash
npm install
npx expo start
\`\`\`

## Cloud build with EAS

1. Install EAS CLI: \`npm i -g eas-cli\`
2. Login: \`eas login\`
3. Configure: \`eas build:configure\`
4. Build APK (preview): \`eas build -p android --profile preview\`
5. Build AAB (production): \`eas build -p android --profile production\`
6. Build IPA: \`eas build -p ios --profile production\`

## GitHub Actions

A workflow is included at \`.github/workflows/eas-build.yml\`.

1. Create a GitHub repository and push this folder.
2. Add repository secret \`EXPO_TOKEN\` (from https://expo.dev/accounts/[account]/settings/access-tokens).
3. Run the workflow via Actions → EAS Build → Run workflow.

Generated by [Dolphine](https://github.com) – HTML to mobile in minutes.
`);
}

function copyDir(src, dest) {
  if (!fs.existsSync(src)) return;
  fs.mkdirSync(dest, { recursive: true });
  for (const item of fs.readdirSync(src)) {
    const s = path.join(src, item);
    const d = path.join(dest, item);
    if (fs.statSync(s).isDirectory()) {
      copyDir(s, d);
    } else {
      fs.copyFileSync(s, d);
    }
  }
}

// ---------- Health ----------
app.get('/api/health', (req, res) => {
  res.json({ status: 'ok', name: 'Dolphine', version: '1.0.0' });
});

// SPA fallback
app.get('*', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

app.listen(PORT, '0.0.0.0', () => {
  console.log(`\n  🐬  Dolphine running at http://0.0.0.0:${PORT}`);
  console.log(`     Local:      http://localhost:${PORT}`);
  console.log(`     Codespaces: forward port ${PORT} and open the URL\n`);
});