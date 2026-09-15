/**
 * Dolphine – HTML → APK / AAB / IPA
 * Minimal, robust, JSON-DB, Expo + GitHub Actions ready
 */
const express = require('express');
const fs = require('fs');
const path = require('path');
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
app.post('/api/projects/:id/upload', auth, upload.single('file'), (req, res) => {
  try {
    const db = loadDB();
    const project = db.projects.find(p => p.id === req.params.id && p.userId === req.user.id);
    if (!project) return res.status(404).json({ error: 'Project not found' });

    const projectDir = path.join(USERS_DIR, req.user.id, project.id);
    if (!fs.existsSync(projectDir)) fs.mkdirSync(projectDir, { recursive: true });

    const file = req.file;
    if (!file) return res.status(400).json({ error: 'No file uploaded' });

    const isZip = file.originalname.toLowerCase().endsWith('.zip') || file.mimetype === 'application/zip';

    if (isZip) {
      const zip = new AdmZip(file.path);
      const entries = zip.getEntries();
      // Extract only files, flatten if needed, but keep structure under root
      entries.forEach(entry => {
        if (entry.isDirectory) return;
        // Prevent path traversal
        const safeName = path.normalize(entry.entryName).replace(/^(\.\.[/\\])+/, '');
        if (safeName.includes('..')) return;
        const dest = path.join(projectDir, safeName);
        const destDir = path.dirname(dest);
        if (!fs.existsSync(destDir)) fs.mkdirSync(destDir, { recursive: true });
        fs.writeFileSync(dest, entry.getData());
      });
      // Record files
      project.files = listFiles(projectDir);
    } else {
      // Single file upload (e.g. index.html, logo.png)
      const dest = path.join(projectDir, file.originalname);
      fs.renameSync(file.path, dest);
      project.files = listFiles(projectDir);
    }

    // Cleanup tmp
    if (fs.existsSync(file.path)) fs.unlinkSync(file.path);

    project.updatedAt = new Date().toISOString();
    saveDB(db);
    res.json({ ok: true, files: project.files, project });
  } catch (e) {
    console.error(e);
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

// ---------- Build ----------
app.post('/api/projects/:id/build', auth, async (req, res) => {
  try {
    const { platform = 'android', profile = 'preview' } = req.body; // android | ios | all
    const db = loadDB();
    const project = db.projects.find(p => p.id === req.params.id && p.userId === req.user.id);
    if (!project) return res.status(404).json({ error: 'Project not found' });

    const projectDir = path.join(USERS_DIR, req.user.id, project.id);
    const hasIndex = fs.existsSync(path.join(projectDir, 'index.html'));
    if (!hasIndex) {
      return res.status(400).json({ error: 'index.html required at project root' });
    }

    const buildId = uuidv4();
    const buildDir = path.join(BUILDS_DIR, buildId);
    fs.mkdirSync(buildDir, { recursive: true });

    // Generate Expo project that wraps the HTML via WebView + assets
    await generateExpoProject(buildDir, project, projectDir);

    const buildRecord = {
      id: buildId,
      projectId: project.id,
      userId: req.user.id,
      platform,
      profile,
      status: 'prepared', // prepared → queued → building → success | failed
      createdAt: new Date().toISOString(),
      message: 'Expo project generated. Ready for EAS / GitHub Action.',
      artifacts: []
    };
    db.builds.push(buildRecord);
    saveDB(db);

    // In a real deployment you would:
    // 1. Push buildDir to a GitHub repo (or use a template repo + content API)
    // 2. Trigger workflow_dispatch with EXPO_TOKEN secret
    // 3. Poll EAS for status
    // For this minimal version we mark as prepared and expose the generated project.

    res.json({
      ok: true,
      build: buildRecord,
      note: 'Expo project prepared. See /api/builds/:id for status. Configure EXPO_TOKEN + GitHub to enable real cloud builds.'
    });
  } catch (e) {
    console.error(e);
    res.status(500).json({ error: 'Build preparation failed: ' + e.message });
  }
});

app.get('/api/builds', auth, (req, res) => {
  const db = loadDB();
  const builds = db.builds
    .filter(b => b.userId === req.user.id)
    .sort((a, b) => new Date(b.createdAt) - new Date(a.createdAt));
  res.json(builds);
});

app.get('/api/builds/:id', auth, (req, res) => {
  const db = loadDB();
  const build = db.builds.find(b => b.id === req.params.id && b.userId === req.user.id);
  if (!build) return res.status(404).json({ error: 'Build not found' });
  res.json(build);
});

// ---------- Generate Expo project ----------
async function generateExpoProject(targetDir, project, sourceDir) {
  const cfg = project.config || {};
  const name = cfg.name || project.name;
  const slug = cfg.slug || name.toLowerCase().replace(/[^a-z0-9]+/g, '-');
  const packageName = (cfg.android && cfg.android.package) || `com.dolphine.${project.id.slice(0, 8)}`;
  const bundleId = (cfg.ios && cfg.ios.bundleIdentifier) || packageName;

  // package.json
  fs.writeFileSync(path.join(targetDir, 'package.json'), JSON.stringify({
    name: slug,
    version: cfg.version || '1.0.0',
    main: 'expo-router/entry',
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
      'expo-constants': '~17.0.0'
    },
    devDependencies: {
      '@babel/core': '^7.25.0'
    },
    private: true
  }, null, 2));

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
      extra: cfg.extra || {},
      plugins: []
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

  // Copy all project files into assets/www
  const wwwDir = path.join(targetDir, 'assets', 'www');
  fs.mkdirSync(wwwDir, { recursive: true });
  copyDir(sourceDir, wwwDir);

  // App entry (App.js) – WebView loading local assets
  fs.writeFileSync(path.join(targetDir, 'App.js'), `import React from 'react';
import { StyleSheet, View, StatusBar, Platform } from 'react-native';
import { WebView } from 'react-native-webview';
import { Asset } from 'expo-asset';
import * as FileSystem from 'expo-file-system';

export default function App() {
  const [uri, setUri] = React.useState(null);

  React.useEffect(() => {
    (async () => {
      try {
        // Load bundled index.html
        const asset = Asset.fromModule(require('./assets/www/index.html'));
        await asset.downloadAsync();
        // For file:// we need the local URI
        setUri(asset.localUri || asset.uri);
      } catch (e) {
        console.warn('Asset load failed, falling back', e);
        setUri(null);
      }
    })();
  }, []);

  // Fallback: inject HTML string if asset loading is tricky on some platforms
  const htmlFallback = \`
<!DOCTYPE html>
<html>
<head>
  <meta name="viewport" content="width=device-width, initial-scale=1, maximum-scale=1, user-scalable=no">
  <style>body{margin:0;font-family:system-ui;background:#0f172a;color:#f1f5f9;display:flex;align-items:center;justify-content:center;height:100vh;text-align:center;padding:20px}</style>
</head>
<body>
  <div>
    <h1>Dolphine</h1>
    <p>Your HTML content is being prepared.</p>
    <p>If you see this, ensure index.html is at the root of the project.</p>
  </div>
</body>
</html>\`;

  return (
    <View style={styles.container}>
      <StatusBar barStyle="light-content" />
      <WebView
        originWhitelist={['*']}
        source={uri ? { uri } : { html: htmlFallback }}
        style={styles.webview}
        javaScriptEnabled
        domStorageEnabled
        allowFileAccess
        allowUniversalAccessFromFileURLs
        mixedContentMode="always"
        startInLoadingState
        scalesPageToFit
      />
    </View>
  );
}

const styles = StyleSheet.create({
  container: { flex: 1, backgroundColor: '#0f172a' },
  webview: { flex: 1 }
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

app.listen(PORT, () => {
  console.log(`\n  🐬  Dolphine running at http://localhost:${PORT}\n`);
});
