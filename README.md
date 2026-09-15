# 🐬 Dolphine

**HTML → APK / AAB / IPA**  
Mobile-first web app that turns a simple HTML project into native mobile builds using Expo + GitHub Actions.

## Features

- **Login / Register** – JWT auth, JSON file database
- **Projects** – each project is a local file directory (not GitHub)
- **Upload ZIP** – drop a ZIP with `index.html` + `logo.png` at root → auto extracts into the project “repo”
- **Or manual** – create project then upload individual files
- **High configuration** – app name, slug, version, orientation, Android package, iOS bundle ID, splash color, etc.
- **Build preparation** – generates a complete Expo project that wraps your HTML in a WebView, plus:
  - `app.json` / `eas.json`
  - GitHub Action workflow (`.github/workflows/eas-build.yml`)
  - Ready for `eas build` or cloud builds
- **No ZIP output** of the final app – the goal is APK / AAB / IPA via EAS
- **Very few files**, robust, easy to run
- **DM Sans** font, modern icons (Lucide), mobile-first UI

## Quick start

```bash
cd dolphine
npm install
npm start
```

Open **http://localhost:3847**

## How builds work

1. Create a project and upload `index.html` (+ optional `logo.png` and other assets).
2. Adjust config (package name, version, orientation…).
3. Click **Build** → Dolphine generates a full Expo project under `data/builds/<id>/`.
4. The generated project includes a GitHub Action that runs EAS Build.

### Real cloud builds (optional)

- Create an Expo account and generate an access token.
- Push the generated Expo folder to a GitHub repository.
- Add repository secret `EXPO_TOKEN`.
- Run the workflow (or locally: `eas build -p android --profile preview`).

Profiles available:
- `preview` → APK (internal)
- `production` → AAB (Play Store) / IPA
- `development` → Expo development client

## Project structure

```
dolphine/
├── server.js          # All backend (Express, auth, upload, build generation)
├── package.json
├── public/
│   └── index.html     # Single-page mobile-first frontend
├── data/              # JSON DB + user projects + builds (created at runtime)
│   ├── db.json
│   ├── users/
│   └── builds/
└── README.md
```

## Tech

- Node.js ≥ 18
- Express, bcryptjs, jsonwebtoken, multer, adm-zip, uuid
- JSON file database (no external DB required)
- Expo SDK 52 style template + react-native-webview
- GitHub Actions + expo-github-action for CI builds

## License

MIT
