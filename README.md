# Windows Postsetup Updater

A fast, lightweight, and zero-dependency cross-platform updater for Windows post-installation software. It automatically detects, verifies, and downloads the latest Windows installers (`.exe`, `.zip`) from their upstream sources directly into a dedicated `Installers/` directory.

---

## ✨ Key Features

* **Zero Dependencies:** Pure Go standalone single-file executables (`updater.exe` for Windows and `updater-linux` for Linux). No runtime, Python, or package manager required.
* **Dedicated Directory Isolation (`Installers/`):**
  * All managed application installers are kept organized in the `Installers/` folder.
  * When an update is detected, older versions (e.g. `SDIO_2.0.1...`) are automatically deleted and replaced.
  * **License Protection:** Custom user license files such as `Installers/Winrar/rarreg.key` are strictly preserved and never modified or deleted.
* **Smart Upstream Verification:**
  * **Static Filename Apps (`BraveOriginSetup.exe`, `fdm_x64_setup.exe`):** Checks server `ETag`, `Last-Modified`, and `Content-Length` headers to detect new builds even when filenames never change.
  * **GitHub Releases (`VisualCppRedist AIO`, `Brave Origin Unlocker`):** Queries GitHub's `releases/latest` API for the newest releases and assets.
  * **GitHub Actions Builds (`Jellium Desktop`):** Tracks the latest successful Windows artifacts directly from GitHub Actions CI.
  * **Dynamic Versioned Files (`SDIO`, `WinRAR`, `AMD Adrenalin`):** Dynamically scrapes upstream pages with regex to fetch the newest version strings.
* **Safe Atomic Downloads:** Files are downloaded with a temporary `.tmp` extension and SHA-256 verified before being atomically finalized.
* **One-Click Execution:** No command-line arguments needed. Double-click `updater.exe` on Windows or run `./updater-linux` on Linux to check and update everything in one pass.

---

## 📂 Directory Layout

```text
postsetup/
├── updater.exe                               # Windows standalone executable (Double-click to run)
├── updater-linux                             # Linux standalone executable
│
└── Installers/                               # Dedicated managed folder
    ├── BraveOriginSetup.exe                  # Brave Origin Web Installer
    ├── unlock-win.exe                        # Brave Origin Unlocker
    ├── VisualCppRedist_AIO_x86_x64.exe       # Visual C++ Redistributable AIO
    ├── Jellium windows-x64.zip               # Jellium Desktop Client
    ├── SDIO_2.0.3.886.zip                    # Snappy Driver Installer Origin
    ├── fdm_x64_setup.exe                     # Free Download Manager 6.x
    ├── amd-software-adrenalin-edition-...exe # AMD Adrenalin Minimal Setup
    └── Winrar/
        ├── rarreg.key                        # Your personal license key (PRESERVED)
        └── winrar-x64-723tr.exe              # WinRAR Turkish 64-bit Installer
```

---

## 🚀 Usage

### On Windows:
* **Double-click `updater.exe`**.
* The updater scans all applications, downloads required updates with a real-time progress bar, removes obsolete versions, and pauses on completion so you can review the summary report.

### On Linux:
* Run via terminal:
```bash
./updater-linux
```

---

## 🤖 Automated CI/CD Builds

Whenever changes are pushed to this repository, GitHub Actions (`.github/workflows/build.yml`) automatically builds standalone Windows (`updater.exe`) and Linux (`updater-linux`) binaries and publishes them directly to the `latest` GitHub Release.
