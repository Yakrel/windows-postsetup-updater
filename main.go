package main

import (
	"bufio"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
)

const AppVersion = "1.0.0"

// AppConfig defines the hardcoded configuration for an individual application
type AppConfig struct {
	ID            string            `json:"id"`
	Name          string            `json:"name"`
	Category      string            `json:"category,omitempty"`
	Enabled       bool              `json:"enabled"`
	Type          string            `json:"type"` // "github_release", "github_actions", "http_direct", "html_scrape"
	Repo          string            `json:"repo,omitempty"`
	Workflow      string            `json:"workflow,omitempty"`
	Artifact      string            `json:"artifact,omitempty"`
	URL           string            `json:"url,omitempty"`
	AssetPattern  string            `json:"asset_pattern,omitempty"`
	Pattern       string            `json:"pattern,omitempty"`
	TargetFile    string            `json:"target_file,omitempty"`
	TargetDir     string            `json:"target_dir,omitempty"`
	CleanPattern  string            `json:"clean_pattern,omitempty"`
	PreserveFiles []string          `json:"preserve_files,omitempty"`
	Headers       map[string]string `json:"headers,omitempty"`
	Notes         string            `json:"notes,omitempty"`
}

// AppState stores metadata about the downloaded version
type AppState struct {
	ID           string    `json:"id"`
	Version      string    `json:"version"`
	Filename     string    `json:"filename"`
	ETag         string    `json:"etag,omitempty"`
	LastModified string    `json:"last_modified,omitempty"`
	FileSize     int64     `json:"file_size"`
	SHA256       string    `json:"sha256,omitempty"`
	UpdatedAt    time.Time `json:"updated_at"`
}

type StateRegistry struct {
	Apps map[string]*AppState `json:"apps"`
}

type CheckResult struct {
	App           *AppConfig
	NeedsUpdate   bool
	Reason        string
	LocalVersion  string
	RemoteVersion string
	LocalFile     string
	RemoteFile    string
	DownloadURL   string
	Headers       map[string]string
	RemoteSize    int64
	RemoteETag    string
	RemoteLastMod string
	OldFiles      []string
	Err           error
}

const defaultUserAgent = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/128.0.0.0 Safari/537.36"

var httpClient = &http.Client{
	Timeout: 35 * time.Second,
}

// Hardcoded default applications
func GetHardcodedApps() []AppConfig {
	return []AppConfig{
		{
			ID:           "unlocker",
			Name:         "Brave Origin Unlocker",
			Category:     "Browser",
			Enabled:      true,
			Type:         "github_release",
			Repo:         "ObjectAscended/brave-origin-unlocker",
			AssetPattern: `^unlock-win\.exe$`,
			TargetFile:   "unlock-win.exe",
			TargetDir:    "Installers",
		},
		{
			ID:           "vcredist",
			Name:         "VisualCppRedist AIO",
			Category:     "Runtime",
			Enabled:      true,
			Type:         "github_release",
			Repo:         "abbodi1406/vcredist",
			AssetPattern: `^VisualCppRedist_AIO_x86_x64\.exe$`,
			TargetFile:   "VisualCppRedist_AIO_x86_x64.exe",
			TargetDir:    "Installers",
		},
		{
			ID:         "jellium",
			Name:       "Jellium Desktop",
			Category:   "Media",
			Enabled:    true,
			Type:       "github_actions",
			Repo:       "andrewrabert/jellium-desktop",
			Workflow:   "build-windows",
			Artifact:   "windows-x64",
			TargetFile: "Jellium windows-x64.zip",
			TargetDir:  "Installers",
		},
		{
			ID:         "brave-origin",
			Name:       "Brave Origin Browser",
			Category:   "Browser",
			Enabled:    true,
			Type:       "http_direct",
			URL:        "https://laptop-updates.brave.com/latest/origin",
			TargetFile: "BraveOriginSetup.exe",
			TargetDir:  "Installers",
		},
		{
			ID:            "winrar",
			Name:          "WinRAR (Turkish x64)",
			Category:      "Utility",
			Enabled:       true,
			Type:          "html_scrape",
			URL:           "https://www.rarlab.com/download.htm",
			Pattern:       `href="([^"]*winrar-x64-([0-9a-z]*tr)\.exe)"`,
			TargetDir:     "Installers/Winrar",
			CleanPattern:  `winrar-x64-.*\.exe`,
			PreserveFiles: []string{"rarreg.key"},
		},
		{
			ID:         "fdm",
			Name:       "Free Download Manager",
			Category:   "Utility",
			Enabled:    true,
			Type:       "http_direct",
			URL:        "https://files2.freedownloadmanager.org/6/latest/fdm_x64_setup.exe",
			TargetFile: "fdm_x64_setup.exe",
			TargetDir:  "Installers",
		},
		{
			ID:           "sdio",
			Name:         "Snappy Driver Installer Origin",
			Category:     "Driver",
			Enabled:      true,
			Type:         "html_scrape",
			URL:          "https://www.glenn.delahoy.com/snappy-driver-installer-origin/",
			Pattern:      `href="([^"]*/downloads/sdio/SDIO_([0-9\.]+)\.zip)"`,
			TargetDir:    "Installers",
			CleanPattern: `SDIO_.*\.zip`,
		},
		{
			ID:           "amd-adrenalin",
			Name:         "AMD Adrenalin Auto-Detect / Minimal",
			Category:     "Driver",
			Enabled:      true,
			Type:         "html_scrape",
			URL:          "https://www.amd.com/en/support/download/drivers.html",
			Pattern:      `href="(https://drivers\.amd\.com/drivers/installer/[^"]*/(amd-software-adrenalin-edition-[^"]*-minimalsetup-[^"]*_web\.exe))"`,
			TargetDir:    "Installers",
			CleanPattern: `amd-software-adrenalin-edition-.*-minimalsetup-.*\.exe`,
			Headers: map[string]string{
				"Referer": "https://www.amd.com/en/support",
			},
		},
	}
}

func LoadState(stateFile string) *StateRegistry {
	reg := &StateRegistry{Apps: make(map[string]*AppState)}
	data, err := os.ReadFile(stateFile)
	if err == nil {
		_ = json.Unmarshal(data, reg)
	}
	if reg.Apps == nil {
		reg.Apps = make(map[string]*AppState)
	}
	return reg
}

func SaveState(stateFile string, reg *StateRegistry) error {
	data, err := json.MarshalIndent(reg, "", "  ")
	if err != nil {
		return err
	}
	tmpFile := stateFile + ".tmp"
	if err := os.WriteFile(tmpFile, data, 0644); err != nil {
		return err
	}
	return os.Rename(tmpFile, stateFile)
}

func doRequest(method, reqURL string, customHeaders map[string]string) (*http.Response, error) {
	req, err := http.NewRequest(method, reqURL, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", defaultUserAgent)
	for k, v := range customHeaders {
		req.Header.Set(k, v)
	}
	return httpClient.Do(req)
}

func CheckApp(ctx context.Context, app *AppConfig, baseDir string, stateReg *StateRegistry) *CheckResult {
	res := &CheckResult{
		App:     app,
		Headers: make(map[string]string),
	}
	for k, v := range app.Headers {
		res.Headers[k] = v
	}

	state := stateReg.Apps[app.ID]
	targetDir := baseDir
	if app.TargetDir != "" && app.TargetDir != "." {
		targetDir = filepath.Join(baseDir, app.TargetDir)
	}

	switch app.Type {
	case "github_release":
		checkGitHubRelease(app, targetDir, state, res)
	case "github_actions":
		checkGitHubActions(app, targetDir, state, res)
	case "http_direct":
		checkHTTPDirect(app, targetDir, state, res)
	case "html_scrape":
		checkHTMLScrape(app, targetDir, state, res)
	default:
		res.Err = fmt.Errorf("bilinmeyen app tipi: %s", app.Type)
	}

	return res
}

func checkGitHubRelease(app *AppConfig, targetDir string, state *AppState, res *CheckResult) {
	apiURL := fmt.Sprintf("https://api.github.com/repos/%s/releases/latest", app.Repo)
	resp, err := doRequest("GET", apiURL, nil)
	if err != nil {
		res.Err = fmt.Errorf("GitHub API hatasi: %w", err)
		return
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		res.Err = fmt.Errorf("GitHub API HTTP %d", resp.StatusCode)
		return
	}

	var rel struct {
		TagName string `json:"tag_name"`
		Assets  []struct {
			Name               string `json:"name"`
			Size               int64  `json:"size"`
			BrowserDownloadURL string `json:"browser_download_url"`
			UpdatedAt          string `json:"updated_at"`
		} `json:"assets"`
	}

	if err := json.NewDecoder(resp.Body).Decode(&rel); err != nil {
		res.Err = fmt.Errorf("JSON parse hatasi: %w", err)
		return
	}

	res.RemoteVersion = rel.TagName
	targetName := app.TargetFile
	var matchedAsset *struct {
		Name               string `json:"name"`
		Size               int64  `json:"size"`
		BrowserDownloadURL string `json:"browser_download_url"`
		UpdatedAt          string `json:"updated_at"`
	}

	re, err := regexp.Compile(app.AssetPattern)
	if err != nil {
		res.Err = fmt.Errorf("regex hatasi: %w", err)
		return
	}

	for i := range rel.Assets {
		if re.MatchString(rel.Assets[i].Name) {
			matchedAsset = &rel.Assets[i]
			break
		}
	}

	if matchedAsset == nil {
		res.Err = fmt.Errorf("uygun asset bulunamadi (%s)", rel.TagName)
		return
	}

	if targetName == "" {
		targetName = matchedAsset.Name
	}
	res.RemoteFile = targetName
	res.DownloadURL = matchedAsset.BrowserDownloadURL
	res.RemoteSize = matchedAsset.Size
	res.LocalFile = filepath.Join(targetDir, targetName)

	localInfo, err := os.Stat(res.LocalFile)
	if os.IsNotExist(err) {
		res.NeedsUpdate = true
		res.Reason = "dosya yerelde yok"
		return
	} else if err != nil {
		res.Err = fmt.Errorf("stat hatasi: %w", err)
		return
	}

	if state != nil && state.Version != "" {
		res.LocalVersion = state.Version
		if state.Version != rel.TagName {
			res.NeedsUpdate = true
			res.Reason = fmt.Sprintf("yeni surum: %s (yerel: %s)", rel.TagName, state.Version)
			return
		}
	} else {
		res.LocalVersion = rel.TagName
	}

	if localInfo.Size() != matchedAsset.Size {
		res.NeedsUpdate = true
		res.Reason = fmt.Sprintf("boyut farkli (yerel: %d, sunucu: %d)", localInfo.Size(), matchedAsset.Size)
		return
	}
}

func checkGitHubActions(app *AppConfig, targetDir string, state *AppState, res *CheckResult) {
	apiURL := fmt.Sprintf("https://api.github.com/repos/%s/actions/runs?status=success&branch=main&per_page=1", app.Repo)
	resp, err := doRequest("GET", apiURL, nil)
	if err != nil {
		res.Err = fmt.Errorf("GitHub Actions API hatasi: %w", err)
		return
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		res.Err = fmt.Errorf("GitHub Actions API HTTP %d", resp.StatusCode)
		return
	}

	var runsResp struct {
		WorkflowRuns []struct {
			ID        int64  `json:"id"`
			CreatedAt string `json:"created_at"`
			HeadSHA   string `json:"head_sha"`
		} `json:"workflow_runs"`
	}

	if err := json.NewDecoder(resp.Body).Decode(&runsResp); err != nil || len(runsResp.WorkflowRuns) == 0 {
		res.Err = fmt.Errorf("basarili workflow run bulunamadi")
		return
	}

	latestRun := runsResp.WorkflowRuns[0]
	runVersion := fmt.Sprintf("run-%d", latestRun.ID)
	res.RemoteVersion = runVersion

	nightlyURL := fmt.Sprintf("https://nightly.link/%s/workflows/%s/main/%s.zip", app.Repo, app.Workflow, app.Artifact)
	res.DownloadURL = nightlyURL

	targetName := app.TargetFile
	if targetName == "" {
		targetName = fmt.Sprintf("%s.zip", app.Artifact)
	}
	res.RemoteFile = targetName
	res.LocalFile = filepath.Join(targetDir, targetName)

	localInfo, err := os.Stat(res.LocalFile)
	if os.IsNotExist(err) {
		res.NeedsUpdate = true
		res.Reason = "dosya yerelde yok"
		return
	} else if err != nil {
		res.Err = fmt.Errorf("stat hatasi: %w", err)
		return
	}

	if state != nil && state.Version != "" {
		res.LocalVersion = state.Version
		if state.Version != runVersion {
			res.NeedsUpdate = true
			res.Reason = fmt.Sprintf("yeni build: %s (yerel: %s)", runVersion, state.Version)
			return
		}
	} else {
		res.LocalVersion = runVersion
	}

	req, _ := http.NewRequest("GET", nightlyURL, nil)
	req.Header.Set("User-Agent", defaultUserAgent)
	req.Header.Set("Range", "bytes=0-0")
	headResp, err := httpClient.Do(req)
	if err == nil {
		defer headResp.Body.Close()
		cr := headResp.Header.Get("Content-Range")
		if cr != "" {
			parts := strings.Split(cr, "/")
			if len(parts) == 2 {
				if sz, err := strconv.ParseInt(parts[1], 10, 64); err == nil {
					res.RemoteSize = sz
					if localInfo.Size() != sz {
						res.NeedsUpdate = true
						res.Reason = "build boyutu farkli"
						return
					}
				}
			}
		}
	}
}

func checkHTTPDirect(app *AppConfig, targetDir string, state *AppState, res *CheckResult) {
	resp, err := doRequest("HEAD", app.URL, app.Headers)
	if err != nil {
		req, _ := http.NewRequest("GET", app.URL, nil)
		req.Header.Set("User-Agent", defaultUserAgent)
		req.Header.Set("Range", "bytes=0-0")
		for k, v := range app.Headers {
			req.Header.Set(k, v)
		}
		resp, err = httpClient.Do(req)
		if err != nil {
			res.Err = fmt.Errorf("HTTP baglanti hatasi: %w", err)
			return
		}
	}
	defer resp.Body.Close()

	if resp.StatusCode >= 400 {
		res.Err = fmt.Errorf("sunucu HTTP %d dondu", resp.StatusCode)
		return
	}

	res.DownloadURL = app.URL
	res.RemoteETag = resp.Header.Get("ETag")
	res.RemoteLastMod = resp.Header.Get("Last-Modified")
	if cl, err := strconv.ParseInt(resp.Header.Get("Content-Length"), 10, 64); err == nil {
		res.RemoteSize = cl
	}

	targetName := app.TargetFile
	if targetName == "" {
		parsedURL, err := url.Parse(resp.Request.URL.String())
		if err == nil {
			targetName = filepath.Base(parsedURL.Path)
		}
	}
	res.RemoteFile = targetName
	res.LocalFile = filepath.Join(targetDir, targetName)

	localInfo, err := os.Stat(res.LocalFile)
	if os.IsNotExist(err) {
		res.NeedsUpdate = true
		res.Reason = "dosya yerelde yok"
		return
	} else if err != nil {
		res.Err = fmt.Errorf("stat hatasi: %w", err)
		return
	}

	if state != nil {
		res.LocalVersion = state.Version
		if res.RemoteETag != "" && state.ETag != "" && res.RemoteETag != state.ETag {
			res.NeedsUpdate = true
			res.Reason = "sunucu ETag degisti (yeni dosya yuklendi)"
			return
		}
		if res.RemoteLastMod != "" && state.LastModified != "" && res.RemoteLastMod != state.LastModified {
			res.NeedsUpdate = true
			res.Reason = "sunucu Last-Modified guncellendi"
			return
		}
	}

	if res.RemoteSize > 0 && localInfo.Size() != res.RemoteSize {
		res.NeedsUpdate = true
		res.Reason = fmt.Sprintf("dosya boyutu degisti (yerel: %d, sunucu: %d)", localInfo.Size(), res.RemoteSize)
		return
	}

	if res.RemoteLastMod != "" {
		res.RemoteVersion = res.RemoteLastMod
		if res.LocalVersion == "" {
			res.LocalVersion = res.RemoteLastMod
		}
	}
}

func checkHTMLScrape(app *AppConfig, targetDir string, state *AppState, res *CheckResult) {
	resp, err := doRequest("GET", app.URL, app.Headers)
	if err != nil {
		res.Err = fmt.Errorf("sayfa cekme hatasi: %w", err)
		return
	}
	defer resp.Body.Close()

	bodyBytes, err := io.ReadAll(resp.Body)
	if err != nil {
		res.Err = fmt.Errorf("govde okuma hatasi: %w", err)
		return
	}
	html := string(bodyBytes)

	re, err := regexp.Compile(app.Pattern)
	if err != nil {
		res.Err = fmt.Errorf("regex hatasi: %w", err)
		return
	}

	matches := re.FindStringSubmatch(html)
	if len(matches) < 2 {
		res.Err = fmt.Errorf("desen bulunamadi")
		return
	}

	rawLink := matches[1]
	downloadURL, err := resolveURL(app.URL, rawLink)
	if err != nil {
		res.Err = fmt.Errorf("gecersiz link: %w", err)
		return
	}
	res.DownloadURL = downloadURL

	var remoteVersion string
	if len(matches) >= 3 {
		remoteVersion = matches[2]
	}
	res.RemoteVersion = remoteVersion

	parsedURL, _ := url.Parse(downloadURL)
	remoteFilename := filepath.Base(parsedURL.Path)
	res.RemoteFile = remoteFilename
	res.LocalFile = filepath.Join(targetDir, remoteFilename)

	if app.CleanPattern != "" {
		cleanRE, err := regexp.Compile(app.CleanPattern)
		if err == nil {
			entries, err := os.ReadDir(targetDir)
			if err == nil {
				for _, e := range entries {
					if e.IsDir() {
						continue
					}
					fname := e.Name()
					if cleanRE.MatchString(fname) {
						isPreserved := false
						for _, p := range app.PreserveFiles {
							if strings.EqualFold(fname, p) {
								isPreserved = true
								break
							}
						}
						if !isPreserved && fname != remoteFilename {
							res.OldFiles = append(res.OldFiles, filepath.Join(targetDir, fname))
						}
					}
				}
			}
		}
	}

	localInfo, err := os.Stat(res.LocalFile)
	if os.IsNotExist(err) {
		res.NeedsUpdate = true
		if len(res.OldFiles) > 0 {
			res.Reason = fmt.Sprintf("yeni surum: %s (eski %s silinecek)", remoteFilename, filepath.Base(res.OldFiles[0]))
		} else {
			res.Reason = "dosya yerelde yok"
		}
		return
	} else if err != nil {
		res.Err = fmt.Errorf("stat hatasi: %w", err)
		return
	}

	if state != nil && state.Version != "" {
		res.LocalVersion = state.Version
		if remoteVersion != "" && state.Version != remoteVersion {
			res.NeedsUpdate = true
			res.Reason = fmt.Sprintf("surum guncellendi (%s -> %s)", state.Version, remoteVersion)
			return
		}
	} else if remoteVersion != "" {
		res.LocalVersion = remoteVersion
	}

	_ = localInfo
}

func resolveURL(baseURLStr, refURLStr string) (string, error) {
	refURL, err := url.Parse(refURLStr)
	if err != nil {
		return "", err
	}
	if refURL.IsAbs() {
		return refURL.String(), nil
	}
	baseURL, err := url.Parse(baseURLStr)
	if err != nil {
		return "", err
	}
	return baseURL.ResolveReference(refURL).String(), nil
}

func DownloadFile(ctx context.Context, check *CheckResult, stateReg *StateRegistry, stateFile string) error {
	app := check.App
	targetFile := check.LocalFile
	targetDir := filepath.Dir(targetFile)

	if err := os.MkdirAll(targetDir, 0755); err != nil {
		return fmt.Errorf("klasor olusturulamadi: %s: %w", targetDir, err)
	}

	tmpFile := targetFile + ".tmp"
	_ = os.Remove(tmpFile)

	req, err := http.NewRequestWithContext(ctx, "GET", check.DownloadURL, nil)
	if err != nil {
		return err
	}
	req.Header.Set("User-Agent", defaultUserAgent)
	for k, v := range check.Headers {
		req.Header.Set(k, v)
	}

	resp, err := httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("indirme hatasi: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("sunucu HTTP %d dondu", resp.StatusCode)
	}

	totalSize := resp.ContentLength
	out, err := os.OpenFile(tmpFile, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0644)
	if err != nil {
		return fmt.Errorf("gecici dosya olusturulamadi: %s: %w", tmpFile, err)
	}

	hasher := sha256.New()
	multiWriter := io.MultiWriter(out, hasher)

	startTime := time.Now()
	var downloaded int64
	buf := make([]byte, 64*1024)

	fmt.Printf("   -> Indiriliyor: %s...\n", filepath.Base(targetFile))

	ticker := time.NewTicker(200 * time.Millisecond)
	defer ticker.Stop()

	doneChan := make(chan bool)
	go func() {
		for {
			select {
			case <-ticker.C:
				elapsed := time.Since(startTime).Seconds()
				if elapsed <= 0 {
					elapsed = 0.001
				}
				speed := float64(downloaded) / elapsed / 1024 / 1024
				if totalSize > 0 {
					pct := float64(downloaded) / float64(totalSize) * 100
					fmt.Printf("\r      Ilerleme: [%-20s] %5.1f%% (%4.1f MB / %4.1f MB) @ %4.1f MB/s",
						strings.Repeat("=", int(pct/5))+strings.Repeat(" ", 20-int(pct/5)),
						pct,
						float64(downloaded)/(1024*1024),
						float64(totalSize)/(1024*1024),
						speed)
				} else {
					fmt.Printf("\r      Indirildi: %4.1f MB @ %4.1f MB/s", float64(downloaded)/(1024*1024), speed)
				}
			case <-doneChan:
				return
			}
		}
	}()

	for {
		n, rErr := resp.Body.Read(buf)
		if n > 0 {
			wN, wErr := multiWriter.Write(buf[:n])
			if wErr != nil {
				_ = out.Close()
				_ = os.Remove(tmpFile)
				doneChan <- true
				return fmt.Errorf("yazma hatasi: %w", wErr)
			}
			downloaded += int64(wN)
		}
		if rErr != nil {
			if rErr == io.EOF {
				break
			}
			_ = out.Close()
			_ = os.Remove(tmpFile)
			doneChan <- true
			return fmt.Errorf("okuma hatasi: %w", rErr)
		}
	}

	doneChan <- true
	_ = out.Close()

	elapsed := time.Since(startTime).Seconds()
	if elapsed <= 0 {
		elapsed = 0.001
	}
	speed := float64(downloaded) / elapsed / 1024 / 1024
	fmt.Printf("\r      Ilerleme: [====================] 100.0%% (%4.1f MB) @ %4.1f MB/s - Tamamlandi!    \n",
		float64(downloaded)/(1024*1024), speed)

	// Atomic rename
	if err := os.Rename(tmpFile, targetFile); err != nil {
		return fmt.Errorf("dosya adlandirma hatasi: %s: %w", targetFile, err)
	}

	// Clean older versions if any, preserving user files (like rarreg.key)
	for _, oldFile := range check.OldFiles {
		oldBase := filepath.Base(oldFile)
		isPreserved := false
		for _, p := range app.PreserveFiles {
			if strings.EqualFold(oldBase, p) {
				isPreserved = true
				break
			}
		}
		if !isPreserved && oldFile != targetFile {
			fmt.Printf("   -> Eski surum siliniyor: %s\n", oldBase)
			_ = os.Remove(oldFile)
		}
	}

	// Update state registry
	shaStr := hex.EncodeToString(hasher.Sum(nil))
	v := check.RemoteVersion
	if v == "" {
		v = check.RemoteLastMod
	}
	stateReg.Apps[app.ID] = &AppState{
		ID:           app.ID,
		Version:      v,
		Filename:     filepath.Base(targetFile),
		ETag:         check.RemoteETag,
		LastModified: check.RemoteLastMod,
		FileSize:     downloaded,
		SHA256:       shaStr,
		UpdatedAt:    time.Now(),
	}
	_ = SaveState(stateFile, stateReg)

	return nil
}

func main() {
	noPause := flag.Bool("no-pause", false, "Cikista Enter bekleme")
	flag.Parse()

	baseDir, err := os.Getwd()
	if err != nil {
		fmt.Printf("Calisma dizini alinamadi: %v\n", err)
		os.Exit(1)
	}

	// Ensure Installers folder exists
	_ = os.MkdirAll(filepath.Join(baseDir, "Installers"), 0755)

	apps := GetHardcodedApps()
	stateFile := filepath.Join(baseDir, ".updater_state.json")
	stateReg := LoadState(stateFile)

	fmt.Println("================================================================================")
	fmt.Printf("  Windows Postsetup Updater v%s\n", AppVersion)
	fmt.Printf("  Calisma Dizini: %s\n", baseDir)
	fmt.Printf("  Kurulum Klasoru: %s\n", filepath.Join(baseDir, "Installers"))
	fmt.Println("================================================================================")

	var activeApps []AppConfig
	for _, app := range apps {
		if app.Enabled {
			activeApps = append(activeApps, app)
		}
	}

	fmt.Printf("\n[1/2] %d uygulama icin guncellik kontrol ediliyor...\n\n", len(activeApps))

	var wg sync.WaitGroup
	checkResults := make([]*CheckResult, len(activeApps))

	for i := range activeApps {
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()
			checkResults[idx] = CheckApp(context.Background(), &activeApps[idx], baseDir, stateReg)
		}(i)
	}
	wg.Wait()

	sort.Slice(checkResults, func(i, j int) bool {
		return checkResults[i].App.Name < checkResults[j].App.Name
	})

	fmt.Println("--------------------------------------------------------------------------------")
	fmt.Printf("%-32s %-16s %-16s %-14s\n", "UYGULAMA", "MEVCUT SURUM", "GUNCEL SURUM", "DURUM")
	fmt.Println("--------------------------------------------------------------------------------")

	var updatesToApply []*CheckResult
	for _, res := range checkResults {
		locV := res.LocalVersion
		if locV == "" {
			locV = "-"
		}
		remV := res.RemoteVersion
		if remV == "" {
			remV = "-"
		}
		statusStr := "Guncel"
		if res.Err != nil {
			statusStr = "HATA"
		} else if res.NeedsUpdate {
			statusStr = "GUNCELLEME VAR"
			updatesToApply = append(updatesToApply, res)
		}

		fmt.Printf("%-32s %-16s %-16s %-14s\n", truncate(res.App.Name, 31), truncate(locV, 15), truncate(remV, 15), statusStr)
		if res.Err != nil {
			fmt.Printf("   └─ Hata: %v\n", res.Err)
		} else if res.NeedsUpdate {
			fmt.Printf("   └─ Neden: %s\n", res.Reason)
		}
	}
	fmt.Println("--------------------------------------------------------------------------------")

	if len(updatesToApply) == 0 {
		fmt.Println("\nTum programlar en guncel surumde! Indirme yapilmasina gerek yok.")
		autoPause(*noPause)
		return
	}

	fmt.Printf("\n[2/2] %d uygulama icin guncellemeler indiriliyor...\n\n", len(updatesToApply))

	var successCount, failCount int
	for idx, res := range updatesToApply {
		fmt.Printf("[%d/%d] Guncelleniyor: %s...\n", idx+1, len(updatesToApply), res.App.Name)
		if err := DownloadFile(context.Background(), res, stateReg, stateFile); err != nil {
			fmt.Printf("   [BASARISIZ] %v\n\n", err)
			failCount++
		} else {
			fmt.Printf("   [TAMAMLANDI] %s guncellendi.\n\n", filepath.Base(res.LocalFile))
			successCount++
		}
	}

	fmt.Println("================================================================================")
	fmt.Printf("Islem Tamamlandi! %d basarili, %d basarisiz.\n", successCount, failCount)
	fmt.Println("================================================================================")

	autoPause(*noPause)
}

func autoPause(noPause bool) {
	// On Windows, or interactive terminal, pause so window doesn't close on double click
	if !noPause && (runtime.GOOS == "windows" || isTerminal()) {
		fmt.Print("\nKapatmak icin Enter tusuna basin...")
		reader := bufio.NewReader(os.Stdin)
		_, _ = reader.ReadString('\n')
	}
}

func isTerminal() bool {
	fi, err := os.Stdin.Stat()
	if err != nil {
		return false
	}
	return (fi.Mode() & os.ModeCharDevice) != 0
}

func truncate(str string, maxLen int) string {
	if len(str) <= maxLen {
		return str
	}
	return str[:maxLen-3] + "..."
}
