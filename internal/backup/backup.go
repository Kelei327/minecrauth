// Copyright 2025 - Alby Hernández and the minecrauth contributors
// SPDX-License-Identifier: Apache-2.0

// Package backup provides functions to create, validate, and apply backup archives of the whole state directory.
package backup

import (
	"archive/tar"
	"compress/gzip"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// CreateArchive writes a .tar.gz to w. dbSnapshotPath is a path to a fresh DB
// snapshot already produced by store.BackupTo. stateDir is cfg.StateDir.
// configPath may be "" (then config is omitted).
func CreateArchive(w io.Writer, stateDir, dbSnapshotPath, configPath string) error {
	gw := gzip.NewWriter(w)
	defer func() { _ = gw.Close() }()

	tw := tar.NewWriter(gw)
	defer func() { _ = tw.Close() }()

	// 1. MANIFEST
	manifestBytes, err := json.Marshal(map[string]any{
		"format":     "minecrauth-backup",
		"version":    1,
		"created_at": time.Now().UTC().Format(time.RFC3339),
	})
	if err != nil {
		return fmt.Errorf("marshaling manifest: %w", err)
	}

	manifestHeader := &tar.Header{
		Name:    "MANIFEST",
		Mode:    0o600,
		Size:    int64(len(manifestBytes)),
		ModTime: time.Now().UTC(),
	}
	if err := tw.WriteHeader(manifestHeader); err != nil {
		return fmt.Errorf("writing manifest header: %w", err)
	}
	if _, err := tw.Write(manifestBytes); err != nil {
		return fmt.Errorf("writing manifest content: %w", err)
	}

	// 2. db/minecrauth.db
	if err := addFileToTar(tw, "db/minecrauth.db", dbSnapshotPath, 0o600); err != nil {
		return fmt.Errorf("adding database to archive: %w", err)
	}

	// 3. signing.key
	keyPath := filepath.Join(stateDir, "signing.key")
	if _, err := os.Stat(keyPath); err == nil {
		if err := addFileToTar(tw, "signing.key", keyPath, 0o600); err != nil {
			return fmt.Errorf("adding signing key to archive: %w", err)
		}
	}

	// 4. textures/...
	texturesDir := filepath.Join(stateDir, "textures")
	if fi, err := os.Stat(texturesDir); err == nil && fi.IsDir() {
		err = filepath.Walk(texturesDir, func(path string, info os.FileInfo, err error) error {
			if err != nil {
				return err
			}
			if info.IsDir() {
				return nil
			}
			rel, err := filepath.Rel(texturesDir, path)
			if err != nil {
				return err
			}
			tarName := "textures/" + filepath.ToSlash(rel)
			if err := addFileToTar(tw, tarName, path, 0o644); err != nil {
				return err
			}
			return nil
		})
		if err != nil {
			return fmt.Errorf("walking textures directory: %w", err)
		}
	}

	// 5. config.yaml
	if configPath != "" {
		if _, err := os.Stat(configPath); err == nil {
			if err := addFileToTar(tw, "config.yaml", configPath, 0o600); err != nil {
				return fmt.Errorf("adding config to archive: %w", err)
			}
		}
	}

	return nil
}

// ValidateArchive reads a .tar.gz from r and returns an error if it is not a
// recognizable minecrauth backup (must contain MANIFEST with the right format
// and a db/minecrauth.db entry). Returns nil if valid. Does not extract.
func ValidateArchive(r io.Reader) error {
	gr, err := gzip.NewReader(r)
	if err != nil {
		return fmt.Errorf("initializing gzip reader: %w", err)
	}
	defer func() { _ = gr.Close() }()

	tr := tar.NewReader(gr)
	foundManifest := false
	foundDB := false

	for {
		hdr, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return fmt.Errorf("reading next tar entry: %w", err)
		}

		cleanName := filepath.ToSlash(filepath.Clean(hdr.Name))
		cleanName = strings.TrimPrefix(cleanName, "./")
		cleanName = strings.TrimPrefix(cleanName, "/")

		if err := checkPathTraversal(cleanName); err != nil {
			return err
		}

		switch cleanName {
		case "MANIFEST":
			manifestBytes, err := io.ReadAll(tr)
			if err != nil {
				return fmt.Errorf("reading manifest bytes: %w", err)
			}
			var manifest struct {
				Format  string `json:"format"`
				Version int    `json:"version"`
			}
			if err := json.Unmarshal(manifestBytes, &manifest); err != nil {
				return fmt.Errorf("decoding manifest: %w", err)
			}
			if manifest.Format != "minecrauth-backup" || manifest.Version != 1 {
				return fmt.Errorf("invalid manifest format or version")
			}
			foundManifest = true
		case "db/minecrauth.db":
			foundDB = true
		}
	}

	if !foundManifest {
		return fmt.Errorf("missing MANIFEST file in archive")
	}
	if !foundDB {
		return fmt.Errorf("missing database snapshot (db/minecrauth.db) in archive")
	}

	return nil
}

// Apply extracts the .tar.gz from r into stateDir (db -> stateDir/minecrauth.db,
// signing.key -> stateDir/signing.key, textures/* -> stateDir/textures/*) and, when
// configPath != "" and the archive contains config.yaml, writes it to configPath
// best-effort (on write failure: log a warning and continue, do NOT fail the whole
// restore — the config mount may be read-only). It first removes the existing
// stateDir/textures directory so deleted textures do not linger. GUARD against path
// traversal: reject any tar entry whose cleaned path escapes the target (contains ".."
// or is absolute) — return an error.
func Apply(r io.Reader, stateDir, configPath string) error {
	// First remove the existing stateDir/textures directory so deleted textures do not linger
	texturesDir := filepath.Join(stateDir, "textures")
	if err := os.RemoveAll(texturesDir); err != nil {
		slog.Warn("failed to remove existing textures directory before restore", "path", texturesDir, "error", err)
	}

	gr, err := gzip.NewReader(r)
	if err != nil {
		return fmt.Errorf("initializing gzip reader: %w", err)
	}
	defer func() { _ = gr.Close() }()

	tr := tar.NewReader(gr)

	for {
		hdr, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return fmt.Errorf("reading next tar entry: %w", err)
		}

		cleanName := filepath.ToSlash(filepath.Clean(hdr.Name))
		cleanName = strings.TrimPrefix(cleanName, "./")
		cleanName = strings.TrimPrefix(cleanName, "/")

		if err := checkPathTraversal(cleanName); err != nil {
			return err
		}

		// Skip directories (we'll create parent dirs as needed)
		if hdr.Typeflag == tar.TypeDir {
			continue
		}

		// Map to target path
		var targetPath string
		var mode os.FileMode

		if cleanName == "MANIFEST" {
			// Skip manifest extraction
			continue
		} else if cleanName == "db/minecrauth.db" {
			targetPath = filepath.Join(stateDir, "minecrauth.db")
			mode = 0o600
		} else if cleanName == "signing.key" {
			targetPath = filepath.Join(stateDir, "signing.key")
			mode = 0o600
		} else if strings.HasPrefix(cleanName, "textures/") {
			targetPath = filepath.Join(stateDir, cleanName)
			mode = 0o644
		} else if cleanName == "config.yaml" {
			if configPath == "" {
				continue
			}
			if err := writeConfigBestEffort(tr, configPath); err != nil {
				slog.Warn("failed to restore config file (best effort)", "path", configPath, "error", err)
			}
			continue
		} else {
			// Ignore unexpected files
			continue
		}

		// Ensure parent directory exists
		parentDir := filepath.Dir(targetPath)
		if err := os.MkdirAll(parentDir, 0o755); err != nil {
			return fmt.Errorf("creating directory %s: %w", parentDir, err)
		}

		// Write file
		if err := extractFile(tr, targetPath, mode); err != nil {
			return fmt.Errorf("extracting entry %s to %s: %w", cleanName, targetPath, err)
		}
	}

	return nil
}

func addFileToTar(tw *tar.Writer, tarName string, srcPath string, mode int64) error {
	fi, err := os.Stat(srcPath)
	if err != nil {
		return err
	}
	f, err := os.Open(srcPath)
	if err != nil {
		return err
	}
	defer func() { _ = f.Close() }()

	hdr, err := tar.FileInfoHeader(fi, "")
	if err != nil {
		return err
	}
	hdr.Name = tarName
	hdr.Mode = mode

	if err := tw.WriteHeader(hdr); err != nil {
		return err
	}
	if _, err := io.Copy(tw, f); err != nil {
		return err
	}
	return nil
}

func extractFile(tr io.Reader, targetPath string, mode os.FileMode) error {
	f, err := os.OpenFile(targetPath, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, mode)
	if err != nil {
		return err
	}
	defer func() { _ = f.Close() }()

	if _, err := io.Copy(f, tr); err != nil {
		return err
	}
	return nil
}

func writeConfigBestEffort(tr io.Reader, configPath string) error {
	parent := filepath.Dir(configPath)
	if err := os.MkdirAll(parent, 0o755); err != nil {
		return err
	}
	f, err := os.OpenFile(configPath, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o600)
	if err != nil {
		return err
	}
	defer func() { _ = f.Close() }()
	_, err = io.Copy(f, tr)
	return err
}

func checkPathTraversal(tarName string) error {
	if filepath.IsAbs(tarName) {
		return fmt.Errorf("absolute path not allowed in backup: %s", tarName)
	}
	if strings.HasPrefix(tarName, "/") || strings.HasPrefix(tarName, "\\") {
		return fmt.Errorf("absolute path not allowed in backup: %s", tarName)
	}
	parts := strings.Split(tarName, "/")
	for _, part := range parts {
		if part == ".." {
			return fmt.Errorf("path traversal attempt detected: %s", tarName)
		}
	}
	partsBack := strings.Split(tarName, "\\")
	for _, part := range partsBack {
		if part == ".." {
			return fmt.Errorf("path traversal attempt detected: %s", tarName)
		}
	}
	return nil
}
