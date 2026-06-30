// SPDX-License-Identifier: Apache-2.0

package backup_test

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/achetronic/minecrauth/internal/backup"
)

func TestBackupRestoreRoundTrip(t *testing.T) {
	tmpDir, err := os.MkdirTemp("", "minecrauth-backup-test-*")
	if err != nil {
		t.Fatalf("failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tmpDir)

	// Set up source layout
	srcStateDir := filepath.Join(tmpDir, "src-state")
	if err := os.MkdirAll(srcStateDir, 0o755); err != nil {
		t.Fatalf("failed to create src-state: %v", err)
	}

	srcConfigPath := filepath.Join(tmpDir, "src-config.yaml")

	// Create fake db file (must not be inside stateDir because store.BackupTo creates snapshot outside)
	dbSnapshotPath := filepath.Join(tmpDir, "snapshot.db")
	dbContent := "fake sqlite database content"
	if err := os.WriteFile(dbSnapshotPath, []byte(dbContent), 0o600); err != nil {
		t.Fatalf("failed to write fake db: %v", err)
	}

	signingKeyContent := "fake private key rsa contents"
	if err := os.WriteFile(filepath.Join(srcStateDir, "signing.key"), []byte(signingKeyContent), 0o600); err != nil {
		t.Fatalf("failed to write signing key: %v", err)
	}

	// Create a couple of textures
	texturesDir := filepath.Join(srcStateDir, "textures")
	if err := os.MkdirAll(texturesDir, 0o755); err != nil {
		t.Fatalf("failed to create textures dir: %v", err)
	}
	tex1Content := "skin texture data 1"
	if err := os.WriteFile(filepath.Join(texturesDir, "skin1.png"), []byte(tex1Content), 0o644); err != nil {
		t.Fatalf("failed to write texture 1: %v", err)
	}
	tex2Content := "skin texture data 2"
	if err := os.WriteFile(filepath.Join(texturesDir, "skin2.png"), []byte(tex2Content), 0o644); err != nil {
		t.Fatalf("failed to write texture 2: %v", err)
	}

	configContent := "minecrauth: config: dev"
	if err := os.WriteFile(srcConfigPath, []byte(configContent), 0o600); err != nil {
		t.Fatalf("failed to write config: %v", err)
	}

	// Create archive
	var buf bytes.Buffer
	err = backup.CreateArchive(&buf, srcStateDir, dbSnapshotPath, srcConfigPath)
	if err != nil {
		t.Fatalf("failed to create backup archive: %v", err)
	}

	// Validate archive
	err = backup.ValidateArchive(bytes.NewReader(buf.Bytes()))
	if err != nil {
		t.Fatalf("archive validation failed: %v", err)
	}

	// Apply archive to a fresh dest
	destStateDir := filepath.Join(tmpDir, "dest-state")
	destConfigPath := filepath.Join(tmpDir, "dest-config.yaml")
	if err := os.MkdirAll(destStateDir, 0o755); err != nil {
		t.Fatalf("failed to create dest-state: %v", err)
	}

	err = backup.Apply(bytes.NewReader(buf.Bytes()), destStateDir, destConfigPath)
	if err != nil {
		t.Fatalf("failed to apply backup: %v", err)
	}

	// Verify extracted files
	// 1. Database
	gotDbBytes, err := os.ReadFile(filepath.Join(destStateDir, "minecrauth.db"))
	if err != nil {
		t.Errorf("missing or unreadable minecrauth.db: %v", err)
	} else if string(gotDbBytes) != dbContent {
		t.Errorf("minecrauth.db content mismatch: got %q, want %q", gotDbBytes, dbContent)
	}

	// 2. Signing Key
	gotKeyBytes, err := os.ReadFile(filepath.Join(destStateDir, "signing.key"))
	if err != nil {
		t.Errorf("missing or unreadable signing.key: %v", err)
	} else if string(gotKeyBytes) != signingKeyContent {
		t.Errorf("signing.key content mismatch: got %q, want %q", gotKeyBytes, signingKeyContent)
	}

	// 3. Textures
	gotTex1Bytes, err := os.ReadFile(filepath.Join(destStateDir, "textures", "skin1.png"))
	if err != nil {
		t.Errorf("missing or unreadable skin1.png: %v", err)
	} else if string(gotTex1Bytes) != tex1Content {
		t.Errorf("skin1.png content mismatch")
	}

	gotTex2Bytes, err := os.ReadFile(filepath.Join(destStateDir, "textures", "skin2.png"))
	if err != nil {
		t.Errorf("missing or unreadable skin2.png: %v", err)
	} else if string(gotTex2Bytes) != tex2Content {
		t.Errorf("skin2.png content mismatch")
	}

	// 4. Config
	gotConfigBytes, err := os.ReadFile(destConfigPath)
	if err != nil {
		t.Errorf("missing or unreadable config.yaml: %v", err)
	} else if string(gotConfigBytes) != configContent {
		t.Errorf("config.yaml content mismatch: got %q, want %q", gotConfigBytes, configContent)
	}
}

func TestValidateArchiveRejections(t *testing.T) {
	// 1. Missing MANIFEST
	{
		var buf bytes.Buffer
		gw := gzip.NewWriter(&buf)
		tw := tar.NewWriter(gw)
		addMockFileToTar(t, tw, "db/minecrauth.db", "db snapshot data")
		tw.Close()
		gw.Close()

		err := backup.ValidateArchive(bytes.NewReader(buf.Bytes()))
		if err == nil || !strings.Contains(err.Error(), "missing MANIFEST") {
			t.Errorf("expected error containing 'missing MANIFEST', got: %v", err)
		}
	}

	// 2. Missing db/minecrauth.db
	{
		var buf bytes.Buffer
		gw := gzip.NewWriter(&buf)
		tw := tar.NewWriter(gw)
		addMockFileToTar(t, tw, "MANIFEST", `{"format":"minecrauth-backup","version":1}`)
		tw.Close()
		gw.Close()

		err := backup.ValidateArchive(bytes.NewReader(buf.Bytes()))
		if err == nil || !strings.Contains(err.Error(), "missing database snapshot") {
			t.Errorf("expected error containing 'missing database snapshot', got: %v", err)
		}
	}

	// 3. Invalid Manifest version
	{
		var buf bytes.Buffer
		gw := gzip.NewWriter(&buf)
		tw := tar.NewWriter(gw)
		addMockFileToTar(t, tw, "MANIFEST", `{"format":"minecrauth-backup","version":2}`)
		addMockFileToTar(t, tw, "db/minecrauth.db", "db snapshot data")
		tw.Close()
		gw.Close()

		err := backup.ValidateArchive(bytes.NewReader(buf.Bytes()))
		if err == nil || !strings.Contains(err.Error(), "invalid manifest") {
			t.Errorf("expected error containing 'invalid manifest', got: %v", err)
		}
	}
}

func TestPathTraversalRejections(t *testing.T) {
	// Path traversal in ValidateArchive
	{
		var buf bytes.Buffer
		gw := gzip.NewWriter(&buf)
		tw := tar.NewWriter(gw)
		addMockFileToTar(t, tw, "../evil", "mischief")
		tw.Close()
		gw.Close()

		err := backup.ValidateArchive(bytes.NewReader(buf.Bytes()))
		if err == nil || !strings.Contains(err.Error(), "path traversal") {
			t.Errorf("expected path traversal error, got: %v", err)
		}
	}

	// Path traversal in Apply
	{
		var buf bytes.Buffer
		gw := gzip.NewWriter(&buf)
		tw := tar.NewWriter(gw)
		addMockFileToTar(t, tw, "MANIFEST", `{"format":"minecrauth-backup","version":1}`)
		addMockFileToTar(t, tw, "db/minecrauth.db", "db snapshot")
		addMockFileToTar(t, tw, "textures/../../evil", "mischief")
		tw.Close()
		gw.Close()

		tmpDir, err := os.MkdirTemp("", "minecrauth-backup-traversal-*")
		if err != nil {
			t.Fatalf("failed to create temp dir: %v", err)
		}
		defer os.RemoveAll(tmpDir)

		err = backup.Apply(bytes.NewReader(buf.Bytes()), tmpDir, "")
		if err == nil || !strings.Contains(err.Error(), "path traversal") {
			t.Errorf("expected path traversal error in Apply, got: %v", err)
		}
	}
}

func addMockFileToTar(t *testing.T, tw *tar.Writer, name, content string) {
	t.Helper()
	hdr := &tar.Header{
		Name: name,
		Mode: 0o600,
		Size: int64(len(content)),
	}
	if err := tw.WriteHeader(hdr); err != nil {
		t.Fatalf("failed to write header for %s: %v", name, err)
	}
	if _, err := io.WriteString(tw, content); err != nil {
		t.Fatalf("failed to write content for %s: %v", name, err)
	}
}
