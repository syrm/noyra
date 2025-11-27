package tlsrefresher

import (
	"bytes"
	"io/fs"
	"log/slog"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// fakeDirEntry implémente fs.DirEntry pour contrôler storagePath.Name() dans les tests.
type fakeDirEntry struct {
	name string
}

func (f fakeDirEntry) Name() string               { return f.name }
func (f fakeDirEntry) IsDir() bool                { return true }
func (f fakeDirEntry) Type() fs.FileMode          { return fs.ModeDir }
func (f fakeDirEntry) Info() (fs.FileInfo, error) { return nil, nil }

func TestService_loadCert(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name        string
		setup       func(t *testing.T, dir string)
		file        string
		wantData    []byte
		wantErr     bool
		wantErrKind error
		wantLogWarn bool
	}{
		{
			name: "success/nominal",
			setup: func(t *testing.T, dir string) {
				t.Helper()
				err := os.WriteFile(filepath.Join(dir, "cert.pem"), []byte("CERT_DATA"), 0600)
				require.NoError(t, err)
			},
			file:     "cert.pem",
			wantData: []byte("CERT_DATA"),
		},
		{
			name: "success/empty file",
			setup: func(t *testing.T, dir string) {
				t.Helper()
				err := os.WriteFile(filepath.Join(dir, "empty.pem"), []byte{}, 0600)
				require.NoError(t, err)
			},
			file:     "empty.pem",
			wantData: []byte{},
		},
		{
			name:        "error/file not found",
			setup:       func(t *testing.T, dir string) {},
			file:        "missing.pem",
			wantErr:     true,
			wantErrKind: os.ErrNotExist,
			wantLogWarn: true,
		},
		{
			name: "error/permission denied",
			setup: func(t *testing.T, dir string) {
				t.Helper()
				path := filepath.Join(dir, "noperm.pem")
				err := os.WriteFile(path, []byte("SECRET"), 0600)
				require.NoError(t, err)
				require.NoError(t, os.Chmod(path, 0000))
				t.Cleanup(func() { _ = os.Chmod(path, 0600) })
			},
			file:        "noperm.pem",
			wantErr:     true,
			wantErrKind: os.ErrPermission,
			wantLogWarn: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			// Arrange — répertoire isolé par sous-test
			dir := t.TempDir()
			tt.setup(t, dir)

			// Arrange — logger qui capture la sortie
			var logBuf bytes.Buffer
			logger := slog.New(slog.NewTextHandler(&logBuf, &slog.HandlerOptions{
				Level: slog.LevelDebug,
			}))

			svc := &Service{
				storagePath: fakeDirEntry{name: dir}, // Name() retourne le chemin absolu du tmpdir
				logger:      logger,
			}

			// Act
			got, err := svc.loadCert(tt.file)

			// Assert — erreur
			if tt.wantErr {
				assert.ErrorIs(t, err, tt.wantErrKind)
				require.Error(t, err)
				assert.Nil(t, got)
			} else {
				require.NoError(t, err)
				assert.Equal(t, tt.wantData, got)
			}

			// Assert — log warn émis uniquement sur les chemins d'erreur
			if tt.wantLogWarn {
				assert.Contains(t, logBuf.String(), "WARN",
					"attendu un log WARN, got: %q", logBuf.String(),
				)
				assert.Contains(t, logBuf.String(), tt.file,
					"le nom du fichier devrait apparaître dans le log",
				)
			} else {
				assert.Empty(t, logBuf.String(), "aucun log attendu sur le chemin nominal")
			}
		})
	}
}
