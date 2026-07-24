package filestore

import (
	"errors"
	"fmt"
	"io"
	"mime/multipart"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"
	"unicode"
)

// ErrInvalidFileName is returned when a file name is not a plain basename
// (e.g. contains path separators or traversal segments).
var ErrInvalidFileName = errors.New("invalid file name")

const (
	// MaxUploadRequestBytes is a hard cap for the complete multipart request,
	// including framing overhead. ParseMultipartForm's argument only limits
	// in-memory buffering and is not a total request-size limit.
	MaxUploadRequestBytes int64 = 32 << 20
	maxUploadMemoryBytes        = 32 << 20
)

// ValidateFileName ensures name is a plain basename that cannot escape the
// store's base directory. It rejects empty names, "."/"..", path separators
// (both OS and Windows style), and NUL bytes.
func ValidateFileName(name string) error {
	if name == "" || name == "." || name == ".." || name != strings.TrimSpace(name) {
		return fmt.Errorf("%w: %q", ErrInvalidFileName, name)
	}
	if strings.ContainsAny(name, "/\\\x00") {
		return fmt.Errorf("%w: %q", ErrInvalidFileName, name)
	}
	if filepath.Base(name) != name {
		return fmt.Errorf("%w: %q", ErrInvalidFileName, name)
	}
	for _, character := range name {
		if unicode.IsControl(character) {
			return fmt.Errorf("%w: %q", ErrInvalidFileName, name)
		}
	}
	return nil
}

// New creates a new FileStore instance
//
// Pre-conditions:
//   - baseDir is a valid directory path
//
// Post-conditions:
//   - Returns an initialized FileStore instance
//   - Creates the base directory if it doesn't exist
//   - Returns an error if directory creation fails
func New(baseDir string) (*FileStore, error) {
	if err := os.MkdirAll(baseDir, 0755); err != nil {
		return nil, err
	}
	return &FileStore{baseDir: baseDir}, nil
}

// HandleUpload handles file upload requests from HTTP
//
// Pre-conditions:
//   - Request contains a valid multipart form with files
//   - Request content size is within the limit (32MB)
//
// Post-conditions:
//   - Files are saved to the store's base directory
//   - Returns an error if parsing or file operations fail
func (fs *FileStore) HandleUpload(r *http.Request) error {
	_, err := fs.HandleUploadWithInfo(r)
	return err
}

// HandleUploadWithInfo stores uploaded files and reports each file that was
// committed before returning. Returning committed metadata lets the operator
// layer produce truthful per-file audit events even if a later file fails.
func (fs *FileStore) HandleUploadWithInfo(r *http.Request) ([]FileInfo, error) {
	if r.ContentLength > MaxUploadRequestBytes {
		return nil, &http.MaxBytesError{Limit: MaxUploadRequestBytes}
	}
	r.Body = http.MaxBytesReader(nil, r.Body, MaxUploadRequestBytes)
	err := r.ParseMultipartForm(maxUploadMemoryBytes)
	if err != nil {
		return nil, err
	}
	defer r.MultipartForm.RemoveAll()

	files := r.MultipartForm.File["files"]
	committed := make([]FileInfo, 0, len(files))
	for _, fileHeader := range files {
		if err := ValidateFileName(fileHeader.Filename); err != nil {
			return committed, err
		}
		info, err := fs.commitUpload(fileHeader)
		if err != nil {
			return committed, err
		}
		committed = append(committed, info)
	}

	return committed, nil
}

// commitUpload copies one parsed multipart part into a private same-directory
// staging file, then atomically replaces the destination name. Opening the
// destination directly would follow a pre-existing symlink and could overwrite
// a file outside the store.
func (fs *FileStore) commitUpload(fileHeader *multipart.FileHeader) (FileInfo, error) {
	source, err := fileHeader.Open()
	if err != nil {
		return FileInfo{}, err
	}

	staged, err := os.CreateTemp(fs.baseDir, ".microc2-upload-*")
	if err != nil {
		_ = source.Close()
		return FileInfo{}, err
	}
	stagedPath := staged.Name()
	keepStaged := false
	defer func() {
		if !keepStaged {
			_ = os.Remove(stagedPath)
		}
	}()

	size, copyErr := io.Copy(staged, source)
	syncErr := staged.Sync()
	stagedInfo, statErr := staged.Stat()
	closeStagedErr := staged.Close()
	closeSourceErr := source.Close()
	switch {
	case copyErr != nil:
		return FileInfo{}, copyErr
	case syncErr != nil:
		return FileInfo{}, syncErr
	case statErr != nil:
		return FileInfo{}, statErr
	case closeStagedErr != nil:
		return FileInfo{}, closeStagedErr
	case closeSourceErr != nil:
		return FileInfo{}, closeSourceErr
	}

	destination := filepath.Join(fs.baseDir, fileHeader.Filename)
	if err := os.Rename(stagedPath, destination); err != nil {
		return FileInfo{}, err
	}
	keepStaged = true
	return FileInfo{
		Name:     fileHeader.Filename,
		Size:     size,
		Modified: stagedInfo.ModTime().UTC().Format(time.RFC3339),
	}, nil
}

// ListFiles returns a list of files in the store
//
// Pre-conditions:
//   - BaseDir exists or can be created
//
// Post-conditions:
//   - Returns a slice of FileInfo structs for all files in the directory
//   - Returns an error if the directory can't be read
func (fs *FileStore) ListFiles() ([]FileInfo, error) {
	if err := os.MkdirAll(fs.baseDir, 0755); err != nil {
		return nil, err
	}

	files, err := os.ReadDir(fs.baseDir)
	if err != nil {
		return nil, err
	}

	fileList := make([]FileInfo, 0)
	for _, file := range files {
		if file.Type()&os.ModeSymlink != 0 {
			continue
		}
		info, err := file.Info()
		if err != nil || !info.Mode().IsRegular() {
			continue
		}
		fileList = append(fileList, FileInfo{
			Name:     info.Name(),
			Size:     info.Size(),
			Modified: info.ModTime().Format(time.RFC3339),
		})
	}

	return fileList, nil
}

// ServeFile serves a file for download via HTTP
//
// Pre-conditions:
//   - fileName is a valid file name without directory traversal characters
//   - File exists in the base directory
//
// Post-conditions:
//   - File is served to the HTTP response writer
//   - Returns an error if file doesn't exist or path is invalid
func (fs *FileStore) ServeFile(fileName string, w http.ResponseWriter, r *http.Request) error {
	file, info, err := fs.OpenFile(fileName)
	if err != nil {
		return err
	}
	defer file.Close()
	modified, err := time.Parse(time.RFC3339, info.Modified)
	if err != nil {
		return err
	}
	http.ServeContent(w, r, info.Name, modified, file)
	return nil
}

// OpenFile opens one validated regular file and returns its public metadata.
// Callers own the returned handle. Symlinks and non-regular filesystem
// objects are rejected so a later stream cannot escape the file-drop root.
func (fs *FileStore) OpenFile(fileName string) (*os.File, FileInfo, error) {
	if err := ValidateFileName(fileName); err != nil {
		return nil, FileInfo{}, err
	}
	path := filepath.Join(fs.baseDir, fileName)
	entryInfo, err := os.Lstat(path)
	if err != nil {
		return nil, FileInfo{}, err
	}
	if entryInfo.Mode()&os.ModeSymlink != 0 || !entryInfo.Mode().IsRegular() {
		return nil, FileInfo{}, os.ErrNotExist
	}
	file, err := os.Open(path)
	if err != nil {
		return nil, FileInfo{}, err
	}
	info, err := file.Stat()
	if err != nil {
		_ = file.Close()
		return nil, FileInfo{}, err
	}
	if !info.Mode().IsRegular() || !os.SameFile(entryInfo, info) {
		_ = file.Close()
		return nil, FileInfo{}, os.ErrNotExist
	}
	return file, FileInfo{
		Name:     info.Name(),
		Size:     info.Size(),
		Modified: info.ModTime().UTC().Format(time.RFC3339),
	}, nil
}

// DeleteFile deletes a file from the store
//
// Pre-conditions:
//   - fileName is a valid file name without directory traversal characters
//   - File exists in the base directory
//
// Post-conditions:
//   - File is deleted from the filesystem
//   - Returns an error if deletion fails or path is invalid
func (fs *FileStore) DeleteFile(fileName string) error {
	// Prevent directory traversal: only plain basenames are deleted
	if err := ValidateFileName(fileName); err != nil {
		return err
	}

	return os.Remove(filepath.Join(fs.baseDir, fileName))
}
