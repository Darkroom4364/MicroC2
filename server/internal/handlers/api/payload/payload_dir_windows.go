//go:build windows

package payload

import (
	"errors"
	"fmt"
	"os"
	"unsafe"

	"golang.org/x/sys/windows"
)

func isPayloadNotExistError(err error) bool {
	return errors.Is(err, os.ErrNotExist) ||
		errors.Is(err, windows.ERROR_FILE_NOT_FOUND) ||
		errors.Is(err, windows.ERROR_PATH_NOT_FOUND) ||
		errors.Is(err, windows.STATUS_OBJECT_NAME_NOT_FOUND) ||
		errors.Is(err, windows.STATUS_OBJECT_PATH_NOT_FOUND)
}

func ensurePayloadClassDirectory(payloadRoot, class string) error {
	if !validPayloadDirectorySegment(class) {
		return errors.New("invalid payload class directory")
	}
	root, err := openWindowsPayloadDirectory(
		windows.InvalidHandle,
		`\??\`+payloadRoot,
		windows.FILE_OPEN,
	)
	if err != nil {
		return fmt.Errorf("open payload root: %w", err)
	}
	defer windows.CloseHandle(root)
	classHandle, err := openWindowsPayloadDirectory(
		root,
		class,
		windows.FILE_OPEN_IF,
	)
	if err != nil {
		return fmt.Errorf("ensure payload class directory: %w", err)
	}
	return windows.CloseHandle(classHandle)
}

func createPayloadBuildDirectory(
	payloadRoot string,
	class string,
	buildID string,
) error {
	if !validPayloadDirectorySegment(class) ||
		!validPayloadDirectorySegment(buildID) {
		return errors.New("invalid payload build directory")
	}
	root, err := openWindowsPayloadDirectory(
		windows.InvalidHandle,
		`\??\`+payloadRoot,
		windows.FILE_OPEN,
	)
	if err != nil {
		return fmt.Errorf("open payload root: %w", err)
	}
	defer windows.CloseHandle(root)
	classHandle, err := openWindowsPayloadDirectory(
		root,
		class,
		windows.FILE_OPEN,
	)
	if err != nil {
		return fmt.Errorf("open payload class directory: %w", err)
	}
	defer windows.CloseHandle(classHandle)
	buildHandle, err := openWindowsPayloadDirectory(
		classHandle,
		buildID,
		windows.FILE_CREATE,
	)
	if err != nil {
		return fmt.Errorf("create payload build directory: %w", err)
	}
	return windows.CloseHandle(buildHandle)
}

func openWindowsPayloadDirectory(
	parent windows.Handle,
	name string,
	disposition uint32,
) (windows.Handle, error) {
	objectName, err := windows.NewNTUnicodeString(name)
	if err != nil {
		return windows.InvalidHandle, err
	}
	attributes := &windows.OBJECT_ATTRIBUTES{
		Length:     uint32(unsafe.Sizeof(windows.OBJECT_ATTRIBUTES{})),
		ObjectName: objectName,
	}
	if parent != windows.InvalidHandle {
		attributes.RootDirectory = parent
	}
	var (
		handle         windows.Handle
		allocationSize int64
		status         windows.IO_STATUS_BLOCK
	)
	err = windows.NtCreateFile(
		&handle,
		windows.FILE_GENERIC_READ|windows.FILE_GENERIC_WRITE,
		attributes,
		&status,
		&allocationSize,
		windows.FILE_ATTRIBUTE_NORMAL,
		windows.FILE_SHARE_READ|
			windows.FILE_SHARE_WRITE|
			windows.FILE_SHARE_DELETE,
		disposition,
		windows.FILE_DIRECTORY_FILE|
			windows.FILE_OPEN_REPARSE_POINT|
			windows.FILE_SYNCHRONOUS_IO_NONALERT,
		0,
		0,
	)
	if err != nil {
		return windows.InvalidHandle, err
	}
	var information windows.ByHandleFileInformation
	if err := windows.GetFileInformationByHandle(
		handle,
		&information,
	); err != nil {
		windows.CloseHandle(handle)
		return windows.InvalidHandle, err
	}
	if information.FileAttributes&windows.FILE_ATTRIBUTE_REPARSE_POINT != 0 {
		windows.CloseHandle(handle)
		return windows.InvalidHandle, errors.New(
			"payload directory is a reparse point",
		)
	}
	return handle, nil
}
