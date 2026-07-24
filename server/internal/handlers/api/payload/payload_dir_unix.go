//go:build unix

package payload

import (
	"errors"
	"fmt"
	"os"

	"golang.org/x/sys/unix"
)

func isPayloadNotExistError(err error) bool {
	return errors.Is(err, os.ErrNotExist)
}

func ensurePayloadClassDirectory(payloadRoot, class string) error {
	if !validPayloadDirectorySegment(class) {
		return errors.New("invalid payload class directory")
	}
	rootFD, err := unix.Open(
		payloadRoot,
		unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC,
		0,
	)
	if err != nil {
		return fmt.Errorf("open payload root: %w", err)
	}
	defer unix.Close(rootFD)

	if err := unix.Mkdirat(rootFD, class, 0700); err != nil &&
		!errors.Is(err, unix.EEXIST) {
		return fmt.Errorf("create payload class directory: %w", err)
	}
	classFD, err := openPayloadDirectoryAt(rootFD, class)
	if err != nil {
		return fmt.Errorf("open payload class directory: %w", err)
	}
	defer unix.Close(classFD)
	if err := unix.Fchmod(classFD, 0700); err != nil {
		return fmt.Errorf("restrict payload class directory: %w", err)
	}
	return nil
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
	rootFD, err := unix.Open(
		payloadRoot,
		unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC,
		0,
	)
	if err != nil {
		return fmt.Errorf("open payload root: %w", err)
	}
	defer unix.Close(rootFD)
	classFD, err := openPayloadDirectoryAt(rootFD, class)
	if err != nil {
		return fmt.Errorf("open payload class directory: %w", err)
	}
	defer unix.Close(classFD)

	if err := unix.Mkdirat(classFD, buildID, 0700); err != nil {
		return fmt.Errorf("create payload build directory: %w", err)
	}
	buildFD, err := openPayloadDirectoryAt(classFD, buildID)
	if err != nil {
		return fmt.Errorf("open payload build directory: %w", err)
	}
	defer unix.Close(buildFD)
	if err := unix.Fchmod(buildFD, 0700); err != nil {
		return fmt.Errorf("restrict payload build directory: %w", err)
	}
	return nil
}

func openPayloadDirectoryAt(parentFD int, name string) (int, error) {
	return unix.Openat(
		parentFD,
		name,
		unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC,
		0,
	)
}
