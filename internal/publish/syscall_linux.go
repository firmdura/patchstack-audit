//go:build linux

package publish

import (
	"runtime"
	"syscall"
	"unsafe"
)

func renameNoReplace(oldFD int, oldName string, newFD int, newName string) error {
	var number uintptr
	switch runtime.GOARCH {
	case "amd64":
		number = 316
	case "arm64", "riscv64", "loong64":
		number = 276
	default:
		return syscall.ENOSYS
	}
	old, err := syscall.BytePtrFromString(oldName)
	if err != nil {
		return err
	}
	new, err := syscall.BytePtrFromString(newName)
	if err != nil {
		return err
	}
	const renameNoReplace = 1
	_, _, errno := syscall.Syscall6(number, uintptr(oldFD), uintptr(unsafe.Pointer(old)), uintptr(newFD), uintptr(unsafe.Pointer(new)), renameNoReplace, 0)
	if errno != 0 {
		return errno
	}
	return nil
}

func removeDirectoryAt(fd int, name string) error {
	ptr, err := syscall.BytePtrFromString(name)
	if err != nil {
		return err
	}
	const atRemoveDir = 0x200
	_, _, errno := syscall.Syscall(syscall.SYS_UNLINKAT, uintptr(fd), uintptr(unsafe.Pointer(ptr)), atRemoveDir)
	if errno != 0 {
		return errno
	}
	return nil
}
