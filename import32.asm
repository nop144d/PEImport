.386
.model flat

include ..\include\windows.inc
includelib ..\lib\import32.lib

extrn	GetStdHandle:		proc
extrn	GetCommandLineA		proc
extrn	WriteConsoleA:		proc
extrn	ReadConsoleA:		proc
extrn	CreateFileA:		proc
extrn	SetFilePointer:		proc
extrn	ReadFile:		proc
extrn	CloseHandle:		proc
extrn	GetAsyncKeyState:	proc
extrn	ExitProcess:		proc
extrn	GetLastError:		proc
extrn	FormatMessageA:		proc

.data
msg_err db 255 dup(0)				; buffer of FormatMessage
msg_invalid db "File is not a valid PE!",0Ah,0Dh,0
msg_FName db "Enter filename: ",0
msg_Exit db "Press ANY key to exit...",0
msg_NumOfLibs db "Number of libraries: ",0
msg_NumOfFuncs db "Total number of imported functions: ",0
endl db 0Ah,0Dh,0
tab db 09h,0
file db 100,101 dup(0)
hFile dd 0
LibraryName db 32 dup(0)
FunctionName db 64 dup(0)
FunctionAddress dd 0
PE_Sign dw 0
dw 0						; Some kind of alignment
PE dd 0
NumOfSec dw 0
dw 0
ObjTable dd 0
SecVSize dd 0
SecRVA dd 0
SecRAW dd 0
IATRVA dd 0
IATRAW dd 0
CurLib dd 0
CurFunc dd 0
NumOfLibs dd 0
NumOfFuncs dd 0
ConsoleIn dd 0
ConsoleOut dd 0
NumOfBytesRW dd 0
DecNum db 11 dup(0)

Library struc
	Lookup dd 0
	Time dd 0
	Chain dd 0
	LibName dd 0
	AddrTable dd 0
Library ends

Libra Library <>

.code
DecPrint proc
	push ebp
	mov ebp,esp
	pushad
	mov eax,[ebp+8]
	xor ecx,ecx
	mov ebx,10
	NxtDig:
		sub ecx,1			; For [Decnum+10+ecx] addressing
		xor edx,edx
		div bx
		add dl,30h
		mov [DecNum+10+ecx],dl		; Storing digits right-to-left
		cmp ax,0
	jne NxtDig
	lea ebx,[DecNum+10+ecx]
	neg ecx
	push 0
	push offset NumOfBytesRW
	push ecx
	push ebx
	push ConsoleOut
	call WriteConsoleA
	popad
	pop ebp
	ret 4
endp DecPrint

print proc
	push ebp
	mov ebp,esp
	pushad
	mov ebx,[ebp+8]
	cmp byte ptr [ebx],0			; Optimization
	je QuitPrint				; (and for add esi,1)
	xor esi,esi
	Count:
		add esi,1
		cmp byte ptr [ebx+esi],0
	jne Count
	push 0
	push offset NumOfBytesRW
	push esi
	push ebx
	push ConsoleOut
	call WriteConsoleA
QuitPrint:
	popad
	pop ebp
	ret 4
endp print

readstr proc
	push ebp
	mov ebp,esp
	pushad
	mov ebx, [ebp+8]			; Address of buffer
	push 0					; NULL
	push offset NumOfBytesRW
	push 1					; Bytes to read
	push ebx				; Address of buffer
	push hFile
	call ReadFile
	cmp byte ptr [ebx],0
	je QuitReadStr
	nextbyte:
		sub esp, 14h			; Restore parameters
		add dword ptr [esp+4],1		; Increase index of buffer
		mov ebx, [esp+4]		; Get index value
		call ReadFile
		cmp byte ptr [ebx],0		; End Of String
	jne nextbyte
QuitReadStr:
	popad
	pop ebp
	ret 4
endp readstr

readdw proc
	push ebp
	mov ebp,esp
	pushad
	mov ebx, [ebp+8]			; Address of buffer
	push 0					; NULL
	push offset NumOfBytesRW
	push 4					; Bytes to read
	push ebx				; Address of buffer
	push hFile
	call ReadFile
	popad
	pop ebp
	ret 4
endp readdw

seek proc
	push ebp
	mov ebp,esp
	pushad
	mov ebx,[ebp+8]				; Distance (goto)
	push 0					; FILE_BEGIN
	push 0					; NULL
	push ebx				; Distance (goto)
	push hFile
	Call SetFilePointer
	popad
	pop ebp
	ret 4
endp seek

readlib proc
	push ebx
	xor eax,eax
	mov ebx,offset Libra
	cycle:
		push ebx
		call readdw
		cmp dword ptr [ebx],0
		je skip
		add eax,1			; Not the last (NULL) library
		skip:
		add ebx,4			; Cycle and structure index at the same time
		cmp ebx,offset Libra + 20	; If iterated 5 times
	jne cycle
	pop ebx
	ret
endp readlib

rva2offset proc
	sub esi,SecRVA
	add esi,SecRAW
	ret
endp rva2offset

GetFilePos proc
	push 1					; FILE_CURRENT
	push 0					; NULL
	push 0					; Don't move the pointer
	push hFile
	call SetFilePointer
	ret
endp GetFilePos


start:
	push -11 ; (STD_OUTPUT_HANDLE)
	call GetStdHandle
	mov ConsoleOut,eax

	push -10 ; (STD_INPUT_HANDLE)
	call GetStdHandle
	mov ConsoleIn,eax

	push offset nunofbytesrw
	call GetCommandLineA

	push offset msg_FName
	call print

	push 0
	push offset NumOfBytesRW
	push 100
	push offset file
	push ConsoleIn
	call ReadConsoleA

	mov eax,NumOfBytesRW			; Convert filename
	mov byte ptr [file-2 + eax], 0		; to ASCIIZ

	push offset endl
	call print

	push 0					; NULL
	push 80h				; FILE_ATTRUBUTE_NORMAL
	push 3					; OPEN_EXISTING
	push 0					; NULL
	push 1					; FILE_SHARE_READ
	push 80000000h				; GENERIC_READ
	push offset file
	call CreateFileA

	cmp eax,-1				; INVALID_HANDLE_VALUE
	jne open
	call GetLastError
	push 0					; va_list pointer
	push 255				; Message max length
	push offset msg_err			; Buffer
	push 0					; LangID
	push eax				; MessageID
	push 0					; Will be ignored (FORMAT_MESSAGE_FROM_SYSTEM)
	push 1000h				; FORMAT_MESSAGE_FROM_SYSTEM
	call FormatMessageA
	push offset msg_err
	call print
	jmp exit
	open:
		mov hFile,eax			; Saving file identifier

; Checking PE validity
	push offset PE_Sign
	call readdw
	cmp PE_Sign,5A4Dh
	jne pe_error
	push dword ptr 3Ch			; Offset of PE Header
	call seek
	push offset PE 
	call readdw
	push PE
	call seek
	push offset PE_Sign
	call readdw
	cmp PE_Sign,4550h
	jne pe_error

; Initializing
	push PE
	pop ObjTable
	add ObjTable,0F8h			; Size of PE Header
	mov eax,PE
	add eax,6				; Offset of NumberOFSections
	push eax
	call seek
	push offset NumOfSec
	call readdw
	mov eax,PE
	add eax,80h				; Offset of IAT RVA
	push eax
	call seek
	push offset IATRVA
	call readdw

; Converting IATRVA to IATRAW
	mov cx,NumOfSec
	mov esi,ObjTable
	add esi,8				; Skiping Section Name
	ReadSec:
		push esi
		call seek
		push offset SecVSize
		call readdw
		push offset SecRVA
		call readdw
		mov eax,SecRVA
		add eax,SecVSize
		cmp eax,IATRVA
		jb NextSec
	mov eax,IATRVA
	sub eax,SecRVA
	add esi,0Ch				; Skiping SecVSize,SecRVA,SecPHSize
	push esi
	call seek
	push offset SecRAW
	call readdw
	add eax,SecRAW
	mov IATRAW,eax
	jmp main
	NextSec:
		dec cx
		test cx,cx
		jz pe_error
		add esi,28h			; Going to the next section
	jmp ReadSec
	pe_error:
		push offset msg_invalid		; Not a valid PE
		call print
		jmp exit

main:
	push IATRAW
read_lib:
	call seek
	call readlib
	cmp ax,0
	je end_of_libs
	call GetFilePos				; Saving offset
	mov CurLib,eax				; of current Library
	add NumOfLibs,1
	mov esi,Libra.LibName
	call rva2offset
	push esi
	call seek
	push offset LibraryName
	call readstr
	push offset LibraryName
	call print
	push offset endl
	call print
	mov esi,Libra.AddrTable
	call rva2offset
	push esi
	call seek
	read_faddr:
		push offset FunctionAddress
		call readdw
		cmp FunctionAddress,0
		je end_of_funcs
		call GetFilePos			; Saving offset
		mov CurFunc,eax			; of current Function Address
		add NumOfFuncs,1
		add FunctionAddress,2		; Skiping 2 bytes at first of Function Name
		mov esi,FunctionAddress
		call rva2offset
		mov FunctionAddress,esi
		push FunctionAddress
		call seek
		push offset FunctionName
		call readstr
		push offset tab
		call print
		push offset FunctionName
		call print
		push offset endl
		call print
		push CurFunc
		call seek
	jmp read_faddr
	end_of_funcs:
	push CurLib
	jmp read_lib
end_of_libs:
	push offset endl
	call print
	push offset msg_NumOfLibs
	call print
	push NumOfLibs
	call DecPrint
	push offset endl
	call print
	push offset msg_NumOfFuncs
	call print
	push NumOfFuncs
	call DecPrint
	push offset endl
	call print
exit:
	push offset endl
	call print
	push hFile
	call CloseHandle
	push offset msg_Exit
	call print
	xor ebx,ebx				; Isn't in use by GeyAsynckeyState function
	CheckKey:
		push ebx
		call GetAsyncKeyState
		add bl,1
		and ax,1000000000000000b
	jz CheckKey
	push 0
	call ExitProcess
end start