.model small
.stack
.data
errmsg_0 db "File Not Found!$"
errmsg_1 db "Folder Not Found!$"
errmsg_2 db "Too Many Opened Files!$"
errmsg_3 db "Access Denied!$"
errmsg_4 db "File is not a valid PE!$"
errmsgs dw 00h,10h,22h,39h,48h
msg_FName db "Enter filename: $"
msg_Exit db "Press any key to exit...$"
msg_NumOfLibs db "Number of libraries: $"
msg_NumOfFuncs db "Total number of imported functions: $"
endl db 10,13,'$'
tab db 09,'$'
file db 100,101 dup(0)
LibraryName db 32 dup(0)
FunctionName db 64 dup(0)
FunctionAddress dd 0
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
NumOfLibs dw 0
NumOfFuncs dw 0

Library struc
	Lookup dd 0
	Time dd 0
	Chain dd 0
	LibName dd 0
	AddrTable dd 0
Library ends

Libra Library <>

.486p
.code

DecPrint proc
	push bp
	mov bp,sp
	pusha
	xor edx,edx
	xor ecx,ecx
	mov ax,[bp+4]
	mov ebx,10
	NxtDig:
	cmp al,0
	je FinDiv
		div bl
		add ah,30h
		xchg al,ah
		push ax
		xchg ah,al
		xor ah,ah
		add cx,1
	jmp NxtDig
	FinDiv:
		mov ah,2
		pop dx
		int 21h
	loop FinDiv
	popa
	pop bp
	ret 2
endp DecPrint

print proc
	push bp
	mov bp,sp
	push ax dx
	mov ah,9
	mov dx,[bp+4]
	int 21h
	pop bp
	pop dx ax
	ret 2
endp print

readstr proc
	push bp
	mov bp,sp
	pusha
	mov cx,1
	mov dx,[bp+4]
	sub dx,1
	nextbyte:
		mov ah,3Fh
		add dx,1
		int 21h
		mov bp,dx
		cmp byte ptr ds:[bp],0
	jne nextbyte
	mov byte ptr ds:[bp],'$'
	popa
	pop bp
	ret 2
endp readstr


readdw proc
	push bp
	mov bp,sp
	pusha
	mov ah,3Fh
	mov cx,4
	mov dx,[bp+4]
	int 21h
	popa
	pop bp
	ret 2
endp readdw

seek proc
	push bp
	mov bp,sp
	pusha
	mov ax,4200h
	mov cx,[bp+6]
	mov dx,[bp+4]
	int 21h
	popa
	pop bp
	ret 4
endp seek

readlib proc
	push bp
	push si
	xor eax,eax
	xor si,si
	cycle:
		mov bp,offset Libra
		add bp,si
		push bp
		call readdw
		cmp dword ptr ds:[bp],0
		je skip
		add ax,1
		skip:
		add si,4
		cmp si,20
	jne cycle
	pop si
	pop bp
	ret
endp readlib

rva2offset proc
	sub esi,SecRVA
	add esi,SecRAW
	ret
endp rva2offset

GetFilePos proc
	push bp
	mov bp,sp
	push si
	mov ax,4201h
	xor cx,cx
	xor dx,dx
	int 21h
	mov si,[bp+4]
	mov [si],ax
	mov [si+2],dx
	mov eax,[si]
	pop si
	pop bp
	ret 2
endp GetFilePos


start:
	mov dx,@data
	mov ds,dx

	push offset msg_FName
	call print
	mov ah,10
	mov dx,offset file
	int 21h
	push offset endl
	call print

	xor cx,cx
	mov cl,[file+1]
	mov si,cx
	mov [file+si+2],'$'

	mov ah,3Dh
	mov al,00010010b
	mov dx,offset file+2
	int 21h
	jnc open
	mov si,ax				; getting error
	shl si,1				; and printing
	sub si,2				; message address
	push [errmsgs+si-2]			; the message
	call print
	jmp exit
	open:
		mov bx,ax			; Saving file identifier

; Initializing
	push dword ptr 3Ch			; Offset of PE Header
	call seek
	push offset PE 
	call readdw
	push PE
	pop ObjTable				;
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
		push word ptr errmsgs[4*2]
		call print
		jmp exit

main:
	push IATRAW
read_lib:
	call seek
	call readlib
	cmp eax,0
	je end_of_libs
	push offset CurLib			; Saving offset
	call GetFilePos				; of current Library
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
		push offset CurFunc		; Saving offset
		call GetFilePos			; of current Function Address
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
	push offset msg_Exit
	call print
	mov ah,1
	int 21h
	mov ax,4C00h
	int 21h
end start