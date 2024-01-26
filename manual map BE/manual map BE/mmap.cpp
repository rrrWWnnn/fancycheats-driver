#include "portable_executable.hpp"

mmap::mmap(INJECTION_TYPE type) {
	if (type == INJECTION_TYPE::KERNEL)
		proc = std::make_unique<kernelmode_proc_handler>();
}

bool mmap::attach_to_process(const char* process_name) {
	this->process_name = process_name;
	if (!proc->attach(process_name)) {
		printf(_xor_("Unable to attach to process!").c_str());
		return false;
	}
	
	return true;
}
 
bool mmap::load_dll(const char* file_name) {
	std::ifstream f(file_name, std::ios::binary | std::ios::ate);

	if (!f) {
		printf(_xor_("skillia ei pystytty avata!").c_str());
		return false;
	}

	std::ifstream::pos_type pos{ f.tellg() };
	data_size = pos; 

	raw_data = new uint8_t[data_size];

	if (!raw_data)
		return false;

	f.seekg(0, std::ios::beg);
	f.read((char*)raw_data, data_size);
	 
	f.close();
	return true;
}
  
bool mmap::inject() {
	if (!proc->is_attached()) {
		return false;
	}

	if (!raw_data) {
		return false;
	}

	//stub compiled with nasm: https://www.nasm.us/
	uint8_t dll_stub[] = { "\x51\x52\x55\x56\x53\x57\x41\x50\x41\x51\x41\x52\x41\x53\x41\x54\x41\x55\x41\x56\x41\x57\x48\xB8\xFF\x00\xDE\xAD\xBE\xEF\x00\xFF\x48\xBA\xFF\x00\xDE\xAD\xC0\xDE\x00\xFF\x48\x89\x10\x48\x31\xC0\x48\x31\xD2\x48\x83\xEC\x28\x48\xB9\xDE\xAD\xBE\xEF\xDE\xAD\xBE\xEF\x48\x31\xD2\x48\x83\xC2\x01\x48\xB8\xDE\xAD\xC0\xDE\xDE\xAD\xC0\xDE\xFF\xD0\x48\x83\xC4\x28\x41\x5F\x41\x5E\x41\x5D\x41\x5C\x41\x5B\x41\x5A\x41\x59\x41\x58\x5F\x5B\x5E\x5D\x5A\x59\x48\x31\xC0\xC3" };
	
	IMAGE_DOS_HEADER *dos_header{ (IMAGE_DOS_HEADER *)raw_data };

	if (dos_header->e_magic != IMAGE_DOS_SIGNATURE) {
		return false;
	}

	IMAGE_NT_HEADERS *nt_header{ (IMAGE_NT_HEADERS *)(&raw_data[dos_header->e_lfanew]) };

	if (nt_header->Signature != IMAGE_NT_SIGNATURE) {
		return false;
	}

	uint64_t base{ proc->virtual_alloc(nt_header->OptionalHeader.SizeOfImage, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE) };

	if (!base) {
		return false;
	}

	uint64_t stub_base{ proc->virtual_alloc(sizeof(dll_stub), MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE) };

	if (!stub_base) {
		return false;
	}

	PIMAGE_IMPORT_DESCRIPTOR import_descriptor{ (PIMAGE_IMPORT_DESCRIPTOR)get_ptr_from_rva((uint64_t)(nt_header->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress), nt_header, raw_data) };

	if (nt_header->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].Size) {
		solve_imports(raw_data, nt_header, import_descriptor);
	}

	PIMAGE_BASE_RELOCATION base_relocation{ (PIMAGE_BASE_RELOCATION) get_ptr_from_rva(nt_header->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress, nt_header, raw_data)};

	if (nt_header->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].Size) {
		solve_relocations((uint64_t) raw_data, base, nt_header, base_relocation, nt_header->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].Size);
	}

	auto pImportingModuleBase = proc->get_module_base(_xor_("user32.dll").c_str()); //user32

	if (!pImportingModuleBase)
	{
		printf(_xor_("cant find import module").c_str());
	}

	std::vector<uint8_t> tmpbuff, mmbuff;
	tmpbuff.resize(0x10000);

	proc->read_memory(pImportingModuleBase, (uintptr_t)tmpbuff.data(), tmpbuff.size());
	portable_executable tmppe(tmpbuff);
	auto imageSize = tmppe.get_nt_headers()->OptionalHeader.SizeOfImage;

	mmbuff.resize(imageSize);
	proc->read_memory(pImportingModuleBase, (uintptr_t)mmbuff.data(), mmbuff.size());

	portable_executable impe(mmbuff);
	auto imports = impe.get_imports((uintptr_t)impe.get_buffer().data());

	auto library = imports.find(_xor_("win32u.dll").c_str());

	if (library == imports.end()) 
		printf(_xor_("cant find target module").c_str());

	auto libraryImports = library->second;
	import_data imprt;
	bool bFound = false;

	for (auto i : libraryImports)
	{
		if (i.name.find(_xor_("NtUserSetWindowPos").c_str()) != std::string::npos) //NtUserSetWindowPos for fornite, NtUserTranslateMessage for r6s
		{
			bFound = true;
			imprt = i;
			break;
		}
	}


	auto fnPtr = pImportingModuleBase + imprt.function_rva;

	uint64_t orginal_function_addr{read_memory<uint64_t>(fnPtr)};

	printf(_xor_("iat: 0x%p").c_str(), fnPtr);
	std::cout << _xor_("").c_str() << std::endl;

	*(uint64_t*)(dll_stub + 0x18) = fnPtr;
	*(uint64_t*)(dll_stub + 0x22) = orginal_function_addr;

	proc->write_memory(base, (uintptr_t)raw_data, nt_header->FileHeader.SizeOfOptionalHeader + sizeof(nt_header->FileHeader) + sizeof(nt_header->Signature));
	map_pe_sections(base, nt_header);

	uint64_t entry_point{ (uint64_t)base + nt_header->OptionalHeader.AddressOfEntryPoint };

	*(uint64_t*)(dll_stub + 0x39) = (uint64_t)base;
	*(uint64_t*)(dll_stub + 0x4a) = entry_point;

	printf(_xor_("Entry point: 0x%p").c_str(), entry_point);

	proc->write_memory(stub_base, (uintptr_t)dll_stub, sizeof(dll_stub));

	proc->virtual_protect(fnPtr, sizeof(uint64_t), PAGE_READWRITE);
	proc->write_memory(fnPtr, (uintptr_t)&stub_base, sizeof(uint64_t));

	system(_xor_("Pause").c_str());
	proc->virtual_protect(fnPtr, sizeof(uint64_t), PAGE_READONLY);

	delete [] raw_data;

	return true;
} 

uint64_t* mmap::get_ptr_from_rva(uint64_t rva, IMAGE_NT_HEADERS * nt_header, uint8_t * image_base) {
	PIMAGE_SECTION_HEADER section_header{ get_enclosing_section_header(rva, nt_header) };

	if (!section_header)
		return 0; 

	int64_t delta{ (int64_t)(section_header->VirtualAddress - section_header->PointerToRawData) };
	return (uint64_t*)(image_base + rva - delta);
}

PIMAGE_SECTION_HEADER mmap::get_enclosing_section_header(uint64_t rva, PIMAGE_NT_HEADERS nt_header) {
	PIMAGE_SECTION_HEADER section{ IMAGE_FIRST_SECTION(nt_header) };  

	for (int i = 0; i < nt_header->FileHeader.NumberOfSections; i++, section++) { 
		uint64_t size{ section->Misc.VirtualSize };
		if (!size)
			size = section->SizeOfRawData;

		if ((rva >= section->VirtualAddress) &&
			(rva < (section->VirtualAddress + size)))
			return section;
	} 

	return 0;
}
  
void mmap::solve_imports(uint8_t *base, IMAGE_NT_HEADERS *nt_header, IMAGE_IMPORT_DESCRIPTOR *import_descriptor) {
	char* module; 
	while ((module = (char *)get_ptr_from_rva((DWORD64)(import_descriptor->Name), nt_header, (PBYTE)base))) {
		HMODULE local_module{LoadLibrary(module)};
		
		IMAGE_THUNK_DATA *thunk_data{ (IMAGE_THUNK_DATA *)get_ptr_from_rva((DWORD64)(import_descriptor->FirstThunk), nt_header, (PBYTE)base) };

		while (thunk_data->u1.AddressOfData) {
			IMAGE_IMPORT_BY_NAME *iibn{ (IMAGE_IMPORT_BY_NAME *)get_ptr_from_rva((DWORD64)((thunk_data->u1.AddressOfData)), nt_header, (PBYTE)base) };
			thunk_data->u1.Function = (uint64_t)(get_proc_address(module, (char *)iibn->Name));
			thunk_data++;
		} 
		import_descriptor++;
	} 

	return;
}
 
void mmap::solve_relocations(uint64_t base, uint64_t relocation_base, IMAGE_NT_HEADERS * nt_header, IMAGE_BASE_RELOCATION * reloc, size_t size) {
	uint64_t image_base{ nt_header->OptionalHeader.ImageBase };
	uint64_t delta{ relocation_base - image_base };
	unsigned int bytes{ 0 };  

	while (bytes < size) {
		uint64_t *reloc_base{ (uint64_t *)get_ptr_from_rva((uint64_t)(reloc->VirtualAddress), nt_header, (PBYTE)base) };
		auto num_of_relocations{ (reloc->SizeOfBlock - sizeof(IMAGE_BASE_RELOCATION)) / sizeof(WORD) };
		auto reloc_data = (uint16_t*)((uint64_t)reloc + sizeof(IMAGE_BASE_RELOCATION));

		for (unsigned int i = 0; i < num_of_relocations; i++) {
			if (((*reloc_data >> 12) & IMAGE_REL_BASED_HIGHLOW))
				*(uint64_t*)((uint64_t)reloc_base + ((uint64_t)(*reloc_data & 0x0FFF))) += delta;
			reloc_data++;
		}

		bytes += reloc->SizeOfBlock;
		reloc = (IMAGE_BASE_RELOCATION *)reloc_data;
	}

	return;
}

void mmap::map_pe_sections(uint64_t base, IMAGE_NT_HEADERS * nt_header) {
	auto header{ IMAGE_FIRST_SECTION(nt_header) };
	size_t virtual_size{ 0 };
	size_t bytes{ 0 }; 

	while(nt_header->FileHeader.NumberOfSections&&(bytes<nt_header->OptionalHeader.SizeOfImage)) { 
		proc->write_memory(base + header->VirtualAddress, (uintptr_t)(raw_data + header->PointerToRawData), header->SizeOfRawData); 
		virtual_size = header->VirtualAddress; 
		virtual_size = (++header)->VirtualAddress - virtual_size;
		bytes += virtual_size;
	}

	return;
}

uint64_t mmap::get_proc_address(const char* module_name, const char* func) {
	uint64_t remote_module{ proc->get_module_base(module_name) };
	uint64_t local_module{ (uint64_t)GetModuleHandle(module_name) };
	uint64_t delta{ remote_module - local_module };

	return ((uint64_t)GetProcAddress((HMODULE)local_module, func) + delta);
}
