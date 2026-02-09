#include "error.hpp"

struct HandleWrapper
{
    HANDLE handle;

    explicit HandleWrapper(HANDLE h) : handle(h) {}

    ~HandleWrapper()
    {
        if (handle != INVALID_HANDLE_VALUE)
        {
            CloseHandle(handle);
        }
    }
};

void print_header(const std::string &title)
{
    constexpr size_t WIDTH = 40;
    size_t first = (WIDTH - title.size()) / 2, second = WIDTH - first - title.size();
    for (size_t i = 0; i < first; i++)
    {
        std::cout << '=';
    }
    std::cout << ' ' << title << ' ';
    for (size_t i = 0; i < second; i++)
    {
        std::cout << '=';
    }
    std::cout << std::endl;
}

int main(int argc, char *argv[])
{
    if (argc < 2)
    {
        std::cerr << "Usage: reader <target_executable>\n";
        return 1;
    }

    char *target = argv[1];
    int required = MultiByteToWideChar(CP_OEMCP, 0, target, -1, nullptr, 0);
    if (required == 0)
    {
        print_last_error();
        return 1;
    }

    std::wstring target_path(required, L'\0');
    if (MultiByteToWideChar(CP_OEMCP, 0, target, -1, target_path.data(), required) == 0)
    {
        print_last_error();
        return 1;
    }

    HandleWrapper file(CreateFileW(
        target_path.c_str(),
        GENERIC_READ,
        0,
        nullptr,
        OPEN_EXISTING,
        FILE_ATTRIBUTE_NORMAL,
        nullptr));
    if (file.handle == INVALID_HANDLE_VALUE)
    {
        print_last_error();
        return 1;
    }

    constexpr size_t SIZE_LIMIT = 20 * 1024 * 1024; // 20 MB
    std::vector<uint8_t> data(SIZE_LIMIT);

    DWORD actual_size = 0;
    if (!ReadFile(file.handle, data.data(), data.size(), &actual_size, nullptr))
    {
        print_last_error();
        return 1;
    }

    data.resize(actual_size);

    IMAGE_DOS_HEADER *dos_header = reinterpret_cast<IMAGE_DOS_HEADER *>(data.data());
    if (dos_header->e_magic != IMAGE_DOS_SIGNATURE)
    {
        std::cerr << "Invalid DOS signature 0x" << std::hex << dos_header->e_magic << std::dec << "\n";
        return 1;
    }

    IMAGE_NT_HEADERS *nt_headers = reinterpret_cast<IMAGE_NT_HEADERS *>(data.data() + dos_header->e_lfanew);
    if (nt_headers->Signature != IMAGE_NT_SIGNATURE)
    {
        std::cerr << "Invalid NT signature 0x" << std::hex << nt_headers->Signature << std::dec << "\n";
        return 1;
    }

    IMAGE_OPTIONAL_HEADER *optional_header = &nt_headers->OptionalHeader;
    if (optional_header->Magic != IMAGE_NT_OPTIONAL_HDR_MAGIC)
    {
        std::cerr << "Invalid optional header magic 0x" << std::hex << optional_header->Magic << std::dec << "\n";
        return 1;
    }

    print_header("DOS HEADER");
    std::cout << "Bytes on last page of file: " << dos_header->e_cblp << "\n";
    std::cout << "Pages in file: " << dos_header->e_cp << "\n";
    std::cout << "Relocations: " << dos_header->e_crlc << "\n";
    std::cout << "Size of header in paragraphs: " << dos_header->e_cparhdr << "\n";
    std::cout << "Minimum extra paragraphs needed: " << dos_header->e_minalloc << "\n";
    std::cout << "Maximum extra paragraphs needed: " << dos_header->e_maxalloc << "\n";
    std::cout << "Initial (relative) SS value: 0x" << std::hex << dos_header->e_ss << std::dec << "\n";
    std::cout << "Initial SP value: 0x" << std::hex << dos_header->e_sp << std::dec << "\n";
    std::cout << "Checksum: 0x" << std::hex << dos_header->e_csum << std::dec << "\n";
    std::cout << "Initial IP value: 0x" << std::hex << dos_header->e_ip << std::dec << "\n";
    std::cout << "Initial (relative) CS value: 0x" << std::hex << dos_header->e_cs << std::dec << "\n";
    std::cout << "File address of relocation table: 0x" << std::hex << dos_header->e_lfarlc << std::dec << "\n";
    std::cout << "Overlay number: " << dos_header->e_ovno << "\n";
    std::cout << "OEM identifier: 0x" << std::hex << dos_header->e_oemid << std::dec << "\n";
    std::cout << "OEM information: 0x" << std::hex << dos_header->e_oeminfo << std::dec << "\n";
    std::cout << "File address of new exe header: 0x" << std::hex << dos_header->e_lfanew << std::dec << "\n";

    IMAGE_FILE_HEADER *file_header = &nt_headers->FileHeader;
    print_header("FILE HEADER");
    std::cout << "Machine: 0x" << std::hex << file_header->Machine << std::dec << "\n";
    std::cout << "Number of sections: " << file_header->NumberOfSections << "\n";
    std::cout << "Low 32 bits of timestamp: 0x" << std::hex << file_header->TimeDateStamp << std::dec << "\n";
    std::cout << "Pointer to symbol table: 0x" << std::hex << file_header->PointerToSymbolTable << std::dec << "\n";
    std::cout << "Number of symbols: " << file_header->NumberOfSymbols << "\n";
    std::cout << "Size of optional header: " << file_header->SizeOfOptionalHeader << "\n";
    std::cout << "Characteristics: 0x" << std::hex << file_header->Characteristics << std::dec << "\n";

    print_header("OPTIONAL HEADER");
    std::cout << "Major linker version: " << (int)optional_header->MajorLinkerVersion << "\n";
    std::cout << "Minor linker version: " << (int)optional_header->MinorLinkerVersion << "\n";
    std::cout << "Size of code: " << optional_header->SizeOfCode << std::dec << "\n";
    std::cout << "Size of initialized data: " << optional_header->SizeOfInitializedData << std::dec << "\n";
    std::cout << "Size of uninitialized data: " << optional_header->SizeOfUninitializedData << std::dec << "\n";
    std::cout << "Address of entry point: 0x" << std::hex << optional_header->AddressOfEntryPoint << std::dec << "\n";
    std::cout << "Base of code: 0x" << std::hex << optional_header->BaseOfCode << std::dec << "\n";
    std::cout << "Image base: 0x" << std::hex << optional_header->ImageBase << std::dec << "\n";
    std::cout << "Section alignment: 0x" << std::hex << optional_header->SectionAlignment << std::dec << "\n";
    std::cout << "File alignment: 0x" << std::hex << optional_header->FileAlignment << std::dec << "\n";
    std::cout << "Major operating system version: " << optional_header->MajorOperatingSystemVersion << "\n";
    std::cout << "Minor operating system version: " << optional_header->MinorOperatingSystemVersion << "\n";
    std::cout << "Major image version: " << optional_header->MajorImageVersion << "\n";
    std::cout << "Minor image version: " << optional_header->MinorImageVersion << "\n";
    std::cout << "Major subsystem version: " << optional_header->MajorSubsystemVersion << "\n";
    std::cout << "Minor subsystem version: " << optional_header->MinorSubsystemVersion << "\n";
    std::cout << "Win32 version value: " << optional_header->Win32VersionValue << "\n";
    std::cout << "Size of image: " << optional_header->SizeOfImage << std::dec << "\n";
    std::cout << "Size of headers: " << optional_header->SizeOfHeaders << std::dec << "\n";
    std::cout << "Checksum: 0x" << std::hex << optional_header->CheckSum << std::dec << "\n";
    std::cout << "Subsystem: 0x" << std::hex << optional_header->Subsystem << std::dec << "\n";
    std::cout << "DLL characteristics: 0x" << std::hex << optional_header->DllCharacteristics << std::dec << "\n";
    std::cout << "Size of stack reserve: " << optional_header->SizeOfStackReserve << std::dec << "\n";
    std::cout << "Size of stack commit: " << optional_header->SizeOfStackCommit << std::dec << "\n";
    std::cout << "Size of heap reserve: " << optional_header->SizeOfHeapReserve << std::dec << "\n";
    std::cout << "Size of heap commit: " << optional_header->SizeOfHeapCommit << std::dec << "\n";
    std::cout << "Loader flags: 0x" << std::hex << optional_header->LoaderFlags << std::dec << "\n";
    std::cout << "Number of RVA and sizes: " << optional_header->NumberOfRvaAndSizes << "\n";

    for (DWORD i = 0; i < optional_header->NumberOfRvaAndSizes; i++)
    {
        std::cout << "DataDirectory[" << i << "]: VirtualAddress=0x" << std::hex
                  << optional_header->DataDirectory[i].VirtualAddress << std::dec
                  << " Size=" << optional_header->DataDirectory[i].Size
                  << "\n";
    }

    IMAGE_SECTION_HEADER *section = IMAGE_FIRST_SECTION(nt_headers);
    for (WORD i = 0; i < nt_headers->FileHeader.NumberOfSections; i++, section++)
    {
        print_header("SECTION HEADER " + std::to_string(i + 1));
        char name[9] = {};
        memcpy(name, section->Name, 8);
        std::cout << "Name: " << name << "\n";
        std::cout << "Virtual size: " << section->Misc.VirtualSize << "\n";
        std::cout << "Virtual address: 0x" << std::hex << section->VirtualAddress << std::dec << "\n";
        std::cout << "Size of raw data: " << section->SizeOfRawData << "\n";
        std::cout << "Pointer to raw data: 0x" << std::hex << section->PointerToRawData << std::dec << "\n";
        std::cout << "Pointer to relocations: 0x" << std::hex << section->PointerToRelocations << std::dec << "\n";
        std::cout << "Pointer to line numbers: 0x" << std::hex << section->PointerToLinenumbers << std::dec << "\n";
        std::cout << "Number of relocations: " << section->NumberOfRelocations << "\n";
        std::cout << "Number of line numbers: " << section->NumberOfLinenumbers << "\n";
        std::cout << "Characteristics: 0x" << std::hex << section->Characteristics << std::dec << "\n";
    }

    return 0;
}
