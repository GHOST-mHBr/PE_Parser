#include <Windows.h>
#include <string>
#include <fstream>
#include <exception>
#include <iostream>
#include <format>

using std::ifstream;
using std::string;
using std::cout;
using std::cin;
using std::endl;

#define OUTPUT

const string dataDirectoriesNames[] = { "Export Directory", "Import Directory" ,\
                                        "Resource Directory", "Exceptions Directory" ,\
                                        "Security Directory" , "Relocation Table" ,\
                                        "Debug Directory", "Architecture Data" , "GP",\
                                        "TLS Directory", "Load Configuration Directory",\
                                        "Bound Import Directory", "Import Address Table" ,\
                                        "Delayed Load Import Descriptors", "COM Runtime descriptor"};

IMAGE_DOS_HEADER* dos_header{0,};
char* dos_stub{0,};
IMAGE_NT_HEADERS* nt_header{0,};


ifstream open_pe(const string& path){
    ifstream pe;
    pe.open(path.c_str(), std::ios::binary);

    if (pe.is_open() && pe.good()) {
        return pe;
    }
    else {
        cout << "[-] PE not found\\:\nTerminating...\n";
        exit(-1);
    }
}

void fillDosHeader(ifstream& pe_file) {
    //Reading dos header's raw bytes from PE
    char* dos_header_raw = new char[sizeof(IMAGE_DOS_HEADER)];
    pe_file.read(dos_header_raw, sizeof(IMAGE_DOS_HEADER));

    //Casting to dos header
    dos_header = (IMAGE_DOS_HEADER*)dos_header_raw;

    //Test
#ifdef OUTPUT
    cout << "[+] DOS header parsed successfully" << endl;
    
    cout << std::format("e_magic: {0:#06x} = {1}{2}\n", dos_header->e_magic, reinterpret_cast<char*>(&dos_header->e_magic)[0], reinterpret_cast<char*>(&dos_header->e_magic)[1]);
    cout << std::format("e_alfnew: {0:#06x}\n\n", dos_header->e_lfanew);
#endif
}

void fillDosStub(ifstream& pe_file) {
    int sizeOfStub = dos_header->e_lfanew - sizeof(IMAGE_DOS_HEADER);
    dos_stub = new char[sizeOfStub];
    pe_file.read(dos_stub, sizeOfStub);
#ifdef OUTPUT
    cout << "[+] DOS Stub parsed successfully"<<endl;
    cout << std::format("size of dos stub(decimal): {}\n\n", sizeOfStub);
#endif
}

void fillNtHeaders(ifstream& pe_file) {
    char* nt_buffer = new char[sizeof(IMAGE_NT_HEADERS)];
    pe_file.read(nt_buffer, sizeof(IMAGE_NT_HEADERS));
    nt_header = reinterpret_cast<IMAGE_NT_HEADERS*>(nt_buffer);

#ifdef OUTPUT
    cout << "[+] NT Headers parsed successfully\n";
    cout << std::format("PE Signature: {0:#08x} = {1}{2}{3}{4}\n", \
        nt_header->Signature, \
        reinterpret_cast<char*>(&nt_header->Signature)[0], \
        reinterpret_cast<char*>(&nt_header->Signature)[1], \
        reinterpret_cast<char*>(&nt_header->Signature)[2], \
        reinterpret_cast<char*>(&nt_header->Signature)[3]);

    cout << std::format("Magic: {0:#06x}\n", nt_header->OptionalHeader.Magic);
    cout << std::format("DLL Charactristics: {0:#06x}\n", nt_header->OptionalHeader.DllCharacteristics);
    cout << std::format("File Alignment: {0:#x}\n", nt_header->OptionalHeader.FileAlignment);
    cout << std::format("Section Alignment: {0:#x}\n", nt_header->OptionalHeader.SectionAlignment);
    cout << std::format("Image Base: {0:#x}\n", nt_header->OptionalHeader.ImageBase);
    cout << std::format("Address of Entry Point: {0:#06x}\n", nt_header->OptionalHeader.AddressOfEntryPoint);
    cout << std::format("Base of code: {0:#06x}\n", nt_header->OptionalHeader.BaseOfCode);
    cout << std::format("Base of data: {0:#06x}\n", nt_header->OptionalHeader.BaseOfData);
    cout << std::format("Number of RVA and size: {0:#x}\n\n", nt_header->OptionalHeader.NumberOfRvaAndSizes);
    cout << "[i] DataDirectories:" << endl;
    for (DWORD i = 0; i < nt_header->OptionalHeader.NumberOfRvaAndSizes; i++) {
        auto cur = nt_header->OptionalHeader.DataDirectory[i];
        if (cur.Size > 0) {
            cout << std::format("Index:{} ({})\n", i, dataDirectoriesNames[i]);
            cout << std::format("VirutalAddress: {0:#x}\t\t", cur.VirtualAddress);
            cout << std::format("Size: {0:#x}\n\n", cur.Size);
        }
    }

#endif
}

int main()
{
    //Getting PE path
    string pe_path = "";
    cout << "Enter PE path please:";
    cin >> pe_path;

    //Opening the PE file
    auto pe_stream = open_pe(pe_path);

    fillDosHeader(pe_stream);
    fillDosStub(pe_stream);
    fillNtHeaders(pe_stream);
    
    delete[] dos_stub;
    delete[] dos_header;
    delete[] nt_header;

    pe_stream.close();
}