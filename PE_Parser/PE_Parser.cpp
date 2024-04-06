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

#define DEBUG


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
#ifdef DEBUG
    cout << "[+] DOS header parsed successfully" << endl;
    
    cout << std::format("e_magic: {0:#06x} = {1}{2}\n", dos_header->e_magic, reinterpret_cast<char*>(&dos_header->e_magic)[0], reinterpret_cast<char*>(&dos_header->e_magic)[1]);
    cout << std::format("e_alfnew: {0:#06x}\n\n", dos_header->e_lfanew);
#endif
}

void fillDosStub(ifstream& pe_file) {
    int sizeOfStub = dos_header->e_lfanew - sizeof(IMAGE_DOS_HEADER);
    dos_stub = new char[sizeOfStub];
    pe_file.read(dos_stub, sizeOfStub);
#ifdef DEBUG
    cout << "[+] DOS Stub parsed successfully"<<endl;
    cout << std::format("size of dos stub(decimal): {}\n\n", sizeOfStub);
#endif
}

void fillNtHeaders(ifstream& pe_file) {
    char* nt_buffer = new char[sizeof(IMAGE_NT_HEADERS)];
    pe_file.read(nt_buffer, sizeof(IMAGE_NT_HEADERS));
    nt_header = reinterpret_cast<IMAGE_NT_HEADERS*>(nt_buffer);

#ifdef DEBUG
    cout << "[+] NT Headers parsed successfully\n";
    cout << std::format("PE Signature: {0:#08x} = {1}{2}\n", \
        nt_header->Signature, \
        reinterpret_cast<char*>(&nt_header->Signature)[0], \
        reinterpret_cast<char*>(&nt_header->Signature)[1]);
    cout << std::format("PE Address of Entry Point: {0:#06x}\n", nt_header->OptionalHeader.AddressOfEntryPoint);
    cout << std::format("PE Image Base: {0:#x}\n\n", nt_header->OptionalHeader.ImageBase);
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