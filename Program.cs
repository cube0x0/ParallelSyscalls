using System;
using System.Collections.Generic;
using System.Linq;
using System.Runtime.InteropServices;
using System.Text;
using System.Threading.Tasks;
using static ParallelSyscalls.Natives;

namespace ParallelSyscalls
{
    class Program
    {
        // Global syscall functions
        public static NtOpenFile funcNtOpenFile;
        public static NtCreateSection funcNtCreateSection;
        public static NtMapViewOfSection funcNtMapViewOfSection;


        public static IntPtr GetSyscall(Dictionary<string, IntPtr> book, string pzSyscallName)
        {
            foreach(var i in book)
            {
                if ((i.Key == pzSyscallName))
                {
                    return i.Value;
                }
            }

            return IntPtr.Zero;
        }

        public static bool InitSyscallsFromLdrpThunkSignature()
        {
            // Find loaded NTDLL.DLL in PEB
            _PEB Peb = GetPeb();
            LDR_DATA_TABLE_ENTRY NtdllLdrEntry = new LDR_DATA_TABLE_ENTRY();
            
            IntPtr startLink = Marshal.PtrToStructure<PEB_LDR_DATA>(Peb.Ldr).InLoadOrderModuleList.Flink;
            LDR_DATA_TABLE_ENTRY LdrEntry = Marshal.PtrToStructure <LDR_DATA_TABLE_ENTRY>(startLink);

            while(true)
            {
                if (LdrEntry.DllBase == IntPtr.Zero)
                {
                    break;
                }
                if (LdrEntry.InLoadOrderLinks.Flink == startLink)
                {
                    break;
                }

                if (LdrEntry.BaseDllName.GetText() == "ntdll.dll")
                {
                    //Console.WriteLine("[+] Found ntdll in PEB: {0}", LdrEntry.DllBase);
                    NtdllLdrEntry = LdrEntry;
                    break;
                }
                LdrEntry = Marshal.PtrToStructure<LDR_DATA_TABLE_ENTRY>(LdrEntry.InLoadOrderLinks.Flink);
            }
            
            if(NtdllLdrEntry.DllBase == IntPtr.Zero)
            {
                Console.WriteLine("[-] Could not find ntdll.dll");
                return false;
            }


            // Get PE sections
            IMAGE_DOS_HEADER dosHeader = Marshal.PtrToStructure<IMAGE_DOS_HEADER>(NtdllLdrEntry.DllBase);
            IMAGE_NT_HEADERS ImageNtHeaders = Marshal.PtrToStructure<IMAGE_NT_HEADERS>(NtdllLdrEntry.DllBase + dosHeader.e_lfanew);
            List<IMAGE_SECTION_HEADER> SectionHeaders = new List<IMAGE_SECTION_HEADER>();
            IntPtr pStart = (IntPtr)(NtdllLdrEntry.DllBase 
                + dosHeader.e_lfanew
                + Marshal.SizeOf(typeof(IMAGE_FILE_HEADER))
                + ImageNtHeaders.FileHeader.SizeOfOptionalHeader
                + sizeof(Int32));
            for (int i = 0; i < ImageNtHeaders.FileHeader.NumberOfSections; i++)
            {
                int offset = i * Marshal.SizeOf(typeof(IMAGE_SECTION_HEADER));
                IMAGE_SECTION_HEADER sectionHeader = Marshal.PtrToStructure<IMAGE_SECTION_HEADER>(pStart + offset);
                SectionHeaders.Add(sectionHeader);
            }

            // Get .data section
            IntPtr DataSectionAddress = IntPtr.Zero;
            uint DataSectionSize = 0;
            for (int i = 0; i < ImageNtHeaders.FileHeader.NumberOfSections; i++)
            {
                if (SectionHeaders[i].SectionName.StartsWith(".data"))
                {
                    DataSectionAddress = NtdllLdrEntry.DllBase + (int)SectionHeaders[i].VirtualAddress;
                    DataSectionSize = SectionHeaders[i].VirtualSize;
                    break;
                }
            }
            if (DataSectionAddress == IntPtr.Zero || DataSectionSize < (16 * 5))
            {
                return false;
            }

            // Get syscalls from LdrpThunkSignature
            uint dwSyscallNo_NtOpenFile = 0, dwSyscallNo_NtCreateSection = 0, dwSyscallNo_NtMapViewOfSection = 0;
            for (int uiOffset = 0; uiOffset < DataSectionSize - (16 * 5); uiOffset++)
            {
                IntPtr offset = DataSectionAddress + uiOffset;
                uint offsetValue = (uint)Marshal.ReadInt32(offset);
                uint offset1Value = (uint)Marshal.ReadInt32(offset, 16);
                uint offset2Value = (uint)Marshal.ReadInt32(offset, 32);
                uint offset3Value = (uint)Marshal.ReadInt32(offset, 48);
                uint offset4Value = (uint)Marshal.ReadInt32(offset, 64);

                if (offsetValue == 0xb8d18b4c &&
                    offset1Value == 0xb8d18b4c &&
                    offset2Value == 0xb8d18b4c &&
                    offset3Value == 0xb8d18b4c &&
                    offset4Value == 0xb8d18b4c)
                {
                    dwSyscallNo_NtOpenFile = (uint)Marshal.ReadInt32(offset, 4);
                    dwSyscallNo_NtCreateSection = (uint)Marshal.ReadInt32(offset, 16 + 4);
                    dwSyscallNo_NtMapViewOfSection = (uint)Marshal.ReadInt32(offset, 64 + 4);

                    break;
                }
            }

            if (dwSyscallNo_NtOpenFile == 0)
            {
                return false;
            }

            int MAX_SYSCALL_STUB_SIZE = 64;
            IntPtr SyscallRegion = VirtualAlloc(IntPtr.Zero, (uint)(3 * MAX_SYSCALL_STUB_SIZE), 0x2000 | 0x1000, 0x00000040);

            if (SyscallRegion == IntPtr.Zero)
            {
                return false;
            }

            IntPtr NtOpenFile = BuildSyscallStub(SyscallRegion, dwSyscallNo_NtOpenFile);
            IntPtr NtCreateSection = BuildSyscallStub(SyscallRegion + MAX_SYSCALL_STUB_SIZE, dwSyscallNo_NtCreateSection);
            IntPtr NtMapViewOfSection = BuildSyscallStub(SyscallRegion + (2 * MAX_SYSCALL_STUB_SIZE), dwSyscallNo_NtMapViewOfSection);

            funcNtOpenFile = Marshal.GetDelegateForFunctionPointer<NtOpenFile>(NtOpenFile);
            funcNtCreateSection = Marshal.GetDelegateForFunctionPointer<NtCreateSection>(NtCreateSection);
            funcNtMapViewOfSection = Marshal.GetDelegateForFunctionPointer<NtMapViewOfSection>(NtMapViewOfSection);

            return true;
        }

        public static IntPtr BuildSyscallStub(IntPtr StubRegion, uint dwSyscallNo)
        {
            byte[] SyscallStub = new byte[]
            {
                0x4c, 0x8b, 0xd1,				// mov r10,rcx
	        	0xb8, 0x00, 0x00, 0x00, 0x00,	// mov eax, 0x?? (?? == Syscall Identifier)
	        	0x0f, 0x05,						// syscall
	        	0xc3							// ret
	        };
            // update SyscallStub template
            SyscallStub[4] = (byte)(dwSyscallNo);

            // copy syscall template bytes to page
            Marshal.Copy(SyscallStub, 0, StubRegion, SyscallStub.Length);
            //Marshal.WriteInt32(StubRegion, 4, (int)dwSyscallNo);

            return StubRegion;
        }

        public static IntPtr LoadNtdllIntoSection()
        {
            NTSTATUS ntStatus;
            IntPtr hFile = IntPtr.Zero;
            OBJECT_ATTRIBUTES ObjectAttributes = new OBJECT_ATTRIBUTES();
            IO_STATUS_BLOCK IoStatusBlock = new IO_STATUS_BLOCK();
            IntPtr hSection = IntPtr.Zero;
            IntPtr lpvSection = IntPtr.Zero;
            ulong viewSize = 0;
            UNICODE_STRING ObjectPath = new UNICODE_STRING();
            RtlInitUnicodeString(ref ObjectPath, "\\??\\C:\\Windows\\System32\\ntdll.dll");
            IntPtr pObjectName = Marshal.AllocHGlobal(Marshal.SizeOf(ObjectPath));
            Marshal.StructureToPtr(ObjectPath, pObjectName, true);

            ObjectAttributes.Length = Marshal.SizeOf(typeof(OBJECT_ATTRIBUTES));
            ObjectAttributes.ObjectName = pObjectName;
            ObjectAttributes.Attributes = 0x40; //OBJ_CASE_INSENSITIVE
            ObjectAttributes.RootDirectory = IntPtr.Zero;
            ObjectAttributes.SecurityDescriptor = IntPtr.Zero;
            ObjectAttributes.SecurityQualityOfService = IntPtr.Zero;



            //NtOpenFile > NtCreateSection > NtMapViewOfSection
            ntStatus = funcNtOpenFile(
                ref hFile, 
                FileAccessFlags.FILE_READ_DATA, 
                ref ObjectAttributes, 
                ref IoStatusBlock, 
                FileShareFlags.FILE_SHARE_READ, 
                0);
            
            if (hFile == IntPtr.Zero)
            {
                return IntPtr.Zero;
            }

            ulong maxsize = 0;
            ntStatus = funcNtCreateSection(
                ref hSection,
                0x0002 | 0x0004 | 0x0008, //SECTION_ALL_ACCESS,
                IntPtr.Zero,
                ref maxsize,
                0x00000002, //PAGE_READONLY
                0x08000000, //sec_commit
                hFile
            );
            
            if (hSection == IntPtr.Zero)
            {
                if (hFile != IntPtr.Zero)
                    CloseHandle(hFile);
                return IntPtr.Zero;
            }

            ntStatus = funcNtMapViewOfSection(
                hSection,
                GetCurrentProcess(),
                out lpvSection,
                IntPtr.Zero,
                IntPtr.Zero,
                IntPtr.Zero,
                out viewSize,
                1,
                0,
                0x00000002); //PAGE_READONLY
            
            if (hSection != IntPtr.Zero) 
                CloseHandle(hSection);
            if (hFile != IntPtr.Zero) 
                CloseHandle(hFile);

            //Console.WriteLine("[+] unhooked ntdll: {0}", lpvSection.ToInt64());

            return lpvSection;
        }


        public static uint ExtractSyscalls(IntPtr pNtdll, ref Dictionary<string, IntPtr> book)
        {
            //
            IMAGE_DOS_HEADER DosHeader = Marshal.PtrToStructure<IMAGE_DOS_HEADER>(pNtdll);
            IMAGE_NT_HEADERS ImageNtHeaders = Marshal.PtrToStructure <IMAGE_NT_HEADERS>(pNtdll + DosHeader.e_lfanew);
            List<IMAGE_SECTION_HEADER> SectionHeaders = new List<IMAGE_SECTION_HEADER>();
            IntPtr pStart = (IntPtr)(pNtdll
                + DosHeader.e_lfanew
                + Marshal.SizeOf(typeof(IMAGE_FILE_HEADER))
                + ImageNtHeaders.FileHeader.SizeOfOptionalHeader
                + sizeof(Int32));
            for (int i = 0; i < ImageNtHeaders.FileHeader.NumberOfSections; i++)
            {
                int offset = i * Marshal.SizeOf(typeof(IMAGE_SECTION_HEADER));
                IMAGE_SECTION_HEADER sectionHeader = Marshal.PtrToStructure<IMAGE_SECTION_HEADER>(pStart + offset);
                SectionHeaders.Add(sectionHeader);
            }

            //
            IMAGE_DATA_DIRECTORY[] DataDirectory = ImageNtHeaders.OptionalHeader.DataDirectory;
            uint VirtualAddress = DataDirectory[0].VirtualAddress;
            IMAGE_EXPORT_DIRECTORY ExportDirectory = Marshal.PtrToStructure<IMAGE_EXPORT_DIRECTORY>(RVAToFileOffsetPointer(pNtdll, VirtualAddress));


            uint NumberOfNames = ExportDirectory.NumberOfNames;
            NumberOfNames = ExportDirectory.NumberOfNames;

            IntPtr Functions = RVAToFileOffsetPointer(pNtdll, ExportDirectory.AddressOfFunctions);
            IntPtr Names = RVAToFileOffsetPointer(pNtdll, ExportDirectory.AddressOfNames);
            IntPtr Ordinals = RVAToFileOffsetPointer(pNtdll, ExportDirectory.AddressOfNameOrdinals);

            //Console.WriteLine("Functions: {0}", Functions);
            //Console.WriteLine("Names: {0}", Names);
            //Console.WriteLine("Ordinals: {0}", Ordinals);

            uint uiCount = 0;
            uint MAX_SYSCALL_STUB_SIZE = 64;
            uint MAX_NUMBER_OF_SYSCALLS = 1024;
            IntPtr pStubs = VirtualAlloc(IntPtr.Zero, MAX_NUMBER_OF_SYSCALLS * MAX_SYSCALL_STUB_SIZE, 0x2000 | 0x1000, 0x00000040);

            if (pStubs == IntPtr.Zero)
            {
                return 0;
            }

            for (int i = 0; i < NumberOfNames && uiCount < MAX_NUMBER_OF_SYSCALLS; i++)
            {
                uint nameAddress = (uint)Marshal.ReadInt32(Names + i * 4);
                IntPtr AddressOfNames_single_offset = RVAToFileOffsetPointer(pNtdll, nameAddress);
                
                byte[] bFunctionName = new byte[1024];
                Marshal.Copy(AddressOfNames_single_offset, bFunctionName, 0, 1024);
                for (int length = 0; length < 1024; length++)
                {
                    if (bFunctionName[length] == 0x00)
                    {
                        bFunctionName = bFunctionName.Take(length).ToArray();
                        break;
                    }
                }
                string sFunctionName = Encoding.ASCII.GetString(bFunctionName);
                //Console.WriteLine(sFunctionName);

                if (sFunctionName.StartsWith("Zw"))
                {
                    uint ordinalAddress  = (uint)Marshal.ReadInt16(Ordinals + 2 * i);
                    uint functionAddress  = (uint)Marshal.ReadInt32(Functions + (int)(4 * ordinalAddress));

                    IntPtr FunctionPtr = RVAToFileOffsetPointer(pNtdll, functionAddress);
                    IntPtr FunctionEnd = FindBytes(FunctionPtr, MAX_SYSCALL_STUB_SIZE, new byte[] { 0x0f, 0x05, 0xc3 }, 3) + 3;

                    //Console.WriteLine("start: {0}, end {1}", FunctionPtr, FunctionEnd);

                    if (FunctionEnd != IntPtr.Zero)
                    {
                        // copy bytes from unhooked ntdll
                        long size = FunctionEnd.ToInt64() - FunctionPtr.ToInt64();
                        byte[] functionbytes = new byte[size];
                        Marshal.Copy(FunctionPtr, functionbytes, 0, (int)size);

                        // copy bytes to syscall page
                        IntPtr pSyscall = pStubs + (int)(uiCount * MAX_SYSCALL_STUB_SIZE);
                        Marshal.Copy(functionbytes, 0, pSyscall, (int)size);

                        book.Add(sFunctionName, pSyscall);
                        uiCount++;
                    }
                }
            }

            return uiCount;
        }

        public static IntPtr FindBytes(IntPtr Source, uint SourceLength, byte[] Search, int SearchLength)
        {
            while (SearchLength <= SourceLength)
            {
                byte[] temp = new byte[SearchLength];
                Marshal.Copy(Source, temp, 0 , SearchLength);
                if(temp.SequenceEqual(Search))
                {
                    return Source;
                }
                
                Source = Source + 1;
                SourceLength--;
            }

            return IntPtr.Zero;
        }

        public static IntPtr RVAToFileOffsetPointer(IntPtr pModule, uint dwRVA)
        {
            IMAGE_DOS_HEADER DosHeader = Marshal.PtrToStructure<IMAGE_DOS_HEADER>(pModule);
            IMAGE_NT_HEADERS ImageNtHeaders = Marshal.PtrToStructure<IMAGE_NT_HEADERS>(pModule + DosHeader.e_lfanew);
            List<IMAGE_SECTION_HEADER> SectionHeaders = new List<IMAGE_SECTION_HEADER>();
            IntPtr pStart = (IntPtr)(pModule
                + DosHeader.e_lfanew
                + Marshal.SizeOf(typeof(IMAGE_FILE_HEADER))
                + ImageNtHeaders.FileHeader.SizeOfOptionalHeader
                + sizeof(Int32));
            for (int i = 0; i < ImageNtHeaders.FileHeader.NumberOfSections; i++)
            {
                int offset = i * Marshal.SizeOf(typeof(IMAGE_SECTION_HEADER));
                IMAGE_SECTION_HEADER sectionHeader = Marshal.PtrToStructure<IMAGE_SECTION_HEADER>(pStart + offset);
                SectionHeaders.Add(sectionHeader);
            }


            for (int i = 0; i < ImageNtHeaders.FileHeader.NumberOfSections; i++)
            {
                if (SectionHeaders[i].VirtualAddress <= dwRVA && SectionHeaders[i].VirtualAddress + SectionHeaders[i].SizeOfRawData > dwRVA)
                {
                    dwRVA -= SectionHeaders[i].VirtualAddress;
                    dwRVA += SectionHeaders[i].PointerToRawData;

                    return pModule + (int)dwRVA;
                }
            }

            return IntPtr.Zero;
        }



        static void Main(string[] args)
        {
            // For storing syscall pointers
            Dictionary<string, IntPtr> book = new Dictionary<string, IntPtr>();

            // Get the necessary syscalls to load an unhooked NTDLL into memory
            InitSyscallsFromLdrpThunkSignature();

            // Load an unhooked NTDLL into memory using the syscalls collected from step 1
            IntPtr pNtdll = LoadNtdllIntoSection();

            // Get syscalls from the unhooked NTDLL
            uint uiCount = ExtractSyscalls(pNtdll, ref book);

            // Get syscall pointer for ZwCreateThreadEx
            IntPtr pZwCreateThreadEx = GetSyscall(book, "ZwCreateThreadEx");
            NtCreateThreadEx zWCreateThreadEx = Marshal.GetDelegateForFunctionPointer<NtCreateThreadEx>(pZwCreateThreadEx);

            // Call ZwCreateThreadEx
            IntPtr hThread = IntPtr.Zero;
            var res = zWCreateThreadEx(
                ref hThread, 
                ACCESS_MASK.GENERIC_ALL, 
                IntPtr.Zero, 
                GetCurrentProcess(), 
                IntPtr.Zero, 
                IntPtr.Zero, 
                false, 
                0, 
                0, 
                0,
                IntPtr.Zero);
            Console.WriteLine("zWCreateThreadEx: {0}", res);
            Console.WriteLine("hThread: {0}", hThread);
        }
    }
}
