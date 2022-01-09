using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Linq;
using System.Runtime.InteropServices;
using System.Text;
using System.Threading.Tasks;

namespace ParallelSyscalls
{
    class Natives
    {
        [UnmanagedFunctionPointer(CallingConvention.StdCall)]
        public delegate NTSTATUS NtCreateThreadEx(
                ref IntPtr threadHandle,
                ACCESS_MASK desiredAccess,
                IntPtr objectAttributes,
                IntPtr processHandle,
                IntPtr startAddress,
                IntPtr parameter,
                bool createSuspended,
                int stackZeroBits,
                int sizeOfStack,
                int maximumStackSize,
                IntPtr attributeList);

        [UnmanagedFunctionPointer(CallingConvention.StdCall)]
        public delegate NTSTATUS NtOpenFile(
                ref IntPtr FileHandle,
                FileAccessFlags DesiredAccess,
                ref OBJECT_ATTRIBUTES ObjAttr,
                ref IO_STATUS_BLOCK IoStatusBlock,
                FileShareFlags ShareAccess,
                int OpenOptions);

        [UnmanagedFunctionPointer(CallingConvention.StdCall)]
        public delegate NTSTATUS NtCreateSection(
                ref IntPtr SectionHandle,
                uint DesiredAccess,
                IntPtr ObjectAttributes,
                ref ulong MaximumSize,
                uint SectionPageProtection,
                uint AllocationAttributes,
                IntPtr FileHandle);

        [UnmanagedFunctionPointer(CallingConvention.StdCall)]
        public delegate NTSTATUS NtMapViewOfSection(
                IntPtr SectionHandle,
                IntPtr ProcessHandle,
                out IntPtr BaseAddress,
                IntPtr ZeroBits,
                IntPtr CommitSize,
                IntPtr SectionOffset,
                out ulong ViewSize,
                uint InheritDisposition,
                uint AllocationType,
                uint Win32Protect);
    

    //[DllImport("ntdll")]
    //internal static extern IntPtr NtCurrentTeb();
    [DllImport("kernel32.dll", SetLastError = true)]
        public static extern bool CloseHandle(IntPtr hObject);


        [DllImport("kernel32.dll", SetLastError = true)]
        public static extern int GetCurrentThread();


        [DllImport("kernel32.dll", SetLastError = true)]
        public static extern IntPtr OpenProcess(
            uint processAccess,
            bool bInheritHandle,
            uint processId
        );
        [DllImport("ntdll.dll")]
        public static extern UInt32 NtQueryInformationProcess(
            IntPtr processHandle,
            UInt32 processInformationClass,
            ref PROCESS_BASIC_INFORMATION processInformation,
            int processInformationLength,
            ref UInt32 returnLength
        );
        [DllImport("kernel32.dll", SetLastError = true, ExactSpelling = true)]
        public static extern IntPtr VirtualAlloc(IntPtr lpAddress, uint dwSize, uint flAllocationType, uint flProtect);

        [DllImport("ntdll.dll")]
        public static extern void RtlInitUnicodeString(ref UNICODE_STRING DestinationString, [MarshalAs(UnmanagedType.LPWStr)] string SourceString);

        [DllImport("kernel32.dll", SetLastError = true)]
        public static extern IntPtr GetCurrentProcess();






        [StructLayout(LayoutKind.Sequential)]
        public struct IO_STATUS_BLOCK
        {
            public IntPtr Status;
            public IntPtr Information;
        }
        [Flags]
        public enum ACCESS_MASK : uint
        {
            DELETE = 0x00010000,
            READ_CONTROL = 0x00020000,
            WRITE_DAC = 0x00040000,
            WRITE_OWNER = 0x00080000,
            SYNCHRONIZE = 0x00100000,
            STANDARD_RIGHTS_REQUIRED = 0x000F0000,
            STANDARD_RIGHTS_READ = 0x00020000,
            STANDARD_RIGHTS_WRITE = 0x00020000,
            STANDARD_RIGHTS_EXECUTE = 0x00020000,
            STANDARD_RIGHTS_ALL = 0x001F0000,
            SPECIFIC_RIGHTS_ALL = 0x0000FFF,
            ACCESS_SYSTEM_SECURITY = 0x01000000,
            MAXIMUM_ALLOWED = 0x02000000,
            GENERIC_READ = 0x80000000,
            GENERIC_WRITE = 0x40000000,
            GENERIC_EXECUTE = 0x20000000,
            GENERIC_ALL = 0x10000000,
            DESKTOP_READOBJECTS = 0x00000001,
            DESKTOP_CREATEWINDOW = 0x00000002,
            DESKTOP_CREATEMENU = 0x00000004,
            DESKTOP_HOOKCONTROL = 0x00000008,
            DESKTOP_JOURNALRECORD = 0x00000010,
            DESKTOP_JOURNALPLAYBACK = 0x00000020,
            DESKTOP_ENUMERATE = 0x00000040,
            DESKTOP_WRITEOBJECTS = 0x00000080,
            DESKTOP_SWITCHDESKTOP = 0x00000100,
            WINSTA_ENUMDESKTOPS = 0x00000001,
            WINSTA_READATTRIBUTES = 0x00000002,
            WINSTA_ACCESSCLIPBOARD = 0x00000004,
            WINSTA_CREATEDESKTOP = 0x00000008,
            WINSTA_WRITEATTRIBUTES = 0x00000010,
            WINSTA_ACCESSGLOBALATOMS = 0x00000020,
            WINSTA_EXITWINDOWS = 0x00000040,
            WINSTA_ENUMERATE = 0x00000100,
            WINSTA_READSCREEN = 0x00000200,
            WINSTA_ALL_ACCESS = 0x0000037F,

            SECTION_ALL_ACCESS = 0x10000000,
            SECTION_QUERY = 0x0001,
            SECTION_MAP_WRITE = 0x0002,
            SECTION_MAP_READ = 0x0004,
            SECTION_MAP_EXECUTE = 0x0008,
            SECTION_EXTEND_SIZE = 0x0010
        }
    
        [Flags]
        public enum FileShareFlags : UInt32
        {
            FILE_SHARE_NONE = 0x0,
            FILE_SHARE_READ = 0x1,
            FILE_SHARE_WRITE = 0x2,
            FILE_SHARE_DELETE = 0x4
        }

        [Flags]
        public enum FileAccessFlags : UInt32
        {
            DELETE = 0x10000,
            FILE_READ_DATA = 0x1,
            FILE_READ_ATTRIBUTES = 0x80,
            FILE_READ_EA = 0x8,
            READ_CONTROL = 0x20000,
            FILE_WRITE_DATA = 0x2,
            FILE_WRITE_ATTRIBUTES = 0x100,
            FILE_WRITE_EA = 0x10,
            FILE_APPEND_DATA = 0x4,
            WRITE_DAC = 0x40000,
            WRITE_OWNER = 0x80000,
            SYNCHRONIZE = 0x100000,
            FILE_EXECUTE = 0x20
        }

        public struct IMAGE_EXPORT_DIRECTORY
        {
            public UInt32 Characteristics;
            public UInt32 TimeDateStamp;
            public UInt16 MajorVersion;
            public UInt16 MinorVersion;
            public UInt32 Name;
            public UInt32 Base;
            public UInt32 NumberOfFunctions;
            public UInt32 NumberOfNames;
            public UInt32 AddressOfFunctions;     // RVA from base of image
            public UInt32 AddressOfNames;     // RVA from base of image
            public UInt32 AddressOfNameOrdinals;  // RVA from base of image
        }

        public enum NTSTATUS : uint
        {
            Success = 0,
            Informational = 0x40000000,
            Error = 0xc0000000
        }

        public struct OBJECT_ATTRIBUTES
        {
            public Int32 Length;
            public IntPtr RootDirectory;
            public IntPtr ObjectName; // -> UNICODE_STRING
            public uint Attributes;
            public IntPtr SecurityDescriptor;
            public IntPtr SecurityQualityOfService;
        }

        // https://github.com/MagicDroidX/ReClass.NET-Kernel/blob/254e27cc4dac7a0746e90c1ac55758ba5b9d199d/KernelPlugin/Structs.cs#L77
        [StructLayout(LayoutKind.Sequential)]
        public struct LIST_ENTRY
        {
            public IntPtr Flink; //_LIST_ENTRY *Flink;
            public IntPtr Blink; //_LIST_ENTRY *Blink;
        }

        [StructLayout(LayoutKind.Sequential)]
        public struct PEB_LDR_DATA
        {
            public uint dwLength;
            public bool dwInitialized;
            public IntPtr lpSsHandle;
            public LIST_ENTRY InLoadOrderModuleList;
            public LIST_ENTRY InMemoryOrderModuleList;
            public LIST_ENTRY InInitializationOrderModuleList;
        }

        [StructLayout(LayoutKind.Sequential, Pack = 8)]
        public struct LDR_DATA_TABLE_ENTRY
        {
            public LIST_ENTRY InLoadOrderLinks;
            public LIST_ENTRY InMemoryOrderLinks;
            public LIST_ENTRY InInitializationOrderLinks;
            public IntPtr DllBase;
            public IntPtr EntryPoint;
            public uint SizeOfImage;
            public UNICODE_STRING FullDllName;
            public UNICODE_STRING BaseDllName;
            public uint Flags;
            public ushort LoadCount;
            public ushort TlsIndex;
            public LIST_ENTRY HashLinks;
            public uint TimeDateStamp;
        }

        [StructLayout(LayoutKind.Sequential)]
        public unsafe struct _TEB
        {
            [MarshalAs(UnmanagedType.ByValArray, SizeConst = 12)]
            public IntPtr[] Reserved1;
            public IntPtr ProcessEnvironmentBlock;
            [MarshalAs(UnmanagedType.ByValArray, SizeConst = 399)]
            public IntPtr[] Reserved2;
            public fixed byte Reserved3[1952];
            [MarshalAs(UnmanagedType.ByValArray, SizeConst = 64)]
            public IntPtr[] TlsSlots;
            public fixed byte Reserved4[8];
            [MarshalAs(UnmanagedType.ByValArray, SizeConst = 26)]
            public IntPtr[] Reserved5;
            public IntPtr ReservedForOle;
            [MarshalAs(UnmanagedType.ByValArray, SizeConst = 4)]
            public IntPtr[] Reserved6;
            public IntPtr TlsExpansionSlots;

            public static _TEB Create(IntPtr tebAddress)
            {
                _TEB teb = (_TEB)Marshal.PtrToStructure(tebAddress, typeof(_TEB));
                return teb;
            }
        }
        [StructLayout(LayoutKind.Sequential)]
        public unsafe struct _PEB
        {
            public fixed byte Reserved1[2];
            public byte BeingDebugged;
            public fixed byte Reserved2[1];
            [MarshalAs(UnmanagedType.ByValArray, SizeConst = 2)]
            public IntPtr[] Reserved3;
            public IntPtr Ldr;
            public IntPtr ProcessParameters;
            [MarshalAs(UnmanagedType.ByValArray, SizeConst = 3)]
            public IntPtr[] Reserved4;
            public IntPtr AtlThunkSListPtr;
            public IntPtr Reserved5;
            public uint Reserved6;
            public IntPtr Reserved7;
            public uint Reserved8;
            public uint AtlThunkSListPtr32;
            [MarshalAs(UnmanagedType.ByValArray, SizeConst = 45)]
            public IntPtr[] Reserved9;
            [MarshalAs(UnmanagedType.ByValArray, SizeConst = 96)]
            public byte[] Reserved10;
            public IntPtr PostProcessInitRoutine;
            public fixed byte Reserved11[128];
            public IntPtr Reserved12;
            public uint SessionId;
        }
        [StructLayout(LayoutKind.Sequential)]
        public struct UNICODE_STRING
        {
            public ushort Length;
            public ushort MaximumLength;
            public IntPtr Buffer;

            public UNICODE_STRING(string s)
            {
                Length = (ushort)(s.Length * 2);
                MaximumLength = (ushort)(Length + 2);
                Buffer = Marshal.StringToHGlobalUni(s);
            }

            public string GetText()
            {
                if (Buffer == IntPtr.Zero || MaximumLength == 0)
                {
                    return "";
                }

                return Marshal.PtrToStringUni(Buffer, Length / 2);
            }
        }

        [StructLayout(LayoutKind.Sequential)]
        public struct PROCESS_BASIC_INFORMATION
        {
            public IntPtr ExitStatus;
            public IntPtr PebBaseAddress;
            public IntPtr AffinityMask;
            public IntPtr BasePriority;
            public UIntPtr UniqueProcessId;
            public IntPtr InheritedFromUniqueProcessId;
        }

        [StructLayout(LayoutKind.Explicit)]
        public unsafe struct IMAGE_SECTION_HEADER
        {
            [FieldOffset(0)]
            [MarshalAs(UnmanagedType.ByValArray, SizeConst = 8)]
            public char[] Name;

            [FieldOffset(8)]
            public UInt32 VirtualSize;

            [FieldOffset(12)]
            public UInt32 VirtualAddress;

            [FieldOffset(16)]
            public UInt32 SizeOfRawData;

            [FieldOffset(20)]
            public UInt32 PointerToRawData;

            [FieldOffset(24)]
            public UInt32 PointerToRelocations;

            [FieldOffset(28)]
            public UInt32 PointerToLinenumbers;

            [FieldOffset(32)]
            public UInt16 NumberOfRelocations;

            [FieldOffset(34)]
            public UInt16 NumberOfLinenumbers;

            [FieldOffset(36)]
            public uint Characteristics;

            public string SectionName
            {
                get { return new string(Name); }
            }

            public uint EndAddress
            {
                get { return (uint)(VirtualAddress + SizeOfRawData); }
            }
        }

        [StructLayout(LayoutKind.Sequential)]
        public struct IMAGE_DATA_DIRECTORY
        {
            public UInt32 VirtualAddress;
            public UInt32 Size;
        }

        [StructLayout(LayoutKind.Sequential)]
        public struct IMAGE_FILE_HEADER
        {
            public UInt16 Machine;
            public UInt16 NumberOfSections;
            public UInt32 TimeDateStamp;
            public UInt32 PointerToSymbolTable;
            public UInt32 NumberOfSymbols;
            public UInt16 SizeOfOptionalHeader;
            public UInt16 Characteristics;
        }

        [Flags]
        public enum DllCharacteristicsType : ushort
        {
            RES_0 = 0x0001,
            RES_1 = 0x0002,
            RES_2 = 0x0004,
            RES_3 = 0x0008,
            IMAGE_DLL_CHARACTERISTICS_DYNAMIC_BASE = 0x0040,
            IMAGE_DLL_CHARACTERISTICS_FORCE_INTEGRITY = 0x0080,
            IMAGE_DLL_CHARACTERISTICS_NX_COMPAT = 0x0100,
            IMAGE_DLLCHARACTERISTICS_NO_ISOLATION = 0x0200,
            IMAGE_DLLCHARACTERISTICS_NO_SEH = 0x0400,
            IMAGE_DLLCHARACTERISTICS_NO_BIND = 0x0800,
            RES_4 = 0x1000,
            IMAGE_DLLCHARACTERISTICS_WDM_DRIVER = 0x2000,
            IMAGE_DLLCHARACTERISTICS_TERMINAL_SERVER_AWARE = 0x8000
        }

        public enum SubSystemType : ushort
        {
            IMAGE_SUBSYSTEM_UNKNOWN = 0,
            IMAGE_SUBSYSTEM_NATIVE = 1,
            IMAGE_SUBSYSTEM_WINDOWS_GUI = 2,
            IMAGE_SUBSYSTEM_WINDOWS_CUI = 3,
            IMAGE_SUBSYSTEM_POSIX_CUI = 7,
            IMAGE_SUBSYSTEM_WINDOWS_CE_GUI = 9,
            IMAGE_SUBSYSTEM_EFI_APPLICATION = 10,
            IMAGE_SUBSYSTEM_EFI_BOOT_SERVICE_DRIVER = 11,
            IMAGE_SUBSYSTEM_EFI_RUNTIME_DRIVER = 12,
            IMAGE_SUBSYSTEM_EFI_ROM = 13,
            IMAGE_SUBSYSTEM_XBOX = 14
        }

        public enum MagicType : ushort
        {
            IMAGE_NT_OPTIONAL_HDR32_MAGIC = 0x10b,
            IMAGE_NT_OPTIONAL_HDR64_MAGIC = 0x20b
        }

        [StructLayout(LayoutKind.Explicit)]
        public struct IMAGE_OPTIONAL_HEADER32
        {
            [FieldOffset(0)]
            public MagicType Magic;

            [FieldOffset(2)]
            public byte MajorLinkerVersion;

            [FieldOffset(3)]
            public byte MinorLinkerVersion;

            [FieldOffset(4)]
            public uint SizeOfCode;

            [FieldOffset(8)]
            public uint SizeOfInitializedData;

            [FieldOffset(12)]
            public uint SizeOfUninitializedData;

            [FieldOffset(16)]
            public uint AddressOfEntryPoint;

            [FieldOffset(20)]
            public uint BaseOfCode;

            // PE32 contains this additional field
            [FieldOffset(24)]
            public uint BaseOfData;

            [FieldOffset(28)]
            public uint ImageBase;

            [FieldOffset(32)]
            public uint SectionAlignment;

            [FieldOffset(36)]
            public uint FileAlignment;

            [FieldOffset(40)]
            public ushort MajorOperatingSystemVersion;

            [FieldOffset(42)]
            public ushort MinorOperatingSystemVersion;

            [FieldOffset(44)]
            public ushort MajorImageVersion;

            [FieldOffset(46)]
            public ushort MinorImageVersion;

            [FieldOffset(48)]
            public ushort MajorSubsystemVersion;

            [FieldOffset(50)]
            public ushort MinorSubsystemVersion;

            [FieldOffset(52)]
            public uint Win32VersionValue;

            [FieldOffset(56)]
            public uint SizeOfImage;

            [FieldOffset(60)]
            public uint SizeOfHeaders;

            [FieldOffset(64)]
            public uint CheckSum;

            [FieldOffset(68)]
            public SubSystemType Subsystem;

            [FieldOffset(70)]
            public DllCharacteristicsType DllCharacteristics;

            [FieldOffset(72)]
            public uint SizeOfStackReserve;

            [FieldOffset(76)]
            public uint SizeOfStackCommit;

            [FieldOffset(80)]
            public uint SizeOfHeapReserve;

            [FieldOffset(84)]
            public uint SizeOfHeapCommit;

            [FieldOffset(88)]
            public uint LoaderFlags;

            [FieldOffset(92)]
            public uint NumberOfRvaAndSizes;

            [FieldOffset(96)]
            public IMAGE_DATA_DIRECTORY ExportTable;

            [FieldOffset(104)]
            public IMAGE_DATA_DIRECTORY ImportTable;

            [FieldOffset(112)]
            public IMAGE_DATA_DIRECTORY ResourceTable;

            [FieldOffset(120)]
            public IMAGE_DATA_DIRECTORY ExceptionTable;

            [FieldOffset(128)]
            public IMAGE_DATA_DIRECTORY CertificateTable;

            [FieldOffset(136)]
            public IMAGE_DATA_DIRECTORY BaseRelocationTable;

            [FieldOffset(144)]
            public IMAGE_DATA_DIRECTORY Debug;

            [FieldOffset(152)]
            public IMAGE_DATA_DIRECTORY Architecture;

            [FieldOffset(160)]
            public IMAGE_DATA_DIRECTORY GlobalPtr;

            [FieldOffset(168)]
            public IMAGE_DATA_DIRECTORY TLSTable;

            [FieldOffset(176)]
            public IMAGE_DATA_DIRECTORY LoadConfigTable;

            [FieldOffset(184)]
            public IMAGE_DATA_DIRECTORY BoundImport;

            [FieldOffset(192)]
            public IMAGE_DATA_DIRECTORY IAT;

            [FieldOffset(200)]
            public IMAGE_DATA_DIRECTORY DelayImportDescriptor;

            [FieldOffset(208)]
            public IMAGE_DATA_DIRECTORY CLRRuntimeHeader;

            [FieldOffset(216)]
            public IMAGE_DATA_DIRECTORY Reserved;
        }

        [StructLayout(LayoutKind.Explicit)]
        public struct IMAGE_OPTIONAL_HEADER64
        {
            [FieldOffset(0)]
            public MagicType Magic;

            [FieldOffset(2)]
            public byte MajorLinkerVersion;

            [FieldOffset(3)]
            public byte MinorLinkerVersion;

            [FieldOffset(4)]
            public uint SizeOfCode;

            [FieldOffset(8)]
            public uint SizeOfInitializedData;

            [FieldOffset(12)]
            public uint SizeOfUninitializedData;

            [FieldOffset(16)]
            public uint AddressOfEntryPoint;

            [FieldOffset(20)]
            public uint BaseOfCode;

            [FieldOffset(24)]
            public ulong ImageBase;

            [FieldOffset(32)]
            public uint SectionAlignment;

            [FieldOffset(36)]
            public uint FileAlignment;

            [FieldOffset(40)]
            public ushort MajorOperatingSystemVersion;

            [FieldOffset(42)]
            public ushort MinorOperatingSystemVersion;

            [FieldOffset(44)]
            public ushort MajorImageVersion;

            [FieldOffset(46)]
            public ushort MinorImageVersion;

            [FieldOffset(48)]
            public ushort MajorSubsystemVersion;

            [FieldOffset(50)]
            public ushort MinorSubsystemVersion;

            [FieldOffset(52)]
            public uint Win32VersionValue;

            [FieldOffset(56)]
            public uint SizeOfImage;

            [FieldOffset(60)]
            public uint SizeOfHeaders;

            [FieldOffset(64)]
            public uint CheckSum;

            [FieldOffset(68)]
            public SubSystemType Subsystem;

            [FieldOffset(70)]
            public DllCharacteristicsType DllCharacteristics;

            [FieldOffset(72)]
            public ulong SizeOfStackReserve;

            [FieldOffset(80)]
            public ulong SizeOfStackCommit;

            [FieldOffset(88)]
            public ulong SizeOfHeapReserve;

            [FieldOffset(96)]
            public ulong SizeOfHeapCommit;

            [FieldOffset(104)]
            public uint LoaderFlags;

            [FieldOffset(108)]
            public uint NumberOfRvaAndSizes;

            [FieldOffset(112)]
            public IMAGE_DATA_DIRECTORY ExportTable;

            [FieldOffset(120)]
            public IMAGE_DATA_DIRECTORY ImportTable;

            [FieldOffset(128)]
            public IMAGE_DATA_DIRECTORY ResourceTable;

            [FieldOffset(136)]
            public IMAGE_DATA_DIRECTORY ExceptionTable;

            [FieldOffset(144)]
            public IMAGE_DATA_DIRECTORY CertificateTable;

            [FieldOffset(152)]
            public IMAGE_DATA_DIRECTORY BaseRelocationTable;

            [FieldOffset(160)]
            public IMAGE_DATA_DIRECTORY Debug;

            [FieldOffset(168)]
            public IMAGE_DATA_DIRECTORY Architecture;

            [FieldOffset(176)]
            public IMAGE_DATA_DIRECTORY GlobalPtr;

            [FieldOffset(184)]
            public IMAGE_DATA_DIRECTORY TLSTable;

            [FieldOffset(192)]
            public IMAGE_DATA_DIRECTORY LoadConfigTable;

            [FieldOffset(200)]
            public IMAGE_DATA_DIRECTORY BoundImport;

            [FieldOffset(208)]
            public IMAGE_DATA_DIRECTORY IAT;

            [FieldOffset(216)]
            public IMAGE_DATA_DIRECTORY DelayImportDescriptor;

            [FieldOffset(224)]
            public IMAGE_DATA_DIRECTORY CLRRuntimeHeader;

            [FieldOffset(232)]
            public IMAGE_DATA_DIRECTORY Reserved;
        }

        [StructLayout(LayoutKind.Sequential)]
        public unsafe struct IMAGE_NT_HEADERS
        {
            public int Signature;
            public IMAGE_FILE_HEADER FileHeader;
            public IMAGE_OPTIONAL_HEADER642 OptionalHeader;
        }
        [StructLayout(LayoutKind.Explicit)]
        public struct IMAGE_OPTIONAL_HEADER642
        {
            [FieldOffset(112)]
            [MarshalAs(UnmanagedType.ByValArray, SizeConst = 16)]
            public IMAGE_DATA_DIRECTORY[] DataDirectory;
        }

        [StructLayout(LayoutKind.Sequential)]
        public struct IMAGE_DOS_HEADER
        {
            [MarshalAs(UnmanagedType.ByValArray, SizeConst = 2)]
            public char[] e_magic;       // Magic number
            public UInt16 e_cblp;    // Bytes on last page of file
            public UInt16 e_cp;      // Pages in file
            public UInt16 e_crlc;    // Relocations
            public UInt16 e_cparhdr;     // Size of header in paragraphs
            public UInt16 e_minalloc;    // Minimum extra paragraphs needed
            public UInt16 e_maxalloc;    // Maximum extra paragraphs needed
            public UInt16 e_ss;      // Initial (relative) SS value
            public UInt16 e_sp;      // Initial SP value
            public UInt16 e_csum;    // Checksum
            public UInt16 e_ip;      // Initial IP value
            public UInt16 e_cs;      // Initial (relative) CS value
            public UInt16 e_lfarlc;      // File address of relocation table
            public UInt16 e_ovno;    // Overlay number
            [MarshalAs(UnmanagedType.ByValArray, SizeConst = 4)]
            public UInt16[] e_res1;    // Reserved words
            public UInt16 e_oemid;       // OEM identifier (for e_oeminfo)
            public UInt16 e_oeminfo;     // OEM information; e_oemid specific
            [MarshalAs(UnmanagedType.ByValArray, SizeConst = 10)]
            public UInt16[] e_res2;    // Reserved words
            public Int32 e_lfanew;      // File address of new exe header

            private string Magic
            {
                get { return new string(e_magic); }
            }

            public bool IsValid
            {
                get { return Magic == "MZ"; }
            }
        }




        public static _PEB GetPeb()
        {
            IntPtr pebAddress = GetPebAddress(out _);
            return GetPeb(pebAddress);
        }

        public static IntPtr GetPebAddress(out IntPtr pebAddress)
        {
            PROCESS_BASIC_INFORMATION PROCESS_BASIC_INFORMATION_instance = new PROCESS_BASIC_INFORMATION();
            IntPtr hProcess = GetCurrentProcess();
            uint sizePtr = 0;
            UInt32 QueryResult = NtQueryInformationProcess(
                hProcess,
                0,
                ref PROCESS_BASIC_INFORMATION_instance,
                Marshal.SizeOf(PROCESS_BASIC_INFORMATION_instance),
                ref sizePtr
            );
            if (hProcess != IntPtr.Zero)
                CloseHandle(hProcess);

            pebAddress = PROCESS_BASIC_INFORMATION_instance.PebBaseAddress;
            return pebAddress;
        }

        public static _PEB GetPeb(IntPtr pebAddress)
        {
            return Marshal.PtrToStructure<_PEB>(pebAddress);
        }
    }
}
