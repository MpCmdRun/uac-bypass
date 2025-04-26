using System;
using System.Runtime.InteropServices;

internal class NativeMethods
{
    public const int COINIT_APARTMENTTHREADED = 0x2;
    public const int COINIT_DISABLE_OLE1DDE = 0x4;
    public const int SW_HIDE = 0;
    public const uint FOF_NOCONFIRMATION = 0x0010;
    public const uint FOF_NOERRORUI = 0x0400;
    public const uint FOFX_NOCOPYHOOKS = 0x00000080;
    public const uint FOFX_REQUIREELEVATION = 0x00000100;


    [DllImport("ole32.dll")]
    public static extern int CoInitializeEx(IntPtr pvReserved, int dwCoInit);

    [DllImport("ole32.dll")]
    public static extern void CoUninitialize();

    [DllImport("shell32.dll", CharSet = CharSet.Unicode)]
    public static extern IntPtr ShellExecuteW(IntPtr hwnd, string lpOperation, string lpFile, string lpParameters, string lpDirectory, int nShowCmd);

    [DllImport("kernel32.dll", CharSet = CharSet.Unicode)]
    public static extern IntPtr GetModuleHandle(string lpModuleName);

    [DllImport("kernel32.dll", CharSet = CharSet.Ansi)]
    public static extern IntPtr GetProcAddress(IntPtr hModule, string procName);

    [DllImport("ntdll.dll")]
    public static extern uint LdrEnumerateLoadedModules(int Reserved, PLdrEnumModulesCallback CallbackFunction, IntPtr Context);

    public delegate bool PLdrEnumModulesCallback(IntPtr ModuleInformation, IntPtr Context, ref bool StopEnumeration);

    public static IntPtr GetImageBase()
    {
        return Marshal.GetHINSTANCE(typeof(NativeMethods).Module);
    }

    public static dynamic CreateElevatedFileOperation()
    {
        try
        {
            Type shellType = Type.GetTypeFromCLSID(new Guid("3AD05575-8857-4850-9277-11B85BDB8E09"));
            return Activator.CreateInstance(shellType);
        }
        catch (Exception ex)
        {
            Console.WriteLine("Error creating Elevated File Operation COM object: " + ex.Message);
            return null;
        }
    }

    public static dynamic CreateShellItemFromPath(string path)
    {
        try
        {
            Type shellItemType = Type.GetTypeFromCLSID(new Guid("43826D1E-E718-42EE-BC55-A1E261C37BFE"));
            return Activator.CreateInstance(shellItemType, path);
        }
        catch (Exception ex)
        {
            Console.WriteLine("Error creating Shell Item from path: " + ex.Message);
            return null;
        }
    }
}