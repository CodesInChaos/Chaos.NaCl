using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Linq;
using System.Management;
using System.Text;

namespace Chaos.NaCl.Benchmark
{
    class Cpu
    {
        public static uint CpuFreq = GetMaxCpuFreq();

        private const uint CpuFreqFallback = 2901;

        public static void Setup()
        {
            Process.GetCurrentProcess().ProcessorAffinity = (IntPtr)1;
            Process.GetCurrentProcess().PriorityClass = ProcessPriorityClass.RealTime;
        }

        private static uint GetCpuFreq(string name)
        {
            try
            {
                using (ManagementBaseObject mo = new ManagementObject("Win32_Processor.DeviceID='CPU0'"))
                {
                    return (uint)(mo[name]);
                }
            }
            catch (Exception)
            {
                Console.WriteLine("Could not get CPU Frequency");
                return CpuFreqFallback;
            }
        }

        static uint GetCurrentCpuFreq()
        {
            return GetCpuFreq("CurrentClockSpeed");
        }

        public static uint GetMaxCpuFreq()
        {
            return GetCpuFreq("MaxClockSpeed");
        }

        public static void CheckCurrentCpuFreq()
        {
            var currentFreq = GetCurrentCpuFreq();
            if (currentFreq != CpuFreq)
                Console.WriteLine("Current CPU-Frequency: {0} MHz differs from max", currentFreq);
        }
    }
}
