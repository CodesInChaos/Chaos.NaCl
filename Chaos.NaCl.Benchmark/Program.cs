using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Management;
using System.Globalization;
using System.Threading;

namespace Chaos.NaCl.Benchmark
{
	class Program
	{
		static uint CpuFreq;

		static uint GetCurrentCpuFreq()
		{
			using (ManagementBaseObject mo = new ManagementObject("Win32_Processor.DeviceID='CPU0'"))
			{
				return (uint)(mo["CurrentClockSpeed"]);
			}
		}

		static uint GetMaxCpuFreq()
		{
			using (ManagementBaseObject mo = new ManagementObject("Win32_Processor.DeviceID='CPU0'"))
			{
				return (uint)(mo["MaxClockSpeed"]);
			}
		}

		static void CheckCurrentCpuFreq()
		{
			var currentFreq = GetCurrentCpuFreq();
			if (currentFreq != CpuFreq)
				Console.WriteLine("Current CPU-Frequency: {0} MHz differs from max", currentFreq);
		}



		static void Benchmark(Action action, int n)
		{
			var start = DateTime.UtcNow;
			for (int i = 0; i < n; i++)
				action();
			var total = (DateTime.UtcNow - start).TotalSeconds;
			var perIteration = total / n;
			Console.WriteLine("{0} us / {1} per second / {2} cycles", Math.Round(perIteration * 1E6, 2), Math.Round(1 / perIteration), Math.Round(perIteration * CpuFreq * 1E6));
		}

		static void Main(string[] args)
		{
			Thread.CurrentThread.CurrentCulture = CultureInfo.InvariantCulture;
			Console.WriteLine("Architecture: {0} bit", IntPtr.Size * 8);
			CpuFreq = GetMaxCpuFreq();
			Console.WriteLine("CPU-Frequency: {0} MHz", CpuFreq);
			Console.WriteLine();
			var m = new byte[100];
			var seed = new byte[32];
			byte[] privateKey;
			byte[] publicKey;
			Ed25519.KeyPairFromSeed(out publicKey, out privateKey, seed);
			var sig = Ed25519.Sign(m, privateKey);
			for (int i = 0; i < 10000; i++)
			{
				Ed25519.Sign(m, privateKey);
			}

			if (!Ed25519.Verify(sig, m, publicKey))
				throw new Exception("Bug");
			if (Ed25519.Verify(sig, m.Concat(new byte[] { 1 }).ToArray(), publicKey))
				throw new Exception("Bug");

			const int n = 100000;

			CheckCurrentCpuFreq();
			Console.Write("Sign ");
			Benchmark(() => { Ed25519.Sign(m, privateKey); }, n);
			CheckCurrentCpuFreq();
			Console.Write("KeyGen ");
			Benchmark(() => { Ed25519.KeyPairFromSeed(out publicKey, out privateKey, seed); }, n);
			CheckCurrentCpuFreq();
			Console.WriteLine("Verify ");
			Benchmark(() => { Ed25519.Verify(sig, m, publicKey); }, n);
			CheckCurrentCpuFreq();
		}
	}
}
