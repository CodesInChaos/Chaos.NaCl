using System;
using System.Collections.Generic;
using System.Linq;
using System.Management;
using System.Globalization;
using System.Security.Cryptography;
using System.Threading;
using Chaos.NaCl.Internal;
using Chaos.NaCl.Internal.Salsa;

namespace Chaos.NaCl.Benchmark
{
    public class BenchmarkProgram
    {
        static uint CpuFreq;

        private const uint CpuFreqFallback = 2901;

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

        static uint GetMaxCpuFreq()
        {
            return GetCpuFreq("MaxClockSpeed");
        }

        static void CheckCurrentCpuFreq()
        {
            var currentFreq = GetCurrentCpuFreq();
            if (currentFreq != CpuFreq)
                Console.WriteLine("Current CPU-Frequency: {0} MHz differs from max", currentFreq);
        }

        static void Benchmark(Action action, int n, int bytes = 0)
        {
            GC.Collect();
            GC.WaitForPendingFinalizers();
            var start = DateTime.UtcNow;
            for (int i = 0; i < n; i++)
                action();
            var total = (DateTime.UtcNow - start).TotalSeconds;
            var perIteration = total / n;
            Console.WriteLine("{0} us / {1} per second / {2} cycles", Math.Round(perIteration * 1E6, 2), Math.Round(1 / perIteration), Math.Round(perIteration * CpuFreq * 1E6));
            if (bytes > 0)
            {
                double bytesPerSecond = bytes / perIteration;
                double cyclesPerByte = (CpuFreq * 1E6) / bytesPerSecond;
                Console.WriteLine("{0} MB/s / {1} cycles/byte", Math.Round(bytesPerSecond / 1E6, 2), Math.Round(cyclesPerByte, 2));
            }
        }

        public static void Main()
        {
            Thread.CurrentThread.CurrentCulture = CultureInfo.InvariantCulture;
            Console.WriteLine("Architecture: {0} bit", IntPtr.Size * 8);
            CpuFreq = GetMaxCpuFreq();
            Console.WriteLine("CPU-Frequency: {0} MHz", CpuFreq);
            Console.WriteLine();
            Console.ReadKey();

            var m = new byte[100];
            var seed = new byte[32];
            byte[] privateKey;
            byte[] publicKey;
            Ed25519.KeyPairFromSeed(out publicKey, out privateKey, seed);
            var sig = Ed25519.Sign(m, privateKey);
            Ed25519.Sign(m, privateKey);

            if (!Ed25519.Verify(sig, m, publicKey))
                throw new Exception("Bug");
            if (Ed25519.Verify(sig, m.Concat(new byte[] { 1 }).ToArray(), publicKey))
                throw new Exception("Bug");

            const int n = 10000;

            Console.WriteLine("HSalsa20Core");
            Benchmark(() =>
                {
                    byte[] input = new byte[64]{
				        6,124, 83,146, 38,191,9, 50,4,161, 47,222,122,182,223,185,
				        75, 27,0,216, 16,122,7, 89,162,104,101,147,213, 21, 54, 95,
				        225,253,139,176,105,132, 23,116, 76, 41,176,207,221, 34,157,108,
				        94, 94, 99, 52, 90,117, 91,220,146,190,239,143,196,176,130,186};
                    Array16<UInt32> state;
                    ByteIntegerConverter.Array16LoadLittleEndian32(out state, input, 0);
                    for (int i = 0; i < 1000000; i++)
                    {
                        SalsaCore.HSalsa(out state, ref state, 20);
                    }
                }, 100, 64000000);

            Console.WriteLine("=== Edwards ===");
            CheckCurrentCpuFreq();
            Console.Write("KeyGen ");
            Benchmark(() => Ed25519.KeyPairFromSeed(out publicKey, out privateKey, seed), n);
            CheckCurrentCpuFreq();
            Console.Write("Sign ");
            Benchmark(() => Ed25519.Sign(m, privateKey), n);
            CheckCurrentCpuFreq();
            Console.Write("Verify ");
            Benchmark(() => Ed25519.Verify(sig, m, publicKey), n);
            CheckCurrentCpuFreq();
            Console.Write("KeyExchange ");
            Benchmark(() => Ed25519.KeyExchange(publicKey, privateKey), n);

            Console.WriteLine();
            Console.WriteLine("=== Montgomery ===");
            CheckCurrentCpuFreq();
            Console.Write("KeyGen ");
            Benchmark(() => MontgomeryCurve25519.GetPublicKey(seed), n);
            CheckCurrentCpuFreq();
            Console.Write("KeyExchange ");
            Benchmark(() => MontgomeryCurve25519.KeyExchange(publicKey, seed), n);
            Console.WriteLine();

            Console.WriteLine("=== Symmetric ===");
            CheckCurrentCpuFreq();
            {
                const int size = 128 * 1024;
                Console.WriteLine("XSalsa20Poly1305 Encrypt {0} KiB", size / 1024.0);
                var message = new byte[size];
                var ciphertext = new byte[message.Length + 16];
                var key = new byte[32];
                var nonce = new byte[24];
                Benchmark(() => SecretBox.XSalsa20Poly1305.Create(key).Encrypt(new ArraySegment<byte>(ciphertext), new ArraySegment<byte>(message), new ArraySegment<byte>(nonce)), n, size);
                Console.WriteLine("SHA512Managed");
                Benchmark(() => new SHA512Managed().ComputeHash(message), n, size);
                Console.WriteLine("SHA512Cng");
                Benchmark(() => new SHA512Cng().ComputeHash(message), n, size);
                Console.WriteLine("SHA512CSP");
                Benchmark(() => new SHA512CryptoServiceProvider().ComputeHash(message), n, size);
                Console.WriteLine("SHA512Chaos");
                Benchmark(() => Sha512.Hash(message), n, size);
            }
            CheckCurrentCpuFreq();
        }
    }
}
