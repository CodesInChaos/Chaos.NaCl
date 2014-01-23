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
    class Program
    {
        static uint CpuFreq;

        static uint GetCurrentCpuFreq()
        {
            return 2901;
            using (ManagementBaseObject mo = new ManagementObject("Win32_Processor.DeviceID='CPU0'"))
            {
                return (uint)(mo["CurrentClockSpeed"]);
            }
        }

        static uint GetMaxCpuFreq()
        {
            return 2901;
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
                }, 100);

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
                Console.WriteLine("XSalsa20Poly1305 Encrypt 16 kB");
                var message = new byte[128 * 1024];
                var ciphertext = new byte[message.Length + 16];
                var key = new byte[32];
                var nonce = new byte[24];
                Benchmark(() => XSalsa20Poly1305.Encrypt(new ArraySegment<byte>(ciphertext), new ArraySegment<byte>(message), new ArraySegment<byte>(key), new ArraySegment<byte>(nonce)), n);
                Console.WriteLine("SHA512Managed");
                Benchmark(() => new SHA512Managed().ComputeHash(message), n);
                Console.WriteLine("SHA512Cng");
                Benchmark(() => new SHA512Cng().ComputeHash(message), n);
                Console.WriteLine("SHA512CSP");
                Benchmark(() => new SHA512CryptoServiceProvider().ComputeHash(message), n);
                Console.WriteLine("SHA512Chaos");
                Benchmark(() => Sha512.Hash(message), n);
            }
            CheckCurrentCpuFreq();
        }
    }
}
