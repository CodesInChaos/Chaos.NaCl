using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Linq;
using System.Globalization;
using System.Security.Cryptography;
using System.Threading;
using Chaos.NaCl.Internal;
using Chaos.NaCl.Internal.Salsa;

namespace Chaos.NaCl.Benchmark
{
    public class BenchmarkProgram
    {
        static void Benchmark(string name, Action action, int n, int bytes = 0)
        {
            Console.ForegroundColor = ConsoleColor.White;
            Console.WriteLine(name);
            Console.ForegroundColor = ConsoleColor.Gray;
            GC.Collect();
            GC.WaitForPendingFinalizers();
            var watch = new Stopwatch();
            var start = DateTime.UtcNow;
            var values = new float[n];
            for (int i = 0; i < n; i++)
            {
                watch.Restart();
                action();
                watch.Stop();
                double thisIteration = watch.Elapsed.TotalSeconds;
                values[i] = (float)thisIteration;
            }
            var total = (DateTime.UtcNow - start).TotalSeconds;
            Cpu.CheckCurrentCpuFreq();
            var perIteration = total / n;
            Array.Sort(values);
            double sum = values.Sum();
            double sumOfSquares = values.Sum(x => x * x);
            double average = sum / n;
            double stdDev = Math.Sqrt(sumOfSquares / n - average * average);
            double median = values[n / 2];
            double min = values.Min();
            double max = values.Max();

            double low90 = values[n / 10];
            double high90 = values[n - 1 - n / 10];
            double delta90 = (high90 - low90) / 2;
            double relativeDelta90 = delta90 / median;
            double average90 = values.Where(x => (x >= low90) && (x <= high90)).Average();

            double low75 = values[n / 4];
            double high75 = values[n - 1 - n / 4];
            double delta75 = (high75 - low75) / 2;
            double relativeDelta75 = delta75 / median;
            double average75 = values.Where(x => (x >= low75) && (x <= high75)).Average();

            Console.WriteLine("{0} us / {1} per second / {2} cycles",
                Math.Round(average90 * 1E6, 2), Math.Round(1 / average90), Math.Round(average90 * Cpu.CpuFreq * 1E6));
            Console.WriteLine("Average {0} us, Median {1} us, min {2}, max {3}", Math.Round(average * 1E6, 2),
                              Math.Round(median * 1E6, 2), Math.Round(min * 1E6, 2), Math.Round(max * 1E6, 2));
            Console.WriteLine("80% within ±{0}% average {1} | 50% within ±{2}% average {3}",
                Math.Round(relativeDelta90 * 100, 2), Math.Round(average90 * 1E6, 2),
                Math.Round(relativeDelta75 * 100, 2), Math.Round(average75 * 1E6, 2));
            if (bytes > 0)
            {
                double bytesPerSecond = bytes / average90;
                double cyclesPerByte = (Cpu.CpuFreq * 1E6) / bytesPerSecond;
                Console.WriteLine("{0} MB/s / {1} cycles/byte",
                    Math.Round(bytesPerSecond / 1E6, 2), Math.Round(cyclesPerByte, 2));
            }
            Console.WriteLine();
        }

        public static void Main()
        {
            const int n = 10000;

            Thread.CurrentThread.CurrentCulture = CultureInfo.InvariantCulture;
            Console.WriteLine("Architecture: {0} bit", IntPtr.Size * 8);
            Console.WriteLine("CPU-Frequency: {0} MHz", Cpu.CpuFreq);
            Cpu.Setup();
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

            Console.BackgroundColor = ConsoleColor.Black;

            {
                Console.ForegroundColor = ConsoleColor.Yellow;
                Console.WriteLine("=== Edwards ===");
                Benchmark("KeyGen", () => Ed25519.KeyPairFromSeed(out publicKey, out privateKey, seed), n);
                Benchmark("Sign", () => Ed25519.Sign(m, privateKey), n);
                Benchmark("Verify", () => Ed25519.Verify(sig, m, publicKey), n);
                Benchmark("KeyExchange", () => Ed25519.KeyExchange(publicKey, privateKey), n);
                Console.WriteLine();
            }

            {
                Console.ForegroundColor = ConsoleColor.Yellow;
                Console.WriteLine("=== Montgomery ===");
                Benchmark("KeyGen", () => MontgomeryCurve25519.GetPublicKey(seed), n);
                Benchmark("KeyExchange", () => MontgomeryCurve25519.KeyExchange(publicKey, seed), n);
                Console.WriteLine();
            }

            foreach (var size in new[] { 1, 128 * 1024 })
            {
                Console.ForegroundColor = ConsoleColor.Yellow;
                Console.WriteLine("=== Symmetric ({0}) ===", SizeToString(size));
                var message = new byte[size];
                var ciphertext = new byte[message.Length + 16];
                var key = new byte[32];
                var nonce = new byte[24];
                Benchmark("HSalsa20Core", () => HSalsa20Core(size), n, size);
                Benchmark("XSalsa20Poly1305 Encrypt", () => XSalsa20Poly1305.Encrypt(new ArraySegment<byte>(ciphertext), new ArraySegment<byte>(message), new ArraySegment<byte>(key), new ArraySegment<byte>(nonce)), n, size);
                Benchmark("SHA512Managed", () => new SHA512Managed().ComputeHash(message), n, size);
                Benchmark("SHA512Cng", () => new SHA512Cng().ComputeHash(message), n, size);
                Benchmark("SHA512CSP", () => new SHA512CryptoServiceProvider().ComputeHash(message), n, size);
                Benchmark("SHA512Chaos", () => Sha512.Hash(message), n, size);
            }
        }

        private static string SizeToString(int size)
        {
            if (size > 2048)
                return String.Format("{0} KiB", size / 1024);
            else
                return String.Format("{0} B", size);
        }

        private static void HSalsa20Core(int size)
        {
            byte[] input = new byte[64]{
				        6,124, 83,146, 38,191,9, 50,4,161, 47,222,122,182,223,185,
				        75, 27,0,216, 16,122,7, 89,162,104,101,147,213, 21, 54, 95,
				        225,253,139,176,105,132, 23,116, 76, 41,176,207,221, 34,157,108,
				        94, 94, 99, 52, 90,117, 91,220,146,190,239,143,196,176,130,186};
            Array16<UInt32> state;
            ByteIntegerConverter.Array16LoadLittleEndian32(out state, input, 0);
            for (int i = 0; i < (size + 63) / 64; i++)
            {
                SalsaCore.HSalsa(out state, ref state, 20);
            }
        }
    }
}
