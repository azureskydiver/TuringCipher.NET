using System;
using System.Collections.Generic;
using System.Security.Cryptography;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using AXFSoftware.Security.Cryptography.Turing;
using System.Diagnostics;

namespace PerfTests
{
    class Program
    {
        const int Size = ((10000000 / TuringTransform.BlockSizeBytes) + 1) * TuringTransform.BlockSizeBytes;
        const int NumberOfRuns = 10;

        Tuple<TimeSpan,int> DoRun(ICryptoTransform transform, byte [] clear, byte [] cipher)
        {
            var stopwatch = new Stopwatch();

            stopwatch.Start();
            int count = transform.TransformBlock(clear, 0, Size, cipher, 0);
            stopwatch.Stop();
            return Tuple.Create(stopwatch.Elapsed, count);
        }

        double MBPerSecond(int size, TimeSpan time)
        {
            double mb = size / 1000000;
            return Math.Round(mb / time.TotalSeconds, 3);
        }

        void TimeRun<T>() where T : Turing, new()
        {
            var turing = new T();
            string name = turing.GetType().Name;
            Console.WriteLine($"{name}: ");

            turing.Key = Encoding.ASCII.GetBytes("test key 128bits");
            byte[] clear = new byte[Size];
            byte[] cipher = new byte[clear.Length];
            TimeSpan totalTime = new TimeSpan(0);
            int totalSize = 0;
            for(int run = 0; run < NumberOfRuns; run++)
            {
                var tuple = DoRun(turing.CreateEncryptor(), clear, cipher);
                Console.WriteLine($"{tuple.Item1}   ({MBPerSecond(tuple.Item2, tuple.Item1)} MB/sec)");
                totalTime += tuple.Item1;
                totalSize += tuple.Item2;
            }
            TimeSpan averageTime = TimeSpan.FromMilliseconds(totalTime.TotalMilliseconds / NumberOfRuns);
            int averageSize = totalSize / NumberOfRuns;
            Console.WriteLine($"==> Average: {averageTime}   ({MBPerSecond(averageSize, averageTime)} MB/sec)");
        }

        void TimeXors(Func<int, byte [], int, byte [], int, byte [], int, int> xorbytes)
        {
            Console.WriteLine($"{xorbytes.Method.Name}: ");

            var stopwatch = new Stopwatch();
            byte[] clear = new byte[Size];
            byte[] pad = new byte[clear.Length];
            byte[] cipher = new byte[clear.Length];
            TimeSpan totalTime = new TimeSpan(0);
            int totalSize = 0;
            for (int run = 0; run < NumberOfRuns; run++)
            {
                stopwatch.Reset();
                stopwatch.Start();
                xorbytes(Size, clear, 0, pad, 0, cipher, 0);
                stopwatch.Stop();
                Console.WriteLine($"{stopwatch.Elapsed}   ({MBPerSecond(Size, stopwatch.Elapsed)} MB/sec)");
                totalTime += stopwatch.Elapsed;
                totalSize += Size;
            }
            TimeSpan averageTime = TimeSpan.FromMilliseconds(totalTime.TotalMilliseconds / NumberOfRuns);
            int averageSize = totalSize / NumberOfRuns;
            Console.WriteLine($"==> Average: {averageTime}   ({MBPerSecond(averageSize, averageTime)} MB/sec)");
        }

        void Run(string[] args)
        {
            TimeRun<ReferenceTuring>();
            TimeRun<TableTuring>();
            TimeRun<FastTuring>();
            TimeXors(UnsafeMethods.XorBytes64);
            TimeXors(UnsafeMethods.XorBytes32);
            Console.ReadKey();
        }

        static void Main(string[] args)
        {
            new Program().Run(args);
        }
    }
}
