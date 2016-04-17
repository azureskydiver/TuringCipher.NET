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
        const int Size = 10000000;
        const int NumberOfRuns = 5;

        Tuple<TimeSpan,int> DoRun(ICryptoTransform transform, byte [] clear, byte [] cipher)
        {
            var stopwatch = new Stopwatch();

            stopwatch.Start();
            int count = 0;
            while (count < Size)
                count += transform.TransformBlock(clear, 0, transform.InputBlockSize / 8, cipher, 0);
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
            byte[] clear = new byte[340];
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

        void Run(string[] args)
        {
            TimeRun<ReferenceTuring>();
            TimeRun<TableTuring>();
            TimeRun<FastTuring>();
            Console.ReadKey();
        }

        static void Main(string[] args)
        {
            new Program().Run(args);
        }
    }
}
