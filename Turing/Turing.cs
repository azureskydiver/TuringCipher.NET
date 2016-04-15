using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.Security.Cryptography;

namespace AXFSoftware.Security.Cryptography.Turing
{
    public abstract class Turing : SymmetricAlgorithm
    {
        static KeySizes[] s_legalKeySizes = { new KeySizes(TuringTransform.KeySizeMinBits, TuringTransform.KeySizeMaxBits, TuringTransform.KeySizeSkipBits) };
        static KeySizes[] s_legalBlockSizes = { new KeySizes(TuringTransform.BlockSize, TuringTransform.BlockSize, 0) };
        static Dictionary<string, Type> s_implementations = new Dictionary<string, Type>()
        {
            ["FastTuring"] = typeof(FastTuring),
            ["ReferenceTuring"] = typeof(ReferenceTuring),
            ["TableTuring"] = typeof(TableTuring),
            ["Turing"] = typeof(ReferenceTuring),
        };

        Lazy<RandomNumberGenerator> _rng = new Lazy<RandomNumberGenerator>(RandomNumberGenerator.Create);

        RandomNumberGenerator SecureRandom
        {
            get { return _rng.Value; }
        }

        protected Turing()
        {
            LegalKeySizesValue = s_legalKeySizes;
            LegalBlockSizesValue = s_legalBlockSizes;
        }

        public static void Register()
        {
            //$ TODO: Need to figure out how to automatically register

            foreach (var kvp in s_implementations)
                CryptoConfig.AddAlgorithm(kvp.Value, kvp.Key);
        }

        public static new Turing Create()
        {
            return Create("Turing");
        }

        public static new Turing Create(string name)
        {
            if (s_implementations.ContainsKey(name))
                return Activator.CreateInstance(s_implementations[name]) as Turing;
            return SymmetricAlgorithm.Create(name) as Turing;
        }

        byte [] GetRandomBytes(int size)
        {
            var data = new byte[KeySize / 8];
            SecureRandom.GetBytes(data);
            return data;
        }

        public override void GenerateKey()
        {
            if (KeySize <= 0)                
                KeySize = LegalKeySizes.Max(ks => ks.MaxSize);

            Key = GetRandomBytes(KeySize / 8);
        }

        public override void GenerateIV()
        {
            if (Key == null || KeySize <= 0)
                throw new InvalidOperationException("Failed to find a key.");

            IV = GetRandomBytes((TuringTransform.KeySizeMaxBits - KeySize) / 8);
        }

        public override ICryptoTransform CreateEncryptor(byte[] rgbKey, byte[] rgbIV)
        {
            if (rgbKey == null || rgbKey.Length == 0)
                rgbKey = Key;
            if (rgbIV == null || rgbIV.Length == 0)
                rgbIV = IV;

            return CreateTransform(rgbKey, rgbIV);
        }

        public override ICryptoTransform CreateDecryptor(byte[] rgbKey, byte[] rgbIV)
        {
            return CreateTransform(rgbKey, rgbIV);
        }

        protected abstract ICryptoTransform CreateTransform(byte[] rgbKey, byte[] rgbIV);
    }
}
