using System;
using System.Linq;
using System.Text;
using Xunit;
using UChainDB.BingChain.Engine.Cryptography;

namespace test
{
    public class UnitTest
    {
        private Secp256k1 signAlgo;

        public UnitTest()
        {
            this.signAlgo = new Secp256k1();
        }

        [Theory]
        [InlineData(
            "03ea01cb94bdaf0cd1c01b159d474f9604f4af35a3e2196f6bdfdb33b2aa4961fa",
            "hello",
            "5331be791532d157df5b5620620d938bcb622ad02c81cfc184c460efdad18e69",
            "5480d77440c511e9ad02ea30d773cb54e88f8cbb069644aefa283957085f38b5")]
        [InlineData(
            "03661b86d54eb3a8e7ea2399e0db36ab65753f95fff661da53ae0121278b881ad0",
            "world",
            "b1e6ff4f40536fb7ed706b0f7567903cc227a5241a079fb86f3de51b8321c1e6",
            "90f37ad0c788848605c1653567935845f0d35a8a1a37174dcbbd235caac8e969")]
        [InlineData(
            "03661b86d54eb3a8e7ea2399e0db36ab65753f95fff661da53ae0121278b881ad0",
            "中文",
            "b8cba1ff42304d74d083e87706058f59cdd4f755b995926d2cd80a734c5a3c37",
            "e4583bfd4339ac762c1c91eee3782660a6baf62cd29e407eccd3da3e9de55a02")]
        public void EcDsaVerifyTest(string pubKeyHex, string message, string rStr, string sStr)
        {
            var pubKey = ToByteArray(pubKeyHex);
            var sig = ToByteArray(rStr).Concat(ToByteArray(sStr)).ToArray();
            var data = Encoding.UTF8.GetBytes(message);
            var result = this.signAlgo.Verify(pubKey, sig, data);
            Assert.True(result);
        }

        [Theory]
        [InlineData("D53667F8592D0577E543E2D344A3536E2D91E19D8AC2AE4F08B8556DB822B1C2", "hello")]
        [InlineData("43f0f9f3af867d6276118efd1f72001d75fd89ecc9a8b0038a4a9a9f3728da40", "中文")]
        public void EcDsaSignTest(string privKeyHex, string message)
        {
            var privKey = ToByteArray(privKeyHex);
            var pubKey = this.signAlgo.GetPublicKey(privKey);
            var data = Encoding.UTF8.GetBytes(message);
            var sig = this.signAlgo.Sign(privKey, data);

            var result = this.signAlgo.Verify(pubKey, sig, data);
            Assert.True(result);
        }

        private static byte[] ToByteArray(string hex)
        {
            hex = hex.Replace(" ", "").Replace("\r\n", "");
            int NumberChars = hex.Length;
            byte[] bytes = new byte[NumberChars / 2];
            for (int i = 0; i < NumberChars; i += 2)
                bytes[i / 2] = Convert.ToByte(hex.Substring(i, 2), 16);
            return bytes;
        }
    }
}