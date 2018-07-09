using Cryptography.ECDSA;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Numerics;
using UChainDB.BingChain.Contracts.Chain;
using UChainDB.BingChain.Engine.Cryptography.EC;

namespace UChainDB.BingChain.Engine.Cryptography
{
    public class ECDsaSignAlgorithm : ISignAlgorithm
    {
        internal readonly ECCurve SelectedCurve = ECCurve.Secp256k1;
        public PrivateKey GenerateRandomPrivateKey(long random = 0)
        {
            byte[] privateKey = new byte[32];
            using (var rng = System.Security.Cryptography.RandomNumberGenerator.Create())
            {
                rng.GetBytes(privateKey);
            }

            return new PrivateKey(privateKey);
        }

        public PublicKey GetPublicKey(PrivateKey privateKey)
        {
            var publicKey = this.SelectedCurve.G * privateKey;
            return new PublicKey(publicKey.EncodePoint(true));
        }

        public Signature Sign(IEnumerable<byte[]> data, PrivateKey privateKey)
        {
            var dataHash = new Hash(data);
            var signature = Secp256k1Manager.SignCompressedCompact(dataHash, privateKey);
            var r = signature.Skip(1).Take(32).ToArray();
            var s = signature.Skip(33).Take(32).ToArray();
            var sig = new Signature(r.Concat(s).ToArray());
            return sig;
        }

        public bool Verify(IEnumerable<byte[]> data, PublicKey publicKey, Signature sig)
        {
            var r = new BigInteger(((byte[])sig).Take(32).Reverse().Concat(new byte[1]).ToArray());
            var s = new BigInteger(((byte[])sig).Skip(32).Reverse().Concat(new byte[1]).ToArray());
            var pubKey = ECPoint.DecodePoint(publicKey, this.SelectedCurve);
            var dsa = new ECDsa(pubKey);
            var dataHash = new Hash(data);
            return dsa.VerifySignature(dataHash, r, s);
        }

        private byte[] TrimSignatureFactor(byte[] data, int length)
        {
            if (data.Length > length && data.Take(data.Length - length).Sum(_ => _) > 0)
            {
                throw new ArgumentException($"Valid data excess expected length [{length}]", nameof(data));
            }

            return (new byte[32]).Concat(data).Skip(data.Length).ToArray();
        }
    }
}
