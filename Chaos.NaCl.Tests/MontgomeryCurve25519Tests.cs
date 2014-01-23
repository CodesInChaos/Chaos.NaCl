using System;
using System.Linq;
using Microsoft.VisualStudio.TestTools.UnitTesting;

namespace Chaos.NaCl.Tests
{
    [TestClass]
    public class MontgomeryCurve25519Tests
    {
        [TestMethod]
        public void GetPublicKeyAlice()
        {
            var calculatedAlicePublicKey = MontgomeryCurve25519.GetPublicKey(MontgomeryCurve25519TestVectors.AlicePrivateKey);
            Assert.IsTrue(MontgomeryCurve25519TestVectors.AlicePublicKey.SequenceEqual(calculatedAlicePublicKey));
        }

        [TestMethod]
        public void GetPublicKeyBob()
        {
            var calculatedBobPublicKey = MontgomeryCurve25519.GetPublicKey(MontgomeryCurve25519TestVectors.BobPrivateKey);
            Assert.IsTrue(MontgomeryCurve25519TestVectors.BobPublicKey.SequenceEqual(calculatedBobPublicKey));
        }

        [TestMethod]
        public void GetPublicKeySegments()
        {
            var privateKey = MontgomeryCurve25519TestVectors.BobPrivateKey.Pad();
            var calculatedBobPublicKey = new byte[32].Pad();
            MontgomeryCurve25519.GetPublicKey(calculatedBobPublicKey, privateKey);
            TestHelpers.AssertEqualBytes(MontgomeryCurve25519TestVectors.BobPublicKey, calculatedBobPublicKey.ToArray());
        }

        [TestMethod]
        public void GetSharedKeySegments()
        {
            var bobPublic = MontgomeryCurve25519TestVectors.BobPublicKey.Pad();
            var alicePrivate = MontgomeryCurve25519TestVectors.AlicePrivateKey.Pad();
            var calculatedSharedAlice = new byte[32].Pad();
            MontgomeryCurve25519.KeyExchange(calculatedSharedAlice, bobPublic, alicePrivate);
            TestHelpers.AssertEqualBytes(MontgomeryCurve25519TestVectors.AliceBobSharedKey, calculatedSharedAlice.ToArray());
        }

        [TestMethod]
        public void GetSharedKeyAliceBob()
        {
            var calculatedSharedAlice = MontgomeryCurve25519.KeyExchange(MontgomeryCurve25519TestVectors.BobPublicKey, MontgomeryCurve25519TestVectors.AlicePrivateKey);
            Assert.AreEqual(BitConverter.ToString(MontgomeryCurve25519TestVectors.AliceBobSharedKey), BitConverter.ToString(calculatedSharedAlice));
        }

        [TestMethod]
        public void GetSharedKeyAliceFrank0()
        {
            var calculatedSharedAliceFrank = MontgomeryCurve25519.KeyExchange(MontgomeryCurve25519TestVectors.FrankPublicKey0, MontgomeryCurve25519TestVectors.AlicePrivateKey);
            Assert.AreEqual(BitConverter.ToString(MontgomeryCurve25519TestVectors.AliceFrankSharedKey), BitConverter.ToString(calculatedSharedAliceFrank));
        }

        [TestMethod]
        public void GetSharedKeyAliceFrank()
        {
            var calculatedSharedAliceFrank = MontgomeryCurve25519.KeyExchange(MontgomeryCurve25519TestVectors.FrankPublicKey, MontgomeryCurve25519TestVectors.AlicePrivateKey);
            Assert.AreEqual(BitConverter.ToString(MontgomeryCurve25519TestVectors.AliceFrankSharedKey), BitConverter.ToString(calculatedSharedAliceFrank));
        }


        [TestMethod]
        public void GetSharedKeyBobAlice()
        {
            var calculatedSharedBob = MontgomeryCurve25519.KeyExchange(MontgomeryCurve25519TestVectors.AlicePublicKey, MontgomeryCurve25519TestVectors.BobPrivateKey);
            Assert.AreEqual(BitConverter.ToString(MontgomeryCurve25519TestVectors.AliceBobSharedKey), BitConverter.ToString(calculatedSharedBob));
        }

        [TestMethod]
        public void GetSharedKeyBobFrank()
        {
            var calculatedSharedBobFrank = MontgomeryCurve25519.KeyExchange(MontgomeryCurve25519TestVectors.FrankPublicKey, MontgomeryCurve25519TestVectors.BobPrivateKey);
            Assert.AreEqual(BitConverter.ToString(MontgomeryCurve25519TestVectors.BobFrankSharedKey), BitConverter.ToString(calculatedSharedBobFrank));
        }

        [TestMethod]
        public void GetSharedKeyBobAlice2()
        {
            var calculatedSharedBob = MontgomeryCurve25519.KeyExchange(MontgomeryCurve25519TestVectors.AlicePublicKey2, MontgomeryCurve25519TestVectors.BobPrivateKey);
            Assert.AreEqual(BitConverter.ToString(MontgomeryCurve25519TestVectors.AliceBobSharedKey), BitConverter.ToString(calculatedSharedBob));
        }

        public MontgomeryCurve25519Tests()
        {
            //Warmup
            MontgomeryCurve25519.GetPublicKey(MontgomeryCurve25519TestVectors.AlicePrivateKey);
            MontgomeryCurve25519.KeyExchange(MontgomeryCurve25519TestVectors.AlicePublicKey, MontgomeryCurve25519TestVectors.AlicePrivateKey);
            MontgomeryCurve25519.KeyExchange(MontgomeryCurve25519TestVectors.BobPublicKey, MontgomeryCurve25519TestVectors.BobPrivateKey);
        }
    }
}
