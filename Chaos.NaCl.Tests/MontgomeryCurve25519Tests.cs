using System;
using System.Linq;
using Xunit;

namespace Chaos.NaCl.Tests
{
    
    public class MontgomeryCurve25519Tests
    {
        [Fact]
        public void GetPublicKeyAlice()
        {
            var calculatedAlicePublicKey = MontgomeryCurve25519.GetPublicKey(MontgomeryCurve25519TestVectors.AlicePrivateKey);
            Assert.True(MontgomeryCurve25519TestVectors.AlicePublicKey.SequenceEqual(calculatedAlicePublicKey));
        }

        [Fact]
        public void GetPublicKeyBob()
        {
            var calculatedBobPublicKey = MontgomeryCurve25519.GetPublicKey(MontgomeryCurve25519TestVectors.BobPrivateKey);
            Assert.True(MontgomeryCurve25519TestVectors.BobPublicKey.SequenceEqual(calculatedBobPublicKey));
        }

        [Fact]
        public void GetPublicKeySegments()
        {
            var privateKey = MontgomeryCurve25519TestVectors.BobPrivateKey.Pad();
            var calculatedBobPublicKey = new byte[32].Pad();
            MontgomeryCurve25519.GetPublicKey(calculatedBobPublicKey, privateKey);
            TestHelpers.AssertEqualBytes(MontgomeryCurve25519TestVectors.BobPublicKey, calculatedBobPublicKey.UnPad());
        }

        [Fact]
        public void GetSharedKeySegments()
        {
            var bobPublic = MontgomeryCurve25519TestVectors.BobPublicKey.Pad();
            var alicePrivate = MontgomeryCurve25519TestVectors.AlicePrivateKey.Pad();
            var calculatedSharedAlice = new byte[32].Pad();
            MontgomeryCurve25519.KeyExchange(calculatedSharedAlice, bobPublic, alicePrivate);
            TestHelpers.AssertEqualBytes(MontgomeryCurve25519TestVectors.AliceBobSharedKey, calculatedSharedAlice.UnPad());
        }

        [Fact]
        public void GetSharedKeyAliceBob()
        {
            var calculatedSharedAlice = MontgomeryCurve25519.KeyExchange(MontgomeryCurve25519TestVectors.BobPublicKey, MontgomeryCurve25519TestVectors.AlicePrivateKey);
            TestHelpers.AssertEqualBytes(MontgomeryCurve25519TestVectors.AliceBobSharedKey, calculatedSharedAlice);
        }

        [Fact]
        public void GetSharedKeyAliceFrank0()
        {
            var calculatedSharedAliceFrank = MontgomeryCurve25519.KeyExchange(MontgomeryCurve25519TestVectors.FrankPublicKey0, MontgomeryCurve25519TestVectors.AlicePrivateKey);
            TestHelpers.AssertEqualBytes(MontgomeryCurve25519TestVectors.AliceFrankSharedKey, calculatedSharedAliceFrank);
        }

        [Fact]
        public void GetSharedKeyAliceFrank()
        {
            var calculatedSharedAliceFrank = MontgomeryCurve25519.KeyExchange(MontgomeryCurve25519TestVectors.FrankPublicKey, MontgomeryCurve25519TestVectors.AlicePrivateKey);
            TestHelpers.AssertEqualBytes(MontgomeryCurve25519TestVectors.AliceFrankSharedKey, calculatedSharedAliceFrank);
        }


        [Fact]
        public void GetSharedKeyBobAlice()
        {
            var calculatedSharedBob = MontgomeryCurve25519.KeyExchange(MontgomeryCurve25519TestVectors.AlicePublicKey, MontgomeryCurve25519TestVectors.BobPrivateKey);
            TestHelpers.AssertEqualBytes(MontgomeryCurve25519TestVectors.AliceBobSharedKey, calculatedSharedBob);
        }

        [Fact]
        public void GetSharedKeyBobFrank()
        {
            var calculatedSharedBobFrank = MontgomeryCurve25519.KeyExchange(MontgomeryCurve25519TestVectors.FrankPublicKey, MontgomeryCurve25519TestVectors.BobPrivateKey);
            TestHelpers.AssertEqualBytes(MontgomeryCurve25519TestVectors.BobFrankSharedKey, calculatedSharedBobFrank);
        }

        [Fact]
        public void GetSharedKeyBobAlice2()
        {
            var calculatedSharedBob = MontgomeryCurve25519.KeyExchange(MontgomeryCurve25519TestVectors.AlicePublicKey2, MontgomeryCurve25519TestVectors.BobPrivateKey);
            TestHelpers.AssertEqualBytes(MontgomeryCurve25519TestVectors.AliceBobSharedKey, calculatedSharedBob);
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
