using System.Linq;

namespace Chaos.NaCl.Tests
{
    public class TestFixture
    {
        public TestFixture()
        {
            Ed25519TestVectors.LoadTestCases();
            //Warmup
            var pk = Ed25519.PublicKeyFromSeed(new byte[32]);
            var sk = Ed25519.ExpandedPrivateKeyFromSeed(new byte[32]);
            var sig = Ed25519.Sign(Ed25519TestVectors.TestCases.Last().Message, sk);
            Ed25519.Verify(sig, new byte[10], pk);
        }
    }
}
