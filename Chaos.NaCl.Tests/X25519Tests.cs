using Chaos.NaCl.Internal.Ed25519Ref10;
using Multiformats.Base;
using System.Linq;
using Xunit;

namespace Chaos.NaCl.Tests
{
    public class X25519Tests
    {
        [Fact]
        public void ConvertEd25519ToX25519PrivateKey()
        {
            var edPrivate = Multibase.Base58.Decode("47QbyJEDqmHTzsdg8xzqXD8gqKuLufYRrKWTmB7eAaWHG2EAsQ2GUyqRqWWYT15dGuag52Sf3j4hs2mu7w52mgps");

            var expected = "96do29HaLryHStVdCD7jB5TdbM1iGwPUDJvnPkfcqhMB";
            var xPublic = "2AbNdSuzFSpGvsiSPBfnamcKzk9Q3WRRpY2EToHZEuKW";

            var actual = System.Security.Cryptography.SHA512.Create().ComputeHash(edPrivate.Take(32).ToArray());

            ScalarOperations.sc_clamp(actual, 0);
            actual = actual.Take(32).ToArray();

            Assert.Equal(expected, Multibase.Base58.Encode(actual));

            var expectedPublic = MontgomeryCurve25519.GetPublicKey(actual);
            Assert.Equal(xPublic, Multibase.Base58.Encode(expectedPublic));
        }

        [Fact]
        public void ConvertEd25519ToX25519PublicKey()
        {
            var edPublic = Multibase.Base58.Decode("dbDmZLTWuEYYZNHFLKLoRkEX4sZykkSLNQLXvMUyMB1");

            var expected = "2AbNdSuzFSpGvsiSPBfnamcKzk9Q3WRRpY2EToHZEuKW";

            var actual = new byte[32];
            MontgomeryCurve25519.EdwardsToMontgomery(actual, edPublic);

            Assert.Equal(expected, Multibase.Base58.Encode(actual));
        }
    }
}
