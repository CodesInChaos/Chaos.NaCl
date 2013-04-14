using System;
using System.Collections.Generic;
using System.Text;

namespace Chaos.NaCl
{
	// This class is mainly for compatibility with NaCl's Curve25519 implementation
	// If you don't need that compatibility, use Ed25519.KeyExchange
	public static class MontgomeryCurve25519
	{
		public static readonly int PublicKeySizeInBytes = 32;
		public static readonly int PrivateKeySizeInBytes = 32;
		public static readonly int SharedKeySizeInBytes = 32;

		public static byte[] KeyExchange(byte[] publicKey, byte[] privateKey)
		{
			var sharedKey = new byte[SharedKeySizeInBytes];
			KeyExchange(new ArraySegment<byte>(sharedKey), new ArraySegment<byte>(publicKey), new ArraySegment<byte>(privateKey));
			return sharedKey;
		}

		public static void KeyExchange(ArraySegment<byte> sharedKey, ArraySegment<byte> publicKey, ArraySegment<byte> privateKey)
		{
			
		}

		/*[Obsolete]
public static byte[] EdwardsToMontgomeryX(byte[] edwardsPoint)
{
	Contract.Requires<ArgumentNullException>(edwardsPoint != null);
	Contract.Requires<ArgumentException>(edwardsPoint.Length == PublicKeySizeInBytes);
	var edwardsY = Ed25519Slow.decodepoint(edwardsPoint).Item2;
	var montgomeryX = Ed25519Slow.mod((edwardsY + 1) * Ed25519Slow.inv(1 - edwardsY), Ed25519Slow.q);
	return Ed25519Slow.encodeint(montgomeryX);
}*/
	}
}
