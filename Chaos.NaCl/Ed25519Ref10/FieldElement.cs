using System;
using System.Diagnostics;

namespace Chaos.NaCl.Ed25519Ref10
{
	internal struct FieldElement
	{
		internal int x0;
		internal int x1;
		internal int x2;
		internal int x3;
		internal int x4;
		internal int x5;
		internal int x6;
		internal int x7;
		internal int x8;
		internal int x9;

		public static readonly FieldElement Zero = new FieldElement();
		public static readonly FieldElement One = new FieldElement() { x0 = 1 };

		internal int this[int i]
		{
			get
			{
				switch (i)
				{
					case 0:
						return x0;
					case 1:
						return x1;
					case 2:
						return x2;
					case 3:
						return x3;
					case 4:
						return x4;
					case 5:
						return x5;
					case 6:
						return x6;
					case 7:
						return x7;
					case 8:
						return x8;
					case 9:
						return x9;
					default:
						throw new ArgumentOutOfRangeException("i");
				}
			}
			set
			{
				switch (i)
				{
					case 0:
						x0 = value;
						break;
					case 1:
						x1 = value;
						break;
					case 2:
						x2 = value;
						break;
					case 3:
						x3 = value;
						break;
					case 4:
						x4 = value;
						break;
					case 5:
						x5 = value;
						break;
					case 6:
						x6 = value;
						break;
					case 7:
						x7 = value;
						break;
					case 8:
						x8 = value;
						break;
					case 9:
						x9 = value;
						break;
					default:
						throw new ArgumentOutOfRangeException("i");
				}
			}
		}

		internal FieldElement(params int[] elements)
		{
			Debug.Assert(elements.Length == 10);
			x0 = elements[0];
			x1 = elements[1];
			x2 = elements[2];
			x3 = elements[3];
			x4 = elements[4];
			x5 = elements[5];
			x6 = elements[6];
			x7 = elements[7];
			x8 = elements[8];
			x9 = elements[9];
		}
	}
}
