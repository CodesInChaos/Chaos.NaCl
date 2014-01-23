using System;
using System.Collections.Generic;

namespace Chaos.NaCl.Internal
{
    /* internal static class ArrayCache
     {
         internal const int MaxSize = 256;
         [ThreadStatic]
         private static byte[] _array;

 #if DEBUG
         [ThreadStatic]
         private static int _aquiredSize;
 #endif

         public static byte[] Aquire(int size)
         {
 #if DEBUG
             if ((uint)size > MaxSize)
                 throw new ArgumentException("size");
             if (_aquiredSize != 0)
                 throw new InvalidOperationException("Aquiring already aquired array");
             _aquiredSize = size;
 #endif
             if (_array == null)
                 _array = new byte[MaxSize];
             return _array;
         }

         public static void WipeAndRelease(byte[] array, int size)
         {
 #if DEBUG
             if (array != _array)
                 throw new ArgumentException("Unexpected array");
             if (_aquiredSize == 0)
                 throw new ArgumentException("Releasing unaquired array");
             if (_aquiredSize != size)
                 throw new ArgumentException("Unexpected size");
             _aquiredSize = 0;
 #endif
             CryptoBytes.InternalWipe(array, 0, size);
         }
     }*/
}
