using System;
using System.Collections.Generic;

namespace Chaos.NaCl.Internal
{
    internal struct Array16<T>
    {
        public T x0;
        public T x1;
        public T x2;
        public T x3;
        public T x4;
        public T x5;
        public T x6;
        public T x7;
        public T x8;
        public T x9;
        public T x10;
        public T x11;
        public T x12;
        public T x13;
        public T x14;
        public T x15;

        public static void FromBytesLittleEndian(out Array16<UInt32> output, byte[] input, int inputOffset)
        {
            output.x0 = ByteIntegerConverter.LoadLittleEndian32(input, inputOffset + 0);
            output.x1 = ByteIntegerConverter.LoadLittleEndian32(input, inputOffset + 4);
            output.x2 = ByteIntegerConverter.LoadLittleEndian32(input, inputOffset + 8);
            output.x3 = ByteIntegerConverter.LoadLittleEndian32(input, inputOffset + 12);
            output.x4 = ByteIntegerConverter.LoadLittleEndian32(input, inputOffset + 16);
            output.x5 = ByteIntegerConverter.LoadLittleEndian32(input, inputOffset + 20);
            output.x6 = ByteIntegerConverter.LoadLittleEndian32(input, inputOffset + 24);
            output.x7 = ByteIntegerConverter.LoadLittleEndian32(input, inputOffset + 28);
            output.x8 = ByteIntegerConverter.LoadLittleEndian32(input, inputOffset + 32);
            output.x9 = ByteIntegerConverter.LoadLittleEndian32(input, inputOffset + 36);
            output.x10 = ByteIntegerConverter.LoadLittleEndian32(input, inputOffset + 40);
            output.x11 = ByteIntegerConverter.LoadLittleEndian32(input, inputOffset + 44);
            output.x12 = ByteIntegerConverter.LoadLittleEndian32(input, inputOffset + 48);
            output.x13 = ByteIntegerConverter.LoadLittleEndian32(input, inputOffset + 52);
            output.x14 = ByteIntegerConverter.LoadLittleEndian32(input, inputOffset + 56);
            output.x15 = ByteIntegerConverter.LoadLittleEndian32(input, inputOffset + 60);
        }

        public static void ToBytesLittleEndian(byte[] output, int outputOffset, ref Array16<UInt32> input)
        {
            ByteIntegerConverter.StoreLittleEndian32(output, outputOffset + 0, input.x0);
            ByteIntegerConverter.StoreLittleEndian32(output, outputOffset + 4, input.x1);
            ByteIntegerConverter.StoreLittleEndian32(output, outputOffset + 8, input.x2);
            ByteIntegerConverter.StoreLittleEndian32(output, outputOffset + 12, input.x3);
            ByteIntegerConverter.StoreLittleEndian32(output, outputOffset + 16, input.x4);
            ByteIntegerConverter.StoreLittleEndian32(output, outputOffset + 20, input.x5);
            ByteIntegerConverter.StoreLittleEndian32(output, outputOffset + 24, input.x6);
            ByteIntegerConverter.StoreLittleEndian32(output, outputOffset + 28, input.x7);
            ByteIntegerConverter.StoreLittleEndian32(output, outputOffset + 32, input.x8);
            ByteIntegerConverter.StoreLittleEndian32(output, outputOffset + 36, input.x9);
            ByteIntegerConverter.StoreLittleEndian32(output, outputOffset + 40, input.x10);
            ByteIntegerConverter.StoreLittleEndian32(output, outputOffset + 44, input.x11);
            ByteIntegerConverter.StoreLittleEndian32(output, outputOffset + 48, input.x12);
            ByteIntegerConverter.StoreLittleEndian32(output, outputOffset + 52, input.x13);
            ByteIntegerConverter.StoreLittleEndian32(output, outputOffset + 56, input.x14);
            ByteIntegerConverter.StoreLittleEndian32(output, outputOffset + 60, input.x15);
        }

        /*public static void ToBytesLittleEndian(byte[] output, int outputOffset, ref Array16<UInt32> input, int inputOffset, int length)
        {
            var temp = new byte[64];//todo: remove allocation
            ToBytesLittleEndian(temp, 0, ref input);
            Array.Copy(temp, 0, output, outputOffset, length);
        }*/
    }
}
