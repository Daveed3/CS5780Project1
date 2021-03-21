package security;

import java.io.IOException;
import java.io.OutputStream;
import java.io.PrintStream;
import java.util.Random;

public class OneTimeKey {
	public static void main(String[] paramArrayOfString) throws Exception {
		if (paramArrayOfString.length < 2) {
			System.out.println("java OneTimeKey <key>  <text> [ <text> ... ]");
			System.exit(1);
		}

		byte[] arrayOfByte1 = paramArrayOfString[0].getBytes();

		for (int i = 1; i < paramArrayOfString.length; i++) {
			System.out.println("The Original text is " + paramArrayOfString[i]);
			byte[] arrayOfByte2 = xor(paramArrayOfString[i].getBytes(), arrayOfByte1);
			System.out.println("Encoded into " + new String(arrayOfByte2));
			byte[] arrayOfByte3 = xor(arrayOfByte2, arrayOfByte1);
			System.out.println("Decoded into " + new String(arrayOfByte3));
		}
	}

	public static byte[] newKey(int paramInt) {
		return newKey(new Random(), paramInt);
	}

	public static byte[] newKey(Random paramRandom, int paramInt) {
		byte[] arrayOfByte = new byte[paramInt];
		paramRandom.nextBytes(arrayOfByte);
		return arrayOfByte;
	}

	public static void printKey(byte[] paramArrayOfByte, OutputStream paramOutputStream) throws IOException {
		for (int i = 0; i < paramArrayOfByte.length; i++)
			paramOutputStream.write(paramArrayOfByte[i]);
	}

	public static byte[] xor(byte[] paramArrayOfByte1, byte[] paramArrayOfByte2) {
		if (paramArrayOfByte1.length % paramArrayOfByte2.length != 0) {
			throw new RuntimeException("ERROR in Length of one-time key !!!");
		}
		byte[] arrayOfByte = new byte[paramArrayOfByte1.length];
		System.arraycopy(paramArrayOfByte1, 0, arrayOfByte, 0, paramArrayOfByte1.length);

		int j = 0;

		for (int i = 0; i < paramArrayOfByte1.length / paramArrayOfByte2.length; i++) {
			for (int k = 0; k < paramArrayOfByte2.length; k++) {
				arrayOfByte[j] = ((byte)(arrayOfByte[j] ^ paramArrayOfByte2[k]));
				j++;
			}
		}
		return arrayOfByte;
	}
}