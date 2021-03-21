package security;

import java.io.ByteArrayInputStream;
import java.io.EOFException;
import java.io.IOException;
import java.io.InputStream;
import java.math.BigInteger;
import java.util.Random;

/*
 * Generate the public and private key pairs and test encoding and decoding 
 */
public class RSA {
	public static byte[] cipher(String paramString, Key paramKey) throws Exception {
		return cipher(paramString.getBytes(), paramKey);
	}

	public static byte[] cipher(byte[] paramArrayOfByte, Key paramKey) throws Exception {
		byte[] arrayOfByte1 = new byte[paramArrayOfByte.length + 1];
		arrayOfByte1[0] = 0;
		for (int i = 0; i < paramArrayOfByte.length; i++) {
			arrayOfByte1[(i + 1)] = paramArrayOfByte[i];
		}
		byte[] arrayOfByte2 = new BigInteger(arrayOfByte1).modPow(paramKey.getKey(), paramKey.getN()).toByteArray();

		if (arrayOfByte2[0] != 0) {
			return arrayOfByte2;
		}
		byte[] arrayOfByte3 = new byte[arrayOfByte2.length - 1];
		System.arraycopy(arrayOfByte2, 1, arrayOfByte3, 0, arrayOfByte2.length - 1);
		return arrayOfByte3;
	}

	public static KeyPair generateKeys(BigInteger paramBigInteger1, BigInteger paramBigInteger2) {
		BigInteger localBigInteger1 = BigInteger.ONE;
		BigInteger localBigInteger2 = paramBigInteger1.multiply(paramBigInteger2);
		BigInteger localBigInteger3 = paramBigInteger1.subtract(localBigInteger1).multiply(paramBigInteger2.subtract(localBigInteger1));
		BigInteger localBigInteger4 = relativePrime(localBigInteger3);
		BigInteger localBigInteger5 = localBigInteger4.modInverse(localBigInteger3);
		return new KeyPair(new PrivateKey(localBigInteger5, localBigInteger2), new PublicKey(localBigInteger4, localBigInteger2));
	}

	// Menu for the code, determines to run the help or the rest of the program
	public static void main(String[] paramArrayOfString) throws Exception {
		if (paramArrayOfString.length >= 1) {
			// Displays the help menu
			if (paramArrayOfString[0].equals("-help")) {
				help();
			}
			
			// Generates the public and private key pairs and tests encryption and decryption
			if ((paramArrayOfString[0].equals("-gen")) && (paramArrayOfString.length <= 2)) {
				String str1 = System.getProperty("prime_size");
				String str2 = System.getProperty("prime_certainty");
				int i;
				if (str1 == null) {
					i = 256; // Fixed set bytes if user didn't specify prime_size
				} else {
					i = Integer.parseInt(str1);
				}
				int j;
				if (str2 == null) {
					j = 5; // Fixed set bytes if user didn't specify prime_certainty
				} else {
					j = Integer.parseInt(str2);
				}
				// Prime numbers p and q
				BigInteger localBigInteger1 = new BigInteger(i, j, new Random());
				BigInteger localBigInteger2 = new BigInteger(i, j, new Random());
				KeyPair localKeyPair = generateKeys(localBigInteger1, localBigInteger2);
				System.out.println(localKeyPair);
				if (paramArrayOfString.length == 2) {
					byte[] arrayOfByte1 = paramArrayOfString[1].getBytes();
					byte[] arrayOfByte2 = cipher(arrayOfByte1, localKeyPair.getPublicKey());
					byte[] arrayOfByte3 = cipher(arrayOfByte1, localKeyPair.getPrivateKey());
					System.out.println("KU(KR(M))=" + new String(cipher(arrayOfByte2, localKeyPair.getPrivateKey())));
					System.out.println("KR(KU(M))=" + new String(cipher(arrayOfByte3, localKeyPair.getPublicKey())));
				}
				return;
			}
		}
		System.out.println("java RSA -help");
	}

	private static BigInteger relativePrime(BigInteger paramBigInteger) {
		Random localRandom = new Random();
		int i = paramBigInteger.toByteArray().length;
		BigInteger localBigInteger1 = BigInteger.ONE;
		BigInteger localBigInteger2;
		do {
			byte[] arrayOfByte = new byte[i];
			localRandom.nextBytes(arrayOfByte);
			localBigInteger2 = new BigInteger(arrayOfByte).abs();
			localBigInteger2 = localBigInteger2.mod(paramBigInteger);
		} while (paramBigInteger.gcd(localBigInteger2).compareTo(localBigInteger1) != 0);
		return localBigInteger2;
	}

	public static class Key {
		protected BigInteger key;
		protected BigInteger n;
		private static final BigInteger zero = BigInteger.ZERO;

		public Key() {
			this(zero, zero);
		}

		public Key(BigInteger paramBigInteger1, BigInteger paramBigInteger2) {
			this.key = paramBigInteger1;
			this.n = paramBigInteger2;
		}

		protected BigInteger getKey() {
			return this.key;
		}

		protected BigInteger getN() {
			return this.n;
		}

		public void read(InputStream paramInputStream) throws IOException {
			int i;
			while ((i = paramInputStream.read()) != 123)
				switch (i)
				{
				default:
					throw new IOException("Wrong Format");
				case 9:
				case 10:
				case 13:
				case 32: }  StringBuffer localStringBuffer = new StringBuffer(128);
				while ((i = paramInputStream.read()) != 44) {
					if (i == -1) throw new EOFException("Unexpected End of File");
					localStringBuffer.append((char)i);
				}
				try {
					this.key = new BigInteger(localStringBuffer.toString());
				} catch (NumberFormatException localNumberFormatException1) {
					throw new IOException(localNumberFormatException1.toString());
				}

				localStringBuffer.setLength(0);

				while ((i = paramInputStream.read()) != 125) {
					if (i == -1) throw new EOFException("Unexpected End of File");
					localStringBuffer.append((char)i);
				}
				try {
					this.n = new BigInteger(localStringBuffer.toString());
				} catch (NumberFormatException localNumberFormatException2) {
					throw new IOException(localNumberFormatException2.toString());
				}
			}

		public void read(byte[] paramArrayOfByte) throws IOException {
			read(new ByteArrayInputStream(paramArrayOfByte));
		}

		public String toString() {
			return '{' + this.key.toString() + ',' + this.n.toString() + '}';
		}
	}

	public static class PublicKey extends RSA.Key {
		public PublicKey(InputStream paramInputStream) throws IOException {
			read(paramInputStream);
		}

		protected PublicKey(BigInteger paramBigInteger1, BigInteger paramBigInteger2) {
			super(paramBigInteger1,paramBigInteger2);
		}

		public PublicKey(byte[] paramArrayOfByte) throws IOException {
			read(paramArrayOfByte);
		}
	}

	public static class PrivateKey extends RSA.Key {
		public PrivateKey(InputStream paramInputStream) throws IOException {
			read(paramInputStream);
		}

		protected PrivateKey(BigInteger paramBigInteger1, BigInteger paramBigInteger2) {
			super(paramBigInteger1,paramBigInteger2);
		}

		public PrivateKey(byte[] paramArrayOfByte) throws IOException {
			read(paramArrayOfByte);
		}
	}

	public static class KeyPair {
		private RSA.PrivateKey kR;
		private RSA.PublicKey kU;

		public KeyPair(RSA.PrivateKey paramPrivateKey, RSA.PublicKey paramPublicKey) {
			this.kR = paramPrivateKey;
			this.kU = paramPublicKey;
		}

		public RSA.PrivateKey getPrivateKey() {
			return this.kR;
		}

		public RSA.PublicKey getPublicKey() {
			return this.kU;
		}

		public String toString() {
			return "KR=" + this.kR + System.getProperty("line.separator") + "KU=" + this.kU;
		}
	}

	// Helper function to show help menu
	public static void help() {
		System.out.println("java RSA -help ");
		System.out.println("   - this message");
		System.out.println();
		System.out.println("java RSA -gen [ <text> ]");
		System.out.println("   - generate private (KR) and public (KU) keys");
		System.out.println("     and test them on <text> (optional)");
		System.out.println();
		return;
	}

}