package security;

import java.io.PrintStream;
import java.math.BigInteger;

public class Hash {
	private int nDatabytes;
	private int nCheckbytes;
	private byte pattern;
	private int k;

	public Hash(int paramInt1, int paramInt2, byte paramByte, int paramInt3) {
		this.nDatabytes = paramInt1;
		this.nCheckbytes = paramInt2;
		this.pattern = paramByte;
		this.k = paramInt3;
	}

	public int getNumberOfDataBytes() {
		return this.nDatabytes;
	}

	public int getPacketSize() {
		return this.nDatabytes + this.nCheckbytes + 1;
	}

	public static void main(String[] paramArrayOfString) throws Exception {
		if (paramArrayOfString.length < 5) {
	      System.out.println("java Hash <databytes> <checkbytes> <pattern> <k> <text> [ <text> ... ]");
	      System.exit(1);
		}

	    int i = Integer.parseInt(paramArrayOfString[0]);
	    int j = Integer.parseInt(paramArrayOfString[1]);
	    int m = (byte)Integer.parseInt(paramArrayOfString[2]);
	    int n = Integer.parseInt(paramArrayOfString[3]);

	    for (int i1 = 4; i1 < paramArrayOfString.length; i1++) {
	    	byte[] arrayOfByte = pack(paramArrayOfString[i1].getBytes(), i, j, (byte)m, n);
	    	System.out.println("packed Bytes");
	    	System.out.println(new String(arrayOfByte));
	    	System.out.println("unpacked Bytes");
	    	System.out.println(new String(unpack(arrayOfByte, i, j, (byte)m, n)));
	    }
	}

	public byte[] pack(byte[] paramArrayOfByte) {
		return pack(paramArrayOfByte, this.nDatabytes, this.nCheckbytes, this.pattern, this.k);
	}

	public byte[] pack(byte[] paramArrayOfByte, int paramInt) {
	    byte[] arrayOfByte = new byte[paramInt];
	    System.arraycopy(paramArrayOfByte, 0, arrayOfByte, 0, paramInt);
	    return pack(arrayOfByte, this.nDatabytes, this.nCheckbytes, this.pattern, this.k);
	}

	public static byte[] pack(byte[] paramArrayOfByte, int paramInt1, int paramInt2, byte paramByte, int paramInt3) {
		if (paramInt1 > 256) {
			throw new RuntimeException("Databytes MAX Size is 255.");
		}
		int i = paramArrayOfByte.length;
		int j = paramInt1 + paramInt2 + 1;
		int m = i % paramInt1 == 0 ? i / paramInt1 : i / paramInt1 + 1;

		byte[] arrayOfByte = new byte[m * j];
		int i2 = 0;

	    for (int n = 0; n < m; n++) {
	    	byte i3 = (byte)((n + 1) * paramInt1 > i ? i % paramInt1 : paramInt1);
	
	    	arrayOfByte[(n * j)] = i3;
	
	    	BigInteger localBigInteger = BigInteger.valueOf(0L);
	
	    	for (int i1 = 0; i1 < i3; i1++) {
		        byte b = paramArrayOfByte[i2];
		        i2++;
		        localBigInteger = localBigInteger.add(BigInteger.valueOf((paramByte & b) * paramInt3));
		        arrayOfByte[(n * j + i1 + 1)] = b;
	    	}
	
	    	localBigInteger = localBigInteger.mod(BigInteger.valueOf((int)Math.pow(2.0D, 8 * paramInt2)));
	
	    	byte b = (byte) localBigInteger.toByteArray().length;
	    	for (int i4 = 0; i4 < paramInt2; i4++) {
	    		if (paramInt2 - i4 > b)
	    			arrayOfByte[(n * j + paramInt1 + i4 + 1)] = 0;
	    		else {
	    			arrayOfByte[(n * j + paramInt1 + i4 + 1)] = localBigInteger.toByteArray()[(i4 - (paramInt2 - b))];
	    		}
	    	}
	    }
	    return arrayOfByte;
	}

	public byte[] unpack(byte[] paramArrayOfByte) throws Exception {
		return unpack(paramArrayOfByte, this.nDatabytes, this.nCheckbytes, this.pattern, this.k);
	}

	public static byte[] unpack(byte[] paramArrayOfByte, int paramInt1, int paramInt2, byte paramByte, int paramInt3) throws Exception {
		if (paramInt1 > 256) {
			throw new RuntimeException("Databytes MAX Size is 256");
		}
		int i = paramArrayOfByte.length;
		int j = 1 + paramInt1 + paramInt2;
		if (i % j != 0) {
			throw new Exception("Wrong Packet Size !!!");
		}
		int m = i / j;

		int n = 0;
		for (int i1 = 0; i1 < m; i1++) {
			n += paramArrayOfByte[(i1 * j)];
		}

		byte[] arrayOfByte = new byte[n];
		int i2 = 0;
		int i3 = 0;
		int i4 = 0;
		for (; i2 < m; i2++) {
			int i5 = paramArrayOfByte[(i2 * j)];
			BigInteger localBigInteger = BigInteger.valueOf(0L);
			i3++;

			for (int i6 = 0; i6 < i5; i6++) {
				byte b = paramArrayOfByte[i3];
				i3++;
				localBigInteger = localBigInteger.add(BigInteger.valueOf((b & paramByte) * paramInt3));
				arrayOfByte[i4] = b;
				i4++;
			}

			if (i5 < paramInt1) {
				i3 += paramInt1 - i5;
			}
			localBigInteger = localBigInteger.mod(BigInteger.valueOf((int)Math.pow(2.0D, 8 * paramInt2)));
			byte b = (byte) localBigInteger.toByteArray().length;

			for (int i7 = paramInt2 - b; i7 < paramInt2; i7++) {
				if (i7 >= 0) {
					int i8 = paramArrayOfByte[(i2 * j + paramInt1 + i7 + 1)];
					int i9 = localBigInteger.toByteArray()[(b - paramInt2 + i7)];
					if (i8 != i9) {
						throw new Exception("Checksum ERROR !!!");
					}
				}
			}
			i3 += paramInt2;
		}
		return arrayOfByte;
	}
}