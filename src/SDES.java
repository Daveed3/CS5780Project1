import java.util.ArrayList;

/*1. SDES

In this section, you will implement a simplified version of the DES block cipher algorithm. Naturally enough, it is called SDES, and it is designed to have the 
features of the DES algorithm but scaled down so it is more tractable to understand. (Note however, that SDES is in no way secure and should not be used for 
serious cryptographic applications.) Here  (Links to an external site.)is the detailed specifications of SDES.


SDES encryption takes a 10 bit raw key (from which two 8 bit keys are generated as describedin the handout) and encrypts an 8 bit plaintext to produce an 8 bit 
ciphertext.
Implement the SDES algorithm in a class called SDES. The encryption an decryption methods should match the interface below:
 
public static byte[] Encrypt(byte[] rawkey, byte[] plaintext)
public static byte[] Decrypt(byte[] rawkey, byte[] ciphertext)
 
Here, rather than compactly representing the SDES plaintext and ciphertext using byte-sized (8-bit) variables, the data is represented using byte arrays of 
length 8. Similarly the 10 bit keys are represented as arrays of length 10. Although this design is extremely inefficient (it uses 8 times more space), it 
makes the algorithm easier to implement and experiment with.
For example, one might declare a 10-bit raw key in a test program like this:
byte key1[] = {1, 1, 1, 0, 0, 0, 1, 1, 1, 0};
 */

/* Test Cases
 * To verify that your implementation of SDES is correct, try the following test cases:

Raw Key           Plaintext             Ciphertext
0000000000     10101010            00010001
1110001110     10101010            11001010
1110001110     01010101            01110000
1111111111     10101010            00000100

Use your implementation to complete the following table:

Raw Key         Plaintext             Ciphertext
00000 00000     0000 0000                 ?
11111 11111     1111 1111                 ?
00000 11111     0000 0000                 ?
00000 11111     1111 1111                 ?
10001 01110     ?                       0001 1100
10001 01110     ?                       1100 0010
00100 11111     ?                       1001 1101
00100 11111     ?                       1001 0000
 */

public class SDES {
	
	static String[][] __s0 = { {"01", "00", "11", "10"}, 
			{"11", "10", "01", "00"}, 
			{"00", "10", "01", "11"},
			{"11", "01", "11", "10"} };
	static String[][] __s1 = { {"00", "01", "10", "11"},
			{"10", "00", "01", "11"},
			{"11", "00", "01", "00"},
			{"10", "01", "00", "11"} };
		
	static boolean debug = false;

	public static void main(String[] args) {	
		projectExamples();
		problem1();
	}
	
	public static byte[] Encrypt(byte[] rawkey, byte[] plaintext) {
		byte[] encryptedText = new byte[plaintext.length];
		
		// Method consisting of P10, Left Shifts, and P8 to generate keys
		ArrayList<byte[]> keys = GenerateKeys(rawkey);
		byte[] k1 = keys.get(0);
		byte[] k2 = keys.get(1);
		
		// If plaintext is longer than 8 bits
		int ceiling = (int) Math.ceil(plaintext.length / 8) * 8;
		for (int i=0; i<plaintext.length; i+=8) {
			byte[] subplaintext = subArray(plaintext, i, i+7);
			// Initial Permutation
			byte[] ip = InitialPermutation(subplaintext);
			
			// Round consisting of Expand/Permutate, XOR, S0 and S1, P4, and final XOR
			byte[] round1 = round(ip, k1);
			
			// Swap
			byte[] combined = combineBytes(subArray(ip, 4, 7), round1);
			
			// Round 2
			byte[] round2 = round(combined, k2);
			
			// Swap 2
			byte[] combined2 = combineBytes(round2, subArray(combined, 4, 7));
			
			// Inverse Permutation
			byte[] subEncryptedText = InversePermutation(combined2);
			
			for (int j=0; j<8; j++) {
				encryptedText[i+j] = subEncryptedText[j];
			}
			
		}
		
		return encryptedText;
	}
	
	public static byte[] Decrypt(byte[] rawkey, byte[] ciphertext) {
		byte[] decryptedText = new byte[ciphertext.length];
		
		ArrayList<byte[]> keys = GenerateKeys(rawkey);
		byte[] k1 = keys.get(0);
		byte[] k2 = keys.get(1);
		
		// In case ciphertext is greater than 8 bits
		int ceiling = (int) Math.ceil(ciphertext.length / 8) * 8;
		for (int i=0; i<ciphertext.length; i+=8) {
			byte[] subciphertext = subArray(ciphertext, i, i+7);
			
			//IP
			byte[] ip = InitialPermutation(subciphertext);
			
			//fk w/ K2
			byte[] round1 = round(ip, k2);
			
			//SW
			byte[] combined = combineBytes(subArray(ip, 4, 7), round1);
			
			//fk w/ K1
			byte[] round2 = round(combined, k1);
			byte[] combined2 = combineBytes(round2, subArray(combined, 4, 7));		
			
			//InvP
			byte[] subDecryptedText = InversePermutation(combined2);	
			
			for (int j=0; j<8; j++) {
				decryptedText[i+j] = subDecryptedText[j];
			}
			
		}
			
		return decryptedText;
	}
	
	public static byte[] P10(byte[] rawkey) {
		//P10
		// 3 5 2 7 4 - 10 1 9 8 6
		int[] p10Arrangement = {3, 5, 2, 7, 4, 10, 1, 9, 8, 6};
		byte[] p10 = new byte[10]; 
		for (int i=0; i<rawkey.length; i++) {
			p10[i] = rawkey[p10Arrangement[i]-1];
		}
		if (debug) {
			System.out.println("P10");
			printArray(p10);			
		}
		
		return p10;
	}
	
	public static byte[] LeftShift(byte[] array, int count) {
		// Left Shift the halves
		byte[] shifted = new byte[array.length];

		for (int i=0; i<array.length/2; i++) {
			shifted[i] = array[(i+count) % (array.length/2)];
		}
		
		for (int i=array.length/2; i<array.length; i++) {
			if ( ((i+count) % (array.length)) == 0 ) {
				count+=5;
			}
			shifted[i] = array[(i+count) % (array.length)];
		}
		if (debug) {
			System.out.println("Left Shift");
			printArray(shifted);			
		}
		
		return shifted;
	}

	public static byte[] P8(byte[] array) {
		// P8 (first 2 discarded)
		// x x 6 3 7 4 8 5 10 9
		int[] p8Arrangement = {6, 3, 7, 4, 8, 5, 10, 9};
		// AKA K1
		byte[] key = new byte[8];
		for (int i=0; i< key.length; i++) {
			key[i] = array[p8Arrangement[i]-1];
		}
		if (debug) {
			System.out.println("Key");
			printArray(key);			
		}
		
		return key;
	}
	
	public static byte[] InitialPermutation(byte[] array) {
		// Initial Permutation
		// 2 6 3 1 4 8 5 7
		int[] permutationArrangement = {2, 6, 3, 1, 4, 8, 5, 7};
		byte[] ip = new byte[8];
		
		for (int i=0; i<ip.length; i++) {
			ip[i] = array[permutationArrangement[i]-1];
		}
		if (debug) {
			System.out.println("Initial Permutation");
			printArray(ip);				
		}	
		
		return ip;
	}
	
	public static byte[] ExpandAndPermutate(byte[] array) {
		// Expand / Permutate
		// 4 1 2 3 2 3 4 1
		int[] eAndPArrangement = {4, 1, 2, 3, 2, 3, 4, 1};
		byte[] ep = new byte[8];
		for (int i=0; i<ep.length; i++) { 
			ep[i] = array[eAndPArrangement[i]-1];
		}
		if (debug) {
			System.out.println("Expand and Permutate");
			printArray(ep);			
		}
		
		return ep;
	}
	
	public static byte[] xor(byte[] array, byte[] key) {
		// XOR with Key
		byte[] xor = new byte[array.length];
		for (int i=0; i<array.length; i++) {
			if (array[i] == key[i]) {
				xor[i] = 0;
			} else {
				xor[i] = 1;
			}
		}
		if (debug) {
			System.out.println("XOR");
			printArray(xor);			
		}
		
		return xor;
	}
	
	public static String sBox(byte[] array, String[][] sBox) {
		int row; //array[0]array[3]
		if (array[0] == 0 && array[3] == 0) {
			row = 0;
		} else if (array[0] == 0 && array[3] == 1) {
			row = 1;
		} else if (array[0] == 1 && array[3] == 0) {
			row = 2;
		} else {
			row = 3;
		}
		int col; //array[1]array[2]
		if (array[1] == 0 && array[2] == 0) {
			col = 0;
		} else if (array[1] == 0 && array[2] == 1) {
			col = 1;
		} else if (array[1] == 1 && array[2] == 0) {
			col = 2;
		} else {
			col = 3;
		}
		
		String s0 = sBox[row][col];
		if (debug) {
			System.out.println("S Box");
			System.out.println(s0);			
		}
		
		return s0;
	}
	
	public static byte[] subArray(byte[] array, int start, int stop) {
		byte[] newArray = new byte[stop-start+1];
		
		for (int i=0; i<newArray.length; i++) {
			newArray[i] = array[start+i];
		}
		
		return newArray;
	}
	
	public static byte[] P4(String s0, String s1) {
		// P4
		// 2 4 3 1
		byte[] p4 = new byte[4];
		p4[0] = (byte)(s0.charAt(1)-48);
		p4[1] = (byte)(s1.charAt(1)-48);
		p4[2] = (byte)(s1.charAt(0)-48);
		p4[3] = (byte)(s0.charAt(0)-48);
		if (debug) {
			System.out.println("P4");
			printArray(p4);			
		}
		
		return p4;
	}
	
	public static byte[] combineBytes(byte[] array1, byte[] array2) {
		// Combine the 2 bytes
		byte[] combined = new byte[8];
		combined[0] = array1[0];
		combined[1] = array1[1];
		combined[2] = array1[2];
		combined[3] = array1[3];
		combined[4] = array2[0];
		combined[5] = array2[1];
		combined[6] = array2[2];
		combined[7] = array2[3];
		if (debug) {
			System.out.println("Swapped");
			printArray(combined);			
		}
		
		return combined;
	}
	
	public static byte[] round(byte[] ip, byte[] key) {
		// Expand / Permutate
		byte[] ep = ExpandAndPermutate(subArray(ip, 4, 7));
		
		// XOR with K1
		byte[] xor = xor(ep, key);
		
		// S0
		String s0 = sBox(subArray(xor, 0, 3), __s0);
		
		// S1
		String s1 = sBox(subArray(xor, 4, 7), __s1);
		
		// P4
		byte[] p4 = P4(s0, s1);
				
		// XOR with 1st left 4 bits
		byte[] xor2 = xor(p4, subArray(ip, 0, 4));
		
		return xor2;
	}
	
	public static byte[] InversePermutation(byte[] array) {
		//Inverse Permutation
		// 4 1 3 5 7 2 8 6
		int[] invPermArrangement = {4, 1, 3, 5, 7, 2, 8, 6};
		byte[] invP = new byte[8];
		
		for (int i=0; i<invP.length; i++) {
			invP[i] = array[invPermArrangement[i]-1];
		}
		if (debug) {
			System.out.println("Inverse Permutation");
			printArray(invP);			
		}
		
		return invP;
	}
	
	public static ArrayList<byte[]> GenerateKeys(byte[] rawkey) {
		//P10
		byte[] p10 = P10(rawkey);
		// Left Shift the halves
		rawkey = LeftShift(p10, 1);
		// P8 (first 2 discarded) AKA K1
		byte[] k1 = P8(rawkey);
		// Left Shift by 2
		// 4 5 1 2 3 - 9 10 6 7 8 
		rawkey = LeftShift(rawkey,2);
		// P8-2 (first 2 discarded) AKA K2
		byte[] k2 = P8(rawkey);
		
		ArrayList<byte[]> keys = new ArrayList<byte[]>();
		keys.add(k1);
		keys.add(k2);
		return keys;
	}
	
	public static void projectExamples() {
		byte[] rk0 = {1,0,1,0,0,0,0,0,1,0};
		byte[] rk1 = {0,0,0,0,0,0,0,0,0,0};
		byte[] rk2 = {1,1,1,0,0,0,1,1,1,0};
		byte[] rk3 = {1,1,1,0,0,0,1,1,1,0};
		byte[] rk4 = {1,1,1,1,1,1,1,1,1,1};
		ArrayList<byte[]> rawkeyList = new ArrayList<byte[]>();
		rawkeyList.add(rk0);
		rawkeyList.add(rk1);
		rawkeyList.add(rk2);
		rawkeyList.add(rk3);
		rawkeyList.add(rk4);
		
		byte[] pt0 = {0,1,1,1,0,0,1,0};
		byte[] pt1 = {1,0,1,0,1,0,1,0};
		byte[] pt2 = {1,0,1,0,1,0,1,0};
		byte[] pt3 = {0,1,0,1,0,1,0,1};
		byte[] pt4 = {1,0,1,0,1,0,1,0};
		ArrayList<byte[]> plaintextList = new ArrayList<byte[]>();
		plaintextList.add(pt0);
		plaintextList.add(pt1);
		plaintextList.add(pt2);
		plaintextList.add(pt3);
		plaintextList.add(pt4);
		
		byte[] ct0 = {0,1,1,1,0,1,1,1};
		byte[] ct1 = {0,0,0,1,0,0,0,1};
		byte[] ct2 = {1,1,0,0,1,0,1,0};
		byte[] ct3 = {0,1,1,1,0,0,0,0};
		byte[] ct4 = {0,0,0,0,0,1,0,0};
		ArrayList<byte[]> ciphertextList = new ArrayList<byte[]>();
		ciphertextList.add(ct0);
		ciphertextList.add(ct1);
		ciphertextList.add(ct2);
		ciphertextList.add(ct3);
		ciphertextList.add(ct4);
		
		System.out.println("Rawkey\t\t\tEncrypted Text\t\tDecrypted Text");
		for (int i=0; i<rawkeyList.size(); i++) {
			beautifyPrint(rawkeyList.get(i), Encrypt(rawkeyList.get(i), plaintextList.get(i)), Decrypt(rawkeyList.get(i), ciphertextList.get(i)));
		}
		System.out.println();
	}
	
	public static void problem1() {	
		byte[] rawkey1 = {0,0,0,0,0, 0,0,0,0,0};
		byte[] rawkey2 = {1,1,1,1,1, 1,1,1,1,1};
		byte[] rawkey3 = {0,0,0,0,0, 1,1,1,1,1};
		byte[] rawkey4 = {0,0,0,0,0, 1,1,1,1,1};
		byte[] rawkey5 = {1,0,0,0,1, 0,1,1,1,0};
		byte[] rawkey6 = {1,0,0,0,1, 0,1,1,1,0};
		byte[] rawkey7 = {0,0,1,0,0, 1,1,1,1,1};
		byte[] rawkey8 = {0,0,1,0,0, 1,1,1,1,1}; 
		ArrayList<byte[]> rkList = new ArrayList<byte[]>();
		rkList.add(rawkey1);
		rkList.add(rawkey2);
		rkList.add(rawkey3);
		rkList.add(rawkey4);
		rkList.add(rawkey5);
		rkList.add(rawkey6);
		rkList.add(rawkey7);
		rkList.add(rawkey8);
		byte[] plaintext1 = {0,0,0,0,0,0,0,0};
		byte[] plaintext2 = {1,1,1,1,1,1,1,1};
		byte[] plaintext3 = {0,0,0,0,0,0,0,0};
		byte[] plaintext4 = {1,1,1,1,1,1,1,1}; 
		byte[] plaintext5 = {0,0,1,1, 1,0,0,0};
		byte[] plaintext6 = {0,0,0,0, 1,1,0,0};
		byte[] plaintext7 = {1,1,1,1, 1,1,0,0};
		byte[] plaintext8 = {1,0,1,0, 0,1,0,1};
		ArrayList<byte[]> ptList = new ArrayList<byte[]>();
		ptList.add(plaintext1);
		ptList.add(plaintext2);
		ptList.add(plaintext3);
		ptList.add(plaintext4);
		ptList.add(plaintext5);
		ptList.add(plaintext6);
		ptList.add(plaintext7);
		ptList.add(plaintext8);
		byte[] ciphertext1 = {1,1,1,1, 0,0,0,0};
		byte[] ciphertext2 = {0,0,0,0, 1,1,1,1};
		byte[] ciphertext3 = {0,0,0,0,0,0,0,0};
		byte[] ciphertext4 = {1,1,1,0, 0,0,0,1}; 
		byte[] ciphertext5 = {0,0,0,1, 1,1,0,0};
		byte[] ciphertext6 = {1,1,0,0, 0,0,1,0};
		byte[] ciphertext7 = {1,0,0,1, 1,1,0,1};
		byte[] ciphertext8 = {1,0,0,1, 0,0,0,0};
		ArrayList<byte[]> ctList = new ArrayList<byte[]>();
		ctList.add(ciphertext1);
		ctList.add(ciphertext2);
		ctList.add(ciphertext3);
		ctList.add(ciphertext4);
		ctList.add(ciphertext5);
		ctList.add(ciphertext6);
		ctList.add(ciphertext7);
		ctList.add(ciphertext8);

		System.out.println("Rawkey\t\t\tEncrypted Text\t\tDecrypted Text");
		for (int i=0; i<rkList.size(); i++) {
			beautifyPrint(rkList.get(i), Encrypt(rkList.get(i), ptList.get(i)), Decrypt(rkList.get(i), ctList.get(i)));			
		}
		System.out.println();
		
	}
	
	public static void printArray(byte[] array) {
		for (int i=0; i< array.length; i++) {
			System.out.print(array[i]);
		}
		System.out.println();
	}
	
	public static String getArray(byte[] array) {
		String s = "";
		for (int i=0; i<array.length; i++) {
			s += array[i];
		}
		return s;
	}
	
	public static void beautifyPrint(byte[] rk, byte[] pt, byte[] ct) {
		System.out.println(getArray(rk) + "\t\t" + getArray(pt) + "\t\t" + getArray(ct));
	}
	
	public static byte[] toByteArray (String message){
		byte[] temp = new byte[message.length()];
		for(int i = 0; i < message.length(); i++){
			temp[i] = (message.charAt(i) == '1') ? (byte)1 : (byte)0;
		}
		return temp;
	}
	
}
