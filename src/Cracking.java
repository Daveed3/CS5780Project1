import java.io.File;
import java.io.FileWriter;
import java.util.ArrayList;

/*
 1). Give the SDES encoding of the following CASCII plaintext using the key 0111001101. (The answer
is 64 bits long.)
CRYPTOGRAPHY
 
2). The message in the file msg1.txt (Links to an external site.) was encoded using SDES. Decrypt it, and find the 10-bit raw
key used for its encryption.
 
3). The mesage in the file msg2.txt (Links to an external site.) was encoded using TripleSDES. Decrypt it, and find the two
10-bit raw keys used for its encryption.
 */
public class Cracking {
	
	static String string = "CRYPTOGRAPHY";
	static String msg1 = "1011011001111001001011101111110000111110100000000001110111010001111011111101101100010011000000101101011010101000101111100011101011010111100011101001010111101100101110000010010101110001110111011111010101010100001100011000011010101111011111010011110111001001011100101101001000011011111011000010010001011101100011011110000000110010111111010000011100011111111000010111010100001100001010011001010101010000110101101111111010010110001001000001111000000011110000011110110010010101010100001000011010000100011010101100000010111000000010101110100001000111010010010101110111010010111100011111010101111011101111000101001010001101100101100111001110111001100101100011111001100000110100001001100010000100011100000000001001010011101011100101000111011100010001111101011111100000010111110101010000000100110110111111000000111110111010100110000010110000111010001111000101011111101011101101010010100010111100011100000001010101110111111101101100101010011100111011110101011011";
	static String msg2 = "00011111100111111110011111101100111000000011001011110010101010110001011101001101000000110011010111111110000000001010111111000001010010111001111001010101100000110111100011111101011100100100010101000011001100101000000101111011000010011010111100010001001000100001111100100000001000000001101101000000001010111010000001000010011100101111001101111011001001010001100010100000";

	
	public static void main(String[] args) {		
		part1();
		part2();
		part3(); // Takes about a minute to complete		
	}
	
	public static void part1() {
		String rawkey = "0111001101";
		
		// Convert message to CASCII byte array
		byte[] plaintext = CASCII.Convert(string);
		
		// Encrypt the CASCII message with the key
		byte[] ciphertext = SDES.Encrypt(toByteArray(rawkey), plaintext);
		
		System.out.println("Encrypted Message: ");
		printArray(ciphertext);
		
	}
	
	public static void part2() {
		String currentIter = "0000000000";
		byte[] plaintext;
		byte[] ciphertext = toByteArray(msg1);
		
		// Do 2^10 iterations
		for (int i=0; i<1024; i++) {			
			plaintext = SDES.Decrypt(toByteArray(currentIter), ciphertext);
			currentIter = addBit(currentIter);
			String decrypted = CASCII.toString(plaintext);
			
			// After manually checking, the decryption seems to have a "WHOEVER", "AND", and "HIS" for some reference
			if (decrypted.contains("WHOEVER")) {
				System.out.println("Key: " + currentIter);
				System.out.println(decrypted);				
			}
			
		}
	}
	
	public static void part3() {
		String key1 = "0000000000";
		String key2 = "0000000000";
		
		byte[] plaintext;
		byte[] ciphertext = toByteArray(msg2);
		
		try {
			File file = new File("part3.txt");
			if (file.createNewFile()) {
				System.out.println("created File");
			} else {
				System.out.println("File exists");
			}
			
			FileWriter writer = new FileWriter("part3.txt");
		
		
			// Do 2^10 ^ 2^10 iterations
			for (int i=0; i<1024; i++) {
				for (int j=0; j<1024; j++) {
					plaintext = TripleSDES.Decrypt(toByteArray(key1), toByteArray(key2), ciphertext);
					String decrypted = CASCII.toString(plaintext);
					
					
					// Manually checking, the decrypted message has a "THERE"
					if (decrypted.contains("THERE")) {
						
						System.out.println("Key 1: " + key1 + "\tKey 2: " + key2);
						System.out.println(decrypted);
						writer.write("Key 1: " + key1 + "\nKey 2: " + key2 + "\n");
						writer.write(decrypted);
					}
					key1 = addBit(key1);
				}
				key2 = addBit(key2);
			}
		
			writer.close();
		} catch (Exception e) {
			e.printStackTrace();
		}
		
	}

	public static String addBit(String s) {
		// string is 10 bit
		// Adds 1 bit like the string were binary
		String newString = "";
		boolean isAdding = true;
		
		for (int i=s.length()-1; i>=0; i--) {
			if (s.charAt(i) == '1' && isAdding) {
				newString = '0' + newString;
			} else if (s.charAt(i) == '0' && isAdding){
				newString = '1' + newString;
				isAdding = false;
			} else {
				newString = s.charAt(i) + newString;
			}
		}
		
		return newString;
	}
	
	public static byte[] toByteArray (String message){
		// Tried of turning strings to byte[] manually, so here's a function to do that
		byte[] temp = new byte[message.length()];
		for(int i = 0; i < message.length(); i++){
			temp[i] = (message.charAt(i) == '1') ? (byte)1 : (byte)0;
		}
		return temp;
	}

	public static void printArray(byte[] array) {
		for (int i=0; i< array.length; i++) {
			System.out.print(array[i]);
		}
		System.out.println();
	}
}
