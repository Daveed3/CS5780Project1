package clientServer;

import java.io.FileInputStream;
import java.io.InputStream;
import java.io.OutputStream;
import java.io.PrintStream;
import java.util.Properties;

import security.Hash;
import security.OneTimeKey;
import security.RSA;
import security.SSLSocket;
import security.RSA.PrivateKey;
import security.RSA.PublicKey;

public class Client {
	private SSLSocket s;

	public Client(String paramString1, int paramInt, String paramString2) throws Exception {
		Properties localProperties = new Properties();
		FileInputStream localFileInputStream = new FileInputStream(paramString2 + ".txt");
		localProperties.load(localFileInputStream);
		localFileInputStream.close();
		String str = localProperties.getProperty("company");
		RSA.PublicKey localPublicKey = new RSA.PublicKey(localProperties.getProperty("server.public_key").getBytes());
		RSA.PrivateKey localPrivateKey = new RSA.PrivateKey(localProperties.getProperty("private_key").getBytes());
		byte b = (byte)Integer.parseInt(localProperties.getProperty("pattern"));
		int i = Integer.parseInt(localProperties.getProperty("ndatabytes"));
		int j = Integer.parseInt(localProperties.getProperty("ncheckbytes"));
		int k = Integer.parseInt(localProperties.getProperty("k"));

		Hash localHash = new Hash(i, j, b, k);

		byte[] arrayOfByte1 = RSA.cipher(str.getBytes(), localPrivateKey);
		byte[] arrayOfByte2 = OneTimeKey.newKey(i + j + 1);

		byte[] arrayOfByte3 = RSA.cipher(arrayOfByte2, localPublicKey);

		byte[] arrayOfByte4 = RSA.cipher(paramString2.getBytes(), localPublicKey);
		this.s = new SSLSocket(paramString1, paramInt, arrayOfByte4, arrayOfByte1, arrayOfByte3, arrayOfByte2, localHash);
	}

	public void execute() throws Exception {
		int i = 0;
		int j = 0;
		int k;
		while ((k = System.in.read()) != -1) {
			this.s.getOutputStream().write(k);

			if (((char)k == '\n') || ((char)k == '\r'))
				this.s.getOutputStream().flush();
			i++;
		}
		this.s.getOutputStream().flush();

		for (; (k = this.s.getInputStream().read()) != -1; j = i) {
			System.out.write(k);
			j++;
		}

		System.out.println();
		System.out.println("wrote " + j + " bytes");
		this.s.close();
	}

	public static void main(String[] paramArrayOfString) throws Exception {
		if (paramArrayOfString.length != 3) {
			System.out.println("java Client <host> <port> <name>");
			System.exit(1);
		}
		String str1 = paramArrayOfString[0];
		int i = Integer.parseInt(paramArrayOfString[1]);
		String str2 = paramArrayOfString[2];
		new Client(str1, i, str2).execute();
	}
}