package clientServer;

import java.io.FileInputStream;
import java.io.InputStream;
import java.io.OutputStream;
import java.io.PrintStream;
import java.util.Properties;

import crypto.RSA;
import crypto.RSA.PrivateKey;
import crypto.SSLServerSocket;
import crypto.SSLSocket;

public class Server implements Runnable {
	private RSA.PrivateKey serverPrivateKey;
	private Properties prop;
	private SSLServerSocket server;
	private int port;

	public Server() throws Exception {
		String str1 = System.getProperty("server.private_key");
		if (str1 == null) str1 = "private_key.txt";
		FileInputStream localFileInputStream = new FileInputStream(str1);
		this.serverPrivateKey = new RSA.PrivateKey(localFileInputStream);
		localFileInputStream.close();

		String str2 = System.getProperty("server.users");
		if (str2 == null) { 
			str2 = "users.txt";
		}
		localFileInputStream = new FileInputStream(str2);
		this.prop = new Properties();
		this.prop.load(localFileInputStream);
		localFileInputStream.close();

		String str3 = System.getProperty("server.port");
		if (str3 != null) {
			this.port = Integer.parseInt(str3);			
		} else {
			this.port = 5000;
		}
		this.server = new SSLServerSocket(this.port, this.serverPrivateKey, this.prop);
	}

	public static void main(String[] paramArrayOfString) throws Exception {
		new Server().run();
	}

	public void run() {
		while (true)
			try {
				new Thread(new Server.RequestHandler((SSLSocket)this.server.accept())).run();
		} catch (Exception localException) {
			System.out.println("SERVER: " + localException);
		}
	}

	public class RequestHandler implements Runnable {
		private SSLSocket socket;

		public RequestHandler(SSLSocket arg2) {
			Object localObject = null;
			this.socket = (SSLSocket) localObject;
		}

		public void run() {
			try {
				System.out.println("connect ...");
				int i;
				while ((i = this.socket.getInputStream().read()) != -1) {
					if ((i >= 97) && (i <= 122))
						i -= 32;
					else if ((i >= 65) && (i <= 90)) {
						i += 32;
					}

					this.socket.getOutputStream().write(i);

					if (this.socket.getInputStream().available() == 0) {
						this.socket.getOutputStream().flush();
					}
				}
				this.socket.getOutputStream().flush();
				this.socket.close();
				System.out.println("disconnect ...");
				return;
			} catch (Exception localException) {
				System.out.println("HANDLER: " + localException);
			}
		}
	}
}