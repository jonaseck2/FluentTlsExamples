package sslContextBuilder;

import java.io.BufferedReader;
import java.io.BufferedWriter;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.OutputStream;
import java.io.OutputStreamWriter;
import java.net.ServerSocket;
import java.net.Socket;
import java.nio.ByteBuffer;

import javax.net.ssl.SSLServerSocket;
import javax.net.ssl.SSLSocket;

import org.junit.Assert;
import org.junit.Test;

public class SSLContextBuilderTest {


	@Test
	public void test_can_connect_to_real_ca_using_java_cacerts() throws Exception {
		SSLServerSocket serverSocket = SSLContextBuilder.builder().withSelfSignedKeyAndCert("RSA", 2048).build().socketBuilder().withPort(9999)
		.serverSocket();

		Thread serverThread = new Thread(new ServerRunnable(serverSocket));
		serverThread.start();
		
		SSLSocket sslsocket = SSLContextBuilder.builder().withNonvalidatingTrustManager().socketBuilder().withHost("localhost").withPort(9999)
				.socket();
		
		OutputStream outputstream = sslsocket.getOutputStream();
		OutputStreamWriter outputstreamwriter = new OutputStreamWriter(outputstream);
		BufferedWriter bufferedwriter = new BufferedWriter(outputstreamwriter);

		String string = "This is the string";
		bufferedwriter.write(string + '\n');
		bufferedwriter.flush();

	}

	class ServerRunnable implements Runnable {
		ServerSocket myServerSocket;

		public ServerRunnable(ServerSocket serverSocket) {
			myServerSocket = serverSocket;
		}

		public void run() {
			Socket sslSocket;
			try {
				sslSocket = myServerSocket.accept();
				InputStream inputstream = sslSocket.getInputStream();
				InputStreamReader inputstreamreader = new InputStreamReader(inputstream);
				BufferedReader bufferedreader = new BufferedReader(inputstreamreader);

				String string = null;
				while ((string = bufferedreader.readLine()) != null) {
					System.out.println(string);
					System.out.flush();
				}
			} catch (IOException e) {
				e.printStackTrace();
				Assert.fail();
			}
		}
	}
}
