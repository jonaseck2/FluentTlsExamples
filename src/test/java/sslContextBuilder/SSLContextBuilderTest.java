package sslContextBuilder;

import java.io.BufferedReader;
import java.io.BufferedWriter;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.OutputStream;
import java.io.OutputStreamWriter;
import java.net.ServerSocket;
import java.net.Socket;

import javax.net.ssl.SSLHandshakeException;
import javax.net.ssl.SSLServerSocket;
import javax.net.ssl.SSLSocket;

import org.junit.Assert;
import org.junit.Test;
import org.junit.runner.RunWith;

import com.tngtech.java.junit.dataprovider.DataProvider;
import com.tngtech.java.junit.dataprovider.DataProviderRunner;
import com.tngtech.java.junit.dataprovider.UseDataProvider;

@RunWith(DataProviderRunner.class)
public class SSLContextBuilderTest {

	@Test(expected = SSLHandshakeException.class)
	public void test_can_fail_to_connect_to_real_ca_without_certificate_chain() throws Exception {
		SSLContextBuilder.builder().socketBuilder().withHost("www.google.com").socket();
	}

	@Test
	public void test_can_connect_to_real_ca() throws Exception {
		SSLContextBuilder.builder().withJavaCaCertsFile().socketBuilder().withHost("www.google.com").socket();
	}

	@DataProvider
	public static Object[][] clientServerBuilderCombinationsProvider() throws Exception {
		return new Object[][] { //
				{ "Self signed server key with NonValidatingTrustManager client",
						SSLContextBuilder.builder().withSelfSignedKeyAndCert("RSA", 2048).build(),
						SSLContextBuilder.builder().withNonvalidatingTrustManager() },
				{ "Server and client from same keystore",
						SSLContextBuilder.builder().withKeystoreFile("keys/keystore.jks", "keystorePassword"),
						SSLContextBuilder.builder().withKeystoreFile("keys/keystore.jks", "keystorePassword") }
				//
		};
	}

	@Test
	@UseDataProvider("clientServerBuilderCombinationsProvider")
	public void test_client_server_builder_combinations(String description, SSLContextBuilder serverBuilder,
			SSLContextBuilder clientBuilder) throws Exception {
		SSLServerSocket serverSocket = serverBuilder.socketBuilder().withPort(0).serverSocket();

		new Thread(new ServerRunnable(serverSocket)).start();

		SSLSocket sslsocket = SSLContextBuilder.builder().withNonvalidatingTrustManager().socketBuilder()
				.withHost("localhost").withPort(serverSocket.getLocalPort()).socket();

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
				BufferedReader bufferedreader = new BufferedReader(new InputStreamReader(sslSocket.getInputStream()));
				while ((bufferedreader.readLine()) != null) {
				}
				sslSocket.close();
			} catch (IOException e) {
				e.printStackTrace();
				Assert.fail();
			}
		}
	}
}
