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

	@DataProvider
	public static Object[][] clientServerBuilderCombinationsProvider() throws Exception {
		return new Object[][] { //
				{ "Self signed server key with NonValidatingTrustManager client",
						SSLContextBuilder.builder().withSelfSignedKeyAndCert("RSA", 2048).build(),
						SSLContextBuilder.builder().withNonvalidatingTrustManager() }, };
	}

	@Test
	@UseDataProvider("clientServerBuilderCombinationsProvider")
	public void test_client_server_builder_combinations(String description, SSLContextBuilder serverBuilder,
			SSLContextBuilder clientBuilder) throws Exception {
		SSLServerSocket serverSocket = serverBuilder.socketBuilder().withPort(9999).serverSocket();

		new Thread(new ServerRunnable(serverSocket)).start();

		SSLSocket sslsocket = SSLContextBuilder.builder().withNonvalidatingTrustManager().socketBuilder()
				.withHost("localhost").withPort(9999).socket();

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
