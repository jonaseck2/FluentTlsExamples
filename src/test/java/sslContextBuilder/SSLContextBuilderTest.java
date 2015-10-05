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

	// @formatter:off
	/*
	 #generate self signed CA as jks, key and cert
	 keytool -genkey -aliasserver -keyalg RSA -keysize 2048 -keystore selfsignedCA.jks -storepass changeit -dname "ou=test" -keypass changeit
	 keytool -importkeystore -srckeystore selfsignedCA.jks -srcstorepass changeit -destkeystore selfsignedCA.p12 -deststoretype PKCS12 -srcalias server -deststorepass changeit -destkeypass changeit 
	 openssl pkcs12 -in selfsignedCA.p12 -nokeys -out selfsignedCA.pem.pub -password pass:changeit
	 openssl pkcs12 -in selfsignedCA.p12 -nodes -nocerts -out selfsignedCA.pem -password pass:changeit
	 
	 #generate key to sign and certificate request 
	 keytool -genkey -alias server -keyalg RSA -keysize 2048 -keystore keystore.jks -storepass  changeit -dname "ou=test" -keypass changeit 
	 keytool -importkeystore -srckeystore keystore.jks -srcstorepass changeit -destkeystore keystore.p12 -deststoretype PKCS12 -srcalias server -deststorepass changeit -destkeypass changeit 
	 openssl pkcs12 -in keystore.p12 -nokeys -out keystore.pem.pub -password pass:changeit
	 openssl pkcs12 -in keystore.p12 -nodes -nocerts -out keystore.pem -password pass:changeit
	 
	 keytool -certreq -alias server -keyalg RSA -file keystore.csr -keystore keystore.jks -storepass changeit
	  
	 openssl x509 -req -CA selfsignedCA.pem.pub -CAkey selfsignedCA.pem -in keystore.csr -out keystore-selfsignedCA.signed.pem.pub -days 365 -CAcreateserial
	  
	 keytool -importcert -keystore signed-keystore.jks -file keystore-selfsignedCA.signed.pem.pub -alias server -storepass changeit -noprompt
	 */
	// @formatter:on

	@Test(expected = SSLHandshakeException.class)
	public void test_can_fail_to_connect_to_real_ca_without_certificate_chain() throws Exception {
		SSLContextBuilder.builder().socketBuilder().withHost("www.google.com").socket();
	}

	@Test
	public void test_can_connect_to_real_ca() throws Exception {
		SSLContextBuilder.builder().withJavaCaCertsFile().socketBuilder().withHttpsEndpointIdentificationAlgorithm("HTTPS").withHost("www.google.com").socket();
	}

	@DataProvider
	public static Object[][] clientServerSocketBuilderCombinationsProvider() throws Exception {
		return new Object[][] {
				{ "Self signed server key with NonValidatingTrustManager client",
						SSLContextBuilder.builder().withSelfSignedKeyAndCert("RSA", 2048).build().socketBuilder(),
						SSLContextBuilder.builder().withNonvalidatingTrustManager().socketBuilder() },
				{ "Server and client from same keystore",
						SSLContextBuilder.builder().withKeystoreFile("keys/keystore.jks", "changeit").socketBuilder(),
						SSLContextBuilder.builder().withKeystoreFile("keys/keystore.jks", "changeit").socketBuilder() },
				{ "Server and client from pem",
						SSLContextBuilder.builder().withPemFileKeyFile("keys/selfsignedCA.pem", "keys/selfsignedCA.pem.pub", "RSA").socketBuilder(),
						SSLContextBuilder.builder().withPemFileCertFile("keys/selfsignedCA.pem.pub").socketBuilder() },
				{ "Server signed by client cert",
						SSLContextBuilder.builder().withPemFileKeyFile("keys/keystore.pem", "keys/keystore.pem.pub", "RSA").socketBuilder(),
						SSLContextBuilder.builder().withPemFileCertFile("keys/keystore-selfsignedCA.signed.pem.pub").socketBuilder() },
				{ "Self signed server key with hostvalidating NonValidatingTrustManager client",
						SSLContextBuilder.builder().withSelfSignedKeyAndCert("RSA", 2048).build().socketBuilder(),
						SSLContextBuilder.builder().withNonvalidatingTrustManager().socketBuilder().withHttpsEndpointIdentificationAlgorithm("HTTPS") },

		};

	}

	@Test
	@UseDataProvider("clientServerSocketBuilderCombinationsProvider")
	public void test_client_server_builder_combinations(String description, SSLSocketBuilder serverBuilder,
			SSLSocketBuilder clientBuilder) throws Exception {
		SSLServerSocket serverSocket = serverBuilder.withPort(0).serverSocket();

		new Thread(new ServerRunnable(serverSocket)).start();

		SSLSocket sslsocket = clientBuilder
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
