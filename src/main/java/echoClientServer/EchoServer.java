package echoClientServer;

import java.io.BufferedReader;
import java.io.InputStream;
import java.io.InputStreamReader;

import javax.net.ssl.SSLServerSocket;
import javax.net.ssl.SSLSocket;

import sslContextBuilder.SSLContextBuilder;

public class EchoServer {

	// node private key
	// openssl genrsa -aes256 -out nodeName_https.key 2048
	// certificate authority
	// openssl genrsa -aes256 -out CA.key 2048
	// certificate authority certificate signing request
	// openssl req -new -x509 -days 1095 -key CA.key -out CA.crt
	// node certificate signing request
	// openssl req -new -x509 -days 365 -key nodeName_https.key -out
	// nodeName_https.crt
	// node key signing request
	// openssl req -new -key nodeName_https.key -out nodeName_https.csr
	// node https certificate signed by CA
	// openssl x509 -req -days 365 -in nodeName_https.csr -CA CA.crt
	// -CAkey CA.key -set_serial 01 -out nodeName_csnmt-signed.crt

	private static final String JKS_PATH = "keys/imported.jks";
	private static final String KEYSTORE_PASSWORD = "keystorePassword";

	private static final String[] ENABLED_PROTOCOLS = new String[] { "TLSv1.2" };

	private static final String KEY_ALGORITHM = "RSA";
	private static final int KEY_LENGTH = 2048;

	public static void main(String[] arstring) {
		try {
			System.out.println("Starting");
			// SSLServerSocket sslServerSocket =
			// SSLContextBuilder.builder().withKeystoreFile(JKS_PATH,
			// KEYSTORE_PASSWORD).socketBuilder()
			SSLServerSocket sslServerSocket = SSLContextBuilder.builder() //
					.withSelfSignedKeyAndCert(KEY_ALGORITHM, KEY_LENGTH).build().socketBuilder().withHost("localhost")
					.withPort(9999).withEnabledProtocols(ENABLED_PROTOCOLS).serverSocket();

			SSLSocket sslSocket = (SSLSocket) sslServerSocket.accept();

			InputStream inputstream = sslSocket.getInputStream();
			InputStreamReader inputstreamreader = new InputStreamReader(inputstream);
			BufferedReader bufferedreader = new BufferedReader(inputstreamreader);

			String string = null;
			while ((string = bufferedreader.readLine()) != null) {
				System.out.println(string);
				System.out.flush();
			}
		} catch (Exception exception) {
			exception.printStackTrace();
		}
	}
}