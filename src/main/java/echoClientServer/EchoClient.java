package echoClientServer;

import java.io.BufferedInputStream;
import java.io.BufferedWriter;
import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.OutputStream;
import java.io.OutputStreamWriter;
import java.security.KeyManagementException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.UnrecoverableKeyException;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;

import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLSocket;
import javax.net.ssl.TrustManagerFactory;

import sslContextBuilder.SSLContextBuilder;

public class EchoClient {
	private static final String JKS_PATH = "keys/keystore.jks";
	private static final String KEYSTORE_PASSWORD = "keystorePassword";
	private static final String SSL_CONTEXT = "TLS";
	private static final String[] ENABLED_PROTOCOLS = new String[] { "TLSv1.2" };
	// private static final String CA_FILES[] = {"keys/keytool_node.crt",
	// "keys/keytool_ca.crt"};
	private static final String CA_FILES[] = { "keys/nodeName_https.crt", "keys/CA.crt" };

	public static void main(String[] arstring) {
		SSLSocket sslsocket = null;
		try {

			// SSLContext sslContext =
			// SslContextBuilder.builder().withKeystoreFile(JKS_PATH,
			// KEYSTORE_PASSWORD).build();
			// SSLContext sslContext =
			// SSLContextBuilder.builder().withNonvalidatingTrustStore().build();

			sslsocket = SSLContextBuilder.builder().withNonvalidatingTrustManager().socketBuilder() //
					.withHost("localhost").withPort(9999).withEnabledProtocols(ENABLED_PROTOCOLS).socket();

			System.out.println("Shaking hands");
			sslsocket.startHandshake();

			OutputStream outputstream = sslsocket.getOutputStream();
			OutputStreamWriter outputstreamwriter = new OutputStreamWriter(outputstream);
			BufferedWriter bufferedwriter = new BufferedWriter(outputstreamwriter);

			String string = "This is the string";
			bufferedwriter.write(string + '\n');
			bufferedwriter.flush();
			sslsocket.close();
		} catch (Exception exception) {
			exception.printStackTrace();
		}
	}

	private static SSLContext getPemFileSslContext() throws CertificateException, KeyStoreException,
			NoSuchAlgorithmException, IOException, KeyManagementException, UnrecoverableKeyException {

		KeyStore keyStore = KeyStore.getInstance(KeyStore.getDefaultType());
		keyStore.load(null, null);

		for (String filePath : CA_FILES) {
			File file = new File(filePath);
			FileInputStream fis = new FileInputStream(file);
			X509Certificate certificate = (X509Certificate) CertificateFactory.getInstance("X.509")
					.generateCertificate(new BufferedInputStream(fis));
			keyStore.setCertificateEntry(file.getName(), certificate);
		}

		KeyManagerFactory keyManagerFactory = KeyManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm());
		keyManagerFactory.init(keyStore, null);

		TrustManagerFactory trustManagerFactory = TrustManagerFactory
				.getInstance(TrustManagerFactory.getDefaultAlgorithm());
		trustManagerFactory.init(keyStore);

		SSLContext sslContext = SSLContext.getInstance(SSL_CONTEXT);
		sslContext.init(keyManagerFactory.getKeyManagers(), trustManagerFactory.getTrustManagers(), null);
		return sslContext;
	}
}