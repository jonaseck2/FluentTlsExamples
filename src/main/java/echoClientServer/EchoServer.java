package echoClientServer;

import java.io.BufferedInputStream;
import java.io.BufferedReader;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.security.KeyManagementException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.UnrecoverableKeyException;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;

import javax.net.ssl.KeyManager;
import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLServerSocket;
import javax.net.ssl.SSLServerSocketFactory;
import javax.net.ssl.SSLSocket;
import javax.net.ssl.TrustManager;
import javax.net.ssl.TrustManagerFactory;

import sslContextBuilder.SSLContextBuilder;

public class EchoServer {

	// node private key
	// openssl genrsa -aes256 -out nodeName_https.key 2048
	// certificate authority
	// openssl genrsa -aes256 -out CA.key 2048
	// certificate authority certificate signing request
	// openssl req -new -x509 -days 1095 -key CA.key -out CA.crt
	// node certificate signing request
	// openssl req -new -x509 -days 365 -key nodeName_https.key -out nodeName_https.crt
	// node key signing request
	// openssl req -new -key nodeName_https.key -out nodeName_https.csr
	// node https certificate signed by CA
	// openssl x509 -req -days 365 -in nodeName_https.csr -CA CA.crt
	// -CAkey CA.key -set_serial 01 -out nodeName_csnmt-signed.crt
	// import CA to java keystore
	// keytool -import -alias csnmt -file CA.crt -keystore nodeName.jks -storepass keystorePassword
	// import to java keystore
	// keytool -import -alias nodeName_csnmt-signed -file nodeName_csnmt-signed.crt -keystore nodeName.jks -storepass keystorePassword
	
	private static final String JKS_PATH = "keys/imported.jks";
	private static final String KEYSTORE_PASSWORD = "keystorePassword";
	private static final String[] ENABLED_PROTOCOLS = new String[] { "TLSv1.2" };
	private static final String SSL_CONTEXT = "TLS";
	//private static final String CA_FILES[] = {"keys/keytool_node.crt", "keys/keytool_ca.crt"};
	private static final String CA_FILES[] = {"keys/keytool_ca.key"};

	public static void main(String[] arstring) {
		try {
			System.out.println("Starting");
			SSLContext sslContext = SSLContextBuilder.builder().withKeystoreFile(JKS_PATH, KEYSTORE_PASSWORD).build();

			SSLServerSocketFactory sslServerSocketfactory = sslContext.getServerSocketFactory();
			SSLServerSocket sslServerSocket = (SSLServerSocket) sslServerSocketfactory.createServerSocket(9999);
			sslServerSocket.setEnabledProtocols(ENABLED_PROTOCOLS);
			System.out.println("Listening");
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

	private static SSLContext getPemFileSslContext() throws CertificateException, KeyStoreException, NoSuchAlgorithmException, IOException, KeyManagementException, UnrecoverableKeyException {
		KeyStore keyStore = KeyStore.getInstance(KeyStore.getDefaultType());
		keyStore.load(null);
	
		for (String filePath : CA_FILES)
		{
			File file = new File(filePath);
			FileInputStream fis = new FileInputStream(file);
			
			X509Certificate certificate = (X509Certificate) CertificateFactory.getInstance("X.509")
		                        .generateCertificate(new BufferedInputStream(fis));
			keyStore.setCertificateEntry(file.getName(), certificate);
		}
			

		KeyManagerFactory keyManagerFactory = KeyManagerFactory.getInstance(KeyManagerFactory.getDefaultAlgorithm());
		keyManagerFactory.init(keyStore, null);

		TrustManagerFactory trustManagerFactory = TrustManagerFactory
				.getInstance(TrustManagerFactory.getDefaultAlgorithm());
		trustManagerFactory.init(keyStore);

		SSLContext sslContext = SSLContext.getInstance(SSL_CONTEXT);
		sslContext.init(keyManagerFactory.getKeyManagers(), trustManagerFactory.getTrustManagers(), null);
		return sslContext;
	}
}