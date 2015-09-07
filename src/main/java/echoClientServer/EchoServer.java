package echoClientServer;

import java.io.BufferedReader;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.lang.reflect.Field;
import java.security.KeyManagementException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.UnrecoverableKeyException;
import java.security.cert.CertificateException;

import javax.net.ssl.KeyManager;
import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLServerSocket;
import javax.net.ssl.SSLServerSocketFactory;
import javax.net.ssl.SSLSocket;
import javax.net.ssl.TrustManager;
import javax.net.ssl.TrustManagerFactory;

public class EchoServer {
	private static final String[] ENABLED_PROTOCOLS = new String[] { "TLSv1.2" };

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
	// keytool -import -alias csnmt -file CA.crt -keypass test -keystore nodeName.jks -storepass keystorePassword
	// import to java keystore
	// keytool -import -alias nodeName_csnmt-signed -file
	// nodeName_csnmt-signed.crt -keypass test -keystore nodeName.jks
	// -storepass keystorePassword

	private static final String JAVA_KEYSTORE_INSTANCE_KEY = "JKS";
	private static final String JKS_PATH = "keys/keystore.jks";
	private static final String KEYSTORE_PASSWORD = "keystorePassword";
	private static final String SSL_CONTEXT = "TLS";

	public static void main(String[] arstring) {
		try {

			// Download http://www.oracle.com/technetwork/java/javase/downloads/jce8-download-2133166.html
/*			try {
				Field field = Class.forName("javax.crypto.JceSecurity").getDeclaredField("isRestricted");
				field.setAccessible(true);
				field.set(null, java.lang.Boolean.FALSE);
			} catch (Exception ex) {
				ex.printStackTrace();
			}*/

			SSLContext sslContext = getSslContext();

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

	private static SSLContext getSslContext() throws KeyStoreException, IOException, NoSuchAlgorithmException,
			CertificateException, FileNotFoundException, UnrecoverableKeyException, KeyManagementException {
		KeyStore keyStore = KeyStore.getInstance(JAVA_KEYSTORE_INSTANCE_KEY);
		keyStore.load(new FileInputStream(JKS_PATH), KEYSTORE_PASSWORD.toCharArray());

		KeyManagerFactory keyManagerFactory = KeyManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm());
		keyManagerFactory.init(keyStore, KEYSTORE_PASSWORD.toCharArray());

		TrustManagerFactory trustManagerFactory = TrustManagerFactory
				.getInstance(TrustManagerFactory.getDefaultAlgorithm());
		trustManagerFactory.init(keyStore);

		SSLContext sslContext = SSLContext.getInstance(SSL_CONTEXT);
		//TrustManager[] trustManagers = trustManagerFactory.getTrustManagers();
		TrustManager[] trustManagers = new TrustManager[]{new AllTrustingTrustManager()};
		KeyManager[] keyManagers = keyManagerFactory.getKeyManagers();
		sslContext.init(keyManagers, trustManagers, null);
		return sslContext;
	}
}