package echoClientServer;

import java.io.BufferedReader;
import java.io.BufferedWriter;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.OutputStream;
import java.io.OutputStreamWriter;
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
import javax.net.ssl.SSLSocket;
import javax.net.ssl.SSLSocketFactory;
import javax.net.ssl.TrustManager;
import javax.net.ssl.TrustManagerFactory;

public class EchoClient {
	private static final String JAVA_KEYSTORE_INSTANCE_KEY = "JKS";
	private static final String JKS_PATH = "keys/keystore.jks";
	private static final String KEYSTORE_PASSWORD = "keystorePassword";
	private static final String SSL_CONTEXT = "TLS";
	private static final String[] ENABLED_PROTOCOLS = new String[] { "TLSv1.2" };

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
			
			SSLSocketFactory sslsocketfactory = sslContext.getSocketFactory();
			SSLSocket sslsocket = (SSLSocket) sslsocketfactory.createSocket("localhost", 9999);
			sslsocket.setEnabledProtocols(ENABLED_PROTOCOLS);
			System.out.println("Shaking hands");
			sslsocket.startHandshake();

			InputStream inputstream = System.in;
			InputStreamReader inputstreamreader = new InputStreamReader(inputstream);
			BufferedReader bufferedreader = new BufferedReader(inputstreamreader);

			OutputStream outputstream = sslsocket.getOutputStream();
			OutputStreamWriter outputstreamwriter = new OutputStreamWriter(outputstream);
			BufferedWriter bufferedwriter = new BufferedWriter(outputstreamwriter);

			String string = null;
			while ((string = bufferedreader.readLine()) != null) {
				bufferedwriter.write(string + '\n');
				bufferedwriter.flush();
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
		KeyManager[] keyManagers = keyManagerFactory.getKeyManagers();
		
		TrustManagerFactory trustManagerFactory = TrustManagerFactory
				.getInstance(TrustManagerFactory.getDefaultAlgorithm());
		trustManagerFactory.init(keyStore);
		//TrustManager[] trustManagers = trustManagerFactory.getTrustManagers();
		TrustManager[] trustManagers = new TrustManager[]{new AllTrustingTrustManager()};
		
		SSLContext sslContext = SSLContext.getInstance(SSL_CONTEXT);
		sslContext.init(keyManagers, trustManagers, null);
		return sslContext;
	}
}