package sslContextBuilder;

import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.security.KeyManagementException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.UnrecoverableKeyException;
import java.security.cert.CertificateException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

import javax.net.ssl.KeyManager;
import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.SSLContext;
import javax.net.ssl.TrustManager;
import javax.net.ssl.TrustManagerFactory;

public class SslContextBuilder {
	private static final String SSL_CONTEXT = "TLS";
	private List<KeyManager> myKeyManagers = new ArrayList<>();
	private List<TrustManager> myTrustManagers = new ArrayList<>();

	private SslContextBuilder() {
	};


	public static SslContextBuilder builder() {
		return new SslContextBuilder();
	}

	public SSLContext build() throws KeyManagementException, NoSuchAlgorithmException{
		SSLContext sslContext = SSLContext.getInstance(SSL_CONTEXT);
		sslContext.init((KeyManager[]) myKeyManagers.toArray(), (TrustManager[]) myTrustManagers.toArray(), null);
		return sslContext;
	}
	
	public SslContextBuilder withKeystoreFile(String keystoreFilePath, String keystorePassword) throws KeyStoreException, NoSuchAlgorithmException, CertificateException, FileNotFoundException, IOException, UnrecoverableKeyException{
		KeyStore keyStore = KeyStore.getInstance(KeyStore.getDefaultType());
		keyStore.load(new FileInputStream(keystoreFilePath), keystorePassword.toCharArray());

		KeyManagerFactory keyManagerFactory = KeyManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm());
		keyManagerFactory.init(keyStore, keystorePassword.toCharArray());
		myKeyManagers.addAll(Arrays.asList(keyManagerFactory.getKeyManagers()));

		TrustManagerFactory trustManagerFactory = TrustManagerFactory
				.getInstance(TrustManagerFactory.getDefaultAlgorithm());
		trustManagerFactory.init(keyStore);
		myTrustManagers.addAll(Arrays.asList(trustManagerFactory.getTrustManagers()));
		return this;

	}
}
