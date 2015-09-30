package sslContextBuilder;

import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.security.GeneralSecurityException;
import java.security.KeyManagementException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.UnrecoverableKeyException;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

import javax.net.ssl.KeyManager;
import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.SSLContext;
import javax.net.ssl.TrustManager;
import javax.net.ssl.TrustManagerFactory;
import javax.net.ssl.X509TrustManager;

public class SSLContextBuilder {
	private static final String SSL_CONTEXT = "TLS";
	private List<KeyManager> myKeyManagers = new ArrayList<>();
	private List<TrustManager> myTrustManagers = new ArrayList<>();

	private SSLContextBuilder() {
	};

	public static SSLContextBuilder builder() {
		return new SSLContextBuilder();
	}

	public SSLContext build() throws KeyManagementException, NoSuchAlgorithmException {
		SSLContext sslContext = getContext();
		return sslContext;
	}

	private SSLContext getContext() throws NoSuchAlgorithmException, KeyManagementException {
		SSLContext sslContext = SSLContext.getInstance(SSL_CONTEXT);
		sslContext.init((KeyManager[]) myKeyManagers.toArray(), (TrustManager[]) myTrustManagers.toArray(), null);
		return sslContext;
	}

	public SSLSocketBuilder socketBuilder() throws KeyManagementException, NoSuchAlgorithmException {
		return new SSLSocketBuilder(getContext());
	}

	/**
	 * 
	 * @param keystoreFilePath
	 *            Path to the keystore to use
	 * @param keystorePassword
	 *            Password to the keystore to use
	 * @return
	 */
	public SSLContextBuilder withKeystoreFile(String keystoreFilePath, String keystorePassword)
			throws KeyStoreException, NoSuchAlgorithmException, CertificateException, FileNotFoundException,
			IOException, UnrecoverableKeyException {
		KeyStore keyStore = KeyStore.getInstance(KeyStore.getDefaultType());
		keyStore.load(new FileInputStream(keystoreFilePath), keystorePassword.toCharArray());

		return withKeystore(keyStore, keystorePassword);
	}

	public CertificateBuilder withSelfSignedKeyAndCert(String keyAlgorithm, int keyLength)
			throws GeneralSecurityException, IOException {
		KeyPairGenerator keyGen = KeyPairGenerator.getInstance(keyAlgorithm);
		keyGen.initialize(keyLength);
		KeyPair keyPair = keyGen.generateKeyPair();
		
		return new CertificateBuilder(this, keyPair);
	}

	/**
	 * 
	 * @return a Trust manager that does not validate certificate chain of
	 *         trust
	 */
	public SSLContextBuilder withNonvalidatingTrustStore() {
		myTrustManagers.add(new X509TrustManager() {

			@Override
			public X509Certificate[] getAcceptedIssuers() {
				return null;
			}

			@Override
			public void checkServerTrusted(X509Certificate[] chain, String authType) throws CertificateException {
			}

			@Override
			public void checkClientTrusted(X509Certificate[] chain, String authType) throws CertificateException {

			}
		});
		return this;
	}

	public SSLContextBuilder withKeystore(KeyStore keyStore, String keystorePassword) throws NoSuchAlgorithmException, UnrecoverableKeyException, KeyStoreException {
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
