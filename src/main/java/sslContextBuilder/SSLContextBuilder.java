package sslContextBuilder;

import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.security.GeneralSecurityException;
import java.security.KeyFactory;
import java.security.KeyManagementException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.UnrecoverableKeyException;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Base64;
import java.util.List;

import javax.net.ssl.KeyManager;
import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.SSLContext;
import javax.net.ssl.TrustManager;
import javax.net.ssl.TrustManagerFactory;
import javax.net.ssl.X509TrustManager;

public class SSLContextBuilder {
	private static final String SSL_CONTEXT = "TLS";
	private List<KeyManager> myKeyManagers = new ArrayList<KeyManager>();
	private List<TrustManager> myTrustManagers = new ArrayList<TrustManager>();

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

	public SSLContextBuilder withTrustManager(TrustManager trustManager){
		myTrustManagers.add(trustManager);
		return this;
	}
	
	/**
	 * 
	 * @return a Trust manager that does not validate certificate chain of trust
	 */
	public SSLContextBuilder withNonvalidatingTrustManager() {
		withTrustManager(new X509TrustManager() {
			
			@Override
			public X509Certificate[] getAcceptedIssuers() {
				return null;
			}
			
			@Override
			public void checkServerTrusted(X509Certificate[] arg0, String arg1) throws CertificateException {
			}
			
			@Override
			public void checkClientTrusted(X509Certificate[] arg0, String arg1) throws CertificateException {
			}
		});
		return this;
	}

	public SSLContextBuilder withKeystore(KeyStore keyStore, String keystorePassword)
			throws NoSuchAlgorithmException, UnrecoverableKeyException, KeyStoreException {
		KeyManagerFactory keyManagerFactory = KeyManagerFactory.getInstance(KeyManagerFactory.getDefaultAlgorithm());
		keyManagerFactory.init(keyStore, keystorePassword.toCharArray());
		myKeyManagers.addAll(Arrays.asList(keyManagerFactory.getKeyManagers()));

		TrustManagerFactory trustManagerFactory = TrustManagerFactory
				.getInstance(TrustManagerFactory.getDefaultAlgorithm());
		trustManagerFactory.init(keyStore);
		myTrustManagers.addAll(Arrays.asList(trustManagerFactory.getTrustManagers()));
		return this;
	}
	
	public SSLContextBuilder withPemFileKeyFile(String filePath, String keyAlgorithm) throws FileNotFoundException, IOException, InvalidKeySpecException, NoSuchAlgorithmException{
		byte[] keyBytes = fileToByteArray(filePath);
		
		String pubKey = new String(keyBytes, "UTF-8");
		//TODO Pattern.DOTALL
		pubKey.replaceAll("-+BEGIN RSA PRIVATE KEY+-.*\n\n|-+END RSA PRIVATE KEY+-", "");
		
		byte[] decoded = Base64.getDecoder().decode(keyBytes);

		  PKCS8EncodedKeySpec spec = new PKCS8EncodedKeySpec(decoded);
	      KeyFactory keyFactory = KeyFactory.getInstance(keyAlgorithm);
	      PrivateKey privateKey = keyFactory.generatePrivate(spec);
		
		return this;
	}
	
	public SSLContextBuilder withPemCertificateFile(String filePath, String keyAlgorithm) throws IOException, NoSuchAlgorithmException, InvalidKeySpecException{
		byte[] certBytes = fileToByteArray(filePath);
		
		String pubKey = new String(certBytes, "UTF-8");
		pubKey = pubKey.replaceAll("(-+BEGIN PUBLIC KEY-+\\r?\\n|-+END PUBLIC KEY-+\\r?\\n?)", "");

		byte[] decoded = Base64.getDecoder().decode(certBytes);

		X509EncodedKeySpec spec = new X509EncodedKeySpec(decoded);
		KeyFactory keyFactory = KeyFactory.getInstance(keyAlgorithm);
		PublicKey publicKey = keyFactory.generatePublic(spec);
		
		
		return this;
	}

	private static byte[] fileToByteArray(String filePath) throws FileNotFoundException, IOException {
		FileInputStream in = new FileInputStream(filePath);
		byte[] keyBytes = new byte[in.available()];
		in.read(keyBytes);
		in.close();
		return keyBytes;
	}

}
