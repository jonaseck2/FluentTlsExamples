package sslContextBuilder;

import java.io.BufferedInputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.math.BigInteger;
import java.security.GeneralSecurityException;
import java.security.KeyFactory;
import java.security.KeyManagementException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.SecureRandom;
import java.security.UnrecoverableKeyException;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
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
	private static final String X_509_CERTIFICATE_FACTORY_INSTANCE_NAME = "X.509";
	private static final String SSL_CONTEXT = "TLS";
	private List<KeyManager> myKeyManagers = new ArrayList<KeyManager>();
	private List<TrustManager> myTrustManagers = new ArrayList<TrustManager>();
	private static final SecureRandom myRandom = new SecureRandom();
	private static final int GENERATED_KEYSTORE_PASSWORD_LENGTH = 12;

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

		KeyManager[] keyManagers = new KeyManager[] {};
		keyManagers = myKeyManagers.toArray(keyManagers);

		TrustManager[] trustManagers = new TrustManager[] {};
		trustManagers = myTrustManagers.toArray(trustManagers);

		sslContext.init(keyManagers, trustManagers, null);
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

	public SSLContextBuilder withJavaCaCertsFile() throws UnrecoverableKeyException, KeyStoreException,
			NoSuchAlgorithmException, CertificateException, FileNotFoundException, IOException {
		return withKeystoreFile(System.getProperty("java.home") + "/lib/security/cacerts", "changeit");
	}

	public CertificateBuilder withSelfSignedKeyAndCert(String keyAlgorithm, int keyLength)
			throws GeneralSecurityException, IOException {
		KeyPairGenerator keyGen = KeyPairGenerator.getInstance(keyAlgorithm);
		keyGen.initialize(keyLength);
		KeyPair keyPair = keyGen.generateKeyPair();

		return new CertificateBuilder(this, keyPair);
	}

	public SSLContextBuilder withTrustManager(TrustManager trustManager) {
		myTrustManagers.add(trustManager);
		return this;
	}

	/**
	 * 
	 * @return a Trust manager that does not validate certificate chain of trust
	 */
	public SSLContextBuilder withNonvalidatingTrustManager() {
		return withTrustManager(new X509TrustManager() {

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

	public SSLContextBuilder withPemFileKeyFile(String keyFilePath, String certFilePath)
			throws UnrecoverableKeyException, FileNotFoundException, InvalidKeySpecException, NoSuchAlgorithmException,
			KeyStoreException, CertificateException, IOException {
		return withPemFileKeyFile(keyFilePath, certFilePath, "");
	}

	public SSLContextBuilder withPemFileKeyFile(String keyFilePath, String certFilePath, String suggestedKeyAlgorithm)
			throws FileNotFoundException, IOException, InvalidKeySpecException, NoSuchAlgorithmException,
			KeyStoreException, CertificateException, UnrecoverableKeyException {

		File keyFile = new File(keyFilePath);
		PrivateKey privateKey = getKeyFromPem(keyFile, suggestedKeyAlgorithm);

		File certFile = new File(certFilePath);
		X509Certificate certificate = getCertFromPem(certFile);

		String generatedKayAndKeystorePassword = SSLContextBuilder.getRandomString(GENERATED_KEYSTORE_PASSWORD_LENGTH);

		KeyStore keyStore = KeyStore.getInstance(KeyStore.getDefaultType());
		keyStore.load(null, generatedKayAndKeystorePassword.toCharArray());

		keyStore.setCertificateEntry(certFile.getName(), certificate);

		keyStore.setKeyEntry(keyFile.getName(), privateKey, generatedKayAndKeystorePassword.toCharArray(),
				new Certificate[] { certificate });
		KeyManagerFactory keyManagerFactory = KeyManagerFactory.getInstance(KeyManagerFactory.getDefaultAlgorithm());
		keyManagerFactory.init(keyStore, generatedKayAndKeystorePassword.toCharArray());

		myKeyManagers.addAll(Arrays.asList(keyManagerFactory.getKeyManagers()));

		TrustManagerFactory trustManagerFactory = TrustManagerFactory
				.getInstance(TrustManagerFactory.getDefaultAlgorithm());
		trustManagerFactory.init(keyStore);

		myTrustManagers.addAll(Arrays.asList(trustManagerFactory.getTrustManagers()));

		return this;
	}

	public SSLContextBuilder withPemFileCertFile(String certFilePath)
			throws CertificateException, KeyStoreException, NoSuchAlgorithmException, IOException {
		File certFile = new File(certFilePath);
		X509Certificate certificate = getCertFromPem(certFile);

		String generatedKeystorePassword = SSLContextBuilder.getRandomString(GENERATED_KEYSTORE_PASSWORD_LENGTH);

		KeyStore keyStore = KeyStore.getInstance(KeyStore.getDefaultType());
		keyStore.load(null, generatedKeystorePassword.toCharArray());

		keyStore.setCertificateEntry(certFile.getName(), certificate);

		TrustManagerFactory trustManagerFactory = TrustManagerFactory
				.getInstance(TrustManagerFactory.getDefaultAlgorithm());
		trustManagerFactory.init(keyStore);

		myTrustManagers.addAll(Arrays.asList(trustManagerFactory.getTrustManagers()));

		return this;
	}

	private static X509Certificate getCertFromPem(File keyFile) throws FileNotFoundException, CertificateException {
		FileInputStream fis = new FileInputStream(keyFile);

		X509Certificate certificate = (X509Certificate) CertificateFactory
				.getInstance(X_509_CERTIFICATE_FACTORY_INSTANCE_NAME).generateCertificate(new BufferedInputStream(fis));
		return certificate;
	}

	private static byte[] fileToByteArray(File file) throws FileNotFoundException, IOException {
		FileInputStream in = new FileInputStream(file);
		byte[] keyBytes = new byte[in.available()];
		in.read(keyBytes);
		in.close();
		return keyBytes;
	}

	private static PrivateKey getKeyFromPem(File file, String suggestedKeyAlgorithm) throws FileNotFoundException,
			IOException, UnsupportedEncodingException, NoSuchAlgorithmException, InvalidKeySpecException {
		byte[] keyBytes = fileToByteArray(file);
		String keyAlgorithm = suggestedKeyAlgorithm;

		String key = new String(keyBytes, "ASCII");
		// Pattern pattern = Pattern.compile(".*-+BEGIN *([A-Z]*) PRIVATE
		// KEY-+[\r\n]*|[\r\n]*-+END *[A-Z]* PRIVATE KEY-+", Pattern.DOTALL);
		String[] split = key.split("-+BEGIN *([A-Z]*) PRIVATE KEY-+");
		key = split[split.length - 1].split("-+END *[A-Z]* PRIVATE KEY-+")[0];
		key = key.replaceAll("[\r\n]*", "");
		/*
		 * Matcher matcher = pattern.matcher(key); if (matcher.matches()) { if
		 * (matcher.group(1).length() > 2) { keyAlgorithm = matcher.group(1); }
		 * key = matcher.replaceAll(""); }
		 */
		byte[] decoded = Base64.getDecoder().decode(key);

		PKCS8EncodedKeySpec spec = new PKCS8EncodedKeySpec(decoded);
		KeyFactory keyFactory = KeyFactory.getInstance(keyAlgorithm);
		PrivateKey privateKey = keyFactory.generatePrivate(spec);
		return privateKey;
	}

	public static String getRandomString(int chars) {
		return new BigInteger(chars * 5, myRandom).toString(32);
	}

}
