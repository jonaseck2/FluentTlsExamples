package sslContextBuilder;

import java.io.IOException;
import java.math.BigInteger;
import java.security.InvalidKeyException;
import java.security.KeyPair;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.SecureRandom;
import java.security.SignatureException;
import java.security.UnrecoverableKeyException;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.util.Date;

import sun.security.x509.AlgorithmId;
import sun.security.x509.CertificateAlgorithmId;
import sun.security.x509.CertificateIssuerName;
import sun.security.x509.CertificateSerialNumber;
import sun.security.x509.CertificateSubjectName;
import sun.security.x509.CertificateValidity;
import sun.security.x509.CertificateVersion;
import sun.security.x509.CertificateX509Key;
import sun.security.x509.X500Name;
import sun.security.x509.X509CertImpl;
import sun.security.x509.X509CertInfo;

public class CertificateBuilder {

	private static final int GENERATED_ALIAS_LENGTH = 12;
	private static final long MILLISECONDS_IN_DAY = 86400000l;
	private static final int DEFAULT_NUMBER_OF_DAYS_VALID = 365;
	private static final String ALGORITHM_INFO_KEY = CertificateAlgorithmId.NAME + "." + CertificateAlgorithmId.ALGORITHM;
	private static final AlgorithmId DEFAULT_ALGORITHM_ID = new AlgorithmId(AlgorithmId.md5WithRSAEncryption_oid);
	private static final String DEFAULT_DN = "cn=testcn";
	private static final String DEFAULT_SIGNATURE_ALGORITHM = "SHA256withRSA";
	X509CertInfo myCertInfo = new X509CertInfo();
	private KeyPair myKeyPair;
	private SSLContextBuilder mySSLContextBuilder;
	
	
	public CertificateBuilder(SSLContextBuilder sslContextBuilder, KeyPair keyPair) {
		myKeyPair = keyPair;
		mySSLContextBuilder = sslContextBuilder;
	}

	public SSLContextBuilder build() throws InvalidKeyException, CertificateException, NoSuchAlgorithmException, NoSuchProviderException, SignatureException, IOException, KeyStoreException, UnrecoverableKeyException{
		if(myCertInfo.get(X509CertInfo.VALIDITY) == null){
			withValidityInDays(DEFAULT_NUMBER_OF_DAYS_VALID);
		}
		
		if( myCertInfo.get(X509CertInfo.SERIAL_NUMBER) == null){
			BigInteger sn = new BigInteger(64, new SecureRandom());
			withCertificateSerialNumber(new CertificateSerialNumber(sn));
		}
		
		if( myCertInfo.get(X509CertInfo.SUBJECT) == null || myCertInfo.get(X509CertInfo.ISSUER)  == null){
			X500Name owner = new X500Name(DEFAULT_DN);
			withX500Name(owner);
		}

		if (myCertInfo.get(X509CertInfo.VERSION) == null){
			withVersion(new CertificateVersion(CertificateVersion.V3));
		}

		if (myCertInfo.get(X509CertInfo.ALGORITHM_ID) == null){
			withAlgorithmId(new CertificateAlgorithmId(DEFAULT_ALGORITHM_ID));
		}

		myCertInfo.set(X509CertInfo.KEY, new CertificateX509Key(myKeyPair.getPublic()));
		
		// Sign the cert to identify the algorithm that's used.
		X509CertImpl cert = new X509CertImpl(myCertInfo);
		PrivateKey privkey = myKeyPair.getPrivate();
		cert.sign(privkey, DEFAULT_SIGNATURE_ALGORITHM);

		// Update the algorith, and resign.
		AlgorithmId algo = (AlgorithmId) cert.get(X509CertImpl.SIG_ALG);
		myCertInfo.set(ALGORITHM_INFO_KEY, algo);
		cert = new X509CertImpl(myCertInfo);
		cert.sign(privkey, DEFAULT_SIGNATURE_ALGORITHM);
		
		String generatedKeyAndKeystorePassword = SSLContextBuilder.getRandomString(GENERATED_ALIAS_LENGTH);
		
		KeyStore keyStore = KeyStore.getInstance(KeyStore.getDefaultType());
		keyStore.load(null, generatedKeyAndKeystorePassword.toCharArray());

		keyStore.setCertificateEntry(SSLContextBuilder.getRandomString(GENERATED_ALIAS_LENGTH), cert);
		Certificate[] certificateChain = new Certificate[] { cert };
		keyStore.setKeyEntry(SSLContextBuilder.getRandomString(GENERATED_ALIAS_LENGTH), myKeyPair.getPrivate(), generatedKeyAndKeystorePassword.toCharArray(), certificateChain);
		return mySSLContextBuilder.withKeystore(keyStore, generatedKeyAndKeystorePassword);

	}

	private CertificateBuilder withValidityInDays(int days) throws CertificateException, IOException {
		Date from = new Date();
		Date to = new Date(from.getTime() + days * MILLISECONDS_IN_DAY);
		withValdity(new CertificateValidity(from, to));
		return this;
	}
		
	public CertificateBuilder withValdity(CertificateValidity validity) throws CertificateException, IOException{
		myCertInfo.set(X509CertInfo.VALIDITY, validity);
		return this;
	}

	public CertificateBuilder withCertificateSerialNumber(CertificateSerialNumber sn) throws CertificateException, IOException{
		myCertInfo.set(X509CertInfo.SERIAL_NUMBER, sn);
		return this;
	}
	
	public CertificateBuilder withX500Name(X500Name owner) throws CertificateException, IOException{
		myCertInfo.set(X509CertInfo.SUBJECT, new CertificateSubjectName(owner));
		myCertInfo.set(X509CertInfo.ISSUER, new CertificateIssuerName(owner));
		return this;
	}

	public CertificateBuilder withVersion(CertificateVersion version) throws CertificateException, IOException{
		myCertInfo.set(X509CertInfo.VERSION, version);
		return this;
	}

	public CertificateBuilder withAlgorithmId(CertificateAlgorithmId algo) throws CertificateException, IOException{
		myCertInfo.set(X509CertInfo.ALGORITHM_ID, algo);
		return this;
	}
}
