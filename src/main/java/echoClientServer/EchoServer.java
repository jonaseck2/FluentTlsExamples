package echoClientServer;

import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLServerSocket;
import javax.net.ssl.SSLServerSocketFactory;
import javax.net.ssl.SSLSocket;
import javax.net.ssl.TrustManager;
import javax.net.ssl.TrustManagerFactory;

import java.io.BufferedReader;
import java.io.FileInputStream;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.security.KeyStore;
import java.security.Provider;
import java.security.Security;

public class EchoServer {
	public static void main(String[] arstring) {
		try {
			//node private key
			//openssl genrsa -aes256 -out nodeName_https.key 2048
			//certificate authority
			//openssl genrsa -aes256 -out CA.key 2048
			//certificate authority certificate signing request
			//openssl req -new -x509 -days 1095 -key CA.key -out CA.crt
			//node certificate signing request
			//openssl req -new -x509 -days 365 -key nodeName_https.key -out nodeName_https.crt
			//node key signing request
			//openssl req -new -key nodeName_https.key -out nodeName_https.csr
			//node https certificate signed by CA
			//openssl x509 -req -days 365 -in nodeName_https.csr -CA CA.crt -CAkey CA.key -set_serial 01 -out nodeName_csnmt-signed.crt
			//import CA to java keystore
			//keytool -import -alias csnmt -file CA.crt -keypass test -keystore nodeName.jks -storepass keystorePassword
			//import to java keystore
			//keytool -import -alias nodeName_csnmt-signed -file nodeName_csnmt-signed.crt -keypass test -keystore nodeName.jks -storepass keystorePassword
			
			KeyStore keyStore = KeyStore.getInstance("JKS");
			keyStore.load(new FileInputStream("keys/nodeName.jks"), "keystorePassword".toCharArray());

			for (Provider p : Security.getProviders()){
				System.out.println(p.getName());
			}
			
			//KeyManagerFactory keyManagerFactory = KeyManagerFactory.getInstance("X509");
			KeyManagerFactory keyManagerFactory = KeyManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm());
			keyManagerFactory.init(keyStore, "keystorePassword".toCharArray());

			//KeyManagerFactory keyManagerFactory = KeyManagerFactory.getInstance("X509");
			TrustManagerFactory trustManagerFactory = TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm()); 
			trustManagerFactory.init(keyStore);

			SSLContext sslContext = SSLContext.getInstance("TLS"); 
			TrustManager[] trustManagers = trustManagerFactory.getTrustManagers(); 
			sslContext.init(keyManagerFactory.getKeyManagers(), trustManagers, null); 

			SSLServerSocketFactory sslserversocketfactory = sslContext.getServerSocketFactory(); 
			SSLServerSocket sslserversocket = (SSLServerSocket) sslserversocketfactory.createServerSocket(9999);
			SSLSocket sslsocket = (SSLSocket) sslserversocket.accept();
			
//			SSLServerSocketFactory sslserversocketfactory = (SSLServerSocketFactory) SSLServerSocketFactory.getDefault();
//			SSLServerSocket sslserversocket = (SSLServerSocket) sslserversocketfactory.createServerSocket(9999);
//			SSLSocket sslsocket = (SSLSocket) sslserversocket.accept();

			InputStream inputstream = sslsocket.getInputStream();
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