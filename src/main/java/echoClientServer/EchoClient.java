package echoClientServer;

import java.io.BufferedWriter;
import java.io.IOException;
import java.io.OutputStream;
import java.io.OutputStreamWriter;
import java.security.KeyManagementException;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.UnrecoverableKeyException;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;

import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLSocket;
import javax.net.ssl.SSLSocketFactory;
import javax.net.ssl.TrustManager;
import javax.net.ssl.X509TrustManager;

import sslContextBuilder.SSLContextBuilder;

public class EchoClient {
	private static final String SSL_CONTEXT = "TLS";
	private static final String[] ENABLED_PROTOCOLS = new String[] { "TLSv1.2" };

	public static void main(String[] arstring) {
		SSLSocket sslsocket = null;
		try {

			SSLContext sslContext = SSLContextBuilder.builder().withNonvalidatingTrustManager().build();
			
			//SSLContext sslContext = getTrustingSslContext();

			SSLSocketFactory sslsocketfactory = sslContext.getSocketFactory();
			sslsocket = (SSLSocket) sslsocketfactory.createSocket("localhost", 9999);
			sslsocket.setEnabledProtocols(ENABLED_PROTOCOLS);
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

	private static SSLContext getTrustingSslContext() throws CertificateException, KeyStoreException,
			NoSuchAlgorithmException, IOException, KeyManagementException, UnrecoverableKeyException {

		SSLContext sslContext = SSLContext.getInstance(SSL_CONTEXT);
		sslContext.init(null, new TrustManager[] { new X509TrustManager() {
			
			@Override
			public X509Certificate[] getAcceptedIssuers() {
				// TODO Auto-generated method stub
				return null;
			}
			
			@Override
			public void checkServerTrusted(X509Certificate[] chain, String authType) throws CertificateException {
				// TODO Auto-generated method stub
				
			}
			
			@Override
			public void checkClientTrusted(X509Certificate[] chain, String authType) throws CertificateException {
				// TODO Auto-generated method stub
				
			}
		} }, null);
		return sslContext;
	}
}