package echoClientServer;

import java.io.BufferedWriter;
import java.io.IOException;
import java.io.OutputStream;
import java.io.OutputStreamWriter;

import javax.net.ssl.SSLSocket;

import sslContextBuilder.SSLContextBuilder;

public class EchoClient {
	private static final String[] ENABLED_PROTOCOLS = new String[] { "TLSv1.2" };

	public static void main(String[] arstring) {
		SSLSocket sslsocket = null;
		try {

			sslsocket = SSLContextBuilder.builder().withNonvalidatingTrustManager().socketBuilder()
					.withEnabledProtocols(ENABLED_PROTOCOLS).socket();

			System.out.println("Shaking hands");
			sslsocket.startHandshake();

			OutputStream outputstream = sslsocket.getOutputStream();
			OutputStreamWriter outputstreamwriter = new OutputStreamWriter(outputstream);
			BufferedWriter bufferedwriter = new BufferedWriter(outputstreamwriter);

			String string = "This is the string";
			bufferedwriter.write(string + '\n');
			bufferedwriter.flush();
		} catch (Exception exception) {
			exception.printStackTrace();
		} finally {
			try {
				sslsocket.close();
			} catch (IOException e) {
				e.printStackTrace();
			}
		}
	}
}