package sslContextBuilder;

import java.io.IOException;

import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLParameters;
import javax.net.ssl.SSLServerSocket;
import javax.net.ssl.SSLServerSocketFactory;
import javax.net.ssl.SSLSocket;
import javax.net.ssl.SSLSocketFactory;

public class SSLSocketBuilder {

	private static final int DEFAULT_HTTPS_PORT = 443;
	private SSLContext myContext;
	private String[] myEnabledProtocols;
	private String myHost;
	private int myPort = 0;
	private String myEndointIdentificationAlgorithm;

	public SSLSocketBuilder(SSLContext context) {
		myContext = context;
	}

	public SSLSocket socket() throws IOException {
		SSLSocketFactory sslsocketfactory = myContext.getSocketFactory();
		SSLSocket sslsocket = null;
		if (myHost == null) {
			sslsocket = (SSLSocket) sslsocketfactory.createSocket();
		} else if (myPort == 0) {
			sslsocket = (SSLSocket) sslsocketfactory.createSocket(myHost, DEFAULT_HTTPS_PORT);
		} else {
			sslsocket = (SSLSocket) sslsocketfactory.createSocket(myHost, myPort);
		}
		if (myEnabledProtocols != null) {
			sslsocket.setEnabledProtocols(myEnabledProtocols);
		}
		if (myEndointIdentificationAlgorithm == null){
			SSLParameters sslParams = new SSLParameters();
			sslParams.setEndpointIdentificationAlgorithm(myEndointIdentificationAlgorithm);
			sslsocket.setSSLParameters(sslParams);

		}
		if (sslsocket.isConnected()) {
			sslsocket.startHandshake();
		}

		return sslsocket;
	}

	public SSLServerSocket serverSocket() throws IOException {
		SSLServerSocketFactory sslServerSocketfactory = myContext.getServerSocketFactory();
		SSLServerSocket sslServerSocket = (SSLServerSocket) sslServerSocketfactory.createServerSocket(myPort);
		if (myEnabledProtocols != null) {
			sslServerSocket.setEnabledProtocols(myEnabledProtocols);
		}
		return sslServerSocket;
	}

	public SSLSocketBuilder withEnabledProtocols(String[] protocols) {
		myEnabledProtocols = protocols;
		return this;
	}

	public SSLSocketBuilder withHttpsEndpointIdentificationAlgorithm(String algorithm){
		myEndointIdentificationAlgorithm = algorithm;
		return this;
	}
	
	public SSLSocketBuilder withHost(String host) {
		myHost = host;
		return this;
	}

	public SSLSocketBuilder withPort(int port) {
		myPort = port;
		return this;
	}

}
