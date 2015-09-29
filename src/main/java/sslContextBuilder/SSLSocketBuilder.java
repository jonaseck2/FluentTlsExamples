package sslContextBuilder;

import java.io.IOException;
import java.net.InetAddress;
import java.net.Socket;

import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLSocket;
import javax.net.ssl.SSLSocketFactory;

public class SSLSocketBuilder {

	private SSLContext myContext;
	private String[] myEnabledProtocols;
	private String myHost;
	private int myPort;

	public SSLSocketBuilder(SSLContext context) {
		myContext = context;
	}

	public SSLSocket build() throws IOException {
		SSLSocketFactory sslsocketfactory = myContext.getSocketFactory();
		SSLSocket sslsocket = (SSLSocket) sslsocketfactory.createSocket(myHost, myPort);
		if (myEnabledProtocols != null) {
			sslsocket.setEnabledProtocols(myEnabledProtocols);
		}
		return sslsocket;
	}

	public SSLSocketBuilder withEnabledProtocols(String[] protocols) {
		myEnabledProtocols = protocols;
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
