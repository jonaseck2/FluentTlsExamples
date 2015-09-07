package echoClientServer;

import java.security.cert.X509Certificate;

import javax.net.ssl.X509TrustManager;

public class AllTrustingTrustManager implements X509TrustManager {
    public void checkClientTrusted(X509Certificate[] certs, String authType) {
    }

    public void checkServerTrusted(X509Certificate[] certs, String authType) {
    }

    public java.security.cert.X509Certificate[] getAcceptedIssuers() {
        return null;
    }

}
