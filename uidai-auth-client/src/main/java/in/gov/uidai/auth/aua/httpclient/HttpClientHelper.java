/**
 * DISCLAIMER: The sample code or utility or tool described herein
 * is provided on an "as is" basis, without warranty of any kind.
 * UIDAI does not warrant or guarantee the individual success
 * developers may have in implementing the sample code on their
 * environment.
 *
 * UIDAI does not warrant, guarantee or make any representations
 * of any kind with respect to the sample code and does not make
 * any representations or warranties regarding the use, results
 * of use, accuracy, timeliness or completeness of any data or
 * information relating to the sample code. UIDAI disclaims all
 * warranties, express or implied, and in particular, disclaims
 * all warranties of merchantability, fitness for a particular
 * purpose, and warranties related to the code, or any service
 * or software related thereto.
 *
 * UIDAI is not responsible for and shall not be liable directly
 * or indirectly for any direct, indirect damages or costs of any
 * type arising out of use or any action taken by you or others
 * related to the sample code.
 *
 * THIS IS NOT A SUPPORTED SOFTWARE.
 *
 */
package in.gov.uidai.auth.aua.httpclient;

import java.security.KeyManagementException;
import java.security.NoSuchAlgorithmException;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.concurrent.TimeUnit;

import javax.net.ssl.HostnameVerifier;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLSession;
import javax.net.ssl.TrustManager;
import javax.net.ssl.X509TrustManager;
import javax.ws.rs.client.Client;
import javax.ws.rs.client.ClientBuilder;

import org.apache.commons.lang.math.NumberUtils;

public class HttpClientHelper {

    public static final int DEFAULT_CLIENT_TIMEOUT = 30000;
    public static final String CLIENT_TIME_OUT_PERIOD = "TIMEOUT_PERIOD"; // value in milli seconds

    private static final HostnameVerifier VERIFIER = (String hostname, SSLSession sslSession) -> true;
    private static SSLContext sslContext;

    static {
        TrustManager mytm[] = {new X509TrustManager() {

            @Override
            public void checkClientTrusted(X509Certificate[] arg0,
                    String arg1) throws CertificateException {
            }

            @Override
            public void checkServerTrusted(X509Certificate[] arg0,
                    String arg1) throws CertificateException {
            }

            @Override
            public X509Certificate[] getAcceptedIssuers() {
                return null;
            }
        }};
        try {
            sslContext = SSLContext.getInstance("SSL");
            sslContext.init(null, mytm, null);
        } catch (NoSuchAlgorithmException | KeyManagementException e) {
            e.printStackTrace();
        }
    }

    public static Client getClient(String uriScheme) {
        ClientBuilder clientBuilder = ClientBuilder.newBuilder().readTimeout(NumberUtils.toLong(
                System.getenv(CLIENT_TIME_OUT_PERIOD),
                DEFAULT_CLIENT_TIMEOUT), TimeUnit.MILLISECONDS);

        if (uriScheme.equalsIgnoreCase("https")) {
            clientBuilder = clientBuilder.sslContext(sslContext).hostnameVerifier(VERIFIER);
        }

        return clientBuilder.build();
    }

}
