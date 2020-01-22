/** *****************************************************************************
 * DISCLAIMER: The sample code or utility or tool described herein
 *    is provided on an "as is" basis, without warranty of any kind.
 *    UIDAI does not warrant or guarantee the individual success
 *    developers may have in implementing the sample code on their
 *    environment.
 *
 *    UIDAI does not warrant, guarantee or make any representations
 *    of any kind with respect to the sample code and does not make
 *    any representations or warranties regarding the use, results
 *    of use, accuracy, timeliness or completeness of any data or
 *    information relating to the sample code. UIDAI disclaims all
 *    warranties, express or implied, and in particular, disclaims
 *    all warranties of merchantability, fitness for a particular
 *    purpose, and warranties related to the code, or any service
 *    or software related thereto.
 *
 *    UIDAI is not responsible for and shall not be liable directly
 *    or indirectly for any direct, indirect damages or costs of any
 *    type arising out of use or any action taken by you or others
 *    related to the sample code.
 *
 *    THIS IS NOT A SUPPORTED SOFTWARE.
 ***************************************************************************** */
package in.gov.uidai.auth.aua.httpclient;

import java.io.StringReader;
import java.io.StringWriter;
import java.net.InetAddress;
import java.net.URI;
import java.text.SimpleDateFormat;
import java.util.Date;

import javax.ws.rs.client.Entity;
import javax.xml.bind.JAXBContext;
import javax.xml.bind.JAXBElement;
import javax.xml.bind.JAXBException;
import javax.xml.bind.Unmarshaller;
import javax.xml.namespace.QName;
import javax.xml.transform.sax.SAXSource;

import org.apache.commons.lang.StringUtils;
import org.xml.sax.InputSource;
import org.xml.sax.XMLReader;
import org.xml.sax.helpers.XMLReaderFactory;

import in.gov.uidai.auth.aua.helper.DigitalSigner;
import in.gov.uidai.auth.device.model.OtpResponseDetails;
import in.gov.uidai.authentication.otp._2.Otp;
import in.gov.uidai.authentication.otp._2.OtpRes;

/**
 * <code>OtpClient</code> class can be used for submitting an OTP Generation
 * request to UIDAI OTP Server, and to get the response back
 *
 * @author UIDAI
 *
 */
public class OtpClient {

    private URI otpServerURI = null;

    private String asaLicenseKey;
    private DigitalSigner digitalSignator;

    public OtpClient(URI otpServerURI) {
        this.otpServerURI = otpServerURI;
    }

    public OtpResponseDetails generateOtp(Otp otp) {
        try {
            String signedXML = generateSignedOtpXML(otp);

            System.out.println("Signed request - \n" + signedXML);

            String uriString = otpServerURI.toString() + (otpServerURI.toString().endsWith("/") ? "" : "/")
                    + otp.getAc() + "/" + otp.getUid().charAt(0) + "/" + otp.getUid().charAt(1);

            if (StringUtils.isNotBlank(asaLicenseKey)) {
                uriString = uriString + "/" + asaLicenseKey;
            }

            System.out.println("POST URL is - \n" + uriString);

            URI otpURI = new URI(uriString);

            String responseXML = HttpClientHelper.getClient(otpServerURI.getScheme())
                    .target(otpURI).request().header("REMOTE_ADDR", InetAddress.getLocalHost().getHostAddress())
                    .post(Entity.xml(signedXML)).readEntity(String.class);

            System.out.println("Response is : \n" + responseXML);

            return new OtpResponseDetails(responseXML, parseOtpResponseXML(responseXML));

        } catch (Exception e) {
            e.printStackTrace();
            throw new RuntimeException("Exception during OTP generation " + e.getMessage(), e);
        }

    }

    public String getAadharRequest(Otp otp) {
        SimpleDateFormat dateFormat = new SimpleDateFormat("yyyy-MM-dd HH:mm:ss");
        String ts = dateFormat.format(new Date());
        ts = ts.replace(" ", "T");
        return "<?xml version=\"1.0\" encoding=\"UTF-8\" standalone=\"yes\"?><Otp uid=\"" + otp.getUid() + "\" ts=\"" + ts + "\" ac=\"public\" sa=\"public\" ver=\"2.5\" txn=\"" + otp.getTxn() + "\" lk=\"" + otp.getLk() + "\" type=\"A\"></Otp>";
    }

    private String generateSignedOtpXML(Otp otp) throws JAXBException, Exception {
        StringWriter otpXML = new StringWriter();

        JAXBElement element = new JAXBElement(new QName(
                "http://www.uidai.gov.in/authentication/otp/2.5", "Otp"), Otp.class, otp);

        JAXBContext.newInstance(Otp.class).createMarshaller().marshal(element, otpXML);

        String reqXml = this.getAadharRequest(otp);

        System.out.println("Actual request - \n" + reqXml);

        boolean includeKeyInfo = true;

        if (System.getenv().get("SKIP_DIGITAL_SIGNATURE") != null) {
            return reqXml;
        } else {
            return this.digitalSignator.signXML(reqXml, includeKeyInfo);
        }
    }

    private OtpRes parseOtpResponseXML(String xmlToParse) throws JAXBException {

        //Create an XMLReader to use with our filter
        try {
            //Prepare JAXB objects
            JAXBContext jc = JAXBContext.newInstance(OtpRes.class);
            Unmarshaller u = jc.createUnmarshaller();

            XMLReader reader;
            reader = XMLReaderFactory.createXMLReader();

            //Create the filter (to add namespace) and set the xmlReader as its parent.
            NamespaceFilter inFilter = new NamespaceFilter("http://www.uidai.gov.in/authentication/otp/2.5", true);
            inFilter.setParent(reader);

            //Prepare the input, in this case a java.io.File (output)
            InputSource is = new InputSource(new StringReader(xmlToParse));

            //Create a SAXSource specifying the filter
            SAXSource source = new SAXSource(inFilter, is);

            //Do unmarshalling
            OtpRes res = u.unmarshal(source, OtpRes.class).getValue();
            return res;
        } catch (Exception e) {
            e.printStackTrace();
            throw new RuntimeException("Erorr while parsing response XML" + e.getMessage());
        }
    }

    /**
     * Method to inject an instance of <code>DigitalSigner</code> class.
     *
     * @param digitalSignator
     */
    public void setDigitalSignator(DigitalSigner digitalSignator) {
        this.digitalSignator = digitalSignator;
    }

    public void setAsaLicenseKey(String asaLicenseKey) {
        this.asaLicenseKey = asaLicenseKey;
    }

}
