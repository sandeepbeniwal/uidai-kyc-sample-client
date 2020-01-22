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
package in.gov.uidai.auth.sampleapp.processors;

import in.gov.uidai.auth.aua.helper.AuthRequestCreator;
import in.gov.uidai.auth.aua.httpclient.KYCClient;
import in.gov.uidai.auth.device.helper.AuthAUADataCreator;
import in.gov.uidai.auth.device.helper.PidCreator;
import in.gov.uidai.auth.device.model.AuthDataFromDeviceToAUA;
import in.gov.uidai.auth.device.model.DeviceCollectedAuthData;
import in.gov.uidai.authentication.uid_auth_request._2.Auth;
import in.gov.uidai.authentication.uid_auth_request._2.DataType;
import in.gov.uidai.authentication.uid_auth_request._2.Tkn;
import in.gov.uidai.authentication.uid_auth_request._2.Uses;

public class RequestProcessor implements Runnable {

	private KYCClient client;
	private String aua;
	private boolean raSelected;
	private String asaLicenseKey;
	private Uses uses;

	// auth request creator info
	private String serviceAgency;
	private String auaLicenseKey;
	private DeviceCollectedAuthData authData;
	private Tkn token;

	// authAUADataCreator info
	private String terminalID;
	private AuthAUADataCreator auaDataCreator;
	private boolean useProto;
	
	// custom KYC XML
	private String customKYCXML;

	public RequestProcessor(KYCClient kycClient, String aua,
			boolean raSelected, String asaLicenseKey, Uses uses,
			String serviceAgency, String auaLicenseKey,
			DeviceCollectedAuthData authData, Tkn token,
			AuthAUADataCreator auaDataCreator, boolean useProto,
			String terminalID,String customKYCXML) {
		this.client = kycClient;
		this.aua = aua;
		this.raSelected = raSelected;
		this.asaLicenseKey = asaLicenseKey;
		this.uses = uses;
		// auth request prepare data
		this.serviceAgency = serviceAgency;
		this.auaLicenseKey = auaLicenseKey;
		this.authData = authData;
		this.token = token;

		this.auaDataCreator = auaDataCreator;
		this.useProto = useProto;
		this.terminalID = terminalID;
		this.customKYCXML = customKYCXML;
	}

	@Override
	public void run() {
		AuthDataFromDeviceToAUA auaData = null;
		if (useProto) {
			auaData = auaDataCreator.prepareAUAData(authData.getUid(),
					terminalID, authData.getDeviceMetaData(),
					(Object) PidCreator.createProtoPid(authData), DataType.P);

		} else {
			auaData = auaDataCreator.prepareAUAData(authData.getUid(),
					terminalID, authData.getDeviceMetaData(),
					(Object) PidCreator.createXmlPid(authData), DataType.X);
		}
		Auth auth = AuthRequestCreator.createAuthRequest(aua, serviceAgency,
				auaLicenseKey, uses, token, auaData, authData
						.getDeviceMetaData());
		client.kycTrans(auth, aua, raSelected, asaLicenseKey, uses,customKYCXML);
	}
}
