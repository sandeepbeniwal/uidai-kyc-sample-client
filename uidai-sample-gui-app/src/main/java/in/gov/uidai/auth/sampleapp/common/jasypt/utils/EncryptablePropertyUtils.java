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
package in.gov.uidai.auth.sampleapp.common.jasypt.utils;

import java.util.Properties;

import org.apache.commons.lang.StringUtils;
import org.jasypt.encryption.pbe.StandardPBEStringEncryptor;
import org.jasypt.properties.EncryptableProperties;

/**
 * 
 * @author Sreemanth
 * 
 */
public class EncryptablePropertyUtils {

	private EncryptablePropertyUtils() {
		// prevent instantiation
	}

	public static Properties getEncryptableProperties() {
		StandardPBEStringEncryptor encryptor = getEncryptor();
		Properties encryptableProperties = new EncryptableProperties(encryptor);
		return encryptableProperties;
	}

	public static StandardPBEStringEncryptor getEncryptor() {
		StandardPBEStringEncryptor encryptor = new StandardPBEStringEncryptor();
		String propertiesDecryptPassword = System.getenv("PROP_DEC_PASS");
		if (StringUtils.isBlank(propertiesDecryptPassword)) {
                    //throw new RuntimeException(
		//			"Please set PROP_DEC_PASS environment variable. This is used to decrypt passwords");
                    propertiesDecryptPassword = "UID12345";
		}
		encryptor.setPassword(propertiesDecryptPassword);
		return encryptor;
	}

	public static String wrapWithENC(String value) {
		return "ENC(" + value + ")";
	}
}
