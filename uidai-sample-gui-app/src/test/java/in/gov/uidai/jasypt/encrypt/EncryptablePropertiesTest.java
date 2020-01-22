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
package in.gov.uidai.jasypt.encrypt;

import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;
import java.util.Date;
import java.util.Properties;

import org.jasypt.encryption.pbe.StandardPBEStringEncryptor;
import org.jasypt.properties.EncryptableProperties;

public class EncryptablePropertiesTest {

	public static void main(String[] args) throws FileNotFoundException,
			IOException {
		store();
		load();
	}

	private static void load() throws FileNotFoundException, IOException {
		StandardPBEStringEncryptor encrypter = new StandardPBEStringEncryptor();
		encrypter.setPassword("uid1234");
		Properties encryptableProperties = new EncryptableProperties(encrypter);
		encryptableProperties.load(new FileInputStream("encprop.properties"));
		System.out.println(encryptableProperties.getProperty("com.sree"));

	}

	private static void store() throws FileNotFoundException, IOException {
		StandardPBEStringEncryptor encrypter = new StandardPBEStringEncryptor();
		encrypter.setPassword("uid1234");
		Properties encryptableProperties = new EncryptableProperties(encrypter);
		encryptableProperties.put("com.sree", "PBE Value");
		encryptableProperties.store(new FileOutputStream("encprop.properties"),
				"Generated at" + new Date());

	}
}
