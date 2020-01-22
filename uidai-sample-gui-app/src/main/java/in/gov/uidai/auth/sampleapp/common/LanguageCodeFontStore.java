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
package in.gov.uidai.auth.sampleapp.common;

import java.util.HashMap;
import java.util.Map;
import java.util.Set;

public class LanguageCodeFontStore {

	private static Map<String, String> fontFileNameAndLanguageCodeMap = new HashMap<String, String>();
	private static Map<String, String> languageCodeFontNameMap = new HashMap<String, String>();

	static {
		fontFileNameAndLanguageCodeMap.put("lohit_ass_uid.ttf","01");// Assami        "01", 
		fontFileNameAndLanguageCodeMap.put("lohit_ben_uid.ttf","02");// Bengali       "02", 
		fontFileNameAndLanguageCodeMap.put("lohit_gu_uid.ttf","05");// Gujarathi     "05", 
		fontFileNameAndLanguageCodeMap.put("gargi.ttf","06");// Hindi                "06", 
		fontFileNameAndLanguageCodeMap.put("KedageNormal_UID.ttf","07");// Kanada    "07", 
		fontFileNameAndLanguageCodeMap.put("suruma-UID.ttf","11");// Malayalam       "11", 
		fontFileNameAndLanguageCodeMap.put("lohit_bn_uid.ttf","12");// Manipuri      "12", 
		fontFileNameAndLanguageCodeMap.put("gargi_mar.ttf","13");// Marathi              "13", 
		fontFileNameAndLanguageCodeMap.put("Samyak-Oriya-UID.ttf","15");// Oriaya    "15", 
		fontFileNameAndLanguageCodeMap.put("lohit_pa_uid.ttf","16");// Punjabi       "16", 
		fontFileNameAndLanguageCodeMap.put("lohit_ta_uid.ttf","20");// Tamil         "20", 
		fontFileNameAndLanguageCodeMap.put("lohit_te_uid.ttf","21");// Telugu        "21", 
		fontFileNameAndLanguageCodeMap.put("NafeesWebUID.ttf","22");// Urdu          "22",
		fontFileNameAndLanguageCodeMap.put("arial.ttf","23");// English          "23",
	}
	
	public static String getLanguageCodeByFontFileName(String fileName){
		return fontFileNameAndLanguageCodeMap.get(fileName);
	}

	public static String getFontNameByLanguageCode(String languageCode) {
		return languageCodeFontNameMap.get(languageCode);
	}

	public static void storeLanguageCodeAndFontName(String languageCode,
			String fontName) {
		languageCodeFontNameMap.put(languageCode, fontName);
		System.out.println(languageCodeFontNameMap);
	}
	

	public static Set<String> getAllFontFileNames() {
		
		return fontFileNameAndLanguageCodeMap.keySet();
	}
}
