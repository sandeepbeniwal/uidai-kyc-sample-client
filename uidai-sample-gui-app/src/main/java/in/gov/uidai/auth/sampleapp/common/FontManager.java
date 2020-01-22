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

import java.awt.Font;
import java.awt.FontFormatException;
import java.awt.GraphicsEnvironment;
import java.io.IOException;
import java.io.InputStream;
import java.util.Set;

public class FontManager {

	private FontManager() {
	}

	public static void registerAllFont() throws IOException {
		Set<String> fontFileNames = LanguageCodeFontStore.getAllFontFileNames();
		InputStream is;
		for (String fontFileName: fontFileNames) {
			is = FontManager.class.getResourceAsStream("/font/"+fontFileName);
			loadAndRegisterFont(fontFileName,is, Font.TRUETYPE_FONT);
		}
	}

	public static void loadAndRegisterFont(String fontFileName, InputStream fileIos,
			int fontType) {
		try {
				Font font = Font.createFont(fontType, fileIos);
				String languageCode = LanguageCodeFontStore
						.getLanguageCodeByFontFileName(fontFileName);
				System.out.println(font.getName());
				LanguageCodeFontStore.storeLanguageCodeAndFontName(
						languageCode, font.getName());
				GraphicsEnvironment.getLocalGraphicsEnvironment().registerFont(
						font);
		} catch (FontFormatException e) {
			e.printStackTrace();
		} catch (IOException e) {
			e.printStackTrace();
		}
	}
}
