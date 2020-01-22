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
package in.gov.uidai.auth.sampleapp.converter;

public enum ConverterType {

	 PDF("pdf", "PDF"), PNG("png",
			"PNG"), XML("xml", "XML"), HTML("html", "HTML"),/*POSTSCRIPT("ps", "PS"), EPS("eps", "EPS"), JPEG("jpeg",
			"JPEG"), GIF("gif", "GIF"), SVG("svg", "SVG")*/;

	private String name;
	private String displayName;

	private ConverterType(String name, String displayName) {
		this.name = name;
		this.displayName = displayName;
	}

	public static ConverterType getConverterType(String type) {
		for (ConverterType t : values()) {
			if (t.name.equals(type)) {
				return t;
			}
		}
		return null;
	}

	public static String[] getConverterTypes() {
		String displayNames[] = new String[values().length];
		for (int i = 0; i < values().length; i++) {
			displayNames[i] = values()[i].displayName;
		}
		return displayNames;
	}

}
