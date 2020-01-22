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
package in.gov.uidai.auth.sampleapp.converter.impl;

import in.gov.uidai.auth.sampleapp.SampleClientMainFrame;
import in.gov.uidai.auth.sampleapp.converter.IConverter;

import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.StringReader;

import javax.xml.transform.Transformer;
import javax.xml.transform.TransformerFactory;
import javax.xml.transform.stream.StreamSource;

import org.apache.commons.lang.StringUtils;

public class XMLToHTMLConverter implements IConverter<String> {
	public static final String DEFAULT_XML_2_HTML_TEMPLATE_WITH_LR = "xml2html_with_lr.xsl";
	public static final String DEFAULT_XML_2_HTML_TEMPLATE_WITHOUT_LR = "xml2html_without_lr.xsl";

	@Override
	public byte[] convert(String input) throws Exception {

		TransformerFactory tFactory = TransformerFactory.newInstance();
		StreamSource streamSource;
		/*if (StringUtils.isNotBlank(System.getenv("UIDAI_EKYC_TEMPLATE_FILE"))) {
			streamSource = new StreamSource(new File(System
					.getenv("UIDAI_EKYC_XML_2_HTML_TEMPLATE")));
		} else {
			streamSource = new StreamSource(XMLToHTMLConverter.class
					.getResourceAsStream(DEFAULT_XML_2_HTML_TEMPLATE_WITH_LR));
		}*/
		/*if(SampleClientMainFrame.lrcheckval){
			if (StringUtils.isNotBlank(System.getenv("UIDAI_EKYC_TEMPLATE_FILE"))) {
				streamSource = new StreamSource(new File(System
					.getenv("UIDAI_EKYC_TEMPLATE_FILE")));
			}
			else {
				streamSource = new StreamSource(XSLFOConverter.class
					.getResourceAsStream(DEFAULT_XML_2_HTML_TEMPLATE_WITH_LR));
			}
		}
		else{
			if (StringUtils.isNotBlank(System.getenv("UIDAI_EKYC_TEMPLATE_FILE"))) {
				streamSource = new StreamSource(new File(System
					.getenv("UIDAI_EKYC_TEMPLATE_FILE")));
			}
			else {
				streamSource = new StreamSource(XSLFOConverter.class
					.getResourceAsStream(DEFAULT_XML_2_HTML_TEMPLATE_WITHOUT_LR));
			}
		}*/
		
		if (SampleClientMainFrame.lrcheckval == false ) {
			streamSource = new StreamSource(XMLToHTMLConverter.class
					.getResourceAsStream(DEFAULT_XML_2_HTML_TEMPLATE_WITHOUT_LR));
		} else {
			streamSource = new StreamSource(XMLToHTMLConverter.class
					.getResourceAsStream(DEFAULT_XML_2_HTML_TEMPLATE_WITH_LR));
		}
		Transformer transformer = tFactory.newTransformer(streamSource);
		ByteArrayOutputStream bos = new ByteArrayOutputStream();
		transformer.transform(new javax.xml.transform.stream.StreamSource(
				new StringReader(input)),
				new javax.xml.transform.stream.StreamResult(bos));
		return bos.toByteArray();
	}

}
