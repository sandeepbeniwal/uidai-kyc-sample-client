//
// This file was generated by the JavaTM Architecture for XML Binding(JAXB) Reference Implementation, v2.3.2 
// See <a href="https://javaee.github.io/jaxb-v2/">https://javaee.github.io/jaxb-v2/</a> 
// Any modifications to this file will be lost upon recompilation of the source schema. 
// Generated on: 2019.12.02 at 12:49:59 PM IST 
//


package in.gov.uidai.kyc.uid_kyc_request._2;

import javax.xml.bind.annotation.XmlEnum;
import javax.xml.bind.annotation.XmlType;


/**
 * <p>Java class for raType.
 * 
 * <p>The following schema fragment specifies the expected content contained within this class.
 * <p>
 * <pre>
 * &lt;simpleType name="raType"&gt;
 *   &lt;restriction base="{http://www.w3.org/2001/XMLSchema}string"&gt;
 *     &lt;enumeration value="F"/&gt;
 *     &lt;enumeration value="I"/&gt;
 *     &lt;enumeration value="O"/&gt;
 *     &lt;enumeration value="FI"/&gt;
 *     &lt;enumeration value="FO"/&gt;
 *     &lt;enumeration value="IO"/&gt;
 *     &lt;enumeration value="FIO"/&gt;
 *   &lt;/restriction&gt;
 * &lt;/simpleType&gt;
 * </pre>
 * 
 */
@XmlType(name = "raType")
@XmlEnum
public enum RaType {

    F,
    I,
    O,
    FI,
    FO,
    IO,
    FIO;

    public String value() {
        return name();
    }

    public static RaType fromValue(String v) {
        return valueOf(v);
    }

}