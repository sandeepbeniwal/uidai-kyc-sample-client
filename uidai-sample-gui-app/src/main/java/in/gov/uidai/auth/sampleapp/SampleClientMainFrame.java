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
package in.gov.uidai.auth.sampleapp;

import java.awt.Font;
import java.awt.Image;
import java.awt.Rectangle;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.net.URISyntaxException;
import java.net.URL;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Properties;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;
import java.util.logging.Level;
import java.util.logging.Logger;

import javax.swing.DefaultComboBoxModel;
import javax.swing.GroupLayout;
import javax.swing.GroupLayout.Alignment;
import javax.swing.ImageIcon;
import javax.swing.InputVerifier;
import javax.swing.JCheckBox;
import javax.swing.JComboBox;
import javax.swing.JComponent;
import javax.swing.JFileChooser;
import javax.swing.JFormattedTextField;
import javax.swing.JLabel;
import javax.swing.JOptionPane;
import javax.swing.JPasswordField;
import javax.swing.JTextArea;
import javax.swing.LayoutStyle.ComponentPlacement;
import javax.swing.UIManager;
import javax.xml.bind.JAXBException;

import org.apache.commons.lang.StringUtils;
import org.apache.commons.lang.math.NumberUtils;
import org.jasypt.encryption.StringEncryptor;

import in.gov.uidai.auth.aua.helper.AuthRequestCreator;
import in.gov.uidai.auth.aua.helper.AuthResponseValidator;
import in.gov.uidai.auth.aua.helper.AuthResponseValidator.ValidationResult;
import in.gov.uidai.auth.aua.helper.DigitalSigner;
import in.gov.uidai.auth.aua.helper.OtpRequestCreator;
import in.gov.uidai.auth.aua.helper.SignatureVerifier;
import in.gov.uidai.auth.aua.httpclient.AuthClient;
import in.gov.uidai.auth.aua.httpclient.KYCClient;
import in.gov.uidai.auth.aua.httpclient.OtpClient;
import in.gov.uidai.auth.device.helper.AuthAUADataCreator;
import in.gov.uidai.auth.device.helper.Encrypter;
import in.gov.uidai.auth.device.helper.PidCreator;
import in.gov.uidai.auth.device.model.AuthDataFromDeviceToAUA;
import in.gov.uidai.auth.device.model.DeviceCollectedAuthData;
import in.gov.uidai.auth.device.model.DeviceCollectedBfdData;
import in.gov.uidai.auth.device.model.OtpDataFromDeviceToAUA;
import in.gov.uidai.auth.sampleapp.common.jasypt.utils.EncryptablePropertyUtils;
import in.gov.uidai.auth.sampleapp.processors.RequestProcessor;
import in.gov.uidai.authentication.common.types._2.FingerPosition;
import in.gov.uidai.authentication.common.types._2.LocationType;
import in.gov.uidai.authentication.common.types._2.Meta;
import in.gov.uidai.authentication.otp._2.Otp;
import in.gov.uidai.authentication.otp._2.OtpRes;
import in.gov.uidai.authentication.otp._2.OtpResult;
import in.gov.uidai.authentication.uid_auth_request._2.Auth;
import in.gov.uidai.authentication.uid_auth_request._2.DataType;
import in.gov.uidai.authentication.uid_auth_request._2.Tkn;
import in.gov.uidai.authentication.uid_auth_request._2.Uses;
import in.gov.uidai.authentication.uid_auth_request._2.UsesFlag;
import in.gov.uidai.authentication.uid_auth_response._2.AuthRes;
import in.gov.uidai.authentication.uid_auth_response._2.AuthResult;
import in.gov.uidai.kyc.client.DataDecryptor;
import in.gov.uidai.kyc.client.utils.XMLUtilities;
import in.gov.uidai.kyc.uid_kyc_response._2.KycRes;

@SuppressWarnings("serial")
public class SampleClientMainFrame extends javax.swing.JFrame {

    public static final int DEFAULT_CONCURENT_REQUESTS = 100;
    public static final int DEFAULT_NO_OF_REQUESTS = 10;
    private static Map<String, Font> languageToFontMap = new HashMap<String, Font>();
    public static Map<String, byte[]> skeyMap = new HashMap<String, byte[]>();
    public static boolean lrcheckval;

    static {
        languageToFontMap.put("English", Font.decode("tahoma-plain-10"));
        languageToFontMap.put("Hindi", Font.decode("mangal-plain-10"));
        languageToFontMap.put("Kannada", Font.decode("tunga-plain-10"));
        languageToFontMap.put("Malayalam", Font.decode("kartika-plain-10"));
    }

    private static Map<String, String> languageToCodeMap = new HashMap<String, String>();

    static {
        languageToCodeMap.put("English", "23");
        languageToCodeMap.put("Hindi", "06");
        languageToCodeMap.put("Kannada", "07");
        languageToCodeMap.put("Malayalam", "11");
    }

    private static Map<String, String> tokenLabelToTokenTypeMap = new HashMap<String, String>();

    static {
        tokenLabelToTokenTypeMap.put("Mobile", "001");
    }

    private List<DeviceCollectedAuthData.BiometricData> bioCaptures = new ArrayList<>();

    private AuthClient authClient;
    private OtpClient otpClient;
    private KYCClient kycClient;
    private AuthResponseValidator authResponseValidator;

    private AuthAUADataCreator auaDataCreator = null;

    private String customKYCXML = "";

    /**
     * Name of the class that provides biometric integration API implementation.
     */
    private String biometricAPIImplementationClass = "in.gov.uidai.auth.sampleapp.DigitalPersonaImpl";

    /**
     * Creates new form Test
     */
    public SampleClientMainFrame() throws URISyntaxException {
        setTitle("UIDAI KYC Demo Client");
        Image imageIcon = new javax.swing.ImageIcon(getClass().getResource(
                "/logo3.jpg")).getImage();
        setIconImage(imageIcon);
        initComponents();
        loadPreferences();

        if (StringUtils.isBlank(System.getenv("qa"))
                && StringUtils.isBlank(System.getProperty("qa"))) {
            this.jButton1.setVisible(false);
        } else {
            this.jButton1.setVisible(true);
        }

        // this.jLabelAuthRefCode.setVisible(false);
        // this.jLabelAuthRefCodeValue.setVisible(false);
        this.jLabelAuthStatusTextXML.setVisible(false);
        this.jLabelUidMandatory.setVisible(false);

        jSpinnerNameMatchValue.setEnabled(false);
        jSpinnerNameMatchValue.setValue(100);
        jSpinnerNameMatchValueLocal.setValue(90);

        jSpinnerPfaMatchValue.setEnabled(false);
        jSpinnerPfaMatchValue.setValue(100);
        jSpinnerPfaMatchValueLocal.setValue(90);
        jLabelOtpRequestStatus.setText("");

        jFormattedTextFieldAADHAAR1
                .setFocusLostBehavior(JFormattedTextField.COMMIT);

        jTextFieldPincode.setFocusLostBehavior(JFormattedTextField.COMMIT);

        initializeAuthClient();
    }

    private Map<FingerPosition, JLabel> getBFDPositionLabelMap() {
        Map<FingerPosition, javax.swing.JLabel> fingerPosToLabelMap = new HashMap<>();
        fingerPosToLabelMap.put(FingerPosition.LEFT_LITTLE,
                jLabelBFDRankLeftLittle);
        fingerPosToLabelMap
                .put(FingerPosition.LEFT_RING, jLabelBFDRankLeftRing);
        fingerPosToLabelMap.put(FingerPosition.LEFT_MIDDLE,
                jLabelBFDRankLeftMiddle);
        fingerPosToLabelMap.put(FingerPosition.LEFT_INDEX,
                jLabelBFDRankLeftIndex);
        fingerPosToLabelMap.put(FingerPosition.LEFT_THUMB,
                jLabelBFDRankLeftThumb);
        fingerPosToLabelMap.put(FingerPosition.RIGHT_THUMB,
                jLabelBFDRankRightThumb);
        fingerPosToLabelMap.put(FingerPosition.RIGHT_INDEX,
                jLabelBFDRankRightIndex);
        fingerPosToLabelMap.put(FingerPosition.RIGHT_MIDDLE,
                jLabelBFDRankRightMiddle);
        fingerPosToLabelMap.put(FingerPosition.RIGHT_RING,
                jLabelBFDRankRightRing);
        fingerPosToLabelMap.put(FingerPosition.RIGHT_LITTLE,
                jLabelBFDRankRightLittle);
        return fingerPosToLabelMap;
    }

    private void initializeAuthClient() {
        try {

            authClient = new AuthClient(new URL(
                    this.jTextFieldAuthServerURL.getText()).toURI());
            otpClient = new OtpClient(new URL(
                    this.jTextFieldOTPServerUrl.getText()).toURI());
            kycClient = new KYCClient(new URL(
                    this.jTextFieldKYCServerURL.getText()).toURI());

            DigitalSigner ds = null;
            DataDecryptor dd = null;
            if (System.getenv("USE_DONGLE") == null) {
                ds = new DigitalSigner(this.jTextFieldSignatureFile.getText(),
                        this.jPasswordSignature.getPassword(),
                        this.jTextFieldSignatureAlias.getText());
            } else {
                if (System.getenv("SAFE_SING_CFG_PATH") != null
                        && System.getenv("DONGLE_PIN") != null) {
                    ds = new DigitalSigner(System.getenv("SAFE_SING_CFG_PATH"),
                            System.getenv("DONGLE_PIN").toCharArray());
                } else {
                    System.out
                            .println("Your are using USE_DONGLE please set SAFE_SING_CFG_PATH and ");

                }
            }
            /*dd = new DataDecryptor(this.jTextFieldSignatureFile.getText(),
					this.jPasswordSignature.getPassword(),
					this.jTextFieldDSIGPublicKey.getText());*/
            dd = new DataDecryptor(this.jTextFieldDecryptSignatureFile.getText(),
                    this.jPasswordFieldDecryptSignature.getPassword(),
                    this.jTextFieldDSIGPublicKey.getText());
            authClient.setDigitalSignator(ds);
            otpClient.setDigitalSignator(ds);
            kycClient.setDigitalSignator(ds);
            kycClient.setDataDecryptor(dd);

            authClient.setAsaLicenseKey(this.jTextFieldASALicense.getText());
            otpClient.setAsaLicenseKey(this.jTextFieldASALicense.getText());
            kycClient.setAsaLicenseKey(this.jTextFieldASALicense.getText());

            authResponseValidator = new AuthResponseValidator(
                    new SignatureVerifier(
                            this.jTextFieldDSIGPublicKey.getText()));

            auaDataCreator = new AuthAUADataCreator(new Encrypter(
                    this.jTextFieldPublicKeyFile.getText()),
                    "YES".equalsIgnoreCase(this.jComboBoxUseSSK
                            .getSelectedItem().toString()));

            if ("BOTH".equalsIgnoreCase(jComboBoxPidType.getSelectedItem()
                    .toString())) {
                this.jLabelAuthStatusTextProto.setVisible(true);
                this.jLabelAuthStatusTextXML.setVisible(true);
                this.jLabelAuthStatusProto.setVisible(true);
                this.jLabelAuthStatus.setVisible(true);
            }
            if ("X".equalsIgnoreCase(jComboBoxPidType.getSelectedItem()
                    .toString())) {
                this.jLabelAuthStatusTextProto.setVisible(false);
                this.jLabelAuthStatusTextXML.setVisible(true);
                this.jLabelAuthStatusProto.setVisible(false);
                this.jLabelAuthStatus.setVisible(true);
            }
            if ("P".equalsIgnoreCase(jComboBoxPidType.getSelectedItem()
                    .toString())) {
                this.jLabelAuthStatusTextProto.setVisible(true);
                this.jLabelAuthStatusTextXML.setVisible(false);
                this.jLabelAuthStatusProto.setVisible(true);
                this.jLabelAuthStatus.setVisible(false);
            }

            this.jLabelAuthStatusTextProto.setText("");
            this.jLabelAuthStatusTextXML.setText("");
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    /**
     * This method is called from within the constructor to initialize the form.
     * WARNING: Do NOT modify this code. The content of this method is always
     * regenerated by the Form Editor.
     */
    private void initComponents() {

        jButtonGroupNameMatchStrategy = new javax.swing.ButtonGroup();
        jButtonGroupAddressMatchStrategy = new javax.swing.ButtonGroup();
        jDialogPreferences = new javax.swing.JDialog();
        jPanelPreferences = new javax.swing.JPanel();
        jLabelAUA = new javax.swing.JLabel();
        jTextFieldAua = new javax.swing.JTextField();
        jLabelTerminalID = new javax.swing.JLabel();
        jTextFieldTerminalID = new javax.swing.JTextField();
        jPanelUsesPreferences = new javax.swing.JPanel();
        jCheckBoxPi = new javax.swing.JCheckBox();
        jCheckBoxPfa = new javax.swing.JCheckBox();
        jCheckBoxPin = new javax.swing.JCheckBox();
        jCheckBoxBio = new javax.swing.JCheckBox();
        // new added for DE
        jCheckBoxPa = new javax.swing.JCheckBox();
        jCheckBoxOtp = new javax.swing.JCheckBox();
        jLabelBt = new javax.swing.JLabel();
        jCheckBoxFMR = new javax.swing.JCheckBox();
        jCheckBoxFIR = new javax.swing.JCheckBox();
        jCheckBoxIIR = new javax.swing.JCheckBox();
        jLabel9 = new javax.swing.JLabel();
        jTextFieldAuthServerURL = new javax.swing.JTextField();
        jLabel13 = new javax.swing.JLabel();
        jTextFieldPublicKeyFile = new javax.swing.JTextField();
        jButtonPickPublicKeyFile = new javax.swing.JButton();
        jLabel18 = new javax.swing.JLabel();
        jTextFieldLicenseKey = new javax.swing.JTextField();
        jLabelAUA1 = new javax.swing.JLabel();
        jTextFieldServiceAgency = new javax.swing.JTextField();
        jLabelTerminalID1 = new javax.swing.JLabel();
        jTextFieldSignatureFile = new javax.swing.JTextField();
        jButtonPickPublicKeyFile1 = new javax.swing.JButton();
        jButtonSave = new javax.swing.JButton();
        jLabel5 = new javax.swing.JLabel();
        jTextFieldSignatureAlias = new javax.swing.JTextField();
        jLabel15 = new javax.swing.JLabel();
        jLabelDe = new javax.swing.JLabel();
        jPasswordSignature = new javax.swing.JPasswordField();
        //3333
        jCheckBoxDe = new javax.swing.JCheckBox();
        jCheckBoxDe.setBackground(new java.awt.Color(255, 255, 255));
        jPanelDeviceDetails = new javax.swing.JPanel();
        jLabel22 = new javax.swing.JLabel();
        jTextFieldUDC = new javax.swing.JTextField();
        jLabel23 = new javax.swing.JLabel();
        jTextFieldFDC = new javax.swing.JTextField();
        jLabel24 = new javax.swing.JLabel();
        jTextFieldIDC = new javax.swing.JTextField();
        jLabel26 = new javax.swing.JLabel();
        jTextFieldPIP = new javax.swing.JTextField();
        jPanelLocationDetails = new javax.swing.JPanel();
        jLabel31 = new javax.swing.JLabel();
        jTextFieldLocationValue = new javax.swing.JTextField();
        jLabel25 = new javax.swing.JLabel();
        jComboBoxLocationType = new javax.swing.JComboBox();
        jLabel33 = new javax.swing.JLabel();
        jTextFieldOTPServerUrl = new javax.swing.JTextField();
        jLabel32 = new javax.swing.JLabel();
        jTextFieldDSIGPublicKey = new javax.swing.JTextField();
        jButtonDSIGPublicKey = new javax.swing.JButton();
        jButtonDecryptSignatureFile = new javax.swing.JButton();

        /**
         *
         */
        jLabel35 = new javax.swing.JLabel();
        jTextFieldASALicense = new javax.swing.JTextField();
        jPanel4 = new javax.swing.JPanel();
        jComboBoxPidType = new javax.swing.JComboBox();
        jLabel27 = new javax.swing.JLabel();
        jPanel5 = new javax.swing.JPanel();
        jLabel28 = new javax.swing.JLabel();
        jComboBoxUseSSK = new javax.swing.JComboBox();
        jLabel29 = new javax.swing.JLabel();
        jTextFieldBFDURL = new javax.swing.JTextField();
        jbuttonGroupPfaMatchStrategy = new javax.swing.ButtonGroup();
        jDialogResponseValidationResult = new javax.swing.JDialog();
        jScrollPane3 = new javax.swing.JScrollPane();
        jTextAreaResponseValidationResult = new javax.swing.JTextArea();
        jButtonResultValidationCopyToClipboard = new javax.swing.JButton();
        jButtonResultValidationDone = new javax.swing.JButton();
        buttonGroup1 = new javax.swing.ButtonGroup();
        jOTP = new javax.swing.JDialog();
        jPanel2 = new javax.swing.JPanel();
        jPanel3 = new javax.swing.JPanel();
        jCheckBoxOtpViaSMS = new javax.swing.JCheckBox();
        jCheckBoxOtpViaEmail = new javax.swing.JCheckBox();
        jButtonSendOTPRequest = new javax.swing.JButton();
        jButtonOTPDialogDone = new javax.swing.JButton();
        jLabelOtpRequestStatus = new javax.swing.JLabel();
        jLabel34 = new javax.swing.JLabel();
        jDialogBFD = new javax.swing.JDialog();
        jPanelBFD = new javax.swing.JPanel();
        jPanelBiometricsOuter3 = new javax.swing.JPanel();
        jButtonScanLeftLittle = new javax.swing.JButton();
        jLabelBiometricLeftLittle = new javax.swing.JLabel();
        jButtonScanLeftRing = new javax.swing.JButton();
        jLabelBiometricLeftRing = new javax.swing.JLabel();
        jButtonScanMiddle = new javax.swing.JButton();
        jLabelBiometricLeftMiddle = new javax.swing.JLabel();
        jButtonScanLeftIndex = new javax.swing.JButton();
        jLabelBiometricLeftIndex = new javax.swing.JLabel();
        jButtonScanLeftThumb = new javax.swing.JButton();
        jLabelBiometricLeftThumb = new javax.swing.JLabel();
        jLabel44 = new javax.swing.JLabel();
        jLabel45 = new javax.swing.JLabel();
        jLabel46 = new javax.swing.JLabel();
        jLabel47 = new javax.swing.JLabel();
        jLabel48 = new javax.swing.JLabel();
        jLabelBFDRankLeftLittle = new javax.swing.JLabel();
        jLabelBFDRankLeftRing = new javax.swing.JLabel();
        jLabelBFDRankLeftMiddle = new javax.swing.JLabel();
        jLabelBFDRankLeftIndex = new javax.swing.JLabel();
        jLabelBFDRankLeftThumb = new javax.swing.JLabel();
        jLabelBFDStatusXML = new javax.swing.JLabel();
        jLabelBFDStatusProto = new javax.swing.JLabel();
        jPanelBiometricsOuter4 = new javax.swing.JPanel();
        jButtonScanRightThumb = new javax.swing.JButton();
        jLabelBiometricRightThumb = new javax.swing.JLabel();
        jButtonScanRightIndex = new javax.swing.JButton();
        jLabelBiometricRightIndex = new javax.swing.JLabel();
        jButtonScanRightMiddle = new javax.swing.JButton();
        jLabelBiometricRightMiddle = new javax.swing.JLabel();
        jButtonScanRightRing = new javax.swing.JButton();
        jLabelBiometricRightRing = new javax.swing.JLabel();
        jButtonScanRightLittle = new javax.swing.JButton();
        jLabelBiometricRightLittle = new javax.swing.JLabel();
        jLabel49 = new javax.swing.JLabel();
        jLabel50 = new javax.swing.JLabel();
        jLabel51 = new javax.swing.JLabel();
        jLabel52 = new javax.swing.JLabel();
        jLabel53 = new javax.swing.JLabel();
        jLabelBFDRankRightThumb = new javax.swing.JLabel();
        jLabelBFDRankRightMiddle = new javax.swing.JLabel();
        jLabelBFDRankRightRing = new javax.swing.JLabel();
        jLabelBFDRankRightIndex = new javax.swing.JLabel();
        jLabelBFDRankRightLittle = new javax.swing.JLabel();
        jButtonPerformBFD = new javax.swing.JButton();
        jButtonCustomKYC = new javax.swing.JButton();
        jButtonBFDReset = new javax.swing.JButton();
        jPanel1 = new javax.swing.JPanel();
        jLabelLogo = new javax.swing.JLabel();
        jPanelKYR = new javax.swing.JPanel();
        jLabelAadhaarNumber = new javax.swing.JLabel();
        jPanelIdentificationDetails = new javax.swing.JPanel();
        jFrameIdentificationDetails = new javax.swing.JPanel();
        jLabelName = new javax.swing.JLabel();
        jTextFieldName = new javax.swing.JTextField();
        jLabelGener = new javax.swing.JLabel();
        jComboGender = new javax.swing.JComboBox();
        jLabelDob = new javax.swing.JLabel();
        jLabelPhone = new javax.swing.JLabel();
        jTextFieldEmail = new javax.swing.JTextField();
        jLabelEmail = new javax.swing.JLabel();
        jTextFieldDobYear = new javax.swing.JFormattedTextField();
        jTextFieldDobMonth = new javax.swing.JFormattedTextField();
        jTextFieldDobDay = new javax.swing.JFormattedTextField();
        jLabel3 = new javax.swing.JLabel();
        jLabel4 = new javax.swing.JLabel();
        jTextFieldPhone = new javax.swing.JFormattedTextField();
        jLabelAge = new javax.swing.JLabel();
        jTextFieldAge = new javax.swing.JTextField();
        jLabel10 = new javax.swing.JLabel();
        jSpinnerNameMatchValue = new javax.swing.JSpinner();
        jLabel6 = new javax.swing.JLabel();
        jRadioButtonNameMatchExact = new javax.swing.JRadioButton();
        jRadioButtonNameMatchPartial = new javax.swing.JRadioButton();
        jRadioFuzzyName = new javax.swing.JRadioButton();
        jLabelName1 = new javax.swing.JLabel();
        jTextFieldNameLocal = new javax.swing.JTextField();
        jLabel17 = new javax.swing.JLabel();
        jSpinnerNameMatchValueLocal = new javax.swing.JSpinner();
        jLabel21 = new javax.swing.JLabel();
        jComboBoxDOBType = new javax.swing.JComboBox();
        jPanelAddress = new javax.swing.JPanel();
        jFrameAddressDetails = new javax.swing.JPanel();
        jLabelCareof = new javax.swing.JLabel();
        jTextFieldCareOf = new javax.swing.JTextField();
        jLabelBuilding = new javax.swing.JLabel();
        jTextFieldBuilding = new javax.swing.JTextField();
        jLabelLandmark = new javax.swing.JLabel();
        jTextFieldLandmark = new javax.swing.JTextField();
        jLabelStreet = new javax.swing.JLabel();
        jTextFieldStreet = new javax.swing.JTextField();
        jLabelLocality = new javax.swing.JLabel();
        jTextFieldLocality = new javax.swing.JTextField();
        jTextFieldDistrict = new javax.swing.JTextField();
        jLabeDistrict = new javax.swing.JLabel();
        jTextFieldState = new javax.swing.JTextField();
        jLabelState = new javax.swing.JLabel();
        jLabelPincode = new javax.swing.JLabel();
        jTextFieldVtc = new javax.swing.JTextField();
        jLabelLocality1 = new javax.swing.JLabel();
        jTextFieldPincode = new javax.swing.JFormattedTextField();
        jLabel19 = new javax.swing.JLabel();
        jTextFieldPOName = new javax.swing.JTextField();
        jLabel20 = new javax.swing.JLabel();
        jTextFieldSubdist = new javax.swing.JTextField();
        jRadioButtonAddressPartialMatch = new javax.swing.JRadioButton();
        jRadioButtonAddressExactMatch = new javax.swing.JRadioButton();
        jLabel7 = new javax.swing.JLabel();
        jLabel11 = new javax.swing.JLabel();
        jLabel12 = new javax.swing.JLabel();
        jSpinnerPaMatchValue = new javax.swing.JSpinner();
        jPanelAuthParameters = new javax.swing.JPanel();
        jLabelPIN = new javax.swing.JLabel();
        jLabelPIN1 = new javax.swing.JLabel();
        jPasswordFieldPIN = new javax.swing.JPasswordField();
        jPasswordFieldOTP = new javax.swing.JPasswordField();
        jLabelProgressIndicator = new javax.swing.JLabel();
        jFormattedTextFieldAADHAAR1 = new javax.swing.JFormattedTextField();
        jPanelAuthStatus = new javax.swing.JPanel();
        jLabelAuthStatus = new javax.swing.JLabel();
        jLabelAuthStatusTextXML = new javax.swing.JLabel();
        jButtonValidateResponse = new javax.swing.JButton();
        jLabelAuthStatusProto = new javax.swing.JLabel();
        jLabelAuthStatusTextProto = new javax.swing.JLabel();
        jPanelBiometricsOuter = new javax.swing.JPanel();
        jPanelBiometric = new javax.swing.JPanel();
        jLabelBiometric = new javax.swing.JLabel();
        jButtonScan = new javax.swing.JButton();
        jComboBiometricPosition = new javax.swing.JComboBox();
        jButton1 = new javax.swing.JButton();
        jPanelPfa = new javax.swing.JPanel();
        jLabelPfa = new javax.swing.JLabel();
        jScrollPane1 = new javax.swing.JScrollPane();
        jTextAreaFullAddressValue = new javax.swing.JTextArea();
        jRadioButtonPfaExactMatch = new javax.swing.JRadioButton();
        jRadioButtonPfaPartialMatch = new javax.swing.JRadioButton();
        jLabel8 = new javax.swing.JLabel();
        jLabel1 = new javax.swing.JLabel();
        jSpinnerPfaMatchValue = new javax.swing.JSpinner();
        jRadioAddressFuzzy = new javax.swing.JRadioButton();
        jScrollPane2 = new javax.swing.JScrollPane();
        jTextAreaFullAddressValueLocal = new javax.swing.JTextArea();
        jLabelPfa1 = new javax.swing.JLabel();
        jLabel14 = new javax.swing.JLabel();
        jSpinnerPfaMatchValueLocal = new javax.swing.JSpinner();
        jLabelUidMandatory = new javax.swing.JLabel();
        jLabel16 = new javax.swing.JLabel();
        jLanguageCombo = new javax.swing.JComboBox();
        jLabelToken = new javax.swing.JLabel();
        jTextFieldToken = new javax.swing.JTextField();
        jComboBoxTokenType = new javax.swing.JComboBox();
        jLabelTokenType = new javax.swing.JLabel();
        jButtonAuthenticate = new javax.swing.JButton();
        jButtonClear = new javax.swing.JButton();
        jLabelAuthRefCodeValue = new javax.swing.JLabel();
        jLabelAuthRefCode = new javax.swing.JLabel();
        jLabel2 = new javax.swing.JLabel();
        jLabelBiometricFile = new javax.swing.JLabel();
        jButtonGenerateOTP = new javax.swing.JButton();
        jButtonInitiateBFD = new javax.swing.JButton();
        jMenuBar = new javax.swing.JMenuBar();
        jMenuFile = new javax.swing.JMenu();
        jMenuItem1 = new javax.swing.JMenuItem();
        jMenuOptions = new javax.swing.JMenu();
        jMenuItemPreferences = new javax.swing.JMenuItem();
        jMenuItemResetSSK = new javax.swing.JMenuItem();
        jLabelResConsent = new javax.swing.JLabel();
        jCheckBoxRa = new javax.swing.JCheckBox();

        jLabelKYCServerURL = new javax.swing.JLabel();
        jTextFieldKYCServerURL = new javax.swing.JTextField();
        jLabelKycRefCodeValue = new javax.swing.JLabel();
        jLabelKycRefCode = new javax.swing.JLabel();

        /**
         * new instantiations for the decryption fields in preference tab
         */
        jLabelDecryptSignatureFile = new javax.swing.JLabel();
        jLabelDecryptPrivSignatureAlias = new javax.swing.JLabel();
        jLabelDecryptSignaturePassword = new javax.swing.JLabel();

        jTextFieldDecryptSignatureFile = new javax.swing.JTextField();
        jTextFieldDecryptPrivSignatureAlias = new javax.swing.JTextField();
        jPasswordFieldDecryptSignature = new javax.swing.JPasswordField();

        jDialogPreferences.setTitle("Preferences");
        jDialogPreferences
                .setModalityType(java.awt.Dialog.ModalityType.APPLICATION_MODAL);
        jDialogPreferences.setName("preferencesDialog"); // NOI18N
        jDialogPreferences.setResizable(false);

        jPanelPreferences.setBackground(new java.awt.Color(255, 255, 255));

        jLabelAUA.setText("AUA");

        jTextFieldAua.setText("public");

        jLabelTerminalID.setText("Terminal ID");

        jTextFieldTerminalID.setText("public");

        jPanelUsesPreferences.setBackground(new java.awt.Color(255, 255, 255));
        jPanelUsesPreferences.setBorder(javax.swing.BorderFactory
                .createTitledBorder("Authentication factors ('Uses' element)"));

        jCheckBoxPi.setBackground(new java.awt.Color(255, 255, 255));
        jCheckBoxPi.setText("pi  (Personal Identity)");

        jCheckBoxPfa.setBackground(new java.awt.Color(255, 255, 255));
        jCheckBoxPfa.setText("pfa (Personal Full Address)");

        jCheckBoxPin.setBackground(new java.awt.Color(255, 255, 255));
        jCheckBoxPin.setText("pin (Resident PIN)");

        jCheckBoxBio.setBackground(new java.awt.Color(255, 255, 255));
        jCheckBoxBio.setText("bio (Biometrics)");

        //De added
        jCheckBoxPa.setBackground(new java.awt.Color(255, 255, 255));
        jCheckBoxPa.setText("pa (Personal Address)");

        jCheckBoxOtp.setBackground(new java.awt.Color(255, 255, 255));
        jCheckBoxOtp.setText("otp (One time PIN)");

        jLabelBt.setBackground(new java.awt.Color(255, 255, 255));
        jLabelBt.setText("bt (Biometric types)");

        jCheckBoxFMR.setBackground(new java.awt.Color(255, 255, 255));
        jCheckBoxFMR.setText("FMR (Finger Minutiae)");

        jCheckBoxFIR.setBackground(new java.awt.Color(255, 255, 255));
        jCheckBoxFIR.setText("Finger Image Record");

        jCheckBoxIIR.setBackground(new java.awt.Color(255, 255, 255));
        jCheckBoxIIR.setText("IIR (Iris Image Record)");

        jCheckBoxRa.setBackground(new java.awt.Color(255, 255, 255));
        jCheckBoxRa.setText("Check resident consent");

        jLabelResConsent.setBackground(new java.awt.Color(255, 255, 255));
        jLabelResConsent.setText("Resident Consent");

        javax.swing.GroupLayout jPanelUsesPreferencesLayout = new javax.swing.GroupLayout(
                jPanelUsesPreferences);
        jPanelUsesPreferences.setLayout(jPanelUsesPreferencesLayout);
        jPanelUsesPreferencesLayout
                .setHorizontalGroup(jPanelUsesPreferencesLayout
                        .createParallelGroup(
                                javax.swing.GroupLayout.Alignment.LEADING)
                        .addGroup(
                                jPanelUsesPreferencesLayout
                                        .createSequentialGroup()
                                        .addContainerGap()
                                        .addGroup(
                                                jPanelUsesPreferencesLayout
                                                        .createParallelGroup(
                                                                javax.swing.GroupLayout.Alignment.TRAILING)
                                                        .addGroup(
                                                                jPanelUsesPreferencesLayout
                                                                        .createParallelGroup(
                                                                                javax.swing.GroupLayout.Alignment.TRAILING,
                                                                                false)
                                                                        .addComponent(
                                                                                jCheckBoxOtp,
                                                                                javax.swing.GroupLayout.Alignment.LEADING,
                                                                                javax.swing.GroupLayout.DEFAULT_SIZE,
                                                                                javax.swing.GroupLayout.DEFAULT_SIZE,
                                                                                Short.MAX_VALUE)
                                                                        .addComponent(
                                                                                jCheckBoxPin,
                                                                                javax.swing.GroupLayout.Alignment.LEADING,
                                                                                javax.swing.GroupLayout.DEFAULT_SIZE,
                                                                                javax.swing.GroupLayout.DEFAULT_SIZE,
                                                                                Short.MAX_VALUE)
                                                                        .addComponent(
                                                                                jCheckBoxPi,
                                                                                javax.swing.GroupLayout.Alignment.LEADING,
                                                                                javax.swing.GroupLayout.DEFAULT_SIZE,
                                                                                javax.swing.GroupLayout.DEFAULT_SIZE,
                                                                                Short.MAX_VALUE)
                                                                        .addComponent(
                                                                                jCheckBoxPfa,
                                                                                javax.swing.GroupLayout.Alignment.LEADING,
                                                                                javax.swing.GroupLayout.DEFAULT_SIZE,
                                                                                264,
                                                                                Short.MAX_VALUE))
                                                        .addComponent(
                                                                jCheckBoxPa,
                                                                javax.swing.GroupLayout.DEFAULT_SIZE,
                                                                264,
                                                                Short.MAX_VALUE))
                                        .addGroup(
                                                jPanelUsesPreferencesLayout
                                                        .createParallelGroup(
                                                                javax.swing.GroupLayout.Alignment.LEADING)
                                                        .addGroup(
                                                                jPanelUsesPreferencesLayout
                                                                        .createSequentialGroup()
                                                                        .addPreferredGap(
                                                                                javax.swing.LayoutStyle.ComponentPlacement.RELATED)
                                                                        .addComponent(
                                                                                jLabelBt))
                                                        .addGroup(
                                                                jPanelUsesPreferencesLayout
                                                                        .createSequentialGroup()
                                                                        .addGap(26,
                                                                                26,
                                                                                26)
                                                                        .addGroup(
                                                                                jPanelUsesPreferencesLayout
                                                                                        .createParallelGroup(
                                                                                                javax.swing.GroupLayout.Alignment.LEADING)
                                                                                        .addComponent(
                                                                                                jCheckBoxFIR)
                                                                                        .addComponent(
                                                                                                jCheckBoxFMR)
                                                                                        .addComponent(
                                                                                                jCheckBoxIIR)))
                                                        .addGroup(
                                                                jPanelUsesPreferencesLayout
                                                                        .createSequentialGroup()
                                                                        .addPreferredGap(
                                                                                javax.swing.LayoutStyle.ComponentPlacement.RELATED)
                                                                        .addComponent(
                                                                                jCheckBoxBio,
                                                                                javax.swing.GroupLayout.PREFERRED_SIZE,
                                                                                125,
                                                                                javax.swing.GroupLayout.PREFERRED_SIZE)))
                                        .addContainerGap(19, Short.MAX_VALUE)));
        jPanelUsesPreferencesLayout
                .setVerticalGroup(jPanelUsesPreferencesLayout
                        .createParallelGroup(
                                javax.swing.GroupLayout.Alignment.LEADING)
                        .addGroup(
                                jPanelUsesPreferencesLayout
                                        .createSequentialGroup()
                                        .addGroup(
                                                jPanelUsesPreferencesLayout
                                                        .createParallelGroup(
                                                                javax.swing.GroupLayout.Alignment.LEADING)
                                                        .addGroup(
                                                                jPanelUsesPreferencesLayout
                                                                        .createSequentialGroup()
                                                                        .addGroup(
                                                                                jPanelUsesPreferencesLayout
                                                                                        .createParallelGroup(
                                                                                                javax.swing.GroupLayout.Alignment.BASELINE)
                                                                                        .addComponent(
                                                                                                jCheckBoxPi)
                                                                                        .addComponent(
                                                                                                jCheckBoxBio))
                                                                        .addPreferredGap(
                                                                                javax.swing.LayoutStyle.ComponentPlacement.UNRELATED)
                                                                        .addComponent(
                                                                                jCheckBoxPa)
                                                                        .addPreferredGap(
                                                                                javax.swing.LayoutStyle.ComponentPlacement.RELATED)
                                                                        .addComponent(
                                                                                jCheckBoxPfa)
                                                                        .addPreferredGap(
                                                                                javax.swing.LayoutStyle.ComponentPlacement.RELATED)
                                                                        .addComponent(
                                                                                jCheckBoxPin)
                                                                        .addPreferredGap(
                                                                                javax.swing.LayoutStyle.ComponentPlacement.UNRELATED)
                                                                        .addComponent(
                                                                                jCheckBoxOtp))
                                                        .addGroup(
                                                                jPanelUsesPreferencesLayout
                                                                        .createSequentialGroup()
                                                                        .addGap(37,
                                                                                37,
                                                                                37)
                                                                        .addComponent(
                                                                                jLabelBt)
                                                                        .addPreferredGap(
                                                                                javax.swing.LayoutStyle.ComponentPlacement.RELATED)
                                                                        .addComponent(
                                                                                jCheckBoxFMR)
                                                                        .addPreferredGap(
                                                                                javax.swing.LayoutStyle.ComponentPlacement.UNRELATED)
                                                                        .addComponent(
                                                                                jCheckBoxFIR)
                                                                        .addPreferredGap(
                                                                                javax.swing.LayoutStyle.ComponentPlacement.RELATED)
                                                                        .addComponent(
                                                                                jCheckBoxIIR)))
                                        .addContainerGap(
                                                javax.swing.GroupLayout.DEFAULT_SIZE,
                                                Short.MAX_VALUE)));

        jLabel9.setText("Auth Server URL");
        jTextFieldAuthServerURL.setText("http://developer.uidai.gov.in/auth/");

        jLabelKYCServerURL.setText("KYC Server URL");
        jTextFieldKYCServerURL.setText("http://developer.uidai.gov.in/kyc/");

        jLabel13.setText("Public Key");

        jTextFieldPublicKeyFile.setText("pub");
        jTextFieldPublicKeyFile
                .setToolTipText("UIDAI Public Key for encryption of Skey");

        jButtonPickPublicKeyFile.setText("Browse");
        jButtonPickPublicKeyFile
                .addActionListener(new java.awt.event.ActionListener() {
                    public void actionPerformed(java.awt.event.ActionEvent evt) {
                        jButtonPickPublicKeyFileActionPerformed(evt);
                    }
                });

        jLabel18.setText("AUA License Key");

        jLabelAUA1.setText("Sub AUA");

        jLabelTerminalID1.setText("Signature file");

        jTextFieldSignatureFile.setText("public");
        jTextFieldSignatureFile
                .setToolTipText("Path to AUA's .p12 file which can be used for signing the auth requests.");

        jButtonPickPublicKeyFile1.setText("Browse");
        jButtonPickPublicKeyFile1
                .addActionListener(new java.awt.event.ActionListener() {
                    public void actionPerformed(java.awt.event.ActionEvent evt) {
                        jButtonPickPublicKeyFile1ActionPerformed(evt);
                    }
                });

        jButtonSave.setText("Save");
        jButtonSave.setToolTipText("Save preferences");
        jButtonSave.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                jButtonSaveActionPerformed(evt);
            }
        });

        jLabel5.setText("Signature Key Alias");

        jLabel15.setText("Signature Password");
        //3333
        jLabelDe.setText("DE");

        jLabelDecryptSignatureFile.setText("Decrypt Signature File");

        jButtonDecryptSignatureFile.setText("Browse");
        jButtonDecryptSignatureFile
                .addActionListener(new java.awt.event.ActionListener() {
                    public void actionPerformed(java.awt.event.ActionEvent evt) {
                        jButtonDecryptSignatureFileActionPerformed(evt);
                    }
                });

        jLabelDecryptPrivSignatureAlias.setText("Decrypt Signature Alias");
        jLabelDecryptSignaturePassword.setText("Decrypt Signature Password");

        jPanelDeviceDetails.setBackground(new java.awt.Color(255, 255, 255));
        jPanelDeviceDetails.setBorder(javax.swing.BorderFactory
                .createTitledBorder("Device Details"));

        jLabel22.setText("UDC");

        jLabel23.setText("FDC");

        jLabel24.setText("IDC");

        jLabel26.setText("Public IP");

        javax.swing.GroupLayout jPanelDeviceDetailsLayout = new javax.swing.GroupLayout(
                jPanelDeviceDetails);
        jPanelDeviceDetails.setLayout(jPanelDeviceDetailsLayout);
        jPanelDeviceDetailsLayout
                .setHorizontalGroup(jPanelDeviceDetailsLayout
                        .createParallelGroup(
                                javax.swing.GroupLayout.Alignment.LEADING)
                        .addGroup(
                                jPanelDeviceDetailsLayout
                                        .createSequentialGroup()
                                        .addContainerGap(
                                                javax.swing.GroupLayout.DEFAULT_SIZE,
                                                Short.MAX_VALUE)
                                        .addComponent(jLabel22)
                                        .addPreferredGap(
                                                javax.swing.LayoutStyle.ComponentPlacement.RELATED)
                                        .addComponent(
                                                jTextFieldUDC,
                                                javax.swing.GroupLayout.PREFERRED_SIZE,
                                                157,
                                                javax.swing.GroupLayout.PREFERRED_SIZE)
                                        .addPreferredGap(
                                                javax.swing.LayoutStyle.ComponentPlacement.UNRELATED)
                                        .addComponent(jLabel23)
                                        .addPreferredGap(
                                                javax.swing.LayoutStyle.ComponentPlacement.UNRELATED)
                                        .addComponent(
                                                jTextFieldFDC,
                                                javax.swing.GroupLayout.PREFERRED_SIZE,
                                                80,
                                                javax.swing.GroupLayout.PREFERRED_SIZE)
                                        .addPreferredGap(
                                                javax.swing.LayoutStyle.ComponentPlacement.RELATED)
                                        .addComponent(jLabel24)
                                        .addPreferredGap(
                                                javax.swing.LayoutStyle.ComponentPlacement.UNRELATED)
                                        .addComponent(
                                                jTextFieldIDC,
                                                javax.swing.GroupLayout.PREFERRED_SIZE,
                                                84,
                                                javax.swing.GroupLayout.PREFERRED_SIZE)
                                        .addPreferredGap(
                                                javax.swing.LayoutStyle.ComponentPlacement.RELATED)
                                        .addComponent(jLabel26)
                                        .addPreferredGap(
                                                javax.swing.LayoutStyle.ComponentPlacement.UNRELATED)
                                        .addComponent(
                                                jTextFieldPIP,
                                                javax.swing.GroupLayout.PREFERRED_SIZE,
                                                85,
                                                javax.swing.GroupLayout.PREFERRED_SIZE)
                                        .addContainerGap()));
        jPanelDeviceDetailsLayout
                .setVerticalGroup(jPanelDeviceDetailsLayout
                        .createParallelGroup(
                                javax.swing.GroupLayout.Alignment.LEADING)
                        .addGroup(
                                jPanelDeviceDetailsLayout
                                        .createSequentialGroup()
                                        .addGroup(
                                                jPanelDeviceDetailsLayout
                                                        .createParallelGroup(
                                                                javax.swing.GroupLayout.Alignment.BASELINE)
                                                        .addComponent(
                                                                jTextFieldUDC,
                                                                javax.swing.GroupLayout.PREFERRED_SIZE,
                                                                javax.swing.GroupLayout.DEFAULT_SIZE,
                                                                javax.swing.GroupLayout.PREFERRED_SIZE)
                                                        .addComponent(jLabel22)
                                                        .addComponent(
                                                                jTextFieldPIP,
                                                                javax.swing.GroupLayout.PREFERRED_SIZE,
                                                                javax.swing.GroupLayout.DEFAULT_SIZE,
                                                                javax.swing.GroupLayout.PREFERRED_SIZE)
                                                        .addComponent(jLabel26)
                                                        .addComponent(
                                                                jTextFieldIDC,
                                                                javax.swing.GroupLayout.PREFERRED_SIZE,
                                                                20,
                                                                javax.swing.GroupLayout.PREFERRED_SIZE)
                                                        .addComponent(jLabel24)
                                                        .addComponent(
                                                                jTextFieldFDC,
                                                                javax.swing.GroupLayout.PREFERRED_SIZE,
                                                                javax.swing.GroupLayout.DEFAULT_SIZE,
                                                                javax.swing.GroupLayout.PREFERRED_SIZE)
                                                        .addComponent(jLabel23))
                                        .addContainerGap(
                                                javax.swing.GroupLayout.DEFAULT_SIZE,
                                                Short.MAX_VALUE)));

        jPanelLocationDetails.setBackground(new java.awt.Color(255, 255, 255));
        jPanelLocationDetails.setBorder(javax.swing.BorderFactory
                .createTitledBorder("Location Details"));

        jLabel31.setText("Location Value");

        jTextFieldLocationValue
                .setToolTipText("For \"G\" - Specify (Lat, Long, Alt),  For \"P\", specify pin code");

        jLabel25.setText("Location Type");

        jComboBoxLocationType.setModel(new javax.swing.DefaultComboBoxModel(
                new String[]{"G", "P"}));
        jComboBoxLocationType.setToolTipText("");

        javax.swing.GroupLayout jPanelLocationDetailsLayout = new javax.swing.GroupLayout(
                jPanelLocationDetails);
        jPanelLocationDetails.setLayout(jPanelLocationDetailsLayout);
        jPanelLocationDetailsLayout
                .setHorizontalGroup(jPanelLocationDetailsLayout
                        .createParallelGroup(
                                javax.swing.GroupLayout.Alignment.LEADING)
                        .addGroup(
                                jPanelLocationDetailsLayout
                                        .createSequentialGroup()
                                        .addContainerGap()
                                        .addComponent(jLabel25)
                                        .addGap(18, 18, 18)
                                        .addComponent(
                                                jComboBoxLocationType,
                                                javax.swing.GroupLayout.PREFERRED_SIZE,
                                                javax.swing.GroupLayout.DEFAULT_SIZE,
                                                javax.swing.GroupLayout.PREFERRED_SIZE)
                                        .addGap(18, 18, 18)
                                        .addComponent(jLabel31)
                                        .addPreferredGap(
                                                javax.swing.LayoutStyle.ComponentPlacement.RELATED)
                                        .addComponent(
                                                jTextFieldLocationValue,
                                                javax.swing.GroupLayout.PREFERRED_SIZE,
                                                138,
                                                javax.swing.GroupLayout.PREFERRED_SIZE)
                                        .addContainerGap(219, Short.MAX_VALUE)));
        jPanelLocationDetailsLayout
                .setVerticalGroup(jPanelLocationDetailsLayout
                        .createParallelGroup(
                                javax.swing.GroupLayout.Alignment.LEADING)
                        .addGroup(
                                jPanelLocationDetailsLayout
                                        .createSequentialGroup()
                                        .addGroup(
                                                jPanelLocationDetailsLayout
                                                        .createParallelGroup(
                                                                javax.swing.GroupLayout.Alignment.BASELINE)
                                                        .addComponent(jLabel25)
                                                        .addComponent(
                                                                jComboBoxLocationType,
                                                                javax.swing.GroupLayout.PREFERRED_SIZE,
                                                                javax.swing.GroupLayout.DEFAULT_SIZE,
                                                                javax.swing.GroupLayout.PREFERRED_SIZE)
                                                        .addComponent(jLabel31)
                                                        .addComponent(
                                                                jTextFieldLocationValue,
                                                                javax.swing.GroupLayout.PREFERRED_SIZE,
                                                                javax.swing.GroupLayout.DEFAULT_SIZE,
                                                                javax.swing.GroupLayout.PREFERRED_SIZE))
                                        .addContainerGap(
                                                javax.swing.GroupLayout.DEFAULT_SIZE,
                                                Short.MAX_VALUE)));

        jLabel33.setText("OTP Server URL");

        jTextFieldOTPServerUrl.setText("http://developer.uidai.gov.in/otp/");
        jTextFieldOTPServerUrl
                .addActionListener(new java.awt.event.ActionListener() {
                    public void actionPerformed(java.awt.event.ActionEvent evt) {
                        jTextFieldOTPServerUrlActionPerformed(evt);
                    }
                });

        jLabel32.setText("DSIG Public Key");

        jTextFieldDSIGPublicKey
                .setToolTipText("UIDAI Public Key for digital signature verification");

        jButtonDSIGPublicKey.setText("Browse");
        jButtonDSIGPublicKey
                .addActionListener(new java.awt.event.ActionListener() {
                    public void actionPerformed(java.awt.event.ActionEvent evt) {
                        jButtonDSIGPublicKeyActionPerformed(evt);
                    }
                });

        jLabel35.setText("ASA License Key");

        jPanel4.setBackground(new java.awt.Color(255, 255, 255));
        jPanel4.setBorder(javax.swing.BorderFactory
                .createTitledBorder("Pid Type Option"));

        jComboBoxPidType.setModel(new javax.swing.DefaultComboBoxModel(
                new String[]{"BOTH", "X", "P"}));
        jComboBoxPidType
                .setToolTipText("When \"BOTH\" is specified, two auths are performed, one using XML and one using Protobuf");

        jLabel27.setText("Pid Type to be used for Auth Requests");

        javax.swing.GroupLayout jPanel4Layout = new javax.swing.GroupLayout(
                jPanel4);
        jPanel4.setLayout(jPanel4Layout);
        jPanel4Layout.setHorizontalGroup(jPanel4Layout.createParallelGroup(
                javax.swing.GroupLayout.Alignment.LEADING).addGroup(
                        jPanel4Layout
                                .createSequentialGroup()
                                .addContainerGap(javax.swing.GroupLayout.DEFAULT_SIZE,
                                        Short.MAX_VALUE)
                                .addComponent(jLabel27)
                                .addGap(18, 18, 18)
                                .addComponent(jComboBoxPidType,
                                        javax.swing.GroupLayout.PREFERRED_SIZE,
                                        javax.swing.GroupLayout.DEFAULT_SIZE,
                                        javax.swing.GroupLayout.PREFERRED_SIZE)
                                .addGap(39, 39, 39)));
        jPanel4Layout
                .setVerticalGroup(jPanel4Layout
                        .createParallelGroup(
                                javax.swing.GroupLayout.Alignment.LEADING)
                        .addGroup(
                                jPanel4Layout
                                        .createSequentialGroup()
                                        .addGroup(
                                                jPanel4Layout
                                                        .createParallelGroup(
                                                                javax.swing.GroupLayout.Alignment.BASELINE)
                                                        .addComponent(jLabel27)
                                                        .addComponent(
                                                                jComboBoxPidType,
                                                                javax.swing.GroupLayout.PREFERRED_SIZE,
                                                                javax.swing.GroupLayout.DEFAULT_SIZE,
                                                                javax.swing.GroupLayout.PREFERRED_SIZE))
                                        .addContainerGap(
                                                javax.swing.GroupLayout.DEFAULT_SIZE,
                                                Short.MAX_VALUE)));

        jPanel5.setBackground(new java.awt.Color(255, 255, 255));
        jPanel5.setBorder(javax.swing.BorderFactory
                .createTitledBorder("Synchronized Session Key (SSK) Option"));

        jLabel28.setText("Use SSK");

        jComboBoxUseSSK.setModel(new javax.swing.DefaultComboBoxModel(
                new String[]{"Yes", "No"}));

        javax.swing.GroupLayout jPanel5Layout = new javax.swing.GroupLayout(
                jPanel5);
        jPanel5.setLayout(jPanel5Layout);
        jPanel5Layout
                .setHorizontalGroup(jPanel5Layout
                        .createParallelGroup(
                                javax.swing.GroupLayout.Alignment.LEADING)
                        .addGroup(
                                jPanel5Layout
                                        .createSequentialGroup()
                                        .addContainerGap()
                                        .addComponent(jLabel28)
                                        .addPreferredGap(
                                                javax.swing.LayoutStyle.ComponentPlacement.UNRELATED)
                                        .addComponent(
                                                jComboBoxUseSSK,
                                                javax.swing.GroupLayout.PREFERRED_SIZE,
                                                javax.swing.GroupLayout.DEFAULT_SIZE,
                                                javax.swing.GroupLayout.PREFERRED_SIZE)
                                        .addContainerGap(163, Short.MAX_VALUE)));
        jPanel5Layout
                .setVerticalGroup(jPanel5Layout
                        .createParallelGroup(
                                javax.swing.GroupLayout.Alignment.LEADING)
                        .addGroup(
                                jPanel5Layout
                                        .createSequentialGroup()
                                        .addGroup(
                                                jPanel5Layout
                                                        .createParallelGroup(
                                                                javax.swing.GroupLayout.Alignment.BASELINE)
                                                        .addComponent(jLabel28)
                                                        .addComponent(
                                                                jComboBoxUseSSK,
                                                                javax.swing.GroupLayout.PREFERRED_SIZE,
                                                                javax.swing.GroupLayout.DEFAULT_SIZE,
                                                                javax.swing.GroupLayout.PREFERRED_SIZE))
                                        .addContainerGap(
                                                javax.swing.GroupLayout.DEFAULT_SIZE,
                                                Short.MAX_VALUE)));

        jLabel29.setText("BFD URL");

        jTextFieldBFDURL.setText("http://develope.uidai.gov.in/bfd/");

        /**
         * added for decryption signature file
         */
        jTextFieldDecryptSignatureFile.setText("public");
        jTextFieldDecryptSignatureFile.setToolTipText("Path to AUA's .p12 file which can be used for Decrypting the KYC response");

        javax.swing.GroupLayout jPanelPreferencesLayout = new javax.swing.GroupLayout(
                jPanelPreferences);
        jPanelPreferences.setLayout(jPanelPreferencesLayout);
        jPanelPreferencesLayout
                .setHorizontalGroup(jPanelPreferencesLayout
                        .createParallelGroup(
                                javax.swing.GroupLayout.Alignment.LEADING)
                        .addGroup(
                                jPanelPreferencesLayout
                                        .createSequentialGroup()
                                        .addContainerGap()
                                        .addGroup(
                                                jPanelPreferencesLayout
                                                        .createParallelGroup(
                                                                javax.swing.GroupLayout.Alignment.LEADING)
                                                        .addGroup(
                                                                jPanelPreferencesLayout
                                                                        .createParallelGroup(
                                                                                javax.swing.GroupLayout.Alignment.TRAILING)
                                                                        .addComponent(
                                                                                jLabelKYCServerURL)
                                                                        // .addComponent(jLabel9)
                                                                        .addComponent(
                                                                                jLabel33))
                                                        .addGroup(
                                                                jPanelPreferencesLayout
                                                                        .createSequentialGroup()
                                                                        .addGroup(
                                                                                jPanelPreferencesLayout
                                                                                        .createParallelGroup(
                                                                                                javax.swing.GroupLayout.Alignment.TRAILING)
                                                                                        .addComponent(
                                                                                                jLabelTerminalID1)
                                                                                        .addComponent(
                                                                                                jLabel5)
                                                                                        .addComponent(
                                                                                                jLabel32)
                                                                                        .addComponent(
                                                                                                jLabel13)
                                                                                        .addComponent(
                                                                                                jLabelDecryptSignatureFile)
                                                                                        .addComponent(
                                                                                                jLabelDecryptPrivSignatureAlias))
                                                                        .addPreferredGap(
                                                                                javax.swing.LayoutStyle.ComponentPlacement.RELATED)
                                                                        .addGroup(
                                                                                jPanelPreferencesLayout
                                                                                        .createParallelGroup(
                                                                                                javax.swing.GroupLayout.Alignment.LEADING)
                                                                                        .addGroup(
                                                                                                jPanelPreferencesLayout
                                                                                                        .createSequentialGroup()
                                                                                                        .addComponent(
                                                                                                                jTextFieldSignatureAlias,
                                                                                                                javax.swing.GroupLayout.PREFERRED_SIZE,
                                                                                                                84,
                                                                                                                javax.swing.GroupLayout.PREFERRED_SIZE)
                                                                                                        .addPreferredGap(
                                                                                                                javax.swing.LayoutStyle.ComponentPlacement.UNRELATED)
                                                                                                        .addComponent(
                                                                                                                jLabel15)
                                                                                                        .addGap(18,
                                                                                                                18,
                                                                                                                18)
                                                                                                        .addComponent(
                                                                                                                jPasswordSignature,
                                                                                                                javax.swing.GroupLayout.PREFERRED_SIZE,
                                                                                                                105,
                                                                                                                javax.swing.GroupLayout.PREFERRED_SIZE)
                                                                                                        .addGap(18,
                                                                                                                18,
                                                                                                                18)
                                                                                                        .addComponent(
                                                                                                                jLabelDe)
                                                                                                        .addGap(5,
                                                                                                                5,
                                                                                                                5)
                                                                                                        .addComponent(
                                                                                                                jCheckBoxDe,
                                                                                                                javax.swing.GroupLayout.PREFERRED_SIZE,
                                                                                                                20,
                                                                                                                javax.swing.GroupLayout.PREFERRED_SIZE))
                                                                                        .addGroup(
                                                                                                jPanelPreferencesLayout
                                                                                                        .createSequentialGroup()
                                                                                                        .addComponent(
                                                                                                                jTextFieldDecryptSignatureFile,
                                                                                                                javax.swing.GroupLayout.PREFERRED_SIZE,
                                                                                                                351,
                                                                                                                javax.swing.GroupLayout.PREFERRED_SIZE)
                                                                                                        .addGap(18,
                                                                                                                18,
                                                                                                                18)
                                                                                                        .addComponent(
                                                                                                                jButtonDecryptSignatureFile,
                                                                                                                javax.swing.GroupLayout.PREFERRED_SIZE,
                                                                                                                javax.swing.GroupLayout.DEFAULT_SIZE,
                                                                                                                javax.swing.GroupLayout.PREFERRED_SIZE))
                                                                                        .addGroup(
                                                                                                jPanelPreferencesLayout
                                                                                                        .createSequentialGroup()
                                                                                                        .addComponent(
                                                                                                                jTextFieldDecryptPrivSignatureAlias,
                                                                                                                javax.swing.GroupLayout.PREFERRED_SIZE,
                                                                                                                105,
                                                                                                                javax.swing.GroupLayout.PREFERRED_SIZE)
                                                                                                        .addPreferredGap(
                                                                                                                javax.swing.LayoutStyle.ComponentPlacement.UNRELATED)
                                                                                                        .addComponent(
                                                                                                                jLabelDecryptSignaturePassword)
                                                                                                        .addGap(18,
                                                                                                                18,
                                                                                                                18)
                                                                                                        .addComponent(
                                                                                                                jPasswordFieldDecryptSignature,
                                                                                                                javax.swing.GroupLayout.PREFERRED_SIZE,
                                                                                                                105,
                                                                                                                javax.swing.GroupLayout.PREFERRED_SIZE))
                                                                                        .addGroup(
                                                                                                jPanelPreferencesLayout
                                                                                                        .createSequentialGroup()
                                                                                                        .addGroup(
                                                                                                                jPanelPreferencesLayout
                                                                                                                        .createParallelGroup(
                                                                                                                                javax.swing.GroupLayout.Alignment.LEADING)
                                                                                                                        .addComponent(
                                                                                                                                jTextFieldDSIGPublicKey,
                                                                                                                                javax.swing.GroupLayout.DEFAULT_SIZE,
                                                                                                                                351,
                                                                                                                                Short.MAX_VALUE)
                                                                                                                        .addComponent(
                                                                                                                                jTextFieldSignatureFile,
                                                                                                                                javax.swing.GroupLayout.DEFAULT_SIZE,
                                                                                                                                351,
                                                                                                                                Short.MAX_VALUE)
                                                                                                                        .addComponent(
                                                                                                                                jTextFieldPublicKeyFile,
                                                                                                                                javax.swing.GroupLayout.DEFAULT_SIZE,
                                                                                                                                351,
                                                                                                                                Short.MAX_VALUE))
                                                                                                        .addPreferredGap(
                                                                                                                javax.swing.LayoutStyle.ComponentPlacement.RELATED)
                                                                                                        .addGroup(
                                                                                                                jPanelPreferencesLayout
                                                                                                                        .createParallelGroup(
                                                                                                                                javax.swing.GroupLayout.Alignment.LEADING)
                                                                                                                        .addComponent(
                                                                                                                                jButtonPickPublicKeyFile)
                                                                                                                        .addComponent(
                                                                                                                                jButtonDSIGPublicKey)
                                                                                                                        .addComponent(
                                                                                                                                jButtonPickPublicKeyFile1))))
                                                                        .addGap(163,
                                                                                163,
                                                                                163))
                                                        .addGroup(
                                                                javax.swing.GroupLayout.Alignment.TRAILING,
                                                                jPanelPreferencesLayout
                                                                        .createSequentialGroup()
                                                                        .addGroup(
                                                                                jPanelPreferencesLayout
                                                                                        .createParallelGroup(
                                                                                                javax.swing.GroupLayout.Alignment.TRAILING)
                                                                                        .addComponent(
                                                                                                jLabelAUA)
                                                                                        .addComponent(
                                                                                                jLabel18)
                                                                                        .addComponent(
                                                                                                jLabel35))
                                                                        .addGap(16,
                                                                                16,
                                                                                16)
                                                                        .addGroup(
                                                                                jPanelPreferencesLayout
                                                                                        .createParallelGroup(
                                                                                                javax.swing.GroupLayout.Alignment.TRAILING)
                                                                                        .addComponent(
                                                                                                jTextFieldKYCServerURL,
                                                                                                javax.swing.GroupLayout.Alignment.LEADING,
                                                                                                javax.swing.GroupLayout.PREFERRED_SIZE,
                                                                                                343,
                                                                                                javax.swing.GroupLayout.PREFERRED_SIZE)
                                                                                        // .addComponent(jTextFieldAuthServerURL,
                                                                                        // javax.swing.GroupLayout.Alignment.LEADING,
                                                                                        // javax.swing.GroupLayout.PREFERRED_SIZE,
                                                                                        // 343,
                                                                                        // javax.swing.GroupLayout.PREFERRED_SIZE)
                                                                                        .addGroup(
                                                                                                javax.swing.GroupLayout.Alignment.LEADING,
                                                                                                jPanelPreferencesLayout
                                                                                                        .createSequentialGroup()
                                                                                                        .addGroup(
                                                                                                                jPanelPreferencesLayout
                                                                                                                        .createParallelGroup(
                                                                                                                                javax.swing.GroupLayout.Alignment.TRAILING)
                                                                                                                        .addGroup(
                                                                                                                                javax.swing.GroupLayout.Alignment.LEADING,
                                                                                                                                jPanelPreferencesLayout
                                                                                                                                        .createSequentialGroup()
                                                                                                                                        .addGroup(
                                                                                                                                                jPanelPreferencesLayout
                                                                                                                                                        .createParallelGroup(
                                                                                                                                                                javax.swing.GroupLayout.Alignment.TRAILING,
                                                                                                                                                                false)
                                                                                                                                                        .addComponent(
                                                                                                                                                                jTextFieldOTPServerUrl,
                                                                                                                                                                javax.swing.GroupLayout.Alignment.LEADING)
                                                                                                                                                        .addGroup(
                                                                                                                                                                javax.swing.GroupLayout.Alignment.LEADING,
                                                                                                                                                                jPanelPreferencesLayout
                                                                                                                                                                        .createSequentialGroup()
                                                                                                                                                                        .addComponent(
                                                                                                                                                                                jTextFieldAua,
                                                                                                                                                                                javax.swing.GroupLayout.PREFERRED_SIZE,
                                                                                                                                                                                62,
                                                                                                                                                                                javax.swing.GroupLayout.PREFERRED_SIZE)
                                                                                                                                                                        .addGap(18,
                                                                                                                                                                                18,
                                                                                                                                                                                18)
                                                                                                                                                                        .addComponent(
                                                                                                                                                                                jLabelAUA1)
                                                                                                                                                                        .addPreferredGap(
                                                                                                                                                                                javax.swing.LayoutStyle.ComponentPlacement.UNRELATED)
                                                                                                                                                                        .addComponent(
                                                                                                                                                                                jTextFieldServiceAgency,
                                                                                                                                                                                javax.swing.GroupLayout.PREFERRED_SIZE,
                                                                                                                                                                                59,
                                                                                                                                                                                javax.swing.GroupLayout.PREFERRED_SIZE)))
                                                                                                                                        .addPreferredGap(
                                                                                                                                                javax.swing.LayoutStyle.ComponentPlacement.RELATED)
                                                                                                                                        .addGroup(
                                                                                                                                                jPanelPreferencesLayout
                                                                                                                                                        .createParallelGroup(
                                                                                                                                                                javax.swing.GroupLayout.Alignment.LEADING)
                                                                                                                                                        .addGroup(
                                                                                                                                                                jPanelPreferencesLayout
                                                                                                                                                                        .createSequentialGroup()
                                                                                                                                                                        .addComponent(
                                                                                                                                                                                jLabelTerminalID)
                                                                                                                                                                        .addPreferredGap(
                                                                                                                                                                                javax.swing.LayoutStyle.ComponentPlacement.RELATED)
                                                                                                                                                                        .addComponent(
                                                                                                                                                                                jTextFieldTerminalID,
                                                                                                                                                                                javax.swing.GroupLayout.PREFERRED_SIZE,
                                                                                                                                                                                76,
                                                                                                                                                                                javax.swing.GroupLayout.PREFERRED_SIZE))
                                                                                                                                                        .addGroup(
                                                                                                                                                                jPanelPreferencesLayout
                                                                                                                                                                        .createSequentialGroup()
                                                                                                                                                                        .addComponent(
                                                                                                                                                                                jLabel29)
                                                                                                                                                                        .addPreferredGap(
                                                                                                                                                                                javax.swing.LayoutStyle.ComponentPlacement.RELATED)
                                                                                                                                                                        .addComponent(
                                                                                                                                                                                jTextFieldBFDURL,
                                                                                                                                                                                javax.swing.GroupLayout.DEFAULT_SIZE,
                                                                                                                                                                                251,
                                                                                                                                                                                Short.MAX_VALUE))))
                                                                                                                        .addGroup(
                                                                                                                                javax.swing.GroupLayout.Alignment.LEADING,
                                                                                                                                jPanelPreferencesLayout
                                                                                                                                        .createParallelGroup(
                                                                                                                                                javax.swing.GroupLayout.Alignment.TRAILING,
                                                                                                                                                false)
                                                                                                                                        .addComponent(
                                                                                                                                                jTextFieldLicenseKey,
                                                                                                                                                javax.swing.GroupLayout.Alignment.LEADING)
                                                                                                                                        .addComponent(
                                                                                                                                                jTextFieldASALicense,
                                                                                                                                                javax.swing.GroupLayout.Alignment.LEADING,
                                                                                                                                                javax.swing.GroupLayout.DEFAULT_SIZE,
                                                                                                                                                416,
                                                                                                                                                Short.MAX_VALUE)))
                                                                                                        .addGap(96,
                                                                                                                96,
                                                                                                                96)))
                                                                        .addContainerGap())
                                                        .addGroup(
                                                                javax.swing.GroupLayout.Alignment.TRAILING,
                                                                jPanelPreferencesLayout
                                                                        .createSequentialGroup()
                                                                        .addGroup(
                                                                                jPanelPreferencesLayout
                                                                                        .createParallelGroup(
                                                                                                javax.swing.GroupLayout.Alignment.TRAILING)
                                                                                        .addComponent(
                                                                                                jPanelUsesPreferences,
                                                                                                javax.swing.GroupLayout.Alignment.LEADING,
                                                                                                javax.swing.GroupLayout.PREFERRED_SIZE,
                                                                                                javax.swing.GroupLayout.DEFAULT_SIZE,
                                                                                                javax.swing.GroupLayout.PREFERRED_SIZE)
                                                                                        .addComponent(
                                                                                                jPanelDeviceDetails,
                                                                                                javax.swing.GroupLayout.Alignment.LEADING,
                                                                                                javax.swing.GroupLayout.PREFERRED_SIZE,
                                                                                                587,
                                                                                                javax.swing.GroupLayout.PREFERRED_SIZE)
                                                                                        .addComponent(
                                                                                                jPanelLocationDetails,
                                                                                                javax.swing.GroupLayout.Alignment.LEADING,
                                                                                                javax.swing.GroupLayout.DEFAULT_SIZE,
                                                                                                javax.swing.GroupLayout.DEFAULT_SIZE,
                                                                                                Short.MAX_VALUE))
                                                                        .addGap(96,
                                                                                96,
                                                                                96))
                                                        .addGroup(
                                                                jPanelPreferencesLayout
                                                                        .createSequentialGroup()
                                                                        .addGroup(
                                                                                jPanelPreferencesLayout
                                                                                        .createParallelGroup(
                                                                                                javax.swing.GroupLayout.Alignment.TRAILING)
                                                                                        .addComponent(
                                                                                                jButtonSave)
                                                                                        .addGroup(
                                                                                                jPanelPreferencesLayout
                                                                                                        .createSequentialGroup()
                                                                                                        .addComponent(
                                                                                                                jPanel5,
                                                                                                                javax.swing.GroupLayout.PREFERRED_SIZE,
                                                                                                                javax.swing.GroupLayout.DEFAULT_SIZE,
                                                                                                                javax.swing.GroupLayout.PREFERRED_SIZE)
                                                                                                        .addPreferredGap(
                                                                                                                javax.swing.LayoutStyle.ComponentPlacement.UNRELATED)
                                                                                                        .addComponent(
                                                                                                                jPanel4,
                                                                                                                javax.swing.GroupLayout.PREFERRED_SIZE,
                                                                                                                294,
                                                                                                                javax.swing.GroupLayout.PREFERRED_SIZE)))
                                                                        .addContainerGap()))));
        jPanelPreferencesLayout
                .setVerticalGroup(jPanelPreferencesLayout
                        .createParallelGroup(
                                javax.swing.GroupLayout.Alignment.LEADING)
                        .addGroup(
                                jPanelPreferencesLayout
                                        .createSequentialGroup()
                                        .addContainerGap()
                                        .addGroup(
                                                jPanelPreferencesLayout
                                                        .createParallelGroup(
                                                                javax.swing.GroupLayout.Alignment.BASELINE)
                                                        .addComponent(
                                                                jLabelKYCServerURL)
                                                        .addComponent(
                                                                jTextFieldKYCServerURL,
                                                                javax.swing.GroupLayout.PREFERRED_SIZE,
                                                                javax.swing.GroupLayout.DEFAULT_SIZE,
                                                                javax.swing.GroupLayout.PREFERRED_SIZE))
                                        .addPreferredGap(
                                                javax.swing.LayoutStyle.ComponentPlacement.UNRELATED)
                                        // .addGroup(jPanelPreferencesLayout.createParallelGroup(javax.swing.GroupLayout.Alignment.BASELINE)
                                        // .addComponent(jLabel9)
                                        // .addComponent(jTextFieldAuthServerURL,
                                        // javax.swing.GroupLayout.PREFERRED_SIZE,
                                        // javax.swing.GroupLayout.DEFAULT_SIZE,
                                        // javax.swing.GroupLayout.PREFERRED_SIZE))
                                        // .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.UNRELATED)
                                        .addGroup(
                                                jPanelPreferencesLayout
                                                        .createParallelGroup(
                                                                javax.swing.GroupLayout.Alignment.BASELINE)
                                                        .addComponent(jLabel33)
                                                        .addComponent(
                                                                jTextFieldOTPServerUrl,
                                                                javax.swing.GroupLayout.PREFERRED_SIZE,
                                                                javax.swing.GroupLayout.DEFAULT_SIZE,
                                                                javax.swing.GroupLayout.PREFERRED_SIZE)
                                                        .addComponent(jLabel29)
                                                        .addComponent(
                                                                jTextFieldBFDURL,
                                                                javax.swing.GroupLayout.PREFERRED_SIZE,
                                                                javax.swing.GroupLayout.DEFAULT_SIZE,
                                                                javax.swing.GroupLayout.PREFERRED_SIZE))
                                        .addPreferredGap(
                                                javax.swing.LayoutStyle.ComponentPlacement.RELATED)
                                        .addGroup(
                                                jPanelPreferencesLayout
                                                        .createParallelGroup(
                                                                javax.swing.GroupLayout.Alignment.BASELINE)
                                                        .addComponent(
                                                                jTextFieldAua,
                                                                javax.swing.GroupLayout.PREFERRED_SIZE,
                                                                javax.swing.GroupLayout.DEFAULT_SIZE,
                                                                javax.swing.GroupLayout.PREFERRED_SIZE)
                                                        .addComponent(jLabelAUA)
                                                        .addComponent(
                                                                jLabelAUA1)
                                                        .addComponent(
                                                                jTextFieldServiceAgency,
                                                                javax.swing.GroupLayout.PREFERRED_SIZE,
                                                                javax.swing.GroupLayout.DEFAULT_SIZE,
                                                                javax.swing.GroupLayout.PREFERRED_SIZE)
                                                        .addComponent(
                                                                jLabelTerminalID)
                                                        .addComponent(
                                                                jTextFieldTerminalID,
                                                                javax.swing.GroupLayout.PREFERRED_SIZE,
                                                                javax.swing.GroupLayout.DEFAULT_SIZE,
                                                                javax.swing.GroupLayout.PREFERRED_SIZE))
                                        .addGap(7, 7, 7)
                                        .addGroup(
                                                jPanelPreferencesLayout
                                                        .createParallelGroup(
                                                                javax.swing.GroupLayout.Alignment.BASELINE)
                                                        .addComponent(
                                                                jTextFieldLicenseKey,
                                                                javax.swing.GroupLayout.PREFERRED_SIZE,
                                                                javax.swing.GroupLayout.DEFAULT_SIZE,
                                                                javax.swing.GroupLayout.PREFERRED_SIZE)
                                                        .addComponent(jLabel18))
                                        .addGap(8, 8, 8)
                                        .addGroup(
                                                jPanelPreferencesLayout
                                                        .createParallelGroup(
                                                                javax.swing.GroupLayout.Alignment.TRAILING)
                                                        .addComponent(jLabel35)
                                                        .addComponent(
                                                                jTextFieldASALicense,
                                                                javax.swing.GroupLayout.PREFERRED_SIZE,
                                                                javax.swing.GroupLayout.DEFAULT_SIZE,
                                                                javax.swing.GroupLayout.PREFERRED_SIZE))
                                        .addPreferredGap(
                                                javax.swing.LayoutStyle.ComponentPlacement.UNRELATED)
                                        .addGroup(
                                                jPanelPreferencesLayout
                                                        .createParallelGroup(
                                                                javax.swing.GroupLayout.Alignment.BASELINE)
                                                        .addComponent(jLabel13)
                                                        .addComponent(
                                                                jButtonPickPublicKeyFile)
                                                        .addComponent(
                                                                jTextFieldPublicKeyFile,
                                                                javax.swing.GroupLayout.PREFERRED_SIZE,
                                                                javax.swing.GroupLayout.DEFAULT_SIZE,
                                                                javax.swing.GroupLayout.PREFERRED_SIZE))
                                        .addPreferredGap(
                                                javax.swing.LayoutStyle.ComponentPlacement.RELATED)
                                        .addGroup(
                                                jPanelPreferencesLayout
                                                        .createParallelGroup(
                                                                javax.swing.GroupLayout.Alignment.BASELINE)
                                                        .addComponent(jLabel32)
                                                        .addComponent(
                                                                jTextFieldDSIGPublicKey,
                                                                javax.swing.GroupLayout.PREFERRED_SIZE,
                                                                javax.swing.GroupLayout.DEFAULT_SIZE,
                                                                javax.swing.GroupLayout.PREFERRED_SIZE)
                                                        .addComponent(
                                                                jButtonDSIGPublicKey))
                                        .addPreferredGap(
                                                javax.swing.LayoutStyle.ComponentPlacement.UNRELATED)
                                        .addGroup(
                                                jPanelPreferencesLayout
                                                        .createParallelGroup(
                                                                javax.swing.GroupLayout.Alignment.TRAILING)
                                                        .addComponent(
                                                                jLabelTerminalID1)
                                                        .addGroup(
                                                                jPanelPreferencesLayout
                                                                        .createParallelGroup(
                                                                                javax.swing.GroupLayout.Alignment.BASELINE)
                                                                        .addComponent(
                                                                                jTextFieldSignatureFile,
                                                                                javax.swing.GroupLayout.PREFERRED_SIZE,
                                                                                javax.swing.GroupLayout.DEFAULT_SIZE,
                                                                                javax.swing.GroupLayout.PREFERRED_SIZE)
                                                                        .addComponent(
                                                                                jButtonPickPublicKeyFile1)))
                                        .addPreferredGap(
                                                javax.swing.LayoutStyle.ComponentPlacement.UNRELATED)
                                        .addGroup(
                                                jPanelPreferencesLayout
                                                        .createParallelGroup(
                                                                javax.swing.GroupLayout.Alignment.BASELINE)
                                                        .addComponent(jLabel5)
                                                        .addComponent(
                                                                jTextFieldSignatureAlias,
                                                                javax.swing.GroupLayout.PREFERRED_SIZE,
                                                                javax.swing.GroupLayout.DEFAULT_SIZE,
                                                                javax.swing.GroupLayout.PREFERRED_SIZE)
                                                        .addComponent(jLabel15)
                                                        .addComponent(
                                                                jPasswordSignature,
                                                                javax.swing.GroupLayout.PREFERRED_SIZE,
                                                                javax.swing.GroupLayout.DEFAULT_SIZE,
                                                                javax.swing.GroupLayout.PREFERRED_SIZE)
                                                        .addComponent(jLabelDe)
                                                        .addComponent(
                                                                jCheckBoxDe,
                                                                javax.swing.GroupLayout.PREFERRED_SIZE,
                                                                javax.swing.GroupLayout.DEFAULT_SIZE,
                                                                javax.swing.GroupLayout.PREFERRED_SIZE))
                                        .addPreferredGap(
                                                javax.swing.LayoutStyle.ComponentPlacement.UNRELATED)
                                        .addGroup(
                                                jPanelPreferencesLayout
                                                        .createParallelGroup(
                                                                javax.swing.GroupLayout.Alignment.BASELINE)
                                                        .addComponent(jLabelDecryptSignatureFile)
                                                        .addComponent(
                                                                jTextFieldDecryptSignatureFile,
                                                                javax.swing.GroupLayout.PREFERRED_SIZE,
                                                                javax.swing.GroupLayout.DEFAULT_SIZE,
                                                                javax.swing.GroupLayout.PREFERRED_SIZE)
                                                        .addComponent(
                                                                jButtonDecryptSignatureFile,
                                                                javax.swing.GroupLayout.PREFERRED_SIZE,
                                                                javax.swing.GroupLayout.DEFAULT_SIZE,
                                                                javax.swing.GroupLayout.PREFERRED_SIZE))
                                        .addGroup(
                                                jPanelPreferencesLayout
                                                        .createParallelGroup(
                                                                javax.swing.GroupLayout.Alignment.BASELINE)
                                                        .addComponent(jLabelDecryptPrivSignatureAlias)
                                                        .addComponent(
                                                                jTextFieldDecryptPrivSignatureAlias,
                                                                javax.swing.GroupLayout.PREFERRED_SIZE,
                                                                javax.swing.GroupLayout.DEFAULT_SIZE,
                                                                javax.swing.GroupLayout.PREFERRED_SIZE)
                                                        .addComponent(jLabelDecryptSignaturePassword)
                                                        .addComponent(
                                                                jPasswordFieldDecryptSignature,
                                                                javax.swing.GroupLayout.PREFERRED_SIZE,
                                                                javax.swing.GroupLayout.DEFAULT_SIZE,
                                                                javax.swing.GroupLayout.PREFERRED_SIZE))
                                        .addPreferredGap(
                                                javax.swing.LayoutStyle.ComponentPlacement.UNRELATED)
                                        .addComponent(
                                                jPanelUsesPreferences,
                                                javax.swing.GroupLayout.PREFERRED_SIZE,
                                                javax.swing.GroupLayout.DEFAULT_SIZE,
                                                javax.swing.GroupLayout.PREFERRED_SIZE)
                                        .addPreferredGap(
                                                javax.swing.LayoutStyle.ComponentPlacement.RELATED)
                                        .addComponent(
                                                jPanelDeviceDetails,
                                                javax.swing.GroupLayout.PREFERRED_SIZE,
                                                javax.swing.GroupLayout.DEFAULT_SIZE,
                                                javax.swing.GroupLayout.PREFERRED_SIZE)
                                        .addPreferredGap(
                                                javax.swing.LayoutStyle.ComponentPlacement.RELATED)
                                        .addComponent(
                                                jPanelLocationDetails,
                                                javax.swing.GroupLayout.PREFERRED_SIZE,
                                                javax.swing.GroupLayout.DEFAULT_SIZE,
                                                javax.swing.GroupLayout.PREFERRED_SIZE)
                                        .addPreferredGap(
                                                javax.swing.LayoutStyle.ComponentPlacement.RELATED)
                                        .addGroup(
                                                jPanelPreferencesLayout
                                                        .createParallelGroup(
                                                                javax.swing.GroupLayout.Alignment.LEADING,
                                                                false)
                                                        .addComponent(
                                                                jPanel5,
                                                                javax.swing.GroupLayout.DEFAULT_SIZE,
                                                                javax.swing.GroupLayout.DEFAULT_SIZE,
                                                                Short.MAX_VALUE)
                                                        .addComponent(
                                                                jPanel4,
                                                                javax.swing.GroupLayout.DEFAULT_SIZE,
                                                                javax.swing.GroupLayout.DEFAULT_SIZE,
                                                                Short.MAX_VALUE))
                                        .addPreferredGap(
                                                javax.swing.LayoutStyle.ComponentPlacement.RELATED)
                                        .addComponent(jButtonSave)
                                        .addContainerGap()));

        javax.swing.GroupLayout jDialogPreferencesLayout = new javax.swing.GroupLayout(
                jDialogPreferences.getContentPane());
        jDialogPreferences.getContentPane().setLayout(jDialogPreferencesLayout);
        jDialogPreferencesLayout.setHorizontalGroup(jDialogPreferencesLayout
                .createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
                .addComponent(jPanelPreferences,
                        javax.swing.GroupLayout.PREFERRED_SIZE, 655,
                        javax.swing.GroupLayout.PREFERRED_SIZE));
        jDialogPreferencesLayout.setVerticalGroup(jDialogPreferencesLayout
                .createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
                .addComponent(jPanelPreferences,
                        javax.swing.GroupLayout.PREFERRED_SIZE,
                        javax.swing.GroupLayout.DEFAULT_SIZE,
                        javax.swing.GroupLayout.PREFERRED_SIZE));

        jTextAreaResponseValidationResult.setColumns(20);
        jTextAreaResponseValidationResult.setRows(5);
        jTextAreaResponseValidationResult
                .setText("Results of Response Validation:\n===============================\n\nAadhaar Hash Validation   : PASS\nDemo XML Hash Validation  : PASS\nUIDAI Encoded Value:\n");
        jScrollPane3.setViewportView(jTextAreaResponseValidationResult);

        jButtonResultValidationCopyToClipboard.setText("Copy to clipoard");
        jButtonResultValidationCopyToClipboard
                .addActionListener(new java.awt.event.ActionListener() {
                    public void actionPerformed(java.awt.event.ActionEvent evt) {
                        jButtonResultValidationCopyToClipboardActionPerformed(evt);
                    }
                });

        jButtonResultValidationDone.setText("Done");
        jButtonResultValidationDone
                .addActionListener(new java.awt.event.ActionListener() {
                    public void actionPerformed(java.awt.event.ActionEvent evt) {
                        jButtonResultValidationDoneActionPerformed(evt);
                    }
                });

        javax.swing.GroupLayout jDialogResponseValidationResultLayout = new javax.swing.GroupLayout(
                jDialogResponseValidationResult.getContentPane());
        jDialogResponseValidationResult.getContentPane().setLayout(
                jDialogResponseValidationResultLayout);
        jDialogResponseValidationResultLayout
                .setHorizontalGroup(jDialogResponseValidationResultLayout
                        .createParallelGroup(
                                javax.swing.GroupLayout.Alignment.LEADING)
                        .addGroup(
                                jDialogResponseValidationResultLayout
                                        .createSequentialGroup()
                                        .addContainerGap()
                                        .addGroup(
                                                jDialogResponseValidationResultLayout
                                                        .createParallelGroup(
                                                                javax.swing.GroupLayout.Alignment.LEADING)
                                                        .addComponent(
                                                                jScrollPane3,
                                                                javax.swing.GroupLayout.DEFAULT_SIZE,
                                                                560,
                                                                Short.MAX_VALUE)
                                                        .addGroup(
                                                                javax.swing.GroupLayout.Alignment.TRAILING,
                                                                jDialogResponseValidationResultLayout
                                                                        .createSequentialGroup()
                                                                        .addComponent(
                                                                                jButtonResultValidationCopyToClipboard)
                                                                        .addGap(28,
                                                                                28,
                                                                                28)
                                                                        .addComponent(
                                                                                jButtonResultValidationDone)))
                                        .addContainerGap()));
        jDialogResponseValidationResultLayout
                .setVerticalGroup(jDialogResponseValidationResultLayout
                        .createParallelGroup(
                                javax.swing.GroupLayout.Alignment.LEADING)
                        .addGroup(
                                jDialogResponseValidationResultLayout
                                        .createSequentialGroup()
                                        .addGap(19, 19, 19)
                                        .addComponent(
                                                jScrollPane3,
                                                javax.swing.GroupLayout.PREFERRED_SIZE,
                                                346,
                                                javax.swing.GroupLayout.PREFERRED_SIZE)
                                        .addPreferredGap(
                                                javax.swing.LayoutStyle.ComponentPlacement.RELATED)
                                        .addGroup(
                                                jDialogResponseValidationResultLayout
                                                        .createParallelGroup(
                                                                javax.swing.GroupLayout.Alignment.BASELINE)
                                                        .addComponent(
                                                                jButtonResultValidationDone)
                                                        .addComponent(
                                                                jButtonResultValidationCopyToClipboard))
                                        .addContainerGap(11, Short.MAX_VALUE)));

        jOTP.setTitle("OTP Channels");

        jPanel2.setBackground(new java.awt.Color(255, 255, 255));

        jPanel3.setBackground(new java.awt.Color(255, 255, 255));
        jPanel3.setBorder(javax.swing.BorderFactory
                .createTitledBorder("Select channels for OTP delivery"));

        jCheckBoxOtpViaSMS.setBackground(new java.awt.Color(255, 255, 255));
        jCheckBoxOtpViaSMS.setText("via SMS");

        jCheckBoxOtpViaEmail.setBackground(new java.awt.Color(255, 255, 255));
        jCheckBoxOtpViaEmail.setText("via Email");

        javax.swing.GroupLayout jPanel3Layout = new javax.swing.GroupLayout(
                jPanel3);
        jPanel3.setLayout(jPanel3Layout);
        jPanel3Layout
                .setHorizontalGroup(jPanel3Layout
                        .createParallelGroup(
                                javax.swing.GroupLayout.Alignment.LEADING)
                        .addGroup(
                                jPanel3Layout
                                        .createSequentialGroup()
                                        .addContainerGap()
                                        .addGroup(
                                                jPanel3Layout
                                                        .createParallelGroup(
                                                                javax.swing.GroupLayout.Alignment.TRAILING,
                                                                false)
                                                        .addComponent(
                                                                jCheckBoxOtpViaEmail,
                                                                javax.swing.GroupLayout.Alignment.LEADING,
                                                                javax.swing.GroupLayout.DEFAULT_SIZE,
                                                                javax.swing.GroupLayout.DEFAULT_SIZE,
                                                                Short.MAX_VALUE)
                                                        .addComponent(
                                                                jCheckBoxOtpViaSMS,
                                                                javax.swing.GroupLayout.Alignment.LEADING,
                                                                javax.swing.GroupLayout.DEFAULT_SIZE,
                                                                214,
                                                                Short.MAX_VALUE))
                                        .addContainerGap(236, Short.MAX_VALUE)));
        jPanel3Layout
                .setVerticalGroup(jPanel3Layout
                        .createParallelGroup(
                                javax.swing.GroupLayout.Alignment.LEADING)
                        .addGroup(
                                jPanel3Layout
                                        .createSequentialGroup()
                                        .addComponent(jCheckBoxOtpViaSMS)
                                        .addPreferredGap(
                                                javax.swing.LayoutStyle.ComponentPlacement.RELATED,
                                                javax.swing.GroupLayout.DEFAULT_SIZE,
                                                Short.MAX_VALUE)
                                        .addComponent(jCheckBoxOtpViaEmail)
                                        .addContainerGap()));

        jButtonSendOTPRequest.setText("Generate OTP");
        jButtonSendOTPRequest
                .addActionListener(new java.awt.event.ActionListener() {
                    public void actionPerformed(java.awt.event.ActionEvent evt) {
                        jButtonSendOTPRequestActionPerformed(evt);
                    }
                });

        jButtonOTPDialogDone.setText("Cancel");
        jButtonOTPDialogDone
                .addActionListener(new java.awt.event.ActionListener() {
                    public void actionPerformed(java.awt.event.ActionEvent evt) {
                        jButtonOTPDialogDoneActionPerformed(evt);
                    }
                });

        jLabelOtpRequestStatus.setText(".");

        javax.swing.GroupLayout jPanel2Layout = new javax.swing.GroupLayout(
                jPanel2);
        jPanel2.setLayout(jPanel2Layout);
        jPanel2Layout
                .setHorizontalGroup(jPanel2Layout
                        .createParallelGroup(
                                javax.swing.GroupLayout.Alignment.LEADING)
                        .addGroup(
                                jPanel2Layout
                                        .createSequentialGroup()
                                        .addContainerGap()
                                        .addGroup(
                                                jPanel2Layout
                                                        .createParallelGroup(
                                                                javax.swing.GroupLayout.Alignment.LEADING)
                                                        .addGroup(
                                                                javax.swing.GroupLayout.Alignment.TRAILING,
                                                                jPanel2Layout
                                                                        .createSequentialGroup()
                                                                        .addComponent(
                                                                                jButtonOTPDialogDone)
                                                                        .addPreferredGap(
                                                                                javax.swing.LayoutStyle.ComponentPlacement.RELATED,
                                                                                302,
                                                                                Short.MAX_VALUE)
                                                                        .addComponent(
                                                                                jButtonSendOTPRequest))
                                                        .addComponent(
                                                                jPanel3,
                                                                javax.swing.GroupLayout.DEFAULT_SIZE,
                                                                javax.swing.GroupLayout.DEFAULT_SIZE,
                                                                Short.MAX_VALUE)
                                                        .addComponent(
                                                                jLabelOtpRequestStatus,
                                                                javax.swing.GroupLayout.DEFAULT_SIZE,
                                                                468,
                                                                Short.MAX_VALUE))
                                        .addContainerGap()));
        jPanel2Layout
                .setVerticalGroup(jPanel2Layout
                        .createParallelGroup(
                                javax.swing.GroupLayout.Alignment.LEADING)
                        .addGroup(
                                javax.swing.GroupLayout.Alignment.TRAILING,
                                jPanel2Layout
                                        .createSequentialGroup()
                                        .addContainerGap()
                                        .addComponent(
                                                jPanel3,
                                                javax.swing.GroupLayout.PREFERRED_SIZE,
                                                javax.swing.GroupLayout.DEFAULT_SIZE,
                                                javax.swing.GroupLayout.PREFERRED_SIZE)
                                        .addPreferredGap(
                                                javax.swing.LayoutStyle.ComponentPlacement.UNRELATED)
                                        .addComponent(
                                                jLabelOtpRequestStatus,
                                                javax.swing.GroupLayout.DEFAULT_SIZE,
                                                33, Short.MAX_VALUE)
                                        .addPreferredGap(
                                                javax.swing.LayoutStyle.ComponentPlacement.UNRELATED)
                                        .addGroup(
                                                jPanel2Layout
                                                        .createParallelGroup(
                                                                javax.swing.GroupLayout.Alignment.BASELINE)
                                                        .addComponent(
                                                                jButtonSendOTPRequest)
                                                        .addComponent(
                                                                jButtonOTPDialogDone))
                                        .addGap(28, 28, 28)));

        javax.swing.GroupLayout jOTPLayout = new javax.swing.GroupLayout(
                jOTP.getContentPane());
        jOTP.getContentPane().setLayout(jOTPLayout);
        jOTPLayout.setHorizontalGroup(jOTPLayout.createParallelGroup(
                javax.swing.GroupLayout.Alignment.LEADING).addComponent(
                        jPanel2, javax.swing.GroupLayout.DEFAULT_SIZE,
                        javax.swing.GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE));
        jOTPLayout.setVerticalGroup(jOTPLayout.createParallelGroup(
                javax.swing.GroupLayout.Alignment.LEADING).addComponent(
                        jPanel2, javax.swing.GroupLayout.DEFAULT_SIZE,
                        javax.swing.GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE));

        jLabel34.setText("jLabel34");

        jPanelBFD.setBackground(new java.awt.Color(255, 255, 255));
        jPanelBFD.setBorder(javax.swing.BorderFactory.createTitledBorder(null,
                "Best Finger Detection",
                javax.swing.border.TitledBorder.DEFAULT_JUSTIFICATION,
                javax.swing.border.TitledBorder.DEFAULT_POSITION,
                new java.awt.Font("Tahoma", 1, 12), new java.awt.Color(124,
                        186, 247))); // NOI18N
        jPanelBFD.setToolTipText("");

        jPanelBiometricsOuter3.setBackground(new java.awt.Color(255, 255, 255));
        jPanelBiometricsOuter3.setBorder(javax.swing.BorderFactory
                .createTitledBorder(null, "Left Hand Fingers",
                        javax.swing.border.TitledBorder.DEFAULT_JUSTIFICATION,
                        javax.swing.border.TitledBorder.DEFAULT_POSITION,
                        new java.awt.Font("Tahoma", 1, 11))); // NOI18N
        jPanelBiometricsOuter3
                .setToolTipText("Scan to capture finger minutiae");

        jButtonScanLeftLittle.setText("Scan");
        jButtonScanLeftLittle
                .addActionListener(new java.awt.event.ActionListener() {
                    public void actionPerformed(java.awt.event.ActionEvent evt) {
                        jButtonScanLeftLittleActionPerformed(evt);
                    }
                });

        jLabelBiometricLeftLittle.setBackground(new java.awt.Color(102, 255,
                255));
        jLabelBiometricLeftLittle.setFont(new java.awt.Font("Tahoma", 0, 48));
        jLabelBiometricLeftLittle
                .setHorizontalAlignment(javax.swing.SwingConstants.CENTER);
        jLabelBiometricLeftLittle.setBorder(javax.swing.BorderFactory
                .createLineBorder(new java.awt.Color(0, 0, 0)));
        jLabelBiometricLeftLittle
                .setHorizontalTextPosition(javax.swing.SwingConstants.CENTER);

        jButtonScanLeftRing.setText("Scan");
        jButtonScanLeftRing
                .addActionListener(new java.awt.event.ActionListener() {
                    public void actionPerformed(java.awt.event.ActionEvent evt) {
                        jButtonScanLeftRingActionPerformed(evt);
                    }
                });

        jLabelBiometricLeftRing
                .setBackground(new java.awt.Color(102, 255, 255));
        jLabelBiometricLeftRing.setFont(new java.awt.Font("Tahoma", 0, 48));
        jLabelBiometricLeftRing
                .setHorizontalAlignment(javax.swing.SwingConstants.CENTER);
        jLabelBiometricLeftRing.setBorder(javax.swing.BorderFactory
                .createLineBorder(new java.awt.Color(0, 0, 0)));

        jButtonScanMiddle.setText("Scan");
        jButtonScanMiddle
                .addActionListener(new java.awt.event.ActionListener() {
                    public void actionPerformed(java.awt.event.ActionEvent evt) {
                        jButtonScanMiddleActionPerformed(evt);
                    }
                });

        jLabelBiometricLeftMiddle.setBackground(new java.awt.Color(102, 255,
                255));
        jLabelBiometricLeftMiddle.setFont(new java.awt.Font("Tahoma", 0, 48));
        jLabelBiometricLeftMiddle
                .setHorizontalAlignment(javax.swing.SwingConstants.CENTER);
        jLabelBiometricLeftMiddle.setBorder(javax.swing.BorderFactory
                .createLineBorder(new java.awt.Color(0, 0, 0)));

        jButtonScanLeftIndex.setText("Scan");
        jButtonScanLeftIndex
                .addActionListener(new java.awt.event.ActionListener() {
                    public void actionPerformed(java.awt.event.ActionEvent evt) {
                        jButtonScanLeftIndexActionPerformed(evt);
                    }
                });

        jLabelBiometricLeftIndex
                .setBackground(new java.awt.Color(102, 255, 255));
        jLabelBiometricLeftIndex.setFont(new java.awt.Font("Tahoma", 0, 48));
        jLabelBiometricLeftIndex
                .setHorizontalAlignment(javax.swing.SwingConstants.CENTER);
        jLabelBiometricLeftIndex.setBorder(javax.swing.BorderFactory
                .createLineBorder(new java.awt.Color(0, 0, 0)));

        jButtonScanLeftThumb.setText("Scan");
        jButtonScanLeftThumb
                .addActionListener(new java.awt.event.ActionListener() {
                    public void actionPerformed(java.awt.event.ActionEvent evt) {
                        jButtonScanLeftThumbActionPerformed(evt);
                    }
                });

        jLabelBiometricLeftThumb
                .setBackground(new java.awt.Color(102, 255, 255));
        jLabelBiometricLeftThumb.setFont(new java.awt.Font("Tahoma", 0, 48));
        jLabelBiometricLeftThumb
                .setHorizontalAlignment(javax.swing.SwingConstants.CENTER);
        jLabelBiometricLeftThumb.setBorder(javax.swing.BorderFactory
                .createLineBorder(new java.awt.Color(0, 0, 0)));

        jLabel44.setText("Left Little");

        jLabel45.setText("Left Ring");

        jLabel46.setText("Left Middle");

        jLabel47.setText("Left Index");

        jLabel48.setText("Left Thumb");

        jLabelBFDRankLeftLittle.setFont(new java.awt.Font("Tahoma", 0, 24)); // NOI18N
        jLabelBFDRankLeftLittle.setText("10");

        jLabelBFDRankLeftRing.setFont(new java.awt.Font("Tahoma", 0, 24)); // NOI18N
        jLabelBFDRankLeftRing.setText("10");

        jLabelBFDRankLeftMiddle.setFont(new java.awt.Font("Tahoma", 0, 24)); // NOI18N
        jLabelBFDRankLeftMiddle.setText("10");

        jLabelBFDRankLeftIndex.setFont(new java.awt.Font("Tahoma", 0, 24)); // NOI18N
        jLabelBFDRankLeftIndex.setText("10");

        jLabelBFDRankLeftThumb.setFont(new java.awt.Font("Tahoma", 0, 24)); // NOI18N
        jLabelBFDRankLeftThumb.setText("10");

        javax.swing.GroupLayout jPanelBiometricsOuter3Layout = new javax.swing.GroupLayout(
                jPanelBiometricsOuter3);
        jPanelBiometricsOuter3.setLayout(jPanelBiometricsOuter3Layout);
        jPanelBiometricsOuter3Layout
                .setHorizontalGroup(jPanelBiometricsOuter3Layout
                        .createParallelGroup(
                                javax.swing.GroupLayout.Alignment.LEADING)
                        .addGroup(
                                jPanelBiometricsOuter3Layout
                                        .createSequentialGroup()
                                        .addContainerGap()
                                        .addGroup(
                                                jPanelBiometricsOuter3Layout
                                                        .createParallelGroup(
                                                                javax.swing.GroupLayout.Alignment.LEADING)
                                                        .addComponent(
                                                                jLabelBiometricLeftLittle,
                                                                javax.swing.GroupLayout.PREFERRED_SIZE,
                                                                113,
                                                                javax.swing.GroupLayout.PREFERRED_SIZE)
                                                        .addComponent(
                                                                jButtonScanLeftLittle)
                                                        .addGroup(
                                                                jPanelBiometricsOuter3Layout
                                                                        .createSequentialGroup()
                                                                        .addComponent(
                                                                                jLabel44)
                                                                        .addPreferredGap(
                                                                                javax.swing.LayoutStyle.ComponentPlacement.UNRELATED)
                                                                        .addComponent(
                                                                                jLabelBFDRankLeftLittle)))
                                        .addPreferredGap(
                                                javax.swing.LayoutStyle.ComponentPlacement.RELATED)
                                        .addGroup(
                                                jPanelBiometricsOuter3Layout
                                                        .createParallelGroup(
                                                                javax.swing.GroupLayout.Alignment.LEADING)
                                                        .addComponent(
                                                                jButtonScanLeftRing)
                                                        .addGroup(
                                                                jPanelBiometricsOuter3Layout
                                                                        .createSequentialGroup()
                                                                        .addComponent(
                                                                                jLabel45)
                                                                        .addPreferredGap(
                                                                                javax.swing.LayoutStyle.ComponentPlacement.RELATED)
                                                                        .addComponent(
                                                                                jLabelBFDRankLeftRing))
                                                        .addComponent(
                                                                jLabelBiometricLeftRing,
                                                                javax.swing.GroupLayout.PREFERRED_SIZE,
                                                                113,
                                                                javax.swing.GroupLayout.PREFERRED_SIZE))
                                        .addPreferredGap(
                                                javax.swing.LayoutStyle.ComponentPlacement.RELATED)
                                        .addGroup(
                                                jPanelBiometricsOuter3Layout
                                                        .createParallelGroup(
                                                                javax.swing.GroupLayout.Alignment.LEADING)
                                                        .addComponent(
                                                                jButtonScanMiddle)
                                                        .addGroup(
                                                                jPanelBiometricsOuter3Layout
                                                                        .createSequentialGroup()
                                                                        .addComponent(
                                                                                jLabel46)
                                                                        .addPreferredGap(
                                                                                javax.swing.LayoutStyle.ComponentPlacement.RELATED)
                                                                        .addComponent(
                                                                                jLabelBFDRankLeftMiddle))
                                                        .addComponent(
                                                                jLabelBiometricLeftMiddle,
                                                                javax.swing.GroupLayout.PREFERRED_SIZE,
                                                                113,
                                                                javax.swing.GroupLayout.PREFERRED_SIZE))
                                        .addPreferredGap(
                                                javax.swing.LayoutStyle.ComponentPlacement.RELATED)
                                        .addGroup(
                                                jPanelBiometricsOuter3Layout
                                                        .createParallelGroup(
                                                                javax.swing.GroupLayout.Alignment.LEADING)
                                                        .addGroup(
                                                                jPanelBiometricsOuter3Layout
                                                                        .createSequentialGroup()
                                                                        .addComponent(
                                                                                jLabel47)
                                                                        .addPreferredGap(
                                                                                javax.swing.LayoutStyle.ComponentPlacement.RELATED)
                                                                        .addComponent(
                                                                                jLabelBFDRankLeftIndex))
                                                        .addComponent(
                                                                jLabelBiometricLeftIndex,
                                                                javax.swing.GroupLayout.PREFERRED_SIZE,
                                                                113,
                                                                javax.swing.GroupLayout.PREFERRED_SIZE)
                                                        .addComponent(
                                                                jButtonScanLeftIndex))
                                        .addGroup(
                                                jPanelBiometricsOuter3Layout
                                                        .createParallelGroup(
                                                                javax.swing.GroupLayout.Alignment.LEADING)
                                                        .addGroup(
                                                                jPanelBiometricsOuter3Layout
                                                                        .createSequentialGroup()
                                                                        .addGap(10,
                                                                                10,
                                                                                10)
                                                                        .addComponent(
                                                                                jLabel48)
                                                                        .addPreferredGap(
                                                                                javax.swing.LayoutStyle.ComponentPlacement.RELATED)
                                                                        .addComponent(
                                                                                jLabelBFDRankLeftThumb))
                                                        .addGroup(
                                                                jPanelBiometricsOuter3Layout
                                                                        .createSequentialGroup()
                                                                        .addPreferredGap(
                                                                                javax.swing.LayoutStyle.ComponentPlacement.RELATED)
                                                                        .addGroup(
                                                                                jPanelBiometricsOuter3Layout
                                                                                        .createParallelGroup(
                                                                                                javax.swing.GroupLayout.Alignment.LEADING)
                                                                                        .addComponent(
                                                                                                jButtonScanLeftThumb)
                                                                                        .addComponent(
                                                                                                jLabelBiometricLeftThumb,
                                                                                                javax.swing.GroupLayout.PREFERRED_SIZE,
                                                                                                113,
                                                                                                javax.swing.GroupLayout.PREFERRED_SIZE))))
                                        .addContainerGap()));
        jPanelBiometricsOuter3Layout
                .setVerticalGroup(jPanelBiometricsOuter3Layout
                        .createParallelGroup(
                                javax.swing.GroupLayout.Alignment.LEADING)
                        .addGroup(
                                jPanelBiometricsOuter3Layout
                                        .createSequentialGroup()
                                        .addContainerGap()
                                        .addGroup(
                                                jPanelBiometricsOuter3Layout
                                                        .createParallelGroup(
                                                                javax.swing.GroupLayout.Alignment.TRAILING)
                                                        .addGroup(
                                                                jPanelBiometricsOuter3Layout
                                                                        .createParallelGroup(
                                                                                javax.swing.GroupLayout.Alignment.BASELINE)
                                                                        .addComponent(
                                                                                jLabel45,
                                                                                javax.swing.GroupLayout.PREFERRED_SIZE,
                                                                                14,
                                                                                javax.swing.GroupLayout.PREFERRED_SIZE)
                                                                        .addComponent(
                                                                                jLabel46,
                                                                                javax.swing.GroupLayout.PREFERRED_SIZE,
                                                                                14,
                                                                                javax.swing.GroupLayout.PREFERRED_SIZE)
                                                                        .addComponent(
                                                                                jLabel47,
                                                                                javax.swing.GroupLayout.PREFERRED_SIZE,
                                                                                14,
                                                                                javax.swing.GroupLayout.PREFERRED_SIZE)
                                                                        .addComponent(
                                                                                jLabel48,
                                                                                javax.swing.GroupLayout.PREFERRED_SIZE,
                                                                                14,
                                                                                javax.swing.GroupLayout.PREFERRED_SIZE)
                                                                        .addComponent(
                                                                                jLabelBFDRankLeftThumb)
                                                                        .addComponent(
                                                                                jLabelBFDRankLeftIndex)
                                                                        .addComponent(
                                                                                jLabelBFDRankLeftMiddle)
                                                                        .addComponent(
                                                                                jLabelBFDRankLeftRing))
                                                        .addGroup(
                                                                jPanelBiometricsOuter3Layout
                                                                        .createParallelGroup(
                                                                                javax.swing.GroupLayout.Alignment.BASELINE)
                                                                        .addComponent(
                                                                                jLabel44,
                                                                                javax.swing.GroupLayout.PREFERRED_SIZE,
                                                                                14,
                                                                                javax.swing.GroupLayout.PREFERRED_SIZE)
                                                                        .addComponent(
                                                                                jLabelBFDRankLeftLittle)))
                                        .addPreferredGap(
                                                javax.swing.LayoutStyle.ComponentPlacement.RELATED)
                                        .addGroup(
                                                jPanelBiometricsOuter3Layout
                                                        .createParallelGroup(
                                                                javax.swing.GroupLayout.Alignment.TRAILING)
                                                        .addComponent(
                                                                jLabelBiometricLeftRing,
                                                                javax.swing.GroupLayout.PREFERRED_SIZE,
                                                                94,
                                                                javax.swing.GroupLayout.PREFERRED_SIZE)
                                                        .addComponent(
                                                                jLabelBiometricLeftMiddle,
                                                                javax.swing.GroupLayout.PREFERRED_SIZE,
                                                                94,
                                                                javax.swing.GroupLayout.PREFERRED_SIZE)
                                                        .addComponent(
                                                                jLabelBiometricLeftIndex,
                                                                javax.swing.GroupLayout.PREFERRED_SIZE,
                                                                94,
                                                                javax.swing.GroupLayout.PREFERRED_SIZE)
                                                        .addComponent(
                                                                jLabelBiometricLeftThumb,
                                                                javax.swing.GroupLayout.PREFERRED_SIZE,
                                                                94,
                                                                javax.swing.GroupLayout.PREFERRED_SIZE)
                                                        .addComponent(
                                                                jLabelBiometricLeftLittle,
                                                                javax.swing.GroupLayout.PREFERRED_SIZE,
                                                                94,
                                                                javax.swing.GroupLayout.PREFERRED_SIZE))
                                        .addPreferredGap(
                                                javax.swing.LayoutStyle.ComponentPlacement.RELATED)
                                        .addGroup(
                                                jPanelBiometricsOuter3Layout
                                                        .createParallelGroup(
                                                                javax.swing.GroupLayout.Alignment.LEADING)
                                                        .addGroup(
                                                                jPanelBiometricsOuter3Layout
                                                                        .createParallelGroup(
                                                                                javax.swing.GroupLayout.Alignment.LEADING)
                                                                        .addGroup(
                                                                                javax.swing.GroupLayout.Alignment.TRAILING,
                                                                                jPanelBiometricsOuter3Layout
                                                                                        .createParallelGroup(
                                                                                                javax.swing.GroupLayout.Alignment.BASELINE)
                                                                                        .addComponent(
                                                                                                jButtonScanLeftRing)
                                                                                        .addComponent(
                                                                                                jButtonScanLeftLittle))
                                                                        .addComponent(
                                                                                jButtonScanMiddle,
                                                                                javax.swing.GroupLayout.Alignment.TRAILING))
                                                        .addGroup(
                                                                jPanelBiometricsOuter3Layout
                                                                        .createParallelGroup(
                                                                                javax.swing.GroupLayout.Alignment.BASELINE)
                                                                        .addComponent(
                                                                                jButtonScanLeftIndex)
                                                                        .addComponent(
                                                                                jButtonScanLeftThumb)))
                                        .addContainerGap(
                                                javax.swing.GroupLayout.DEFAULT_SIZE,
                                                Short.MAX_VALUE)));

        jLabelBFDStatusXML.setText("BFD Status for XML based Request");
        jLabelBFDStatusXML
                .setHorizontalTextPosition(javax.swing.SwingConstants.CENTER);

        jLabelBFDStatusProto.setText("BFD Status for Protobuf based Request");
        jLabelBFDStatusProto
                .setHorizontalTextPosition(javax.swing.SwingConstants.CENTER);

        jPanelBiometricsOuter4.setBackground(new java.awt.Color(255, 255, 255));
        jPanelBiometricsOuter4.setBorder(javax.swing.BorderFactory
                .createTitledBorder(null, "Right Hand Fingers",
                        javax.swing.border.TitledBorder.DEFAULT_JUSTIFICATION,
                        javax.swing.border.TitledBorder.DEFAULT_POSITION,
                        new java.awt.Font("Tahoma", 1, 11))); // NOI18N
        jPanelBiometricsOuter4
                .setToolTipText("Scan to capture finger minutiae");

        jButtonScanRightThumb.setText("Scan");
        jButtonScanRightThumb
                .addActionListener(new java.awt.event.ActionListener() {
                    public void actionPerformed(java.awt.event.ActionEvent evt) {
                        jButtonScanRightThumbActionPerformed(evt);
                    }
                });

        jLabelBiometricRightThumb.setBackground(new java.awt.Color(102, 255,
                255));
        jLabelBiometricRightThumb.setFont(new java.awt.Font("Tahoma", 0, 48));
        jLabelBiometricRightThumb
                .setHorizontalAlignment(javax.swing.SwingConstants.CENTER);
        jLabelBiometricRightThumb.setBorder(javax.swing.BorderFactory
                .createLineBorder(new java.awt.Color(0, 0, 0)));

        jButtonScanRightIndex.setText("Scan");
        jButtonScanRightIndex
                .addActionListener(new java.awt.event.ActionListener() {
                    public void actionPerformed(java.awt.event.ActionEvent evt) {
                        jButtonScanRightIndexActionPerformed(evt);
                    }
                });

        jLabelBiometricRightIndex.setBackground(new java.awt.Color(102, 255,
                255));
        jLabelBiometricRightIndex.setFont(new java.awt.Font("Tahoma", 0, 48));
        jLabelBiometricRightIndex
                .setHorizontalAlignment(javax.swing.SwingConstants.CENTER);
        jLabelBiometricRightIndex.setBorder(javax.swing.BorderFactory
                .createLineBorder(new java.awt.Color(0, 0, 0)));

        jButtonScanRightMiddle.setText("Scan");
        jButtonScanRightMiddle
                .addActionListener(new java.awt.event.ActionListener() {
                    public void actionPerformed(java.awt.event.ActionEvent evt) {
                        jButtonScanRightMiddleActionPerformed(evt);
                    }
                });

        jLabelBiometricRightMiddle.setBackground(new java.awt.Color(102, 255,
                255));
        jLabelBiometricRightMiddle.setFont(new java.awt.Font("Tahoma", 0, 48));
        jLabelBiometricRightMiddle
                .setHorizontalAlignment(javax.swing.SwingConstants.CENTER);
        jLabelBiometricRightMiddle.setBorder(javax.swing.BorderFactory
                .createLineBorder(new java.awt.Color(0, 0, 0)));

        jButtonScanRightRing.setText("Scan");
        jButtonScanRightRing
                .addActionListener(new java.awt.event.ActionListener() {
                    public void actionPerformed(java.awt.event.ActionEvent evt) {
                        jButtonScanRightRingActionPerformed(evt);
                    }
                });

        jLabelBiometricRightRing
                .setBackground(new java.awt.Color(102, 255, 255));
        jLabelBiometricRightRing.setFont(new java.awt.Font("Tahoma", 0, 48));
        jLabelBiometricRightRing
                .setHorizontalAlignment(javax.swing.SwingConstants.CENTER);
        jLabelBiometricRightRing.setBorder(javax.swing.BorderFactory
                .createLineBorder(new java.awt.Color(0, 0, 0)));

        jButtonScanRightLittle.setText("Scan");
        jButtonScanRightLittle
                .addActionListener(new java.awt.event.ActionListener() {
                    public void actionPerformed(java.awt.event.ActionEvent evt) {
                        jButtonScanRightLittleActionPerformed(evt);
                    }
                });

        jLabelBiometricRightLittle.setBackground(new java.awt.Color(102, 255,
                255));
        jLabelBiometricRightLittle.setFont(new java.awt.Font("Tahoma", 0, 48));
        jLabelBiometricRightLittle
                .setHorizontalAlignment(javax.swing.SwingConstants.CENTER);
        jLabelBiometricRightLittle.setBorder(javax.swing.BorderFactory
                .createLineBorder(new java.awt.Color(0, 0, 0)));

        jLabel49.setText("Right Thumb");

        jLabel50.setText("Right Index");

        jLabel51.setText("Right Middle");

        jLabel52.setText("Right Ring");

        jLabel53.setText("Right Little");

        jLabelBFDRankRightThumb.setFont(new java.awt.Font("Tahoma", 0, 24)); // NOI18N
        jLabelBFDRankRightThumb.setText("10");

        jLabelBFDRankRightMiddle.setFont(new java.awt.Font("Tahoma", 0, 24)); // NOI18N
        jLabelBFDRankRightMiddle.setText("10");

        jLabelBFDRankRightRing.setFont(new java.awt.Font("Tahoma", 0, 24)); // NOI18N
        jLabelBFDRankRightRing.setText("10");

        jLabelBFDRankRightIndex.setFont(new java.awt.Font("Tahoma", 0, 24)); // NOI18N
        jLabelBFDRankRightIndex.setText("10");

        jLabelBFDRankRightLittle.setFont(new java.awt.Font("Tahoma", 0, 24)); // NOI18N
        jLabelBFDRankRightLittle.setText("10");

        javax.swing.GroupLayout jPanelBiometricsOuter4Layout = new javax.swing.GroupLayout(
                jPanelBiometricsOuter4);
        jPanelBiometricsOuter4.setLayout(jPanelBiometricsOuter4Layout);
        jPanelBiometricsOuter4Layout
                .setHorizontalGroup(jPanelBiometricsOuter4Layout
                        .createParallelGroup(
                                javax.swing.GroupLayout.Alignment.LEADING)
                        .addGroup(
                                jPanelBiometricsOuter4Layout
                                        .createSequentialGroup()
                                        .addContainerGap()
                                        .addGroup(
                                                jPanelBiometricsOuter4Layout
                                                        .createParallelGroup(
                                                                javax.swing.GroupLayout.Alignment.LEADING)
                                                        .addGroup(
                                                                jPanelBiometricsOuter4Layout
                                                                        .createSequentialGroup()
                                                                        .addComponent(
                                                                                jLabel49)
                                                                        .addPreferredGap(
                                                                                javax.swing.LayoutStyle.ComponentPlacement.RELATED)
                                                                        .addComponent(
                                                                                jLabelBFDRankRightThumb))
                                                        .addComponent(
                                                                jButtonScanRightThumb)
                                                        .addComponent(
                                                                jLabelBiometricRightThumb,
                                                                javax.swing.GroupLayout.PREFERRED_SIZE,
                                                                113,
                                                                javax.swing.GroupLayout.PREFERRED_SIZE))
                                        .addPreferredGap(
                                                javax.swing.LayoutStyle.ComponentPlacement.RELATED)
                                        .addGroup(
                                                jPanelBiometricsOuter4Layout
                                                        .createParallelGroup(
                                                                javax.swing.GroupLayout.Alignment.LEADING)
                                                        .addComponent(
                                                                jLabelBiometricRightIndex,
                                                                javax.swing.GroupLayout.PREFERRED_SIZE,
                                                                113,
                                                                javax.swing.GroupLayout.PREFERRED_SIZE)
                                                        .addComponent(
                                                                jButtonScanRightIndex)
                                                        .addGroup(
                                                                jPanelBiometricsOuter4Layout
                                                                        .createSequentialGroup()
                                                                        .addGap(6,
                                                                                6,
                                                                                6)
                                                                        .addComponent(
                                                                                jLabel50)
                                                                        .addPreferredGap(
                                                                                javax.swing.LayoutStyle.ComponentPlacement.RELATED)
                                                                        .addComponent(
                                                                                jLabelBFDRankRightIndex)))
                                        .addPreferredGap(
                                                javax.swing.LayoutStyle.ComponentPlacement.RELATED)
                                        .addGroup(
                                                jPanelBiometricsOuter4Layout
                                                        .createParallelGroup(
                                                                javax.swing.GroupLayout.Alignment.LEADING)
                                                        .addComponent(
                                                                jLabelBiometricRightMiddle,
                                                                javax.swing.GroupLayout.PREFERRED_SIZE,
                                                                113,
                                                                javax.swing.GroupLayout.PREFERRED_SIZE)
                                                        .addGroup(
                                                                jPanelBiometricsOuter4Layout
                                                                        .createSequentialGroup()
                                                                        .addComponent(
                                                                                jLabel51)
                                                                        .addPreferredGap(
                                                                                javax.swing.LayoutStyle.ComponentPlacement.RELATED)
                                                                        .addComponent(
                                                                                jLabelBFDRankRightMiddle))
                                                        .addComponent(
                                                                jButtonScanRightMiddle))
                                        .addPreferredGap(
                                                javax.swing.LayoutStyle.ComponentPlacement.RELATED)
                                        .addGroup(
                                                jPanelBiometricsOuter4Layout
                                                        .createParallelGroup(
                                                                javax.swing.GroupLayout.Alignment.LEADING)
                                                        .addGroup(
                                                                jPanelBiometricsOuter4Layout
                                                                        .createSequentialGroup()
                                                                        .addComponent(
                                                                                jLabel52)
                                                                        .addPreferredGap(
                                                                                javax.swing.LayoutStyle.ComponentPlacement.RELATED)
                                                                        .addComponent(
                                                                                jLabelBFDRankRightRing))
                                                        .addComponent(
                                                                jLabelBiometricRightRing,
                                                                javax.swing.GroupLayout.PREFERRED_SIZE,
                                                                113,
                                                                javax.swing.GroupLayout.PREFERRED_SIZE)
                                                        .addComponent(
                                                                jButtonScanRightRing))
                                        .addPreferredGap(
                                                javax.swing.LayoutStyle.ComponentPlacement.RELATED)
                                        .addGroup(
                                                jPanelBiometricsOuter4Layout
                                                        .createParallelGroup(
                                                                javax.swing.GroupLayout.Alignment.LEADING)
                                                        .addComponent(
                                                                jLabelBiometricRightLittle,
                                                                javax.swing.GroupLayout.PREFERRED_SIZE,
                                                                113,
                                                                javax.swing.GroupLayout.PREFERRED_SIZE)
                                                        .addComponent(
                                                                jButtonScanRightLittle)
                                                        .addGroup(
                                                                jPanelBiometricsOuter4Layout
                                                                        .createSequentialGroup()
                                                                        .addComponent(
                                                                                jLabel53)
                                                                        .addPreferredGap(
                                                                                javax.swing.LayoutStyle.ComponentPlacement.RELATED)
                                                                        .addComponent(
                                                                                jLabelBFDRankRightLittle)))
                                        .addContainerGap()));
        jPanelBiometricsOuter4Layout
                .setVerticalGroup(jPanelBiometricsOuter4Layout
                        .createParallelGroup(
                                javax.swing.GroupLayout.Alignment.LEADING)
                        .addGroup(
                                jPanelBiometricsOuter4Layout
                                        .createSequentialGroup()
                                        .addContainerGap()
                                        .addGroup(
                                                jPanelBiometricsOuter4Layout
                                                        .createParallelGroup(
                                                                javax.swing.GroupLayout.Alignment.LEADING)
                                                        .addComponent(
                                                                jLabelBiometricRightIndex,
                                                                javax.swing.GroupLayout.Alignment.TRAILING,
                                                                javax.swing.GroupLayout.PREFERRED_SIZE,
                                                                94,
                                                                javax.swing.GroupLayout.PREFERRED_SIZE)
                                                        .addGroup(
                                                                javax.swing.GroupLayout.Alignment.TRAILING,
                                                                jPanelBiometricsOuter4Layout
                                                                        .createSequentialGroup()
                                                                        .addGroup(
                                                                                jPanelBiometricsOuter4Layout
                                                                                        .createParallelGroup(
                                                                                                javax.swing.GroupLayout.Alignment.BASELINE)
                                                                                        .addComponent(
                                                                                                jLabel50,
                                                                                                javax.swing.GroupLayout.PREFERRED_SIZE,
                                                                                                14,
                                                                                                javax.swing.GroupLayout.PREFERRED_SIZE)
                                                                                        .addComponent(
                                                                                                jLabel51,
                                                                                                javax.swing.GroupLayout.PREFERRED_SIZE,
                                                                                                14,
                                                                                                javax.swing.GroupLayout.PREFERRED_SIZE)
                                                                                        .addComponent(
                                                                                                jLabel53,
                                                                                                javax.swing.GroupLayout.PREFERRED_SIZE,
                                                                                                14,
                                                                                                javax.swing.GroupLayout.PREFERRED_SIZE)
                                                                                        .addComponent(
                                                                                                jLabel52,
                                                                                                javax.swing.GroupLayout.PREFERRED_SIZE,
                                                                                                14,
                                                                                                javax.swing.GroupLayout.PREFERRED_SIZE)
                                                                                        .addComponent(
                                                                                                jLabel49,
                                                                                                javax.swing.GroupLayout.PREFERRED_SIZE,
                                                                                                14,
                                                                                                javax.swing.GroupLayout.PREFERRED_SIZE)
                                                                                        .addComponent(
                                                                                                jLabelBFDRankRightThumb)
                                                                                        .addComponent(
                                                                                                jLabelBFDRankRightIndex)
                                                                                        .addComponent(
                                                                                                jLabelBFDRankRightMiddle)
                                                                                        .addComponent(
                                                                                                jLabelBFDRankRightRing)
                                                                                        .addComponent(
                                                                                                jLabelBFDRankRightLittle))
                                                                        .addPreferredGap(
                                                                                javax.swing.LayoutStyle.ComponentPlacement.RELATED)
                                                                        .addGroup(
                                                                                jPanelBiometricsOuter4Layout
                                                                                        .createParallelGroup(
                                                                                                javax.swing.GroupLayout.Alignment.TRAILING)
                                                                                        .addComponent(
                                                                                                jLabelBiometricRightMiddle,
                                                                                                javax.swing.GroupLayout.PREFERRED_SIZE,
                                                                                                94,
                                                                                                javax.swing.GroupLayout.PREFERRED_SIZE)
                                                                                        .addComponent(
                                                                                                jLabelBiometricRightRing,
                                                                                                javax.swing.GroupLayout.PREFERRED_SIZE,
                                                                                                94,
                                                                                                javax.swing.GroupLayout.PREFERRED_SIZE)
                                                                                        .addComponent(
                                                                                                jLabelBiometricRightLittle,
                                                                                                javax.swing.GroupLayout.PREFERRED_SIZE,
                                                                                                94,
                                                                                                javax.swing.GroupLayout.PREFERRED_SIZE)
                                                                                        .addComponent(
                                                                                                jLabelBiometricRightThumb,
                                                                                                javax.swing.GroupLayout.PREFERRED_SIZE,
                                                                                                94,
                                                                                                javax.swing.GroupLayout.PREFERRED_SIZE))))
                                        .addPreferredGap(
                                                javax.swing.LayoutStyle.ComponentPlacement.RELATED)
                                        .addGroup(
                                                jPanelBiometricsOuter4Layout
                                                        .createParallelGroup(
                                                                javax.swing.GroupLayout.Alignment.LEADING)
                                                        .addGroup(
                                                                jPanelBiometricsOuter4Layout
                                                                        .createParallelGroup(
                                                                                javax.swing.GroupLayout.Alignment.BASELINE)
                                                                        .addComponent(
                                                                                jButtonScanRightLittle)
                                                                        .addComponent(
                                                                                jButtonScanRightRing)
                                                                        .addComponent(
                                                                                jButtonScanRightMiddle))
                                                        .addGroup(
                                                                jPanelBiometricsOuter4Layout
                                                                        .createParallelGroup(
                                                                                javax.swing.GroupLayout.Alignment.BASELINE)
                                                                        .addComponent(
                                                                                jButtonScanRightThumb)
                                                                        .addComponent(
                                                                                jButtonScanRightIndex)))
                                        .addContainerGap(16, Short.MAX_VALUE)));

        jButtonPerformBFD.setText("Perform BFD");
        jButtonPerformBFD
                .addActionListener(new java.awt.event.ActionListener() {
                    public void actionPerformed(java.awt.event.ActionEvent evt) {
                        jButtonPerformBFDActionPerformed(evt);
                    }
                });

        jButtonCustomKYC.setText("Custom KYC");
        jButtonCustomKYC.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                jButtonCustomKYCActionPerformed(evt);
            }
        });

        jButtonBFDReset.setText("Reset");
        jButtonBFDReset.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                jButtonBFDResetActionPerformed(evt);
            }
        });

        javax.swing.GroupLayout jPanelBFDLayout = new javax.swing.GroupLayout(
                jPanelBFD);
        jPanelBFD.setLayout(jPanelBFDLayout);
        jPanelBFDLayout
                .setHorizontalGroup(jPanelBFDLayout
                        .createParallelGroup(
                                javax.swing.GroupLayout.Alignment.LEADING)
                        .addGroup(
                                jPanelBFDLayout
                                        .createSequentialGroup()
                                        .addContainerGap()
                                        .addGroup(
                                                jPanelBFDLayout
                                                        .createParallelGroup(
                                                                javax.swing.GroupLayout.Alignment.LEADING)
                                                        .addGroup(
                                                                jPanelBFDLayout
                                                                        .createSequentialGroup()
                                                                        .addComponent(
                                                                                jButtonBFDReset)
                                                                        .addGap(467,
                                                                                467,
                                                                                467)
                                                                        .addComponent(
                                                                                jButtonPerformBFD)
                                                                        .addGap(223,
                                                                                223,
                                                                                223))
                                                        .addGroup(
                                                                jPanelBFDLayout
                                                                        .createSequentialGroup()
                                                                        .addGroup(
                                                                                jPanelBFDLayout
                                                                                        .createParallelGroup(
                                                                                                javax.swing.GroupLayout.Alignment.LEADING)
                                                                                        .addGroup(
                                                                                                jPanelBFDLayout
                                                                                                        .createSequentialGroup()
                                                                                                        .addGap(10,
                                                                                                                10,
                                                                                                                10)
                                                                                                        .addGroup(
                                                                                                                jPanelBFDLayout
                                                                                                                        .createParallelGroup(
                                                                                                                                javax.swing.GroupLayout.Alignment.LEADING)
                                                                                                                        .addComponent(
                                                                                                                                jLabelBFDStatusProto,
                                                                                                                                javax.swing.GroupLayout.DEFAULT_SIZE,
                                                                                                                                824,
                                                                                                                                Short.MAX_VALUE)
                                                                                                                        .addComponent(
                                                                                                                                jLabelBFDStatusXML,
                                                                                                                                javax.swing.GroupLayout.PREFERRED_SIZE,
                                                                                                                                512,
                                                                                                                                javax.swing.GroupLayout.PREFERRED_SIZE)))
                                                                                        .addGroup(
                                                                                                jPanelBFDLayout
                                                                                                        .createParallelGroup(
                                                                                                                javax.swing.GroupLayout.Alignment.TRAILING,
                                                                                                                false)
                                                                                                        .addComponent(
                                                                                                                jPanelBiometricsOuter3,
                                                                                                                javax.swing.GroupLayout.Alignment.LEADING,
                                                                                                                javax.swing.GroupLayout.DEFAULT_SIZE,
                                                                                                                javax.swing.GroupLayout.DEFAULT_SIZE,
                                                                                                                Short.MAX_VALUE)
                                                                                                        .addComponent(
                                                                                                                jPanelBiometricsOuter4,
                                                                                                                javax.swing.GroupLayout.Alignment.LEADING,
                                                                                                                javax.swing.GroupLayout.DEFAULT_SIZE,
                                                                                                                javax.swing.GroupLayout.DEFAULT_SIZE,
                                                                                                                Short.MAX_VALUE)))
                                                                        .addContainerGap()))));
        jPanelBFDLayout
                .setVerticalGroup(jPanelBFDLayout
                        .createParallelGroup(
                                javax.swing.GroupLayout.Alignment.LEADING)
                        .addGroup(
                                jPanelBFDLayout
                                        .createSequentialGroup()
                                        .addComponent(
                                                jPanelBiometricsOuter3,
                                                javax.swing.GroupLayout.PREFERRED_SIZE,
                                                javax.swing.GroupLayout.DEFAULT_SIZE,
                                                javax.swing.GroupLayout.PREFERRED_SIZE)
                                        .addPreferredGap(
                                                javax.swing.LayoutStyle.ComponentPlacement.RELATED)
                                        .addComponent(
                                                jPanelBiometricsOuter4,
                                                javax.swing.GroupLayout.PREFERRED_SIZE,
                                                javax.swing.GroupLayout.DEFAULT_SIZE,
                                                javax.swing.GroupLayout.PREFERRED_SIZE)
                                        .addGap(11, 11, 11)
                                        .addComponent(jLabelBFDStatusXML)
                                        .addPreferredGap(
                                                javax.swing.LayoutStyle.ComponentPlacement.RELATED)
                                        .addComponent(jLabelBFDStatusProto)
                                        .addPreferredGap(
                                                javax.swing.LayoutStyle.ComponentPlacement.RELATED)
                                        .addGroup(
                                                jPanelBFDLayout
                                                        .createParallelGroup(
                                                                javax.swing.GroupLayout.Alignment.BASELINE)
                                                        .addComponent(
                                                                jButtonBFDReset,
                                                                javax.swing.GroupLayout.DEFAULT_SIZE,
                                                                23,
                                                                Short.MAX_VALUE)
                                                        .addComponent(
                                                                jButtonPerformBFD))));

        javax.swing.GroupLayout jDialogBFDLayout = new javax.swing.GroupLayout(
                jDialogBFD.getContentPane());
        jDialogBFD.getContentPane().setLayout(jDialogBFDLayout);
        jDialogBFDLayout.setHorizontalGroup(jDialogBFDLayout
                .createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
                .addComponent(jPanelBFD,
                        javax.swing.GroupLayout.PREFERRED_SIZE, 654,
                        javax.swing.GroupLayout.PREFERRED_SIZE));
        jDialogBFDLayout.setVerticalGroup(jDialogBFDLayout.createParallelGroup(
                javax.swing.GroupLayout.Alignment.LEADING).addComponent(
                        jPanelBFD, javax.swing.GroupLayout.PREFERRED_SIZE,
                        javax.swing.GroupLayout.DEFAULT_SIZE,
                        javax.swing.GroupLayout.PREFERRED_SIZE));

        setDefaultCloseOperation(javax.swing.WindowConstants.EXIT_ON_CLOSE);
        setBackground(new java.awt.Color(204, 255, 204));
        setResizable(false);
        addWindowListener(new java.awt.event.WindowAdapter() {
            public void windowOpened(java.awt.event.WindowEvent evt) {
                formWindowOpened(evt);
            }
        });

        jPanel1.setBackground(new java.awt.Color(180, 233, 251));

        jLabelLogo.setFont(new java.awt.Font("Monospaced", 1, 36));
        jLabelLogo.setIcon(new javax.swing.ImageIcon(getClass().getResource(
                "/aadhar-logo.png"))); // NOI18N

        jPanelKYR.setBackground(new java.awt.Color(255, 255, 255));
        jPanelKYR.setBorder(javax.swing.BorderFactory.createTitledBorder(null,
                "KYC Information",
                javax.swing.border.TitledBorder.DEFAULT_JUSTIFICATION,
                javax.swing.border.TitledBorder.DEFAULT_POSITION,
                new java.awt.Font("Tahoma", 1, 12), new java.awt.Color(124,
                        186, 247))); // NOI18N
        jPanelKYR.setToolTipText("");
        jPanelKYR.setName("piFrame"); // NOI18N

        jLabelAadhaarNumber.setText("AADHAAR Number");

        jPanelIdentificationDetails.setBackground(new java.awt.Color(255, 255,
                255));
        jPanelIdentificationDetails.setBorder(javax.swing.BorderFactory
                .createTitledBorder(null, "Personal Identity (Pi)",
                        javax.swing.border.TitledBorder.DEFAULT_JUSTIFICATION,
                        javax.swing.border.TitledBorder.DEFAULT_POSITION,
                        new java.awt.Font("Tahoma", 1, 11))); // NOI18N
        jPanelIdentificationDetails.setToolTipText("");

        jFrameIdentificationDetails.setBackground(new java.awt.Color(255, 255,
                255));
        jFrameIdentificationDetails
                .setBorder(new javax.swing.border.LineBorder(
                        new java.awt.Color(255, 204, 102), 1, true));

        jLabelName.setText("Name");

        jLabelGener.setText("Gender");

        jComboGender
                .setModel(new javax.swing.DefaultComboBoxModel(new String[]{
            "Select gender", "Male", "Female", "Transgender"}));

        jLabelDob.setText("Date of birth");

        jLabelPhone.setText("Phone");

        jLabelEmail.setText("Email");

        try {
            jTextFieldDobYear
                    .setFormatterFactory(new javax.swing.text.DefaultFormatterFactory(
                            new javax.swing.text.MaskFormatter("####")));
        } catch (java.text.ParseException ex) {
            ex.printStackTrace();
        }

        try {
            jTextFieldDobMonth
                    .setFormatterFactory(new javax.swing.text.DefaultFormatterFactory(
                            new javax.swing.text.MaskFormatter("##")));
        } catch (java.text.ParseException ex) {
            ex.printStackTrace();
        }

        try {
            jTextFieldDobDay
                    .setFormatterFactory(new javax.swing.text.DefaultFormatterFactory(
                            new javax.swing.text.MaskFormatter("##")));
        } catch (java.text.ParseException ex) {
            ex.printStackTrace();
        }

        jLabel3.setText("-");

        jLabel4.setText("-");

        jTextFieldPhone
                .setFormatterFactory(new javax.swing.text.DefaultFormatterFactory(
                        new javax.swing.text.NumberFormatter(
                                new java.text.DecimalFormat("#0"))));

        jLabelAge.setText("Age");

        jTextFieldAge.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                jTextFieldAgeActionPerformed(evt);
            }
        });

        jLabel10.setText("Match Value");

        jSpinnerNameMatchValue.setModel(new javax.swing.SpinnerNumberModel(1,
                1, 100, 1));

        jLabel6.setText("Match Strategy");

        jRadioButtonNameMatchExact.setBackground(new java.awt.Color(255, 255,
                255));
        jButtonGroupNameMatchStrategy.add(jRadioButtonNameMatchExact);
        jRadioButtonNameMatchExact.setSelected(true);
        jRadioButtonNameMatchExact.setText("Exact match");
        jRadioButtonNameMatchExact
                .addActionListener(new java.awt.event.ActionListener() {
                    public void actionPerformed(java.awt.event.ActionEvent evt) {
                        jRadioButtonNameMatchExactActionPerformed(evt);
                    }
                });

        jRadioButtonNameMatchPartial.setBackground(new java.awt.Color(255, 255,
                255));
        jButtonGroupNameMatchStrategy.add(jRadioButtonNameMatchPartial);
        jRadioButtonNameMatchPartial.setText("Partial match");
        jRadioButtonNameMatchPartial
                .addActionListener(new java.awt.event.ActionListener() {
                    public void actionPerformed(java.awt.event.ActionEvent evt) {
                        jRadioButtonNameMatchPartialActionPerformed(evt);
                    }
                });

        jRadioFuzzyName.setBackground(new java.awt.Color(255, 255, 255));
        jButtonGroupNameMatchStrategy.add(jRadioFuzzyName);
        jRadioFuzzyName.setText("Fuzzy match");
        jRadioFuzzyName.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                jRadioFuzzyNameActionPerformed(evt);
            }
        });

        jLabelName1.setText("Local Name");

        jLabel17.setText("Local Match Value");

        jSpinnerNameMatchValueLocal
                .setModel(new javax.swing.SpinnerNumberModel(1, 1, 100, 1));

        jLabel21.setHorizontalAlignment(javax.swing.SwingConstants.RIGHT);
        jLabel21.setLabelFor(jComboBoxDOBType);
        jLabel21.setText("DOB type");
        jLabel21.setToolTipText("Date of birth type");

        jComboBoxDOBType.setModel(new javax.swing.DefaultComboBoxModel(
                new String[]{"Select", "A", "V", "D"}));
        jComboBoxDOBType.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                jComboBoxDOBTypeActionPerformed(evt);
            }
        });
        //Added for Mobile/Email ID consent and Local  Language required Consent
        mecCheckbox = new JCheckBox("Mobile/Email ID Consent");

        lrCheckbox = new JCheckBox("Local Language Required Consent");

        javax.swing.GroupLayout jFrameIdentificationDetailsLayout = new javax.swing.GroupLayout(
                jFrameIdentificationDetails);
        jFrameIdentificationDetailsLayout.setHorizontalGroup(
                jFrameIdentificationDetailsLayout.createParallelGroup(Alignment.LEADING)
                        .addGroup(jFrameIdentificationDetailsLayout.createSequentialGroup()
                                .addGroup(jFrameIdentificationDetailsLayout.createParallelGroup(Alignment.LEADING)
                                        .addGroup(jFrameIdentificationDetailsLayout.createSequentialGroup()
                                                .addContainerGap()
                                                .addGroup(jFrameIdentificationDetailsLayout.createParallelGroup(Alignment.LEADING)
                                                        .addComponent(jLabelName)
                                                        .addGroup(jFrameIdentificationDetailsLayout.createSequentialGroup()
                                                                .addGap(39)
                                                                .addComponent(jTextFieldName, GroupLayout.DEFAULT_SIZE, 231, Short.MAX_VALUE)
                                                                .addGap(8)
                                                                .addComponent(jLabel10)
                                                                .addPreferredGap(ComponentPlacement.UNRELATED)
                                                                .addComponent(jSpinnerNameMatchValue, GroupLayout.PREFERRED_SIZE, 48, GroupLayout.PREFERRED_SIZE))
                                                        .addGroup(jFrameIdentificationDetailsLayout.createSequentialGroup()
                                                                .addComponent(jLabel6)
                                                                .addPreferredGap(ComponentPlacement.UNRELATED)
                                                                .addComponent(jRadioButtonNameMatchExact)
                                                                .addPreferredGap(ComponentPlacement.RELATED)
                                                                .addComponent(jRadioButtonNameMatchPartial)
                                                                .addPreferredGap(ComponentPlacement.UNRELATED)
                                                                .addComponent(jRadioFuzzyName)
                                                                .addPreferredGap(ComponentPlacement.RELATED)
                                                                .addComponent(jSpinnerNameMatchValueLocal, GroupLayout.PREFERRED_SIZE, 48, GroupLayout.PREFERRED_SIZE))))
                                        .addGroup(jFrameIdentificationDetailsLayout.createSequentialGroup()
                                                .addContainerGap()
                                                .addComponent(jLabelName1)
                                                .addPreferredGap(ComponentPlacement.RELATED)
                                                .addComponent(jTextFieldNameLocal, GroupLayout.DEFAULT_SIZE, 189, Short.MAX_VALUE)
                                                .addPreferredGap(ComponentPlacement.UNRELATED)
                                                .addComponent(jLabel17)
                                                .addGap(52))
                                        .addGroup(jFrameIdentificationDetailsLayout.createSequentialGroup()
                                                .addGroup(jFrameIdentificationDetailsLayout.createParallelGroup(Alignment.LEADING)
                                                        .addGroup(jFrameIdentificationDetailsLayout.createSequentialGroup()
                                                                .addContainerGap()
                                                                .addComponent(jLabelGener))
                                                        .addGroup(jFrameIdentificationDetailsLayout.createSequentialGroup()
                                                                .addContainerGap()
                                                                .addGroup(jFrameIdentificationDetailsLayout.createParallelGroup(Alignment.TRAILING)
                                                                        .addComponent(jLabelEmail)
                                                                        .addComponent(jLabelPhone))))
                                                .addPreferredGap(ComponentPlacement.RELATED)
                                                .addGroup(jFrameIdentificationDetailsLayout.createParallelGroup(Alignment.TRAILING)
                                                        .addGroup(jFrameIdentificationDetailsLayout.createSequentialGroup()
                                                                .addGroup(jFrameIdentificationDetailsLayout.createParallelGroup(Alignment.LEADING)
                                                                        .addGroup(jFrameIdentificationDetailsLayout.createSequentialGroup()
                                                                                .addComponent(jComboGender, GroupLayout.PREFERRED_SIZE, GroupLayout.DEFAULT_SIZE, GroupLayout.PREFERRED_SIZE)
                                                                                .addGap(12)
                                                                                .addComponent(jLabelAge)
                                                                                .addPreferredGap(ComponentPlacement.RELATED)
                                                                                .addComponent(jTextFieldAge, GroupLayout.DEFAULT_SIZE, 72, Short.MAX_VALUE))
                                                                        .addGroup(jFrameIdentificationDetailsLayout.createSequentialGroup()
                                                                                .addComponent(jTextFieldPhone, GroupLayout.DEFAULT_SIZE, 119, Short.MAX_VALUE)
                                                                                .addGap(18)
                                                                                .addComponent(jLabelDob)
                                                                                .addPreferredGap(ComponentPlacement.RELATED)))
                                                                .addPreferredGap(ComponentPlacement.RELATED, 23, Short.MAX_VALUE)
                                                                .addGroup(jFrameIdentificationDetailsLayout.createParallelGroup(Alignment.TRAILING)
                                                                        .addGroup(jFrameIdentificationDetailsLayout.createSequentialGroup()
                                                                                .addComponent(jTextFieldDobYear, GroupLayout.PREFERRED_SIZE, 43, GroupLayout.PREFERRED_SIZE)
                                                                                .addPreferredGap(ComponentPlacement.UNRELATED)
                                                                                .addComponent(jLabel4)
                                                                                .addGap(2)
                                                                                .addComponent(jTextFieldDobMonth, GroupLayout.PREFERRED_SIZE, 28, GroupLayout.PREFERRED_SIZE)
                                                                                .addPreferredGap(ComponentPlacement.RELATED)
                                                                                .addComponent(jLabel3)
                                                                                .addPreferredGap(ComponentPlacement.RELATED)
                                                                                .addComponent(jTextFieldDobDay, GroupLayout.PREFERRED_SIZE, 28, GroupLayout.PREFERRED_SIZE))
                                                                        .addGroup(jFrameIdentificationDetailsLayout.createSequentialGroup()
                                                                                .addComponent(jLabel21, GroupLayout.DEFAULT_SIZE, 76, Short.MAX_VALUE)
                                                                                .addPreferredGap(ComponentPlacement.RELATED)
                                                                                .addComponent(jComboBoxDOBType, GroupLayout.PREFERRED_SIZE, GroupLayout.DEFAULT_SIZE, GroupLayout.PREFERRED_SIZE))))
                                                        .addComponent(jTextFieldEmail, GroupLayout.DEFAULT_SIZE, 355, Short.MAX_VALUE)
                                                        .addGroup(Alignment.LEADING, jFrameIdentificationDetailsLayout.createSequentialGroup()
                                                                .addComponent(mecCheckbox)
                                                                .addGap(18)
                                                                .addComponent(lrCheckbox)))))
                                .addContainerGap())
        );
        jFrameIdentificationDetailsLayout.setVerticalGroup(
                jFrameIdentificationDetailsLayout.createParallelGroup(Alignment.LEADING)
                        .addGroup(jFrameIdentificationDetailsLayout.createSequentialGroup()
                                .addContainerGap()
                                .addGroup(jFrameIdentificationDetailsLayout.createParallelGroup(Alignment.BASELINE)
                                        .addComponent(jLabelName)
                                        .addComponent(jTextFieldName, GroupLayout.PREFERRED_SIZE, GroupLayout.DEFAULT_SIZE, GroupLayout.PREFERRED_SIZE)
                                        .addComponent(jSpinnerNameMatchValue, GroupLayout.PREFERRED_SIZE, GroupLayout.DEFAULT_SIZE, GroupLayout.PREFERRED_SIZE)
                                        .addComponent(jLabel10))
                                .addPreferredGap(ComponentPlacement.RELATED)
                                .addGroup(jFrameIdentificationDetailsLayout.createParallelGroup(Alignment.BASELINE)
                                        .addComponent(jLabel6)
                                        .addComponent(jRadioButtonNameMatchExact)
                                        .addComponent(jRadioButtonNameMatchPartial)
                                        .addComponent(jRadioFuzzyName))
                                .addGroup(jFrameIdentificationDetailsLayout.createParallelGroup(Alignment.LEADING)
                                        .addGroup(jFrameIdentificationDetailsLayout.createParallelGroup(Alignment.LEADING)
                                                .addGroup(jFrameIdentificationDetailsLayout.createSequentialGroup()
                                                        .addPreferredGap(ComponentPlacement.RELATED, 6, Short.MAX_VALUE)
                                                        .addComponent(jTextFieldNameLocal, GroupLayout.PREFERRED_SIZE, GroupLayout.DEFAULT_SIZE, GroupLayout.PREFERRED_SIZE)
                                                        .addPreferredGap(ComponentPlacement.UNRELATED))
                                                .addGroup(jFrameIdentificationDetailsLayout.createSequentialGroup()
                                                        .addPreferredGap(ComponentPlacement.RELATED)
                                                        .addComponent(jLabelName1)
                                                        .addPreferredGap(ComponentPlacement.RELATED)))
                                        .addGroup(jFrameIdentificationDetailsLayout.createSequentialGroup()
                                                .addPreferredGap(ComponentPlacement.RELATED)
                                                .addGroup(jFrameIdentificationDetailsLayout.createParallelGroup(Alignment.BASELINE)
                                                        .addComponent(jLabel17)
                                                        .addComponent(jSpinnerNameMatchValueLocal, GroupLayout.PREFERRED_SIZE, GroupLayout.DEFAULT_SIZE, GroupLayout.PREFERRED_SIZE))
                                                .addPreferredGap(ComponentPlacement.RELATED)))
                                .addGroup(jFrameIdentificationDetailsLayout.createParallelGroup(Alignment.LEADING)
                                        .addGroup(jFrameIdentificationDetailsLayout.createSequentialGroup()
                                                .addGroup(jFrameIdentificationDetailsLayout.createParallelGroup(Alignment.LEADING)
                                                        .addGroup(jFrameIdentificationDetailsLayout.createSequentialGroup()
                                                                .addPreferredGap(ComponentPlacement.RELATED)
                                                                .addGroup(jFrameIdentificationDetailsLayout.createParallelGroup(Alignment.BASELINE)
                                                                        .addComponent(jLabelGener)
                                                                        .addComponent(jComboGender, GroupLayout.PREFERRED_SIZE, GroupLayout.DEFAULT_SIZE, GroupLayout.PREFERRED_SIZE)))
                                                        .addGroup(jFrameIdentificationDetailsLayout.createSequentialGroup()
                                                                .addPreferredGap(ComponentPlacement.UNRELATED)
                                                                .addGroup(jFrameIdentificationDetailsLayout.createParallelGroup(Alignment.TRAILING)
                                                                        .addComponent(jTextFieldAge, GroupLayout.PREFERRED_SIZE, GroupLayout.DEFAULT_SIZE, GroupLayout.PREFERRED_SIZE)
                                                                        .addComponent(jLabelAge))))
                                                .addPreferredGap(ComponentPlacement.RELATED)
                                                .addGroup(jFrameIdentificationDetailsLayout.createParallelGroup(Alignment.LEADING)
                                                        .addGroup(jFrameIdentificationDetailsLayout.createParallelGroup(Alignment.BASELINE)
                                                                .addComponent(jTextFieldPhone, GroupLayout.PREFERRED_SIZE, GroupLayout.DEFAULT_SIZE, GroupLayout.PREFERRED_SIZE)
                                                                .addComponent(jLabelPhone)
                                                                .addComponent(jLabel4)
                                                                .addComponent(jTextFieldDobDay, GroupLayout.PREFERRED_SIZE, GroupLayout.DEFAULT_SIZE, GroupLayout.PREFERRED_SIZE)
                                                                .addComponent(jLabel3))
                                                        .addGroup(jFrameIdentificationDetailsLayout.createParallelGroup(Alignment.BASELINE)
                                                                .addComponent(jLabelDob)
                                                                .addComponent(jTextFieldDobYear, GroupLayout.PREFERRED_SIZE, GroupLayout.DEFAULT_SIZE, GroupLayout.PREFERRED_SIZE))))
                                        .addGroup(jFrameIdentificationDetailsLayout.createSequentialGroup()
                                                .addGroup(jFrameIdentificationDetailsLayout.createParallelGroup(Alignment.BASELINE)
                                                        .addComponent(jComboBoxDOBType, GroupLayout.PREFERRED_SIZE, GroupLayout.DEFAULT_SIZE, GroupLayout.PREFERRED_SIZE)
                                                        .addComponent(jLabel21))
                                                .addPreferredGap(ComponentPlacement.RELATED)
                                                .addComponent(jTextFieldDobMonth, GroupLayout.PREFERRED_SIZE, GroupLayout.DEFAULT_SIZE, GroupLayout.PREFERRED_SIZE)))
                                .addPreferredGap(ComponentPlacement.RELATED)
                                .addGroup(jFrameIdentificationDetailsLayout.createParallelGroup(Alignment.BASELINE)
                                        .addComponent(jLabelEmail)
                                        .addComponent(jTextFieldEmail, GroupLayout.PREFERRED_SIZE, GroupLayout.DEFAULT_SIZE, GroupLayout.PREFERRED_SIZE))
                                .addPreferredGap(ComponentPlacement.RELATED)
                                .addGroup(jFrameIdentificationDetailsLayout.createParallelGroup(Alignment.BASELINE)
                                        .addComponent(mecCheckbox)
                                        .addComponent(lrCheckbox)))
        );
        jFrameIdentificationDetails
                .setLayout(jFrameIdentificationDetailsLayout);

        javax.swing.GroupLayout jPanelIdentificationDetailsLayout = new javax.swing.GroupLayout(
                jPanelIdentificationDetails);
        jPanelIdentificationDetailsLayout.setHorizontalGroup(
                jPanelIdentificationDetailsLayout.createParallelGroup(Alignment.LEADING)
                        .addGroup(jPanelIdentificationDetailsLayout.createSequentialGroup()
                                .addComponent(jFrameIdentificationDetails, GroupLayout.PREFERRED_SIZE, GroupLayout.DEFAULT_SIZE, GroupLayout.PREFERRED_SIZE)
                                .addContainerGap(GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE))
        );
        jPanelIdentificationDetailsLayout.setVerticalGroup(
                jPanelIdentificationDetailsLayout.createParallelGroup(Alignment.LEADING)
                        .addGroup(jPanelIdentificationDetailsLayout.createSequentialGroup()
                                .addComponent(jFrameIdentificationDetails, GroupLayout.PREFERRED_SIZE, GroupLayout.DEFAULT_SIZE, GroupLayout.PREFERRED_SIZE)
                                .addContainerGap(GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE))
        );
        jPanelIdentificationDetails
                .setLayout(jPanelIdentificationDetailsLayout);

        jPanelAddress.setBackground(new java.awt.Color(255, 255, 255));
        jPanelAddress.setBorder(javax.swing.BorderFactory.createTitledBorder(
                null, "Personal Address (Pa)",
                javax.swing.border.TitledBorder.DEFAULT_JUSTIFICATION,
                javax.swing.border.TitledBorder.DEFAULT_POSITION,
                new java.awt.Font("Tahoma", 1, 11))); // NOI18N
        jPanelAddress.setToolTipText("");

        jFrameAddressDetails.setBackground(new java.awt.Color(255, 255, 255));
        jFrameAddressDetails.setBorder(new javax.swing.border.LineBorder(
                new java.awt.Color(255, 204, 102), 1, true));

        jLabelCareof.setText("Care Of");

        jLabelBuilding.setText("Building");

        jLabelLandmark.setText("Landmark");

        jLabelStreet.setText("Street");

        jLabelLocality.setText("Locality");

        jTextFieldLocality
                .addActionListener(new java.awt.event.ActionListener() {
                    public void actionPerformed(java.awt.event.ActionEvent evt) {
                        jTextFieldLocalityActionPerformed(evt);
                    }
                });

        jLabeDistrict.setText("District");

        jLabelState.setText("State");

        jLabelPincode.setText("Pincode");

        jLabelLocality1.setText("Village/Town/City");

        try {
            jTextFieldPincode
                    .setFormatterFactory(new javax.swing.text.DefaultFormatterFactory(
                            new javax.swing.text.MaskFormatter("######")));
        } catch (java.text.ParseException ex) {
            ex.printStackTrace();
        }

        jLabel19.setText("PO Name");

        jLabel20.setText("Subdist");

        javax.swing.GroupLayout jFrameAddressDetailsLayout = new javax.swing.GroupLayout(
                jFrameAddressDetails);
        jFrameAddressDetails.setLayout(jFrameAddressDetailsLayout);
        jFrameAddressDetailsLayout
                .setHorizontalGroup(jFrameAddressDetailsLayout
                        .createParallelGroup(
                                javax.swing.GroupLayout.Alignment.LEADING)
                        .addGroup(
                                jFrameAddressDetailsLayout
                                        .createSequentialGroup()
                                        .addContainerGap()
                                        .addGroup(
                                                jFrameAddressDetailsLayout
                                                        .createParallelGroup(
                                                                javax.swing.GroupLayout.Alignment.TRAILING)
                                                        .addComponent(
                                                                jLabeDistrict)
                                                        .addComponent(
                                                                jLabelCareof)
                                                        .addComponent(
                                                                jLabelLocality1)
                                                        .addComponent(
                                                                jLabelLandmark)
                                                        .addComponent(
                                                                jLabelLocality))
                                        .addPreferredGap(
                                                javax.swing.LayoutStyle.ComponentPlacement.RELATED)
                                        .addGroup(
                                                jFrameAddressDetailsLayout
                                                        .createParallelGroup(
                                                                javax.swing.GroupLayout.Alignment.LEADING)
                                                        .addComponent(
                                                                jTextFieldDistrict,
                                                                javax.swing.GroupLayout.Alignment.TRAILING,
                                                                javax.swing.GroupLayout.DEFAULT_SIZE,
                                                                214,
                                                                Short.MAX_VALUE)
                                                        .addComponent(
                                                                jTextFieldCareOf,
                                                                javax.swing.GroupLayout.DEFAULT_SIZE,
                                                                214,
                                                                Short.MAX_VALUE)
                                                        .addComponent(
                                                                jTextFieldLandmark,
                                                                javax.swing.GroupLayout.DEFAULT_SIZE,
                                                                214,
                                                                Short.MAX_VALUE)
                                                        .addComponent(
                                                                jTextFieldLocality,
                                                                javax.swing.GroupLayout.DEFAULT_SIZE,
                                                                214,
                                                                Short.MAX_VALUE)
                                                        .addComponent(
                                                                jTextFieldVtc,
                                                                javax.swing.GroupLayout.DEFAULT_SIZE,
                                                                214,
                                                                Short.MAX_VALUE))
                                        .addGroup(
                                                jFrameAddressDetailsLayout
                                                        .createParallelGroup(
                                                                javax.swing.GroupLayout.Alignment.LEADING)
                                                        .addGroup(
                                                                jFrameAddressDetailsLayout
                                                                        .createSequentialGroup()
                                                                        .addGap(14,
                                                                                14,
                                                                                14)
                                                                        .addGroup(
                                                                                jFrameAddressDetailsLayout
                                                                                        .createParallelGroup(
                                                                                                javax.swing.GroupLayout.Alignment.LEADING)
                                                                                        .addComponent(
                                                                                                jLabelState,
                                                                                                javax.swing.GroupLayout.Alignment.TRAILING)
                                                                                        .addGroup(
                                                                                                javax.swing.GroupLayout.Alignment.TRAILING,
                                                                                                jFrameAddressDetailsLayout
                                                                                                        .createSequentialGroup()
                                                                                                        .addGroup(
                                                                                                                jFrameAddressDetailsLayout
                                                                                                                        .createParallelGroup(
                                                                                                                                javax.swing.GroupLayout.Alignment.TRAILING)
                                                                                                                        .addComponent(
                                                                                                                                jLabelStreet)
                                                                                                                        .addComponent(
                                                                                                                                jLabelBuilding)
                                                                                                                        .addComponent(
                                                                                                                                jLabel19))
                                                                                                        .addPreferredGap(
                                                                                                                javax.swing.LayoutStyle.ComponentPlacement.RELATED)))
                                                                        .addGroup(
                                                                                jFrameAddressDetailsLayout
                                                                                        .createParallelGroup(
                                                                                                javax.swing.GroupLayout.Alignment.LEADING)
                                                                                        .addComponent(
                                                                                                jTextFieldStreet,
                                                                                                javax.swing.GroupLayout.DEFAULT_SIZE,
                                                                                                218,
                                                                                                Short.MAX_VALUE)
                                                                                        .addGroup(
                                                                                                javax.swing.GroupLayout.Alignment.TRAILING,
                                                                                                jFrameAddressDetailsLayout
                                                                                                        .createSequentialGroup()
                                                                                                        .addComponent(
                                                                                                                jTextFieldState,
                                                                                                                javax.swing.GroupLayout.PREFERRED_SIZE,
                                                                                                                91,
                                                                                                                javax.swing.GroupLayout.PREFERRED_SIZE)
                                                                                                        .addPreferredGap(
                                                                                                                javax.swing.LayoutStyle.ComponentPlacement.UNRELATED)
                                                                                                        .addComponent(
                                                                                                                jLabelPincode)
                                                                                                        .addPreferredGap(
                                                                                                                javax.swing.LayoutStyle.ComponentPlacement.RELATED)
                                                                                                        .addComponent(
                                                                                                                jTextFieldPincode,
                                                                                                                javax.swing.GroupLayout.PREFERRED_SIZE,
                                                                                                                76,
                                                                                                                javax.swing.GroupLayout.PREFERRED_SIZE))
                                                                                        .addComponent(
                                                                                                jTextFieldBuilding,
                                                                                                javax.swing.GroupLayout.Alignment.TRAILING,
                                                                                                javax.swing.GroupLayout.DEFAULT_SIZE,
                                                                                                218,
                                                                                                Short.MAX_VALUE)
                                                                                        .addComponent(
                                                                                                jTextFieldPOName,
                                                                                                javax.swing.GroupLayout.DEFAULT_SIZE,
                                                                                                218,
                                                                                                Short.MAX_VALUE)))
                                                        .addGroup(
                                                                jFrameAddressDetailsLayout
                                                                        .createSequentialGroup()
                                                                        .addGap(18,
                                                                                18,
                                                                                18)
                                                                        .addComponent(
                                                                                jLabel20)
                                                                        .addPreferredGap(
                                                                                javax.swing.LayoutStyle.ComponentPlacement.UNRELATED)
                                                                        .addComponent(
                                                                                jTextFieldSubdist,
                                                                                javax.swing.GroupLayout.DEFAULT_SIZE,
                                                                                217,
                                                                                Short.MAX_VALUE)))
                                        .addContainerGap()));
        jFrameAddressDetailsLayout
                .setVerticalGroup(jFrameAddressDetailsLayout
                        .createParallelGroup(
                                javax.swing.GroupLayout.Alignment.LEADING)
                        .addGroup(
                                jFrameAddressDetailsLayout
                                        .createSequentialGroup()
                                        .addContainerGap()
                                        .addGroup(
                                                jFrameAddressDetailsLayout
                                                        .createParallelGroup(
                                                                javax.swing.GroupLayout.Alignment.BASELINE)
                                                        .addComponent(
                                                                jTextFieldCareOf,
                                                                javax.swing.GroupLayout.PREFERRED_SIZE,
                                                                javax.swing.GroupLayout.DEFAULT_SIZE,
                                                                javax.swing.GroupLayout.PREFERRED_SIZE)
                                                        .addComponent(
                                                                jLabelCareof)
                                                        .addComponent(
                                                                jTextFieldBuilding,
                                                                javax.swing.GroupLayout.PREFERRED_SIZE,
                                                                javax.swing.GroupLayout.DEFAULT_SIZE,
                                                                javax.swing.GroupLayout.PREFERRED_SIZE)
                                                        .addComponent(
                                                                jLabelBuilding))
                                        .addPreferredGap(
                                                javax.swing.LayoutStyle.ComponentPlacement.RELATED)
                                        .addGroup(
                                                jFrameAddressDetailsLayout
                                                        .createParallelGroup(
                                                                javax.swing.GroupLayout.Alignment.BASELINE)
                                                        .addComponent(
                                                                jLabelLandmark)
                                                        .addComponent(
                                                                jTextFieldLandmark,
                                                                javax.swing.GroupLayout.PREFERRED_SIZE,
                                                                javax.swing.GroupLayout.DEFAULT_SIZE,
                                                                javax.swing.GroupLayout.PREFERRED_SIZE)
                                                        .addComponent(
                                                                jTextFieldStreet,
                                                                javax.swing.GroupLayout.PREFERRED_SIZE,
                                                                javax.swing.GroupLayout.DEFAULT_SIZE,
                                                                javax.swing.GroupLayout.PREFERRED_SIZE)
                                                        .addComponent(
                                                                jLabelStreet))
                                        .addPreferredGap(
                                                javax.swing.LayoutStyle.ComponentPlacement.RELATED)
                                        .addGroup(
                                                jFrameAddressDetailsLayout
                                                        .createParallelGroup(
                                                                javax.swing.GroupLayout.Alignment.BASELINE)
                                                        .addComponent(
                                                                jLabelLocality)
                                                        .addComponent(
                                                                jTextFieldLocality,
                                                                javax.swing.GroupLayout.PREFERRED_SIZE,
                                                                javax.swing.GroupLayout.DEFAULT_SIZE,
                                                                javax.swing.GroupLayout.PREFERRED_SIZE)
                                                        .addComponent(jLabel19)
                                                        .addComponent(
                                                                jTextFieldPOName,
                                                                javax.swing.GroupLayout.PREFERRED_SIZE,
                                                                javax.swing.GroupLayout.DEFAULT_SIZE,
                                                                javax.swing.GroupLayout.PREFERRED_SIZE))
                                        .addPreferredGap(
                                                javax.swing.LayoutStyle.ComponentPlacement.RELATED)
                                        .addGroup(
                                                jFrameAddressDetailsLayout
                                                        .createParallelGroup(
                                                                javax.swing.GroupLayout.Alignment.BASELINE)
                                                        .addComponent(
                                                                jLabelLocality1)
                                                        .addComponent(
                                                                jTextFieldVtc,
                                                                javax.swing.GroupLayout.PREFERRED_SIZE,
                                                                javax.swing.GroupLayout.DEFAULT_SIZE,
                                                                javax.swing.GroupLayout.PREFERRED_SIZE)
                                                        .addComponent(jLabel20)
                                                        .addComponent(
                                                                jTextFieldSubdist,
                                                                javax.swing.GroupLayout.PREFERRED_SIZE,
                                                                javax.swing.GroupLayout.DEFAULT_SIZE,
                                                                javax.swing.GroupLayout.PREFERRED_SIZE))
                                        .addPreferredGap(
                                                javax.swing.LayoutStyle.ComponentPlacement.RELATED)
                                        .addGroup(
                                                jFrameAddressDetailsLayout
                                                        .createParallelGroup(
                                                                javax.swing.GroupLayout.Alignment.BASELINE)
                                                        .addComponent(
                                                                jTextFieldPincode,
                                                                javax.swing.GroupLayout.PREFERRED_SIZE,
                                                                javax.swing.GroupLayout.DEFAULT_SIZE,
                                                                javax.swing.GroupLayout.PREFERRED_SIZE)
                                                        .addComponent(
                                                                jLabelPincode)
                                                        .addComponent(
                                                                jTextFieldState,
                                                                javax.swing.GroupLayout.PREFERRED_SIZE,
                                                                javax.swing.GroupLayout.DEFAULT_SIZE,
                                                                javax.swing.GroupLayout.PREFERRED_SIZE)
                                                        .addComponent(
                                                                jLabelState)
                                                        .addComponent(
                                                                jLabeDistrict)
                                                        .addComponent(
                                                                jTextFieldDistrict,
                                                                javax.swing.GroupLayout.PREFERRED_SIZE,
                                                                javax.swing.GroupLayout.DEFAULT_SIZE,
                                                                javax.swing.GroupLayout.PREFERRED_SIZE))
                                        .addContainerGap(
                                                javax.swing.GroupLayout.DEFAULT_SIZE,
                                                Short.MAX_VALUE)));

        jRadioButtonAddressPartialMatch.setBackground(new java.awt.Color(255,
                255, 255));
        jButtonGroupAddressMatchStrategy.add(jRadioButtonAddressPartialMatch);
        jRadioButtonAddressPartialMatch
                .setText("Partial match (not supported for Pa)");
        jRadioButtonAddressPartialMatch.setEnabled(false);

        jRadioButtonAddressExactMatch.setBackground(new java.awt.Color(255,
                255, 255));
        jButtonGroupAddressMatchStrategy.add(jRadioButtonAddressExactMatch);
        jRadioButtonAddressExactMatch.setSelected(true);
        jRadioButtonAddressExactMatch.setText("Exact match");

        jLabel7.setText("Match Strategy");

        jLabel11.setText("Match Value");

        jLabel12.setText("(not supported for Pa)");
        jLabel12.setEnabled(false);

        jSpinnerPaMatchValue.setModel(new javax.swing.SpinnerNumberModel(1, 1,
                100, 1));
        jSpinnerPaMatchValue.setEnabled(false);

        javax.swing.GroupLayout jPanelAddressLayout = new javax.swing.GroupLayout(
                jPanelAddress);
        jPanelAddress.setLayout(jPanelAddressLayout);
        jPanelAddressLayout
                .setHorizontalGroup(jPanelAddressLayout
                        .createParallelGroup(
                                javax.swing.GroupLayout.Alignment.LEADING)
                        .addGroup(
                                jPanelAddressLayout
                                        .createSequentialGroup()
                                        .addContainerGap()
                                        .addGroup(
                                                jPanelAddressLayout
                                                        .createParallelGroup(
                                                                javax.swing.GroupLayout.Alignment.LEADING)
                                                        .addComponent(
                                                                jFrameAddressDetails,
                                                                javax.swing.GroupLayout.PREFERRED_SIZE,
                                                                javax.swing.GroupLayout.DEFAULT_SIZE,
                                                                javax.swing.GroupLayout.PREFERRED_SIZE)
                                                        .addGroup(
                                                                jPanelAddressLayout
                                                                        .createSequentialGroup()
                                                                        .addGroup(
                                                                                jPanelAddressLayout
                                                                                        .createParallelGroup(
                                                                                                javax.swing.GroupLayout.Alignment.LEADING)
                                                                                        .addComponent(
                                                                                                jLabel7)
                                                                                        .addComponent(
                                                                                                jLabel11))
                                                                        .addGap(34,
                                                                                34,
                                                                                34)
                                                                        .addGroup(
                                                                                jPanelAddressLayout
                                                                                        .createParallelGroup(
                                                                                                javax.swing.GroupLayout.Alignment.LEADING)
                                                                                        .addGroup(
                                                                                                jPanelAddressLayout
                                                                                                        .createSequentialGroup()
                                                                                                        .addComponent(
                                                                                                                jRadioButtonAddressExactMatch)
                                                                                                        .addPreferredGap(
                                                                                                                javax.swing.LayoutStyle.ComponentPlacement.UNRELATED)
                                                                                                        .addComponent(
                                                                                                                jRadioButtonAddressPartialMatch))
                                                                                        .addGroup(
                                                                                                jPanelAddressLayout
                                                                                                        .createSequentialGroup()
                                                                                                        .addComponent(
                                                                                                                jSpinnerPaMatchValue,
                                                                                                                javax.swing.GroupLayout.PREFERRED_SIZE,
                                                                                                                46,
                                                                                                                javax.swing.GroupLayout.PREFERRED_SIZE)
                                                                                                        .addPreferredGap(
                                                                                                                javax.swing.LayoutStyle.ComponentPlacement.UNRELATED)
                                                                                                        .addComponent(
                                                                                                                jLabel12)))))
                                        .addContainerGap(18, Short.MAX_VALUE)));
        jPanelAddressLayout
                .setVerticalGroup(jPanelAddressLayout
                        .createParallelGroup(
                                javax.swing.GroupLayout.Alignment.LEADING)
                        .addGroup(
                                javax.swing.GroupLayout.Alignment.TRAILING,
                                jPanelAddressLayout
                                        .createSequentialGroup()
                                        .addComponent(
                                                jFrameAddressDetails,
                                                javax.swing.GroupLayout.PREFERRED_SIZE,
                                                javax.swing.GroupLayout.DEFAULT_SIZE,
                                                javax.swing.GroupLayout.PREFERRED_SIZE)
                                        .addPreferredGap(
                                                javax.swing.LayoutStyle.ComponentPlacement.RELATED)
                                        .addGroup(
                                                jPanelAddressLayout
                                                        .createParallelGroup(
                                                                javax.swing.GroupLayout.Alignment.BASELINE)
                                                        .addComponent(
                                                                jRadioButtonAddressPartialMatch)
                                                        .addComponent(
                                                                jRadioButtonAddressExactMatch)
                                                        .addComponent(jLabel7))
                                        .addPreferredGap(
                                                javax.swing.LayoutStyle.ComponentPlacement.RELATED,
                                                16, Short.MAX_VALUE)
                                        .addGroup(
                                                jPanelAddressLayout
                                                        .createParallelGroup(
                                                                javax.swing.GroupLayout.Alignment.BASELINE)
                                                        .addComponent(jLabel11)
                                                        .addComponent(jLabel12)
                                                        .addComponent(
                                                                jSpinnerPaMatchValue,
                                                                javax.swing.GroupLayout.PREFERRED_SIZE,
                                                                javax.swing.GroupLayout.DEFAULT_SIZE,
                                                                javax.swing.GroupLayout.PREFERRED_SIZE))));

        jPanelAuthParameters.setBackground(new java.awt.Color(255, 255, 255));
        jPanelAuthParameters.setBorder(javax.swing.BorderFactory
                .createTitledBorder(null, "PIN values (Pv)",
                        javax.swing.border.TitledBorder.DEFAULT_JUSTIFICATION,
                        javax.swing.border.TitledBorder.DEFAULT_POSITION,
                        new java.awt.Font("Tahoma", 1, 11))); // NOI18N

        jLabelPIN.setText("PIN");

        jLabelPIN1.setText("OTP");

        javax.swing.GroupLayout jPanelAuthParametersLayout = new javax.swing.GroupLayout(
                jPanelAuthParameters);
        jPanelAuthParameters.setLayout(jPanelAuthParametersLayout);
        jPanelAuthParametersLayout
                .setHorizontalGroup(jPanelAuthParametersLayout
                        .createParallelGroup(
                                javax.swing.GroupLayout.Alignment.LEADING)
                        .addGroup(
                                jPanelAuthParametersLayout
                                        .createSequentialGroup()
                                        .addContainerGap()
                                        .addComponent(jLabelPIN)
                                        .addPreferredGap(
                                                javax.swing.LayoutStyle.ComponentPlacement.RELATED)
                                        .addComponent(
                                                jPasswordFieldPIN,
                                                javax.swing.GroupLayout.PREFERRED_SIZE,
                                                60,
                                                javax.swing.GroupLayout.PREFERRED_SIZE)
                                        .addPreferredGap(
                                                javax.swing.LayoutStyle.ComponentPlacement.RELATED,
                                                24, Short.MAX_VALUE)
                                        .addComponent(jLabelPIN1)
                                        .addPreferredGap(
                                                javax.swing.LayoutStyle.ComponentPlacement.RELATED)
                                        .addComponent(
                                                jPasswordFieldOTP,
                                                javax.swing.GroupLayout.PREFERRED_SIZE,
                                                60,
                                                javax.swing.GroupLayout.PREFERRED_SIZE)
                                        .addContainerGap()));
        jPanelAuthParametersLayout
                .setVerticalGroup(jPanelAuthParametersLayout
                        .createParallelGroup(
                                javax.swing.GroupLayout.Alignment.LEADING)
                        .addGroup(
                                jPanelAuthParametersLayout
                                        .createSequentialGroup()
                                        .addGroup(
                                                jPanelAuthParametersLayout
                                                        .createParallelGroup(
                                                                javax.swing.GroupLayout.Alignment.BASELINE)
                                                        .addComponent(
                                                                jPasswordFieldPIN,
                                                                javax.swing.GroupLayout.PREFERRED_SIZE,
                                                                javax.swing.GroupLayout.DEFAULT_SIZE,
                                                                javax.swing.GroupLayout.PREFERRED_SIZE)
                                                        .addComponent(
                                                                jPasswordFieldOTP,
                                                                javax.swing.GroupLayout.PREFERRED_SIZE,
                                                                javax.swing.GroupLayout.DEFAULT_SIZE,
                                                                javax.swing.GroupLayout.PREFERRED_SIZE)
                                                        .addComponent(
                                                                jLabelPIN1)
                                                        .addComponent(jLabelPIN))
                                        .addContainerGap()));

        try {
            jFormattedTextFieldAADHAAR1
                    .setFormatterFactory(new javax.swing.text.DefaultFormatterFactory(
                            new javax.swing.text.MaskFormatter("############")));
        } catch (java.text.ParseException ex) {
            ex.printStackTrace();
        }
        jFormattedTextFieldAADHAAR1
                .addActionListener(new java.awt.event.ActionListener() {
                    public void actionPerformed(java.awt.event.ActionEvent evt) {
                        jFormattedTextFieldAADHAAR1ActionPerformed(evt);
                    }
                });

        jPanelAuthStatus.setBackground(new java.awt.Color(255, 255, 255));
        jPanelAuthStatus.setBorder(javax.swing.BorderFactory
                .createTitledBorder(null, "KYC response Status",
                        javax.swing.border.TitledBorder.DEFAULT_JUSTIFICATION,
                        javax.swing.border.TitledBorder.DEFAULT_POSITION,
                        new java.awt.Font("Tahoma", 1, 11))); // NOI18N
        jPanelAuthStatus.setPreferredSize(new java.awt.Dimension(100, 100));

        jLabelAuthStatus.setBackground(new java.awt.Color(255, 153, 51));
        jLabelAuthStatus
                .setHorizontalAlignment(javax.swing.SwingConstants.CENTER);
        jLabelAuthStatus.setIcon(new javax.swing.ImageIcon(getClass()
                .getResource("/unknown.png"))); // NOI18N
        jLabelAuthStatus.setText("XML");
        jLabelAuthStatus
                .setHorizontalTextPosition(javax.swing.SwingConstants.CENTER);
        jLabelAuthStatus
                .setVerticalTextPosition(javax.swing.SwingConstants.BOTTOM);

        jLabelAuthStatusTextXML.setText("Auth Status Here....");
        jLabelAuthStatusTextXML
                .setHorizontalTextPosition(javax.swing.SwingConstants.CENTER);

        jButtonValidateResponse.setText("Validate Response");
        jButtonValidateResponse
                .addActionListener(new java.awt.event.ActionListener() {
                    public void actionPerformed(java.awt.event.ActionEvent evt) {
                        jButtonValidateResponseActionPerformed(evt);
                    }
                });
        jButtonValidateResponse.setVisible(false);
        jLabelAuthStatusProto.setBackground(new java.awt.Color(255, 153, 51));
        jLabelAuthStatusProto
                .setHorizontalAlignment(javax.swing.SwingConstants.CENTER);
        jLabelAuthStatusProto.setIcon(new javax.swing.ImageIcon(getClass()
                .getResource("/unknown.png"))); // NOI18N
        jLabelAuthStatusProto.setText("Proto");
        jLabelAuthStatusProto
                .setHorizontalTextPosition(javax.swing.SwingConstants.CENTER);
        jLabelAuthStatusProto
                .setVerticalTextPosition(javax.swing.SwingConstants.BOTTOM);

        jLabelAuthStatusTextProto.setText("Auth Status Here....");
        jLabelAuthStatusTextProto
                .setHorizontalTextPosition(javax.swing.SwingConstants.CENTER);

        javax.swing.GroupLayout jPanelAuthStatusLayout = new javax.swing.GroupLayout(
                jPanelAuthStatus);
        jPanelAuthStatus.setLayout(jPanelAuthStatusLayout);
        jPanelAuthStatusLayout
                .setHorizontalGroup(jPanelAuthStatusLayout
                        .createParallelGroup(
                                javax.swing.GroupLayout.Alignment.LEADING)
                        .addGroup(
                                jPanelAuthStatusLayout
                                        .createSequentialGroup()
                                        .addContainerGap()
                                        .addGroup(
                                                jPanelAuthStatusLayout
                                                        .createParallelGroup(
                                                                javax.swing.GroupLayout.Alignment.LEADING)
                                                        .addGroup(
                                                                jPanelAuthStatusLayout
                                                                        .createSequentialGroup()
                                                                        .addGroup(
                                                                                jPanelAuthStatusLayout
                                                                                        .createParallelGroup(
                                                                                                javax.swing.GroupLayout.Alignment.LEADING)
                                                                                        .addGroup(
                                                                                                jPanelAuthStatusLayout
                                                                                                        .createSequentialGroup()
                                                                                                        .addComponent(
                                                                                                                jLabelAuthStatus,
                                                                                                                javax.swing.GroupLayout.PREFERRED_SIZE,
                                                                                                                116,
                                                                                                                javax.swing.GroupLayout.PREFERRED_SIZE)
                                                                                                        .addPreferredGap(
                                                                                                                javax.swing.LayoutStyle.ComponentPlacement.UNRELATED)
                                                                                                        .addComponent(
                                                                                                                jLabelAuthStatusProto,
                                                                                                                javax.swing.GroupLayout.PREFERRED_SIZE,
                                                                                                                116,
                                                                                                                javax.swing.GroupLayout.PREFERRED_SIZE))
                                                                                        .addComponent(
                                                                                                jLabelAuthStatusTextXML,
                                                                                                javax.swing.GroupLayout.PREFERRED_SIZE,
                                                                                                245,
                                                                                                javax.swing.GroupLayout.PREFERRED_SIZE)
                                                                                        .addComponent(
                                                                                                jLabelAuthStatusTextProto,
                                                                                                javax.swing.GroupLayout.PREFERRED_SIZE,
                                                                                                245,
                                                                                                javax.swing.GroupLayout.PREFERRED_SIZE))
                                                                        .addContainerGap(
                                                                                29,
                                                                                Short.MAX_VALUE))
                                                        .addGroup(
                                                                javax.swing.GroupLayout.Alignment.TRAILING,
                                                                jPanelAuthStatusLayout
                                                                        .createSequentialGroup()
                                                                        .addComponent(
                                                                                jButtonValidateResponse,
                                                                                javax.swing.GroupLayout.PREFERRED_SIZE,
                                                                                131,
                                                                                javax.swing.GroupLayout.PREFERRED_SIZE)
                                                                        .addGap(64,
                                                                                64,
                                                                                64)))));
        jPanelAuthStatusLayout
                .setVerticalGroup(jPanelAuthStatusLayout
                        .createParallelGroup(
                                javax.swing.GroupLayout.Alignment.LEADING)
                        .addGroup(
                                jPanelAuthStatusLayout
                                        .createSequentialGroup()
                                        .addContainerGap()
                                        .addGroup(
                                                jPanelAuthStatusLayout
                                                        .createParallelGroup(
                                                                javax.swing.GroupLayout.Alignment.TRAILING)
                                                        .addComponent(
                                                                jLabelAuthStatus,
                                                                javax.swing.GroupLayout.PREFERRED_SIZE,
                                                                121,
                                                                javax.swing.GroupLayout.PREFERRED_SIZE)
                                                        .addComponent(
                                                                jLabelAuthStatusProto,
                                                                javax.swing.GroupLayout.PREFERRED_SIZE,
                                                                121,
                                                                javax.swing.GroupLayout.PREFERRED_SIZE))
                                        .addPreferredGap(
                                                javax.swing.LayoutStyle.ComponentPlacement.UNRELATED)
                                        .addComponent(jLabelAuthStatusTextXML)
                                        .addPreferredGap(
                                                javax.swing.LayoutStyle.ComponentPlacement.RELATED,
                                                javax.swing.GroupLayout.DEFAULT_SIZE,
                                                Short.MAX_VALUE)
                                        .addComponent(jLabelAuthStatusTextProto)
                                        .addGap(11, 11, 11)
                                        .addComponent(jButtonValidateResponse))
                );

        jPanelBiometricsOuter.setBackground(new java.awt.Color(255, 255, 255));
        jPanelBiometricsOuter.setBorder(javax.swing.BorderFactory
                .createTitledBorder(null, "Biometrics (Bios)",
                        javax.swing.border.TitledBorder.DEFAULT_JUSTIFICATION,
                        javax.swing.border.TitledBorder.DEFAULT_POSITION,
                        new java.awt.Font("Tahoma", 1, 11))); // NOI18N
        jPanelBiometricsOuter.setToolTipText("Scan to capture finger minutiae");

        jPanelBiometric.setBackground(new java.awt.Color(255, 255, 204));
        jPanelBiometric.setBorder(javax.swing.BorderFactory
                .createLineBorder(new java.awt.Color(255, 204, 102)));

        javax.swing.GroupLayout jPanelBiometricLayout = new javax.swing.GroupLayout(
                jPanelBiometric);
        jPanelBiometric.setLayout(jPanelBiometricLayout);
        jPanelBiometricLayout.setHorizontalGroup(jPanelBiometricLayout
                .createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
                .addComponent(jLabelBiometric,
                        javax.swing.GroupLayout.PREFERRED_SIZE, 113,
                        javax.swing.GroupLayout.PREFERRED_SIZE));
        jPanelBiometricLayout.setVerticalGroup(jPanelBiometricLayout
                .createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
                .addComponent(jLabelBiometric,
                        javax.swing.GroupLayout.PREFERRED_SIZE, 94,
                        javax.swing.GroupLayout.PREFERRED_SIZE));

        jButtonScan.setText("Scan");
        jButtonScan.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                jButtonScanActionPerformed(evt);
            }
        });

        jComboBiometricPosition.setModel(new javax.swing.DefaultComboBoxModel(
                new String[]{"Select", "UNKNOWN", "------------------",
                    "LEFT_IRIS", "RIGHT_IRIS", "------------------",
                    "LEFT_INDEX", "LEFT_LITTLE", "LEFT_MIDDLE",
                    "LEFT_RING", "LEFT_THUMB", "------------------",
                    "RIGHT_INDEX", "RIGHT_LITTLE", "RIGHT_MIDDLE",
                    "RIGHT_RING", "RIGHT_THUMB"}));

        jButton1.setText("Browse");
        jButton1.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                jButton1ActionPerformed(evt);
            }
        });

        javax.swing.GroupLayout jPanelBiometricsOuterLayout = new javax.swing.GroupLayout(
                jPanelBiometricsOuter);
        jPanelBiometricsOuter.setLayout(jPanelBiometricsOuterLayout);
        jPanelBiometricsOuterLayout
                .setHorizontalGroup(jPanelBiometricsOuterLayout
                        .createParallelGroup(
                                javax.swing.GroupLayout.Alignment.LEADING)
                        .addGroup(
                                jPanelBiometricsOuterLayout
                                        .createSequentialGroup()
                                        .addContainerGap(
                                                javax.swing.GroupLayout.DEFAULT_SIZE,
                                                Short.MAX_VALUE)
                                        .addGroup(
                                                jPanelBiometricsOuterLayout
                                                        .createParallelGroup(
                                                                javax.swing.GroupLayout.Alignment.TRAILING,
                                                                false)
                                                        .addComponent(
                                                                jComboBiometricPosition,
                                                                javax.swing.GroupLayout.Alignment.LEADING,
                                                                0,
                                                                javax.swing.GroupLayout.DEFAULT_SIZE,
                                                                Short.MAX_VALUE)
                                                        .addComponent(
                                                                jPanelBiometric,
                                                                javax.swing.GroupLayout.Alignment.LEADING,
                                                                javax.swing.GroupLayout.DEFAULT_SIZE,
                                                                javax.swing.GroupLayout.DEFAULT_SIZE,
                                                                Short.MAX_VALUE))
                                        .addPreferredGap(
                                                javax.swing.LayoutStyle.ComponentPlacement.UNRELATED)
                                        .addGroup(
                                                jPanelBiometricsOuterLayout
                                                        .createParallelGroup(
                                                                javax.swing.GroupLayout.Alignment.LEADING)
                                                        .addComponent(jButton1)
                                                        .addComponent(
                                                                jButtonScan))
                                        .addContainerGap()));
        jPanelBiometricsOuterLayout
                .setVerticalGroup(jPanelBiometricsOuterLayout
                        .createParallelGroup(
                                javax.swing.GroupLayout.Alignment.LEADING)
                        .addGroup(
                                javax.swing.GroupLayout.Alignment.TRAILING,
                                jPanelBiometricsOuterLayout
                                        .createSequentialGroup()
                                        .addComponent(
                                                jComboBiometricPosition,
                                                javax.swing.GroupLayout.PREFERRED_SIZE,
                                                javax.swing.GroupLayout.DEFAULT_SIZE,
                                                javax.swing.GroupLayout.PREFERRED_SIZE)
                                        .addPreferredGap(
                                                javax.swing.LayoutStyle.ComponentPlacement.RELATED,
                                                javax.swing.GroupLayout.DEFAULT_SIZE,
                                                Short.MAX_VALUE)
                                        .addGroup(
                                                jPanelBiometricsOuterLayout
                                                        .createParallelGroup(
                                                                javax.swing.GroupLayout.Alignment.LEADING)
                                                        .addGroup(
                                                                jPanelBiometricsOuterLayout
                                                                        .createSequentialGroup()
                                                                        .addComponent(
                                                                                jButtonScan)
                                                                        .addPreferredGap(
                                                                                javax.swing.LayoutStyle.ComponentPlacement.RELATED)
                                                                        .addComponent(
                                                                                jButton1))
                                                        .addComponent(
                                                                jPanelBiometric,
                                                                javax.swing.GroupLayout.PREFERRED_SIZE,
                                                                javax.swing.GroupLayout.DEFAULT_SIZE,
                                                                javax.swing.GroupLayout.PREFERRED_SIZE))
                                        .addGap(21, 21, 21)));

        jPanelPfa.setBackground(new java.awt.Color(255, 255, 255));
        jPanelPfa.setBorder(javax.swing.BorderFactory.createTitledBorder(null,
                "Personal Full Address (Pfa)",
                javax.swing.border.TitledBorder.DEFAULT_JUSTIFICATION,
                javax.swing.border.TitledBorder.DEFAULT_POSITION,
                new java.awt.Font("Tahoma", 1, 11))); // NOI18N

        jLabelPfa.setText("Address value (av)");

        jTextAreaFullAddressValue.setColumns(20);
        jTextAreaFullAddressValue.setFont(new java.awt.Font("Tahoma", 0, 11));
        jTextAreaFullAddressValue.setLineWrap(true);
        jTextAreaFullAddressValue.setRows(5);
        jTextAreaFullAddressValue.setWrapStyleWord(true);
        jTextAreaFullAddressValue.setBorder(javax.swing.BorderFactory
                .createEmptyBorder(1, 1, 1, 1));
        jScrollPane1.setColumnHeaderView(jTextAreaFullAddressValue);

        jRadioButtonPfaExactMatch.setBackground(new java.awt.Color(255, 255,
                255));
        jbuttonGroupPfaMatchStrategy.add(jRadioButtonPfaExactMatch);
        jRadioButtonPfaExactMatch.setSelected(true);
        jRadioButtonPfaExactMatch.setText("Exact Match");
        jRadioButtonPfaExactMatch
                .addActionListener(new java.awt.event.ActionListener() {
                    public void actionPerformed(java.awt.event.ActionEvent evt) {
                        jRadioButtonPfaExactMatchActionPerformed(evt);
                    }
                });

        jRadioButtonPfaPartialMatch.setBackground(new java.awt.Color(255, 255,
                255));
        jbuttonGroupPfaMatchStrategy.add(jRadioButtonPfaPartialMatch);
        jRadioButtonPfaPartialMatch.setText("Partial Match");
        jRadioButtonPfaPartialMatch
                .addActionListener(new java.awt.event.ActionListener() {
                    public void actionPerformed(java.awt.event.ActionEvent evt) {
                        jRadioButtonPfaPartialMatchActionPerformed(evt);
                    }
                });

        jLabel8.setText("Match Strategy (ms)");

        jLabel1.setText("Match Value (mv)");

        jSpinnerPfaMatchValue.setModel(new javax.swing.SpinnerNumberModel(1, 1,
                100, 1));

        jRadioAddressFuzzy.setBackground(new java.awt.Color(255, 255, 255));
        jbuttonGroupPfaMatchStrategy.add(jRadioAddressFuzzy);
        jRadioAddressFuzzy.setText("Fuzzy match");
        jRadioAddressFuzzy
                .addActionListener(new java.awt.event.ActionListener() {
                    public void actionPerformed(java.awt.event.ActionEvent evt) {
                        jRadioAddressFuzzyActionPerformed(evt);
                    }
                });

        jTextAreaFullAddressValueLocal.setColumns(20);
        jTextAreaFullAddressValueLocal.setFont(new java.awt.Font("Tahoma", 0,
                11));
        jTextAreaFullAddressValueLocal.setLineWrap(true);
        jTextAreaFullAddressValueLocal.setRows(5);
        jTextAreaFullAddressValueLocal.setWrapStyleWord(true);
        jTextAreaFullAddressValueLocal.setBorder(javax.swing.BorderFactory
                .createEmptyBorder(1, 1, 1, 1));
        jScrollPane2.setViewportView(jTextAreaFullAddressValueLocal);

        jLabelPfa1.setText("Local Address value (lav)");

        jLabel14.setText("Local Match Value (lmv)");

        jSpinnerPfaMatchValueLocal.setModel(new javax.swing.SpinnerNumberModel(
                1, 1, 100, 1));

        javax.swing.GroupLayout jPanelPfaLayout = new javax.swing.GroupLayout(
                jPanelPfa);
        jPanelPfa.setLayout(jPanelPfaLayout);
        jPanelPfaLayout
                .setHorizontalGroup(jPanelPfaLayout
                        .createParallelGroup(
                                javax.swing.GroupLayout.Alignment.LEADING)
                        .addGroup(
                                jPanelPfaLayout
                                        .createSequentialGroup()
                                        .addContainerGap()
                                        .addGroup(
                                                jPanelPfaLayout
                                                        .createParallelGroup(
                                                                javax.swing.GroupLayout.Alignment.LEADING)
                                                        .addComponent(
                                                                jScrollPane2,
                                                                javax.swing.GroupLayout.DEFAULT_SIZE,
                                                                274,
                                                                Short.MAX_VALUE)
                                                        .addGroup(
                                                                jPanelPfaLayout
                                                                        .createSequentialGroup()
                                                                        .addComponent(
                                                                                jRadioButtonPfaExactMatch)
                                                                        .addPreferredGap(
                                                                                javax.swing.LayoutStyle.ComponentPlacement.UNRELATED)
                                                                        .addComponent(
                                                                                jRadioButtonPfaPartialMatch)
                                                                        .addPreferredGap(
                                                                                javax.swing.LayoutStyle.ComponentPlacement.RELATED)
                                                                        .addComponent(
                                                                                jRadioAddressFuzzy))
                                                        .addComponent(
                                                                jLabel8,
                                                                javax.swing.GroupLayout.PREFERRED_SIZE,
                                                                101,
                                                                javax.swing.GroupLayout.PREFERRED_SIZE)
                                                        .addGroup(
                                                                jPanelPfaLayout
                                                                        .createSequentialGroup()
                                                                        .addComponent(
                                                                                jLabelPfa)
                                                                        .addGap(52,
                                                                                52,
                                                                                52)
                                                                        .addComponent(
                                                                                jLabel1)
                                                                        .addPreferredGap(
                                                                                javax.swing.LayoutStyle.ComponentPlacement.RELATED)
                                                                        .addComponent(
                                                                                jSpinnerPfaMatchValue,
                                                                                javax.swing.GroupLayout.PREFERRED_SIZE,
                                                                                44,
                                                                                javax.swing.GroupLayout.PREFERRED_SIZE))
                                                        .addGroup(
                                                                jPanelPfaLayout
                                                                        .createSequentialGroup()
                                                                        .addComponent(
                                                                                jLabel14)
                                                                        .addPreferredGap(
                                                                                javax.swing.LayoutStyle.ComponentPlacement.RELATED)
                                                                        .addComponent(
                                                                                jSpinnerPfaMatchValueLocal,
                                                                                javax.swing.GroupLayout.PREFERRED_SIZE,
                                                                                44,
                                                                                javax.swing.GroupLayout.PREFERRED_SIZE))
                                                        .addComponent(
                                                                jLabelPfa1)
                                                        .addComponent(
                                                                jScrollPane1,
                                                                javax.swing.GroupLayout.DEFAULT_SIZE,
                                                                274,
                                                                Short.MAX_VALUE))
                                        .addContainerGap()));
        jPanelPfaLayout
                .setVerticalGroup(jPanelPfaLayout
                        .createParallelGroup(
                                javax.swing.GroupLayout.Alignment.LEADING)
                        .addGroup(
                                jPanelPfaLayout
                                        .createSequentialGroup()
                                        .addComponent(jLabel8)
                                        .addPreferredGap(
                                                javax.swing.LayoutStyle.ComponentPlacement.RELATED)
                                        .addGroup(
                                                jPanelPfaLayout
                                                        .createParallelGroup(
                                                                javax.swing.GroupLayout.Alignment.BASELINE)
                                                        .addComponent(
                                                                jRadioButtonPfaExactMatch)
                                                        .addComponent(
                                                                jRadioAddressFuzzy)
                                                        .addComponent(
                                                                jRadioButtonPfaPartialMatch))
                                        .addGap(3, 3, 3)
                                        .addGroup(
                                                jPanelPfaLayout
                                                        .createParallelGroup(
                                                                javax.swing.GroupLayout.Alignment.TRAILING)
                                                        .addGroup(
                                                                jPanelPfaLayout
                                                                        .createParallelGroup(
                                                                                javax.swing.GroupLayout.Alignment.BASELINE)
                                                                        .addComponent(
                                                                                jLabel1)
                                                                        .addComponent(
                                                                                jSpinnerPfaMatchValue,
                                                                                javax.swing.GroupLayout.PREFERRED_SIZE,
                                                                                javax.swing.GroupLayout.DEFAULT_SIZE,
                                                                                javax.swing.GroupLayout.PREFERRED_SIZE))
                                                        .addComponent(jLabelPfa))
                                        .addPreferredGap(
                                                javax.swing.LayoutStyle.ComponentPlacement.RELATED)
                                        .addComponent(
                                                jScrollPane1,
                                                javax.swing.GroupLayout.PREFERRED_SIZE,
                                                32,
                                                javax.swing.GroupLayout.PREFERRED_SIZE)
                                        .addPreferredGap(
                                                javax.swing.LayoutStyle.ComponentPlacement.RELATED)
                                        .addGroup(
                                                jPanelPfaLayout
                                                        .createParallelGroup(
                                                                javax.swing.GroupLayout.Alignment.BASELINE)
                                                        .addComponent(jLabel14)
                                                        .addComponent(
                                                                jSpinnerPfaMatchValueLocal,
                                                                javax.swing.GroupLayout.PREFERRED_SIZE,
                                                                javax.swing.GroupLayout.DEFAULT_SIZE,
                                                                javax.swing.GroupLayout.PREFERRED_SIZE))
                                        .addPreferredGap(
                                                javax.swing.LayoutStyle.ComponentPlacement.RELATED)
                                        .addComponent(jLabelPfa1)
                                        .addPreferredGap(
                                                javax.swing.LayoutStyle.ComponentPlacement.RELATED)
                                        .addComponent(
                                                jScrollPane2,
                                                javax.swing.GroupLayout.PREFERRED_SIZE,
                                                32,
                                                javax.swing.GroupLayout.PREFERRED_SIZE)));

        jLabelUidMandatory.setForeground(new java.awt.Color(255, 0, 0));
        jLabelUidMandatory.setText("This field is required");

        jLabel16.setText("Language");

        jLanguageCombo.setModel(new javax.swing.DefaultComboBoxModel(
                new String[]{"Select", "Hindi", "Kannada", "Malayalam"}));
        jLanguageCombo.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                jLanguageComboActionPerformed(evt);
            }
        });

        jLabelToken.setText("Token");

        jComboBoxTokenType.setModel(new javax.swing.DefaultComboBoxModel(
                new String[]{"Mobile"}));

        jLabelTokenType.setText("Token Type");

        lblVer = new JLabel("Ver");
        lblPfr = new JLabel("Pfr");

        comboBoxVer = new JComboBox();
        comboBoxVer.setModel(new DefaultComboBoxModel(new String[]{"1.0", "2.0"}));
        comboBoxVer.addActionListener(new ActionListener() {
            public void actionPerformed(ActionEvent evt) {
                comboBoxVerActionPerformed(evt);
            }
        });

        comboBoxPfr = new JComboBox();
        comboBoxPfr.setEnabled(false);
        comboBoxPfr.setModel(new DefaultComboBoxModel(new String[]{"Y", "N"}));

        javax.swing.GroupLayout jPanelKYRLayout = new javax.swing.GroupLayout(
                jPanelKYR);
        jPanelKYRLayout.setHorizontalGroup(
                jPanelKYRLayout.createParallelGroup(Alignment.LEADING)
                        .addGroup(jPanelKYRLayout.createSequentialGroup()
                                .addContainerGap()
                                .addGroup(jPanelKYRLayout.createParallelGroup(Alignment.LEADING)
                                        .addGroup(jPanelKYRLayout.createSequentialGroup()
                                                .addComponent(jPanelAddress, GroupLayout.PREFERRED_SIZE, GroupLayout.DEFAULT_SIZE, GroupLayout.PREFERRED_SIZE)
                                                .addPreferredGap(ComponentPlacement.UNRELATED)
                                                .addGroup(jPanelKYRLayout.createParallelGroup(Alignment.TRAILING)
                                                        .addGroup(jPanelKYRLayout.createSequentialGroup()
                                                                .addComponent(jLabelProgressIndicator, GroupLayout.PREFERRED_SIZE, 242, GroupLayout.PREFERRED_SIZE)
                                                                .addGap(25))
                                                        .addGroup(jPanelKYRLayout.createSequentialGroup()
                                                                .addComponent(jPanelAuthStatus, GroupLayout.DEFAULT_SIZE, 395, Short.MAX_VALUE)
                                                                .addContainerGap())))
                                        .addGroup(jPanelKYRLayout.createSequentialGroup()
                                                .addGap(10)
                                                .addComponent(jLabelAadhaarNumber)
                                                .addGap(2)
                                                .addComponent(jFormattedTextFieldAADHAAR1, GroupLayout.PREFERRED_SIZE, 87, GroupLayout.PREFERRED_SIZE)
                                                .addPreferredGap(ComponentPlacement.RELATED)
                                                .addComponent(jLabelUidMandatory)
                                                .addPreferredGap(ComponentPlacement.RELATED)
                                                .addComponent(jCheckBoxRa)
                                                .addPreferredGap(ComponentPlacement.UNRELATED)
                                                .addComponent(lblVer, GroupLayout.PREFERRED_SIZE, 20, GroupLayout.PREFERRED_SIZE)
                                                .addPreferredGap(ComponentPlacement.RELATED)
                                                .addComponent(comboBoxVer, GroupLayout.PREFERRED_SIZE, 41, GroupLayout.PREFERRED_SIZE)
                                                .addPreferredGap(ComponentPlacement.RELATED)
                                                .addComponent(lblPfr, GroupLayout.PREFERRED_SIZE, 22, GroupLayout.PREFERRED_SIZE)
                                                .addPreferredGap(ComponentPlacement.RELATED)
                                                .addComponent(comboBoxPfr, GroupLayout.PREFERRED_SIZE, GroupLayout.DEFAULT_SIZE, GroupLayout.PREFERRED_SIZE)
                                                .addPreferredGap(ComponentPlacement.RELATED)
                                                .addComponent(jLabelToken, GroupLayout.PREFERRED_SIZE, 31, GroupLayout.PREFERRED_SIZE)
                                                .addGap(2)
                                                .addComponent(jTextFieldToken, 77, 77, 77)
                                                .addPreferredGap(ComponentPlacement.RELATED)
                                                .addComponent(jLabelTokenType)
                                                .addPreferredGap(ComponentPlacement.RELATED)
                                                .addComponent(jComboBoxTokenType, GroupLayout.PREFERRED_SIZE, GroupLayout.DEFAULT_SIZE, GroupLayout.PREFERRED_SIZE)
                                                .addPreferredGap(ComponentPlacement.RELATED)
                                                .addComponent(jLabel16)
                                                .addPreferredGap(ComponentPlacement.RELATED)
                                                .addComponent(jLanguageCombo, GroupLayout.PREFERRED_SIZE, 102, GroupLayout.PREFERRED_SIZE)
                                                .addContainerGap())
                                        .addGroup(jPanelKYRLayout.createSequentialGroup()
                                                .addComponent(jPanelIdentificationDetails, GroupLayout.PREFERRED_SIZE, 434, GroupLayout.PREFERRED_SIZE)
                                                .addPreferredGap(ComponentPlacement.RELATED)
                                                .addGroup(jPanelKYRLayout.createParallelGroup(Alignment.LEADING)
                                                        .addComponent(jPanelAuthParameters, GroupLayout.PREFERRED_SIZE, GroupLayout.DEFAULT_SIZE, GroupLayout.PREFERRED_SIZE)
                                                        .addComponent(jPanelBiometricsOuter, GroupLayout.PREFERRED_SIZE, GroupLayout.DEFAULT_SIZE, GroupLayout.PREFERRED_SIZE))
                                                .addPreferredGap(ComponentPlacement.UNRELATED)
                                                .addComponent(jPanelPfa, GroupLayout.PREFERRED_SIZE, GroupLayout.DEFAULT_SIZE, GroupLayout.PREFERRED_SIZE)
                                                .addContainerGap())))
        );
        jPanelKYRLayout.setVerticalGroup(
                jPanelKYRLayout.createParallelGroup(Alignment.LEADING)
                        .addGroup(jPanelKYRLayout.createSequentialGroup()
                                .addGroup(jPanelKYRLayout.createParallelGroup(Alignment.BASELINE)
                                        .addComponent(jLabelAadhaarNumber)
                                        .addComponent(jFormattedTextFieldAADHAAR1, GroupLayout.PREFERRED_SIZE, 20, GroupLayout.PREFERRED_SIZE)
                                        .addComponent(jLabelUidMandatory)
                                        .addComponent(jCheckBoxRa)
                                        .addComponent(lblVer)
                                        .addComponent(comboBoxVer, GroupLayout.PREFERRED_SIZE, GroupLayout.DEFAULT_SIZE, GroupLayout.PREFERRED_SIZE)
                                        .addComponent(lblPfr)
                                        .addComponent(comboBoxPfr, GroupLayout.PREFERRED_SIZE, GroupLayout.DEFAULT_SIZE, GroupLayout.PREFERRED_SIZE)
                                        .addComponent(jLabelToken)
                                        .addComponent(jTextFieldToken, GroupLayout.PREFERRED_SIZE, GroupLayout.DEFAULT_SIZE, GroupLayout.PREFERRED_SIZE)
                                        .addComponent(jLabelTokenType)
                                        .addComponent(jComboBoxTokenType, GroupLayout.PREFERRED_SIZE, GroupLayout.DEFAULT_SIZE, GroupLayout.PREFERRED_SIZE)
                                        .addComponent(jLabel16)
                                        .addComponent(jLanguageCombo, GroupLayout.PREFERRED_SIZE, GroupLayout.DEFAULT_SIZE, GroupLayout.PREFERRED_SIZE))
                                .addGroup(jPanelKYRLayout.createParallelGroup(Alignment.LEADING)
                                        .addGroup(jPanelKYRLayout.createSequentialGroup()
                                                .addPreferredGap(ComponentPlacement.RELATED)
                                                .addGroup(jPanelKYRLayout.createParallelGroup(Alignment.LEADING)
                                                        .addGroup(jPanelKYRLayout.createParallelGroup(Alignment.BASELINE)
                                                                .addComponent(jPanelAuthParameters, GroupLayout.PREFERRED_SIZE, GroupLayout.DEFAULT_SIZE, GroupLayout.PREFERRED_SIZE)
                                                                .addComponent(jPanelPfa, GroupLayout.DEFAULT_SIZE, 230, Short.MAX_VALUE))
                                                        .addGroup(jPanelKYRLayout.createSequentialGroup()
                                                                .addGap(64)
                                                                .addComponent(jPanelBiometricsOuter, 0, 166, Short.MAX_VALUE))))
                                        .addGroup(jPanelKYRLayout.createSequentialGroup()
                                                .addGap(14)
                                                .addComponent(jPanelIdentificationDetails, GroupLayout.PREFERRED_SIZE, 220, Short.MAX_VALUE)))
                                .addPreferredGap(ComponentPlacement.RELATED)
                                .addGroup(jPanelKYRLayout.createParallelGroup(Alignment.LEADING)
                                        .addComponent(jPanelAddress, GroupLayout.PREFERRED_SIZE, GroupLayout.DEFAULT_SIZE, GroupLayout.PREFERRED_SIZE)
                                        .addComponent(jPanelAuthStatus, GroupLayout.DEFAULT_SIZE, 238, Short.MAX_VALUE))
                                .addPreferredGap(ComponentPlacement.RELATED)
                                .addComponent(jLabelProgressIndicator))
        );
        jPanelKYR.setLayout(jPanelKYRLayout);

        jButtonAuthenticate.setText("Send KYC request");
        jButtonAuthenticate
                .addActionListener(new java.awt.event.ActionListener() {
                    public void actionPerformed(java.awt.event.ActionEvent evt) {
                        jButtonAuthenticateActionPerformed(evt);
                    }
                });

        jButtonClear.setText("Reset");
        jButtonClear.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                jButtonClearActionPerformed(evt);
            }
        });

        jLabelAuthRefCodeValue.setText(".");
        jLabelAuthRefCodeValue.setText(".");

        jLabelAuthRefCode.setText("Auth Response Code:");
        jLabelAuthRefCode.setText("Kyc Response Code:");

        jLabel2.setFont(new java.awt.Font("Tahoma", 1, 18));
        jLabel2.setForeground(new java.awt.Color(102, 102, 102));
        jLabel2.setText(" UIDAI KYC Demo Client  (For API 1.0)");

        jLabelBiometricFile.setText("Biometric Status: No captures yet");

        jButtonGenerateOTP.setText("Generate OTP");
        jButtonGenerateOTP
                .addActionListener(new java.awt.event.ActionListener() {
                    public void actionPerformed(java.awt.event.ActionEvent evt) {
                        jButtonGenerateOTPActionPerformed(evt);
                    }
                });
        jButtonGenerateOTP.setVisible(true);

        jButtonInitiateBFD.setText("Perform BFD");
        jButtonInitiateBFD
                .addActionListener(new java.awt.event.ActionListener() {
                    public void actionPerformed(java.awt.event.ActionEvent evt) {
                        jButtonInitiateBFDActionPerformed(evt);
                    }
                });
        jButtonInitiateBFD.setVisible(true);

        javax.swing.GroupLayout jPanel1Layout = new javax.swing.GroupLayout(
                jPanel1);
        jPanel1.setLayout(jPanel1Layout);
        jPanel1Layout
                .setHorizontalGroup(jPanel1Layout
                        .createParallelGroup(
                                javax.swing.GroupLayout.Alignment.LEADING)
                        .addGroup(
                                jPanel1Layout
                                        .createSequentialGroup()
                                        .addComponent(jLabelLogo)
                                        .addGap(270, 270, 270)
                                        .addComponent(
                                                jLabel2,
                                                javax.swing.GroupLayout.PREFERRED_SIZE,
                                                581,
                                                javax.swing.GroupLayout.PREFERRED_SIZE)
                                        .addGap(18, 18, 18))
                        .addGroup(
                                jPanel1Layout
                                        .createSequentialGroup()
                                        .addComponent(
                                                jPanelKYR,
                                                javax.swing.GroupLayout.DEFAULT_SIZE,
                                                javax.swing.GroupLayout.DEFAULT_SIZE,
                                                Short.MAX_VALUE)
                                        .addContainerGap())
                        .addGroup(
                                jPanel1Layout
                                        .createSequentialGroup()
                                        .addContainerGap()
                                        .addGroup(
                                                jPanel1Layout
                                                        .createParallelGroup(
                                                                javax.swing.GroupLayout.Alignment.TRAILING)
                                                        .addGroup(
                                                                jPanel1Layout
                                                                        .createSequentialGroup()
                                                                        .addGroup(
                                                                                jPanel1Layout
                                                                                        .createParallelGroup(
                                                                                                javax.swing.GroupLayout.Alignment.LEADING)
                                                                                        .addComponent(
                                                                                                jButtonClear)
                                                                                        .addComponent(
                                                                                                jLabelAuthRefCode))
                                                                        .addPreferredGap(
                                                                                javax.swing.LayoutStyle.ComponentPlacement.RELATED)
                                                                        .addGroup(
                                                                                jPanel1Layout
                                                                                        .createParallelGroup(
                                                                                                javax.swing.GroupLayout.Alignment.LEADING,
                                                                                                false)
                                                                                        .addGroup(
                                                                                                jPanel1Layout
                                                                                                        .createSequentialGroup()
                                                                                                        .addGap(450,
                                                                                                                450,
                                                                                                                450)
                                                                                                        .addComponent(
                                                                                                                jButtonCustomKYC)
                                                                                                        // custom
                                                                                                        // KYC
                                                                                                        // XML
                                                                                                        .addPreferredGap(
                                                                                                                javax.swing.LayoutStyle.ComponentPlacement.RELATED,
                                                                                                                javax.swing.GroupLayout.DEFAULT_SIZE,
                                                                                                                Short.MAX_VALUE)
                                                                                                        .addComponent(
                                                                                                                jButtonInitiateBFD)
                                                                                                        .addPreferredGap(
                                                                                                                javax.swing.LayoutStyle.ComponentPlacement.RELATED,
                                                                                                                javax.swing.GroupLayout.DEFAULT_SIZE,
                                                                                                                Short.MAX_VALUE)
                                                                                                        .addComponent(
                                                                                                                jButtonGenerateOTP))
                                                                                        .addComponent(
                                                                                                jLabelAuthRefCodeValue,
                                                                                                javax.swing.GroupLayout.PREFERRED_SIZE,
                                                                                                719,
                                                                                                javax.swing.GroupLayout.PREFERRED_SIZE))
                                                                        .addGap(1,
                                                                                1,
                                                                                1)
                                                                        .addComponent(
                                                                                jButtonAuthenticate))
                                                        .addComponent(
                                                                jLabelBiometricFile,
                                                                javax.swing.GroupLayout.PREFERRED_SIZE,
                                                                945,
                                                                javax.swing.GroupLayout.PREFERRED_SIZE))
                                        .addContainerGap(26, Short.MAX_VALUE)));
        jPanel1Layout
                .setVerticalGroup(jPanel1Layout
                        .createParallelGroup(
                                javax.swing.GroupLayout.Alignment.LEADING)
                        .addGroup(
                                jPanel1Layout
                                        .createSequentialGroup()
                                        .addGroup(
                                                jPanel1Layout
                                                        .createParallelGroup(
                                                                javax.swing.GroupLayout.Alignment.TRAILING)
                                                        .addComponent(
                                                                jLabel2,
                                                                javax.swing.GroupLayout.PREFERRED_SIZE,
                                                                36,
                                                                javax.swing.GroupLayout.PREFERRED_SIZE)
                                                        .addComponent(
                                                                jLabelLogo))
                                        .addPreferredGap(
                                                javax.swing.LayoutStyle.ComponentPlacement.RELATED)
                                        .addComponent(
                                                jPanelKYR,
                                                javax.swing.GroupLayout.PREFERRED_SIZE,
                                                javax.swing.GroupLayout.DEFAULT_SIZE,
                                                javax.swing.GroupLayout.PREFERRED_SIZE)
                                        .addPreferredGap(
                                                javax.swing.LayoutStyle.ComponentPlacement.RELATED)
                                        .addComponent(jLabelBiometricFile)
                                        .addPreferredGap(
                                                javax.swing.LayoutStyle.ComponentPlacement.RELATED)
                                        .addGroup(
                                                jPanel1Layout
                                                        .createParallelGroup(
                                                                javax.swing.GroupLayout.Alignment.BASELINE)
                                                        .addComponent(
                                                                jLabelAuthRefCodeValue)
                                                        .addComponent(
                                                                jLabelAuthRefCode))
                                        .addPreferredGap(
                                                javax.swing.LayoutStyle.ComponentPlacement.RELATED)
                                        .addGroup(
                                                jPanel1Layout
                                                        .createParallelGroup(
                                                                javax.swing.GroupLayout.Alignment.BASELINE)
                                                        .addComponent(
                                                                jButtonClear)
                                                        .addComponent(
                                                                jButtonCustomKYC)
                                                        .addComponent(
                                                                jButtonInitiateBFD)
                                                        .addComponent(
                                                                jButtonGenerateOTP)
                                                        .addComponent(
                                                                jButtonAuthenticate,
                                                                javax.swing.GroupLayout.PREFERRED_SIZE,
                                                                23,
                                                                javax.swing.GroupLayout.PREFERRED_SIZE))
                                        .addContainerGap()));

        jMenuFile.setText("File");

        jMenuItem1.setAccelerator(javax.swing.KeyStroke.getKeyStroke(
                java.awt.event.KeyEvent.VK_X,
                java.awt.event.InputEvent.ALT_MASK));
        jMenuItem1.setText("Exit");
        jMenuItem1.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                exit(evt);
            }
        });
        jMenuFile.add(jMenuItem1);

        jMenuBar.add(jMenuFile);

        jMenuOptions.setText("Edit");
        jMenuOptions.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                jMenuOptionsActionPerformed(evt);
            }
        });

        jMenuItemPreferences.setAccelerator(javax.swing.KeyStroke.getKeyStroke(
                java.awt.event.KeyEvent.VK_P,
                java.awt.event.InputEvent.CTRL_MASK));
        jMenuItemPreferences.setText("Preferences");
        jMenuItemPreferences
                .addActionListener(new java.awt.event.ActionListener() {
                    public void actionPerformed(java.awt.event.ActionEvent evt) {
                        jMenuItemPreferencesActionPerformed(evt);
                    }
                });
        jMenuOptions.add(jMenuItemPreferences);

        jMenuItemResetSSK.setAccelerator(javax.swing.KeyStroke.getKeyStroke(
                java.awt.event.KeyEvent.VK_R,
                java.awt.event.InputEvent.CTRL_MASK));
        jMenuItemResetSSK.setText("Reset SSK");
        jMenuItemResetSSK
                .addActionListener(new java.awt.event.ActionListener() {
                    public void actionPerformed(java.awt.event.ActionEvent evt) {
                        jMenuItemResetSSKActionPerformed(evt);
                    }
                });
        jMenuOptions.add(jMenuItemResetSSK);
        jMenuBar.add(jMenuOptions);

        setJMenuBar(jMenuBar);

        javax.swing.GroupLayout layout = new javax.swing.GroupLayout(
                getContentPane());
        getContentPane().setLayout(layout);
        layout.setHorizontalGroup(layout.createParallelGroup(
                javax.swing.GroupLayout.Alignment.LEADING).addComponent(
                        jPanel1, javax.swing.GroupLayout.PREFERRED_SIZE, 981,
                        javax.swing.GroupLayout.PREFERRED_SIZE));
        layout.setVerticalGroup(layout.createParallelGroup(
                javax.swing.GroupLayout.Alignment.LEADING).addComponent(
                        jPanel1, javax.swing.GroupLayout.PREFERRED_SIZE,
                        javax.swing.GroupLayout.DEFAULT_SIZE,
                        javax.swing.GroupLayout.PREFERRED_SIZE));

        if (StringUtils.isBlank(System.getenv("USE_CUSTOM_KYC_XML"))) {
            jButtonCustomKYC.setVisible(false);
        }

        pack();
    }// </editor-fold>

    private void jMenuItemResetSSKActionPerformed(java.awt.event.ActionEvent evt) {// GEN-FIRST:event_jMenuItemResetSSKActionPerformed

        this.auaDataCreator.restSkeyMap();

        JOptionPane
                .showMessageDialog(
                        this,
                        "SSK has been reset. New Session Key will be sent on next request",
                        "UID Authentication Demo Client",
                        JOptionPane.INFORMATION_MESSAGE);
    }// GEN-LAST:event_jMenuItemResetSSKActionPerformed

    private void jMenuItemPreferencesActionPerformed(
            java.awt.event.ActionEvent evt) {// GEN-FIRST:event_jMenuItemPreferencesActionPerformed
        loadPreferences();

        jDialogPreferences.setBounds(50, 50, 625, 740);
        jDialogPreferences.setResizable(true);
        jDialogPreferences.setVisible(true);

    }// GEN-LAST:event_jMenuItemPreferencesActionPerformed

    private void jButtonInitiateBFDActionPerformed(
            java.awt.event.ActionEvent evt) {// GEN-FIRST:event_jButtonInitiateBFDActionPerformed
        if (jFormattedTextFieldAADHAAR1.getText().trim().isEmpty()) {
            jLabelUidMandatory.setVisible(true);
        } else {
            resetBfdRankAndResults();
            resetBfdBiometrics();

            jDialogBFD.setModal(true);
            jDialogBFD.setBounds(100, 100, 670, 567);
            jDialogBFD.setVisible(true);
        }
    }// GEN-LAST:event_jButtonInitiateBFDActionPerformed

    private void scanForBFD(javax.swing.JLabel label, FingerPosition pos) {
        JOptionPane
                .showMessageDialog(
                        this,
                        "Biometric capture implementation not found.\n\n"
                        + "Please ensure that an implementation of in.gov.uidai.auth.biometric.BiometricIntegrationAPI is \n"
                        + "present in classpath, and biometricAPIImplementationClass field of this application is initialized\n"
                        + "with name of that class.",
                        "UID Authentication Demo Client",
                        JOptionPane.ERROR_MESSAGE);
    }

    private void jButtonScanLeftLittleActionPerformed(
            java.awt.event.ActionEvent evt) {// GEN-FIRST:event_jButtonScanLeftLittleActionPerformed
        scanForBFD(jLabelBiometricLeftLittle, FingerPosition.LEFT_LITTLE);
    }// GEN-LAST:event_jButtonScanLeftLittleActionPerformed

    private void jButtonScanLeftRingActionPerformed(
            java.awt.event.ActionEvent evt) {// GEN-FIRST:event_jButtonScanLeftRingActionPerformed
        scanForBFD(jLabelBiometricLeftRing, FingerPosition.LEFT_RING);
    }// GEN-LAST:event_jButtonScanLeftRingActionPerformed

    private void jButtonScanMiddleActionPerformed(java.awt.event.ActionEvent evt) {// GEN-FIRST:event_jButtonScanMiddleActionPerformed
        scanForBFD(jLabelBiometricLeftMiddle, FingerPosition.LEFT_MIDDLE);
    }// GEN-LAST:event_jButtonScanMiddleActionPerformed

    private void jButtonScanLeftIndexActionPerformed(
            java.awt.event.ActionEvent evt) {// GEN-FIRST:event_jButtonScanLeftIndexActionPerformed
        scanForBFD(jLabelBiometricLeftIndex, FingerPosition.LEFT_INDEX);
    }// GEN-LAST:event_jButtonScanLeftIndexActionPerformed

    private void jButtonScanLeftThumbActionPerformed(
            java.awt.event.ActionEvent evt) {// GEN-FIRST:event_jButtonScanLeftThumbActionPerformed
        scanForBFD(jLabelBiometricLeftThumb, FingerPosition.LEFT_THUMB);
    }// GEN-LAST:event_jButtonScanLeftThumbActionPerformed

    private void jButtonScanRightThumbActionPerformed(
            java.awt.event.ActionEvent evt) {// GEN-FIRST:event_jButtonScanRightThumbActionPerformed
        scanForBFD(jLabelBiometricRightThumb, FingerPosition.RIGHT_THUMB);
    }// GEN-LAST:event_jButtonScanRightThumbActionPerformed

    private void jButtonScanRightIndexActionPerformed(
            java.awt.event.ActionEvent evt) {// GEN-FIRST:event_jButtonScanRightIndexActionPerformed
        scanForBFD(jLabelBiometricRightIndex, FingerPosition.RIGHT_INDEX);
    }// GEN-LAST:event_jButtonScanRightIndexActionPerformed

    private void jButtonScanRightMiddleActionPerformed(
            java.awt.event.ActionEvent evt) {// GEN-FIRST:event_jButtonScanRightMiddleActionPerformed
        scanForBFD(jLabelBiometricRightMiddle, FingerPosition.RIGHT_MIDDLE);
    }// GEN-LAST:event_jButtonScanRightMiddleActionPerformed

    private void jButtonScanRightRingActionPerformed(
            java.awt.event.ActionEvent evt) {// GEN-FIRST:event_jButtonScanRightRingActionPerformed
        scanForBFD(jLabelBiometricRightRing, FingerPosition.RIGHT_RING);
    }// GEN-LAST:event_jButtonScanRightRingActionPerformed

    private void jButtonScanRightLittleActionPerformed(
            java.awt.event.ActionEvent evt) {// GEN-FIRST:event_jButtonScanRightLittleActionPerformed
        scanForBFD(jLabelBiometricRightLittle, FingerPosition.RIGHT_LITTLE);
    }// GEN-LAST:event_jButtonScanRightLittleActionPerformed

    private void jButtonPerformBFDActionPerformed(java.awt.event.ActionEvent evt) {// GEN-FIRST:event_jButtonPerformBFDActionPerformed

        if (jFormattedTextFieldAADHAAR1.getText().trim().isEmpty()) {
            jLabelUidMandatory.setVisible(true);
        } else {

            jLabelUidMandatory.setVisible(false);

            resetBfdRankAndResults();

            if ("BOTH".equalsIgnoreCase(jComboBoxPidType.getSelectedItem()
                    .toString())) {
                this.performBfd(constructBfdRequest(), false);
                this.performBfd(constructBfdRequest(), true);
            }
            if ("X".equalsIgnoreCase(jComboBoxPidType.getSelectedItem()
                    .toString())) {
                this.performBfd(constructBfdRequest(), false);
            }
            if ("P".equalsIgnoreCase(jComboBoxPidType.getSelectedItem()
                    .toString())) {
                this.performBfd(constructBfdRequest(), true);
            }

        }

    }// GEN-LAST:event_jButtonPerformBFDActionPerformed

    private void jButtonCustomKYCActionPerformed(java.awt.event.ActionEvent evt) {// GEN-FIRST:event_jButtonPerformBFDActionPerformed
        JTextArea customKYCXMLTextArea = new JTextArea();
        customKYCXMLTextArea.setColumns(80);
        customKYCXMLTextArea.setRows(20);
        customKYCXMLTextArea.setText(customKYCXML);
        final JComponent[] inputs = new JComponent[]{
            new JLabel("Custom KYC XML"), customKYCXMLTextArea,};
        JOptionPane.showMessageDialog(this, inputs, "KYC Demo Client",
                JOptionPane.PLAIN_MESSAGE);
        customKYCXML = customKYCXMLTextArea.getText();
    }// GEN-LAST:event_jButtonPerformBFDActionPerformed

    private void jButtonBFDResetActionPerformed(java.awt.event.ActionEvent evt) {// GEN-FIRST:event_jButtonBFDResetActionPerformed
        resetBfdRankAndResults();
        resetBfdBiometrics();
    }// GEN-LAST:event_jButtonBFDResetActionPerformed

    private void jButtonAuthenticateActionPerformed(
            java.awt.event.ActionEvent evt) {
        // GEN-FIRST:event_jButtonAuthenticateActionPerformed
        if (jFormattedTextFieldAADHAAR1.getText().trim().isEmpty()) {
            jLabelUidMandatory.setVisible(true);
        } else {
            jTextAreaResponseValidationResult.setText("");
            jLabelUidMandatory.setVisible(false);
            this.jLabelAuthRefCodeValue.setText("");

            jLabelAuthStatus.setIcon(new javax.swing.ImageIcon(getClass()
                    .getResource("/unknown.png")));
            jLabelAuthStatusProto.setIcon(new javax.swing.ImageIcon(getClass()
                    .getResource("/unknown.png")));

            if ("BOTH".equalsIgnoreCase(jComboBoxPidType.getSelectedItem()
                    .toString())) {

                this.authenticateRequest(constructAuthRequest(), false);
                this.authenticateRequest(constructAuthRequest(), true);
            }
            if ("X".equalsIgnoreCase(jComboBoxPidType.getSelectedItem()
                    .toString())) {

                this.authenticateRequest(constructAuthRequest(), false);
            }
            if ("P".equalsIgnoreCase(jComboBoxPidType.getSelectedItem()
                    .toString())) {

                this.authenticateRequest(constructAuthRequest(), true);
            }
        }

    }// GEN-LAST:event_jButtonAuthenticateActionPerformed

    private void jButtonScanActionPerformed(java.awt.event.ActionEvent evt) {// GEN-FIRST:event_jButtonScanActionPerformed
        JOptionPane
                .showMessageDialog(
                        this,
                        "Biometric capture implementation not found.\n\n"
                        + "Please ensure that an implementation of in.gov.uidai.auth.biometric.BiometricIntegrationAPI is \n"
                        + "present in classpath, and biometricAPIImplementationClass field of this application is initialized\n"
                        + "with name of that class.",
                        "UID Authentication Demo Client",
                        JOptionPane.ERROR_MESSAGE);
    }// GEN-LAST:event_jButtonScanActionPerformed

    private void jButtonClearActionPerformed(java.awt.event.ActionEvent evt) {// GEN-FIRST:event_jButtonClearActionPerformed
        jLabelAuthStatus.setIcon(new javax.swing.ImageIcon(getClass()
                .getResource("/unknown.png")));
        jLabelAuthStatusProto.setIcon(new javax.swing.ImageIcon(getClass()
                .getResource("/unknown.png")));
        jCheckBoxDe.setSelected(false);
        mecCheckbox.setSelected(false);
        lrCheckbox.setSelected(false);
        this.lrcheckval = false;
        jCheckBoxRa.setSelected(false);
        this.jLabelAuthStatusTextProto.setText("");
        this.jLabelAuthStatusTextXML.setText("");

        this.jLabelAuthRefCodeValue.setText("");

        this.jLabelUidMandatory.setVisible(false);

        jFormattedTextFieldAADHAAR1.setText(null);
        // Fixed issue 17197
        jFormattedTextFieldAADHAAR1.setValue(null);

        jTextFieldNameLocal.setText(null);
        jTextAreaFullAddressValueLocal.setText(null);
        jTextAreaFullAddressValue.setText(null);

        jPasswordFieldOTP.setText(null);
        jPasswordFieldPIN.setText(null);
        jTextFieldBuilding.setText(null);
        jTextFieldCareOf.setText(null);
        jTextFieldDistrict.setText(null);
        jTextFieldDobDay.setText(null);
        jTextFieldDobMonth.setText(null);
        jTextFieldDobYear.setText(null);
        jTextFieldEmail.setText(null);
        jTextFieldLandmark.setText(null);
        jTextFieldLocality.setText(null);
        jTextFieldName.setText(null);
        jTextFieldPhone.setText(null);

        jTextFieldAge.setText(null);
        jTextFieldPOName.setText(null);
        jTextFieldSubdist.setText(null);
        jTextFieldPincode.setText(null);
        jTextFieldState.setText(null);
        jTextFieldStreet.setText(null);
        jTextFieldVtc.setText(null);
        jTextFieldToken.setText(null);
        jComboGender.setSelectedIndex(0);
        jComboBoxDOBType.setSelectedIndex(0);

        resetFingerprintISOFeatureSet();
        jTextAreaResponseValidationResult.setText("");

    }// GEN-LAST:event_jButtonClearActionPerformed

    private void resetFingerprintISOFeatureSet() {
        bioCaptures.clear();
        jLabelBiometric.setIcon(null);
        jLabelBiometricFile.setText("Biometric Status: No captures yet");
        jComboBiometricPosition.setSelectedIndex(0);
    }

    private void loadPreferences() {
        FileInputStream is = null;
        try {
            File preferencesFile = new File("authclient.properties");
            if (preferencesFile.exists()) {
                is = new FileInputStream(preferencesFile);
                // Feature Changes:Encrypting Passoword properties
                Properties p = EncryptablePropertyUtils
                        .getEncryptableProperties();
                // new Properties();
                p.load(is);

                if (p.get("authServerUrl") != null) {
                    jTextFieldAuthServerURL.setText(p.get("authServerUrl")
                            .toString());
                }

                if (p.get("kycServerUrl") != null) {
                    jTextFieldKYCServerURL.setText(p.get("kycServerUrl")
                            .toString());
                }

                if (p.get("otpServerUrl") != null) {
                    jTextFieldOTPServerUrl.setText(p.get("otpServerUrl")
                            .toString());
                }

                if (p.get("auaCode") != null) {
                    jTextFieldAua.setText(p.get("auaCode").toString());
                }
                if (p.get("signKeyStore") != null) {
                    jTextFieldSignatureFile.setText(p.get("signKeyStore")
                            .toString());
                }

                if (p.get("sa") != null) {
                    jTextFieldServiceAgency.setText(p.get("sa").toString());
                }

                if (p.get("licenseKey") != null) {
                    jTextFieldLicenseKey
                            .setText(p.get("licenseKey").toString());
                }

                if (p.get("asaLicenseKey") != null) {
                    jTextFieldASALicense.setText(p.get("asaLicenseKey")
                            .toString());
                }

                if (p.get("terminalId") != null) {
                    jTextFieldTerminalID
                            .setText(p.get("terminalId").toString());
                }

                if (p.get("publicKeyFile") != null) {
                    jTextFieldPublicKeyFile.setText(p.get("publicKeyFile")
                            .toString());
                }

                if (p.get("publicKeyFileDSIG") != null
                        && !StringUtils.isEmpty(p.get("publicKeyFileDSIG")
                                .toString())) {
                    jTextFieldDSIGPublicKey.setText(p.get("publicKeyFileDSIG")
                            .toString());
                } else {
                    jTextFieldDSIGPublicKey.setText(p.get("publicKeyFile")
                            .toString());
                }
                /**
                 * added to save decryption key file path in preeferences
                 */
                if (p.get("decryptprivSignatureFile") != null
                        && !StringUtils.isEmpty(p.get("decryptprivSignatureFile")
                                .toString())) {
                    jTextFieldDecryptSignatureFile.setText(p.get("decryptprivSignatureFile")
                            .toString());
                } else {
                    /*jTextFieldDecryptSignatureFile.setText(p.get("decryptprivSignatureFile")
							.toString());*/
                    jTextFieldDecryptSignatureFile.setText("" + p.get("decryptprivSignatureFile"));
                }
                if (p.get("usesPi") != null) {
                    jCheckBoxPi.setSelected(Boolean.valueOf(p.get("usesPi")
                            .toString()));
                }
                if (p.get("usesDe") != null) {
                    jCheckBoxDe.setSelected(Boolean.valueOf(p.get("usesDe")
                            .toString()));
                }

                if (p.get("usesPa") != null) {
                    jCheckBoxPa.setSelected(Boolean.valueOf(p.get("usesPa")
                            .toString()));
                }

                if (p.get("usesPfa") != null) {
                    jCheckBoxPfa.setSelected(Boolean.valueOf(p.get("usesPfa")
                            .toString()));
                }

                if (p.get("usesPin") != null) {
                    jCheckBoxPin.setSelected(Boolean.valueOf(p.get("usesPin")
                            .toString()));
                }

                if (p.get("usesOtp") != null) {
                    jCheckBoxOtp.setSelected(Boolean.valueOf(p.get("usesOtp")
                            .toString()));
                }

                if (p.get("usesBio") != null) {
                    jCheckBoxBio.setSelected(Boolean.valueOf(p.get("usesBio")
                            .toString()));
                }

                if (p.get("usesBioFMR") != null) {
                    jCheckBoxFMR.setSelected(Boolean.valueOf(p
                            .get("usesBioFMR").toString()));
                }

                if (p.get("usesBioFIR") != null) {
                    jCheckBoxFIR.setSelected(Boolean.valueOf(p
                            .get("usesBioFIR").toString()));
                }

                if (p.get("usesBioIIR") != null) {
                    jCheckBoxIIR.setSelected(Boolean.valueOf(p
                            .get("usesBioIIR").toString()));
                }

                if (p.get("signatureAlias") != null) {
                    jTextFieldSignatureAlias.setText(p.get("signatureAlias")
                            .toString());
                }

                if (p.get("signaturePassword") != null) {
                    // NOTE p.getProperty Only will give decrypted password ,
                    // if we use p.get() this will give raw value(encrypted).
                    jPasswordSignature.setText(p.getProperty(
                            "signaturePassword").toString());
                }
                /**
                 * added for new field
                 */
                if (p.get("DecryptPrivSignatureAlias") != null) {
                    jTextFieldDecryptPrivSignatureAlias.setText(p.get("DecryptPrivSignatureAlias")
                            .toString());
                }
                if (p.get("decryptprivSignaturePassword") != null) {
                    // NOTE p.getProperty Only will give decrypted password ,
                    // if we use p.get() this will give raw value(encrypted).
                    jPasswordSignature.setText(p.getProperty(
                            "decryptprivSignaturePassword").toString());
                }

                if (p.get("udc") != null) {
                    jTextFieldUDC.setText(p.get("udc").toString());
                }

                if (p.get("fdc") != null) {
                    jTextFieldFDC.setText(p.get("fdc").toString());
                }

                if (p.get("idc") != null) {
                    jTextFieldIDC.setText(p.get("idc").toString());
                }

                if (p.get("pincode") != null) {
                    jTextFieldLocationValue
                            .setText(p.get("pincode").toString());
                }

                if (p.get("lot") != null) {
                    jComboBoxLocationType.setSelectedItem(p.get("lot")
                            .toString());
                }

                if (p.get("lov") != null) {
                    jTextFieldLocationValue.setText(p.get("lov").toString());
                }

                if (p.get("publicIP") != null) {
                    jTextFieldPIP.setText(p.get("publicIP").toString());
                }

                if (p.get("useSSK") != null) {
                    jComboBoxUseSSK.setSelectedItem(p.get("useSSK").toString());
                }

                if (p.get("pidType") != null) {
                    jComboBoxPidType.setSelectedItem(p.get("pidType")
                            .toString());
                }

                if (p.get("bfdServerUrl") != null) {
                    jTextFieldBFDURL.setText(p.get("bfdServerUrl").toString());
                }
                /*if(p.get("decryptSignKeyStore") != null){
					jTextFieldDecryptSignatureFile.setText(p.get("decryptSignKeyStore").toString());
				}*/

                if (p.get("decryptSignatureAlias") != null) {
                    jTextFieldDecryptPrivSignatureAlias.setText(p.get("decryptSignatureAlias").toString());
                }

                if (p.get("decryptsignaturePassword") != null) {
                    jPasswordFieldDecryptSignature.setText(p.getProperty("decryptsignaturePassword").toString());
                }
            }

        } catch (IOException ex) {
            Logger.getLogger(SampleClientMainFrame.class.getName()).log(
                    Level.SEVERE, null, ex);
        } finally {
            try {
                if (is != null) {
                    is.close();
                }
            } catch (IOException ex) {
                Logger.getLogger(SampleClientMainFrame.class.getName()).log(
                        Level.SEVERE, null, ex);
            }
        }
    }

    private void exit(java.awt.event.ActionEvent evt) {// GEN-FIRST:event_exit
        System.exit(0);
    }// GEN-LAST:event_exit

    @SuppressWarnings("deprecation")
    private void storePreferences() {
        FileOutputStream of = null;
        FileInputStream is = null;
        try {
            jDialogPreferences.setVisible(false);

            // Feature Changes:Encrypting Passoword properties
            Properties p = EncryptablePropertyUtils.getEncryptableProperties();
            // new Properties();

            File preferencesFile = new File("authclient.properties");
            if (preferencesFile.exists()) {
                is = new FileInputStream(preferencesFile);
                p.load(is);
            }
            is.close();
            is = null;

            p.put("authServerUrl", jTextFieldAuthServerURL.getText());
            p.put("kycServerUrl", jTextFieldKYCServerURL.getText());
            p.put("otpServerUrl", jTextFieldOTPServerUrl.getText());
            p.put("bfdServerUrl", jTextFieldBFDURL.getText());

            p.put("auaCode", jTextFieldAua.getText());

            p.put("sa", jTextFieldServiceAgency.getText());
            p.put("licenseKey", jTextFieldLicenseKey.getText());
            p.put("asaLicenseKey", jTextFieldASALicense.getText());
            p.put("terminalId", jTextFieldTerminalID.getText());
            p.put("publicKeyFile", jTextFieldPublicKeyFile.getText());
            p.put("publicKeyFileDSIG", jTextFieldDSIGPublicKey.getText());
            p.put("decryptprivSignatureFile", jTextFieldDecryptSignatureFile.getText());
            p.put("usesPi", String.valueOf(jCheckBoxPi.isSelected()));
            /**
             * added for new checkbox De
             */
            p.put("usesDe", String.valueOf(jCheckBoxDe.isSelected()));
            p.put("usesPa", String.valueOf(jCheckBoxPa.isSelected()));
            p.put("usesPfa", String.valueOf(jCheckBoxPfa.isSelected()));
            p.put("usesPin", String.valueOf(jCheckBoxPin.isSelected()));
            p.put("usesOtp", String.valueOf(jCheckBoxOtp.isSelected()));
            p.put("usesBio", String.valueOf(jCheckBoxBio.isSelected()));
            p.put("usesBioFMR", String.valueOf(jCheckBoxFMR.isSelected()));
            p.put("usesBioFIR", String.valueOf(jCheckBoxFIR.isSelected()));
            p.put("usesBioIIR", String.valueOf(jCheckBoxIIR.isSelected()));

            boolean signatureAttributeChanged = false;
            if (StringUtils.isNotBlank(jTextFieldSignatureFile.getText())
                    && !jTextFieldSignatureFile.getText().equals(
                            p.get("signKeyStore").toString())) {
                signatureAttributeChanged = true;
            }
            p.put("signKeyStore", jTextFieldSignatureFile.getText());

            if (StringUtils.isNotBlank(jTextFieldSignatureAlias.getText())
                    && !jTextFieldSignatureAlias.getText().equals(
                            p.get("signatureAlias").toString())) {
                signatureAttributeChanged = true;
            }
            p.put("signatureAlias", jTextFieldSignatureAlias.getText());
            /**
             * added to save the new fields from preferences tab
             */

            if (StringUtils.isNotBlank(jTextFieldDecryptPrivSignatureAlias.getText())
                    && !jTextFieldDecryptPrivSignatureAlias.getText().equals(
                            p.get("DecryptPrivSignatureAlias").toString())) {
                signatureAttributeChanged = true;
            }
            p.put("DecryptPrivSignatureAlias", jTextFieldDecryptPrivSignatureAlias.getText());

            if (StringUtils.isNotBlank(jTextFieldDecryptSignatureFile.getText())
                    && !jTextFieldDecryptSignatureFile.getText().equals(
                            p.get("decryptprivSignatureFile").toString())) {
                signatureAttributeChanged = true;
            }
            p.put("decryptprivSignatureFile", jTextFieldDecryptSignatureFile.getText());

            if (StringUtils.isNotBlank(jPasswordFieldDecryptSignature.getText())
                    && !jPasswordFieldDecryptSignature.getText().equals(
                            p.get("decryptsignaturePassword").toString())) {
                signatureAttributeChanged = true;
            }
            StringEncryptor encryptorDecryptResponse = EncryptablePropertyUtils.getEncryptor();
            p.put("decryptsignaturePassword", EncryptablePropertyUtils.wrapWithENC(encryptorDecryptResponse.encrypt(new String(jPasswordFieldDecryptSignature.getPassword()))));

            // Feature Changes:Encrypting Passoword properties
            if (StringUtils.isNotBlank(jPasswordSignature.getText())
                    && !jPasswordSignature.getText().equals(p.getProperty("signaturePassword").toString())) {
                signatureAttributeChanged = true;
            }
            StringEncryptor encryptor = EncryptablePropertyUtils.getEncryptor();
            p.put("signaturePassword", EncryptablePropertyUtils.wrapWithENC(encryptor.encrypt(new String(jPasswordSignature.getPassword()))));

            p.put("udc", jTextFieldUDC.getText());
            p.put("fdc", jTextFieldFDC.getText());
            p.put("idc", jTextFieldIDC.getText());

            p.put("lot", jComboBoxLocationType.getSelectedItem().toString());
            p.put("lov", jTextFieldLocationValue.getText());
            p.put("useSSK", jComboBoxUseSSK.getSelectedItem().toString());
            p.put("pidType", jComboBoxPidType.getSelectedItem().toString());
            p.put("publicIP", jTextFieldPIP.getText());

            p.put("pincode", jTextFieldLocationValue.getText());

            File f = new File("authclient.properties");
            of = new FileOutputStream(f);
            p.store(of, "Auth client preferences");

            initializeAuthClient();

            if (signatureAttributeChanged) {
                JOptionPane
                        .showMessageDialog(
                                this,
                                "Signature related attributes changed. \nPlease RESTART the auth client for it to take effect.",
                                "UID Authentication Demo Client",
                                JOptionPane.ERROR_MESSAGE);
            }

        } catch (IOException ex) {
            Logger.getLogger(SampleClientMainFrame.class.getName()).log(
                    Level.SEVERE, null, ex);
        } finally {
            try {
                if (is != null) {
                    is.close();
                }

                if (of != null) {
                    of.close();
                }
            } catch (IOException ex) {
                Logger.getLogger(SampleClientMainFrame.class.getName()).log(
                        Level.SEVERE, null, ex);
            }
        }
    }

    private void jButtonSaveActionPerformed(java.awt.event.ActionEvent evt) {// GEN-FIRST:event_jButtonSaveActionPerformed
        storePreferences();
    }// GEN-LAST:event_jButtonSaveActionPerformed

    private void jButtonPickPublicKeyFileActionPerformed(
            java.awt.event.ActionEvent evt) {// GEN-FIRST:event_jButtonPickPublicKeyFileActionPerformed
        JFileChooser fc = new JFileChooser();
        int returnVal = fc.showOpenDialog(this.jDialogPreferences);

        if (returnVal == JFileChooser.APPROVE_OPTION) {
            File file = fc.getSelectedFile();
            this.jTextFieldPublicKeyFile.setText(file.getAbsolutePath());
        }

    }// GEN-LAST:event_jButtonPickPublicKeyFileActionPerformed

    private void jRadioButtonNameMatchExactActionPerformed(
            java.awt.event.ActionEvent evt) {// GEN-FIRST:event_jRadioButtonNameMatchExactActionPerformed
        jSpinnerNameMatchValue.setEnabled(false);
        jSpinnerNameMatchValue.setValue(100);
    }// GEN-LAST:event_jRadioButtonNameMatchExactActionPerformed

    private void jRadioButtonNameMatchPartialActionPerformed(
            java.awt.event.ActionEvent evt) {// GEN-FIRST:event_jRadioButtonNameMatchPartialActionPerformed
        jSpinnerNameMatchValue.setEnabled(true);
        jSpinnerNameMatchValue.setValue(1);
    }// GEN-LAST:event_jRadioButtonNameMatchPartialActionPerformed

    private void jRadioButtonPfaExactMatchActionPerformed(
            java.awt.event.ActionEvent evt) {// GEN-FIRST:event_jRadioButtonPfaExactMatchActionPerformed
        jSpinnerPfaMatchValue.setEnabled(false);
        jSpinnerPfaMatchValue.setValue(100);
    }// GEN-LAST:event_jRadioButtonPfaExactMatchActionPerformed

    private void jRadioButtonPfaPartialMatchActionPerformed(
            java.awt.event.ActionEvent evt) {// GEN-FIRST:event_jRadioButtonPfaPartialMatchActionPerformed
        jSpinnerPfaMatchValue.setEnabled(true);
        jSpinnerPfaMatchValue.setValue(75);
    }// GEN-LAST:event_jRadioButtonPfaPartialMatchActionPerformed

    private void formWindowOpened(java.awt.event.WindowEvent evt) {// GEN-FIRST:event_formWindowOpened
        File preferencesFile = new File("authclient.properties");
        if (!preferencesFile.exists()) {
            JOptionPane
                    .showMessageDialog(
                            this,
                            "Default preferences are being used.\nEdit your preferences and and save it by using menu option Edit->Preferences",
                            "UID Authentication Demo Client",
                            JOptionPane.INFORMATION_MESSAGE);
        }
    }// GEN-LAST:event_formWindowOpened

    private void jTextFieldAgeActionPerformed(java.awt.event.ActionEvent evt) {// GEN-FIRST:event_jTextFieldAgeActionPerformed
        // TODO add your handling code here:
    }// GEN-LAST:event_jTextFieldAgeActionPerformed

    private void jRadioFuzzyNameActionPerformed(java.awt.event.ActionEvent evt) {// GEN-FIRST:event_jRadioFuzzyNameActionPerformed
        jSpinnerNameMatchValue.setEnabled(true);
    }// GEN-LAST:event_jRadioFuzzyNameActionPerformed

    private void jRadioAddressFuzzyActionPerformed(
            java.awt.event.ActionEvent evt) {// GEN-FIRST:event_jRadioAddressFuzzyActionPerformed
        jSpinnerPfaMatchValue.setEnabled(true);
    }// GEN-LAST:event_jRadioAddressFuzzyActionPerformed

    private void jLanguageComboActionPerformed(java.awt.event.ActionEvent evt) {// GEN-FIRST:event_jLanguageComboActionPerformed
        String language = "English";
        if (this.jLanguageCombo.getSelectedIndex() > 0) {
            language = this.jLanguageCombo.getSelectedItem().toString();
        }
        Font f = languageToFontMap.get(language);
        this.jTextAreaFullAddressValueLocal.setFont(f);
        this.jTextFieldNameLocal.setFont(f);
    }// GEN-LAST:event_jLanguageComboActionPerformed

    public void comboBoxVerActionPerformed(java.awt.event.ActionEvent evt) {
        if (this.comboBoxVer.getSelectedItem().toString().equals("1.0")) {
            comboBoxPfr.setEnabled(false);
        } else {
            comboBoxPfr.setEnabled(true);
        }

    }

    private void jTextFieldLocalityActionPerformed(
            java.awt.event.ActionEvent evt) {// GEN-FIRST:event_jTextFieldLocalityActionPerformed
        // TODO add your handling code here:
    }// GEN-LAST:event_jTextFieldLocalityActionPerformed

    private void jButtonPickPublicKeyFile1ActionPerformed(
            java.awt.event.ActionEvent evt) {// GEN-FIRST:event_jButtonPickPublicKeyFile1ActionPerformed
        JFileChooser fc = new JFileChooser();
        int returnVal = fc.showOpenDialog(this.jDialogPreferences);

        if (returnVal == JFileChooser.APPROVE_OPTION) {
            File file = fc.getSelectedFile();
            this.jTextFieldSignatureFile.setText(file.getAbsolutePath());
        }
    }// GEN-LAST:event_jButtonPickPublicKeyFile1ActionPerformed

    private void jButton1ActionPerformed(java.awt.event.ActionEvent evt) {// GEN-FIRST:event_jButton1ActionPerformed

        JOptionPane
                .showMessageDialog(
                        this,
                        "Biometrics capture and authemtication not supported.",
                        "UID Authentication Demo Client",
                        JOptionPane.ERROR_MESSAGE);
    }// GEN-LAST:event_jButton1ActionPerformed

    private void jFormattedTextFieldAADHAAR1ActionPerformed(
            java.awt.event.ActionEvent evt) {// GEN-FIRST:event_jFormattedTextFieldAADHAAR1ActionPerformed
        // TODO add your handling code here:
    }// GEN-LAST:event_jFormattedTextFieldAADHAAR1ActionPerformed

    private void jComboBoxDOBTypeActionPerformed(java.awt.event.ActionEvent evt) {// GEN-FIRST:event_jComboBoxDOBTypeActionPerformed
        // TODO add your handling code here:
    }// GEN-LAST:event_jComboBoxDOBTypeActionPerformed

    private void jButtonValidateResponseActionPerformed(
            java.awt.event.ActionEvent evt) {// GEN-FIRST:event_jButtonValidateResponseActionPerformed
        // TODO add your handling code here:

        jDialogResponseValidationResult.setBounds(100, 100, 859, 477);
        jDialogResponseValidationResult.setVisible(true);
        jTextAreaResponseValidationResult.scrollRectToVisible(new Rectangle(0,
                0, 0, 0));

    }// GEN-LAST:event_jButtonValidateResponseActionPerformed

    private void jButtonResultValidationCopyToClipboardActionPerformed(
            java.awt.event.ActionEvent evt) {// GEN-FIRST:event_jButtonResultValidationCopyToClipboardActionPerformed
        jTextAreaResponseValidationResult.selectAll();
        jTextAreaResponseValidationResult.copy();
    }// GEN-LAST:event_jButtonResultValidationCopyToClipboardActionPerformed

    private void jButtonResultValidationDoneActionPerformed(
            java.awt.event.ActionEvent evt) {// GEN-FIRST:event_jButtonResultValidationDoneActionPerformed
        jDialogResponseValidationResult.setVisible(false);
    }// GEN-LAST:event_jButtonResultValidationDoneActionPerformed

    private void jTextFieldLocStateCodeActionPerformed(
            java.awt.event.ActionEvent evt) {// GEN-FIRST:event_jTextFieldLocStateCodeActionPerformed
        // TODO add your handling code here:
    }// GEN-LAST:event_jTextFieldLocStateCodeActionPerformed

    private void jMenuOptionsActionPerformed(java.awt.event.ActionEvent evt) {// GEN-FIRST:event_jMenuOptionsActionPerformed
        // TODO add your handling code here:
    }// GEN-LAST:event_jMenuOptionsActionPerformed

    private void jButtonSendOTPRequestActionPerformed(
            java.awt.event.ActionEvent evt) {// GEN-FIRST:event_jButtonSendOTPRequestActionPerformed
        jLabelOtpRequestStatus.setText("Requesting OTP ...");

        String channel = getPreferredChannel();

        OtpDataFromDeviceToAUA auaData = new OtpDataFromDeviceToAUA(
                jFormattedTextFieldAADHAAR1.getText(),
                jTextFieldTerminalID.getText(), channel);

        OtpRequestCreator requestCreator = new OtpRequestCreator();
        Otp otp = requestCreator.createOtpRequest(this.jTextFieldAua.getText(),
                this.jTextFieldServiceAgency.getText(),
                this.jTextFieldLicenseKey.getText(), auaData);
        try {
            OtpRes res = otpClient.generateOtp(otp).getOtpRes();
            if (res.getRet().equals(OtpResult.N)) {
                jLabelOtpRequestStatus.setText("Failed (Reason: "
                        + res.getErr() + " ("
                        + ErrorCodeDescriptions.getDescription(res.getErr())
                        + "), " + " Code: " + (res.getCode()) + ")");
                jLabelOtpRequestStatus.setToolTipText("Failed (Reason: "
                        + res.getErr() + " ("
                        + ErrorCodeDescriptions.getDescription(res.getErr())
                        + "), " + " Code: " + (res.getCode()) + ")");

            } else {
                jLabelOtpRequestStatus.setText("Success (Code:"
                        + (res.getCode()) + ")");
            }
        } catch (Exception e) {
            jLabelOtpRequestStatus.setText(e.getMessage());
        }

    }// GEN-LAST:event_jButtonSendOTPRequestActionPerformed

    private String getPreferredChannel() {
        String channel = "";
        if (jCheckBoxOtpViaEmail.isSelected()
                && jCheckBoxOtpViaSMS.isSelected()) {
            channel = OtpDataFromDeviceToAUA.BOTH_EMAIL_SMS_CHANNEL;
        } else if (jCheckBoxOtpViaEmail.isSelected()) {
            channel = OtpDataFromDeviceToAUA.EMAIL_CHANNEL;
        } else if (jCheckBoxOtpViaSMS.isSelected()) {
            channel = OtpDataFromDeviceToAUA.SMS_CHANNEL;
        }
        return channel;
    }

    private void jButtonGenerateOTPActionPerformed(
            java.awt.event.ActionEvent evt) {// GEN-FIRST:event_jButtonGenerateOTPActionPerformed
        if (jFormattedTextFieldAADHAAR1.getText().trim().isEmpty()) {
            jLabelUidMandatory.setVisible(true);
        } else {
            jOTP.setModal(true);
            jOTP.setBounds(100, 100, 620, 230);
            jOTP.setVisible(true);
        }
    }// GEN-LAST:event_jButtonGenerateOTPActionPerformed

    private void jButtonOTPDialogDoneActionPerformed(
            java.awt.event.ActionEvent evt) {// GEN-FIRST:event_jButtonOTPDialogDoneActionPerformed
        jOTP.setVisible(false);
        jCheckBoxOtpViaSMS.setSelected(false);
        jCheckBoxOtpViaEmail.setSelected(false);
        jLabelOtpRequestStatus.setText("");

    }// GEN-LAST:event_jButtonOTPDialogDoneActionPerformed

    private void jTextFieldOTPServerUrlActionPerformed(
            java.awt.event.ActionEvent evt) {// GEN-FIRST:event_jTextFieldOTPServerUrlActionPerformed
        // TODO add your handling code here:
    }// GEN-LAST:event_jTextFieldOTPServerUrlActionPerformed

    private void jButtonDSIGPublicKeyActionPerformed(
            java.awt.event.ActionEvent evt) {// GEN-FIRST:event_jButtonDSIGPublicKeyActionPerformed
        JFileChooser fc = new JFileChooser();
        int returnVal = fc.showOpenDialog(this.jDialogPreferences);

        if (returnVal == JFileChooser.APPROVE_OPTION) {
            File file = fc.getSelectedFile();
            this.jTextFieldDSIGPublicKey.setText(file.getAbsolutePath());
        }
    }// GEN-LAST:event_jButtonDSIGPublicKeyActionPerformed

    /**
     *
     * @param added for new brows button
     */
    private void jButtonDecryptSignatureFileActionPerformed(
            java.awt.event.ActionEvent evt) {// GEN-FIRST:event_jButtonDSIGPublicKeyActionPerformed
        JFileChooser fc = new JFileChooser();
        int returnVal = fc.showOpenDialog(this.jDialogPreferences);

        if (returnVal == JFileChooser.APPROVE_OPTION) {
            File file = fc.getSelectedFile();
            this.jTextFieldDecryptSignatureFile.setText(file.getAbsolutePath());
        }
    }

    private DeviceCollectedAuthData constructAuthRequest() {
        DeviceCollectedAuthData request = new DeviceCollectedAuthData();

        String uid = jFormattedTextFieldAADHAAR1.getText();
        request.setUid(uid);

        if (!jLanguageCombo.getSelectedItem().toString()
                .equalsIgnoreCase("select")) {
            String language = languageToCodeMap.get(jLanguageCombo
                    .getSelectedItem().toString());
            request.setLanguage(language);
        } else {
            request.setLanguage(null);
        }

        String name = jTextFieldName.getText().trim();
        if ((name != null) && (name.length() > 0)) {
            request.setName(name);
        }
        String lname = jTextFieldNameLocal.getText().trim();
        if ((lname != null) && (lname.length() > 0)) {
            request.setLname(lname);
        }

        String pinCode = jTextFieldPincode.getText().trim();
        if ((pinCode != null) && (pinCode.length() > 0)) {
            request.setPinCode(pinCode);
        }
        String careOf = jTextFieldCareOf.getText().trim();
        if ((careOf != null) && (careOf.length() > 0)) {
            request.setCareOf(careOf);
        }
        String building = jTextFieldBuilding.getText().trim();
        if ((building != null) && (building.length() > 0)) {
            request.setBuilding(building);
        }
        String street = jTextFieldStreet.getText().trim();
        if ((street != null) && (street.length() > 0)) {
            request.setStreet(street);
        }
        String landmark = jTextFieldLandmark.getText().trim();
        if ((landmark != null) && (landmark.length() > 0)) {
            request.setLandmark(landmark);
        }
        String locality = jTextFieldLocality.getText().trim();
        if ((locality != null) && (locality.length() > 0)) {
            request.setLocality(locality);
        }
        String village = jTextFieldVtc.getText().trim(); // ******
        if ((village != null) && (village.length() > 0)) {
            request.setVillage(village);
        }

        String poName = jTextFieldPOName.getText().trim();
        if ((poName != null) && (poName.length() > 0)) {
            request.setPoName(poName);
        }

        String subdistrict = jTextFieldSubdist.getText().trim();
        if ((subdistrict != null) && (subdistrict.length() > 0)) {
            request.setSubdistrict(subdistrict);
        }

        String district = jTextFieldDistrict.getText().trim();
        if ((district != null) && (district.length() > 0)) {
            request.setDistrict(district);
        }
        String state = (String) jTextFieldState.getText().trim();
        if ((state != null) && (state.trim().length() > 0)) {
            request.setState(state);
        }
        String phoneNo = jTextFieldPhone.getText().trim();
        if ((phoneNo != null) && (phoneNo.length() > 0)) {
            request.setPhoneNo(phoneNo);
        }
        String email = jTextFieldEmail.getText().trim();
        if ((email != null) && (email.length() > 0)) {
            request.setEmail(email);
        }
        String staticPin = (new String(jPasswordFieldPIN.getPassword())).trim();
        if ((staticPin != null) && (staticPin.length() > 0)) {
            request.setStaticPin(staticPin);
        }
        String dynamicPin = (new String(jPasswordFieldOTP.getPassword()))
                .trim();
        if ((dynamicPin != null) && (dynamicPin.length() > 0)) {
            request.setDynamicPin(dynamicPin);
        }

        // Assemble gender
        request.setGender((String) jComboGender.getSelectedItem());

        // Assemble DOB
        String day = jTextFieldDobDay.getText().trim();
        String month = jTextFieldDobMonth.getText().trim();
        String year = jTextFieldDobYear.getText().trim();
        String dob = null;
        if ((year != null) && (year.length() > 0) && (month != null)
                && (month.length() > 0) && (day != null) && (day.length() > 0)) {
            dob = year + "-" + month + "-" + day;
        } else if ((year != null) && (year.length() > 0) && (month != null)
                && (month.length() > 0)) {
            dob = year + "-" + month + "-" + "";
        } else if ((year != null) && (year.length() > 0) && (day != null)
                && (day.length() > 0)) {
            dob = year + "-" + "" + "-" + day;
        } else if ((month != null) && (month.length() > 0) && (day != null)
                && (day.length() > 0)) {
            dob = "" + "-" + month + "-" + day;
        } else if ((month != null) && (month.length() > 0)) {
            dob = "" + "-" + month + "-" + "";
        } else if ((day != null) && (day.length() > 0)) {
            dob = "" + "-" + "" + "-" + day;
        } else if ((year != null) && (year.length() > 0)) {
            dob = year;
        }

        request.setDob(dob);

        if (!"Select".equalsIgnoreCase(jComboBoxDOBType.getSelectedItem()
                .toString())) {
            request.setDobType(jComboBoxDOBType.getSelectedItem().toString());
        }

        if (StringUtils.isNotBlank(this.jTextFieldAge.getText())) {

            request.setAge(jTextFieldAge.getText());
        }
        request.setNameMatchValue((Integer) jSpinnerNameMatchValue.getValue());
        request.setLocalNameMatchValue((Integer) jSpinnerNameMatchValueLocal
                .getValue());

        if (this.bioCaptures.size() > 0) {
            request.setBiometrics(this.bioCaptures);
        }

        request.setFullAddress(this.jTextAreaFullAddressValue.getText());
        request.setLocalFullAddress(this.jTextAreaFullAddressValueLocal
                .getText());
        request.setFullAddressMatchValue((Integer) jSpinnerPfaMatchValue
                .getValue());
        request.setLocalFullAddressMatchValue((Integer) jSpinnerPfaMatchValueLocal
                .getValue());

        Meta m = createMeta();
        request.setDeviceMetaData(m);

        return request;

    }

    private Meta createMeta() {
        Meta m = new Meta();
        m.setFdc(this.jTextFieldFDC.getText());
        m.setIdc(this.jTextFieldIDC.getText());
        m.setPip(this.jTextFieldPIP.getText());
        m.setLot(LocationType.valueOf(this.jComboBoxLocationType
                .getSelectedItem().toString()));
        m.setLov(this.jTextFieldLocationValue.getText());
        m.setUdc(this.jTextFieldUDC.getText());
        return m;
    }

    private void authenticateRequest(DeviceCollectedAuthData authData,
            boolean useProto) {
        try {

            this.repaint();

            try {
                new URL(this.jTextFieldKYCServerURL.getText()).openConnection()
                        .connect();
            } catch (Exception e) {
                JOptionPane
                        .showMessageDialog(
                                this,
                                "Server not reachable.\nVerify the URL in Edit -> Preferences",
                                "UID KYC Demo Client",
                                JOptionPane.ERROR_MESSAGE);
                return;
            }

            if (!(new File(this.jTextFieldPublicKeyFile.getText())).exists()) {
                JOptionPane
                        .showMessageDialog(
                                this,
                                "Public key file not found.\nVerify the file path in Edit -> Preferences",
                                "UID KYC Demo Client",
                                JOptionPane.ERROR_MESSAGE);
                return;
            }

            if (!(new File(this.jTextFieldSignatureFile.getText())).exists()) {
                JOptionPane
                        .showMessageDialog(
                                this,
                                "Signature file not found.\nVerify the file path in Edit -> Preferences",
                                "UID KYC Demo Client",
                                JOptionPane.ERROR_MESSAGE);
                return;
            }

            if (!(new File(this.jTextFieldDecryptSignatureFile.getText())).exists()) {
                JOptionPane.showMessageDialog(this, "Decrypt file not found.\nVerify the file path in Edit -> Preferences",
                        "UID KYC Demo Client", JOptionPane.ERROR_MESSAGE);
                return;
            }

            if (!this.jCheckBoxRa.isSelected()) {
                JOptionPane
                        .showMessageDialog(
                                this,
                                "Cannot send the KYC request without Residnet Consent ",
                                "UID KYC Demo Client",
                                JOptionPane.ERROR_MESSAGE);
                return;
            }

            Uses usesElement = createUsesElement();

            AuthDataFromDeviceToAUA auaData = null;
            /* DataType useProtoDataType; */
            if (useProto) {
                auaData = auaDataCreator.prepareAUAData(authData.getUid(),
                        this.jTextFieldTerminalID.getText(),
                        authData.getDeviceMetaData(),
                        (Object) PidCreator.createProtoPid(authData),
                        DataType.P);
            } else {
                auaData = auaDataCreator.prepareAUAData(authData.getUid(),
                        this.jTextFieldTerminalID.getText(),
                        authData.getDeviceMetaData(),
                        (Object) PidCreator.createXmlPid(authData), DataType.X);
            }

            Tkn token = null;
            if (StringUtils.isNotBlank(this.jTextFieldToken.getText())) {
                token = new Tkn();
                token.setValue(this.jTextFieldToken.getText());
                token.setType(tokenLabelToTokenTypeMap
                        .get((String) this.jComboBoxTokenType.getSelectedItem()));
            }

            Auth auth = AuthRequestCreator.createAuthRequest(
                    this.jTextFieldAua.getText(),
                    this.jTextFieldServiceAgency.getText(),
                    this.jTextFieldLicenseKey.getText(), usesElement, token,
                    auaData, authData.getDeviceMetaData());

            // AuthResponseDetails data = authClient.authenticate(auth);
            // changed for Mobile/Email ID consent and Local  Language required Consent
            lrcheckval = this.lrCheckbox.isSelected();
            //2.0	 new changes for Pfr
            kycClient.setVer(this.comboBoxVer.getSelectedItem().toString());
            kycClient.setPfr(this.comboBoxPfr.getSelectedItem().toString());
            if (StringUtils.isBlank(System.getenv("qa"))) {
                kycClient.setMecLr(this.mecCheckbox.isSelected(), this.lrCheckbox.isSelected());
                kycClient.setDe(this.jCheckBoxDe.isSelected());
                String kycResponseXML = kycClient.kycTrans(auth,
                        this.jTextFieldAua.getText(),
                        this.jCheckBoxRa.isSelected(),
                        this.jTextFieldASALicense.getText(), usesElement,
                        customKYCXML);
                displayAuthResults(kycResponseXML, false);
            } else {
                System.out.println("QA concurrent request mode");
                kycClient.setMecLr(this.mecCheckbox.isSelected(), this.lrCheckbox.isSelected());
                kycClient.setDe(this.jCheckBoxDe.isSelected());

                // to fire concurrent requests set cr=<something> in the environment variables
                if (!StringUtils.isBlank(System.getenv("cr"))) {
                    generateConcurentRequestsAndProcess(kycClient, auth,
                            this.jTextFieldAua.getText(),
                            this.jCheckBoxRa.isSelected(),
                            this.jTextFieldASALicense.getText(), usesElement,
                            this.jTextFieldServiceAgency.getText(),
                            this.jTextFieldLicenseKey.getText(), authData, token,
                            auaDataCreator, useProto,
                            this.jTextFieldTerminalID.getText());
                }
                //
                auth = AuthRequestCreator.createAuthRequest(
                        this.jTextFieldAua.getText(),
                        this.jTextFieldServiceAgency.getText(),
                        this.jTextFieldLicenseKey.getText(), usesElement,
                        token, auaData, authData.getDeviceMetaData());

                String kycResponseXML = kycClient.kycTrans(auth,
                        this.jTextFieldAua.getText(),
                        this.jCheckBoxRa.isSelected(),
                        this.jTextFieldASALicense.getText(), usesElement,
                        customKYCXML);
                displayAuthResults(kycResponseXML, false);
                System.out.println("QA concurrent requests completed");
                JOptionPane.showMessageDialog(this,
                        "All Requests got Response from KYCServer",
                        "UID KYC Demo Client", JOptionPane.INFORMATION_MESSAGE);
            }
            // clearing bio info
            resetFingerprintISOFeatureSet();
        } catch (Exception e) {
            // for all errors
            resetFingerprintISOFeatureSet();
            JOptionPane
                    .showMessageDialog(this, "Error: " + e.getMessage(),
                            "UID Authentication Demo Client",
                            JOptionPane.ERROR_MESSAGE);
            e.printStackTrace();
        }

    }

    private void generateConcurentRequestsAndProcess(KYCClient kycClient,
            Auth auth, String aua, boolean raSelected, String asaLicenseKey,
            Uses uses, String serviceAgency, String auaLicenseKey,
            DeviceCollectedAuthData authData, Tkn token,
            AuthAUADataCreator auaDataCreator, boolean useProto,
            String terminaID) {

        int noOfConcurentRequests = NumberUtils.toInt(
                System.getenv("CONCURRENT_REQUESTS"),
                DEFAULT_CONCURENT_REQUESTS);
        ;
        int noOfRequests = NumberUtils.toInt(System.getenv("NO_OF_REQUESTS"),
                DEFAULT_NO_OF_REQUESTS);
        ExecutorService executorService = Executors
                .newFixedThreadPool(noOfConcurentRequests);
        for (long i = 0; i < noOfRequests - 1; i++) {
            executorService.execute(new RequestProcessor(kycClient, aua,
                    raSelected, asaLicenseKey, uses, serviceAgency,
                    auaLicenseKey, authData, token, auaDataCreator, useProto,
                    terminaID, customKYCXML));
        }
        executorService.shutdown();
        try {
            executorService.awaitTermination(600, TimeUnit.SECONDS);
        } catch (InterruptedException e) {
            e.printStackTrace();
        }
    }

    private Uses createUsesElement() {

        Uses uses = new Uses();
        uses.setPi(UsesFlag.valueOf(jCheckBoxPi.isSelected() ? "Y" : "N"));
        uses.setPa(UsesFlag.valueOf(jCheckBoxPa.isSelected() ? "Y" : "N"));
        uses.setPin(UsesFlag.valueOf(jCheckBoxPin.isSelected() ? "Y" : "N"));
        uses.setOtp(UsesFlag.valueOf(jCheckBoxOtp.isSelected() ? "Y" : "N"));
        uses.setBio(UsesFlag.valueOf(jCheckBoxBio.isSelected() ? "Y" : "N"));
        uses.setPfa(UsesFlag.valueOf(jCheckBoxPfa.isSelected() ? "Y" : "N"));

        String biometricTypes = "";

        if (jCheckBoxFMR.isSelected()) {
            biometricTypes += "FMR";
        }

        if (jCheckBoxFIR.isSelected()) {
            if (StringUtils.isNotBlank(biometricTypes)) {
                biometricTypes += ",";
            }
            biometricTypes += "FIR";
        }

        if (jCheckBoxIIR.isSelected()) {
            if (StringUtils.isNotBlank(biometricTypes)) {
                biometricTypes += ",";
            }
            biometricTypes += "IIR";
        }
        uses.setBt(biometricTypes);
        return uses;
    }

    private void displayAuthResults(String kycResponseXML, boolean useProto)
            throws JAXBException {

        KycRes kycRes = (KycRes) XMLUtilities.parseXML(KycRes.class,
                kycResponseXML);
        javax.swing.JLabel status = (useProto ? this.jLabelAuthStatusTextProto
                : this.jLabelAuthStatusTextXML);
        javax.swing.JLabel statusLabel = (useProto ? this.jLabelAuthStatusProto
                : this.jLabelAuthStatus);

        statusLabel.setText(useProto ? "Proto " : "XML");

        if (kycRes.getRet().toString().equals(AuthResult.Y.toString())) {
            statusLabel.setIcon(new javax.swing.ImageIcon(getClass()
                    .getResource("/success.png")));

            status.setVisible(false);
            status.setText("");

            new KYCResponseWindow(kycRes, kycResponseXML);
        } else {
            statusLabel.setIcon(new javax.swing.ImageIcon(getClass()
                    .getResource("/failure.png")));

            status.setText((useProto ? "Proto " : "XML") + " Error code: "
                    + kycRes.getErr() + " ("
                    + ErrorCodeDescriptions.getDescription(kycRes.getErr())
                    + ")");
            status.setToolTipText((useProto ? "Proto " : "XML")
                    + " Error code: " + kycRes.getErr() + " ("
                    + ErrorCodeDescriptions.getDescription(kycRes.getErr())
                    + ")");
            status.setVisible(true);
        }

        String origValue = StringUtils.isNotBlank(this.jLabelAuthRefCodeValue
                .getText()) ? this.jLabelAuthRefCodeValue.getText() + ", " : "";
        this.jLabelAuthRefCodeValue.setText(origValue + kycRes.getCode());

        this.jLabelAuthRefCodeValue.setVisible(true);
        this.jLabelAuthRefCode.setVisible(true);
    }

    private void resetBfdRankAndResults() {
        Map<FingerPosition, JLabel> fingerPosToLabelMap = getBFDPositionLabelMap();
        for (JLabel jl : fingerPosToLabelMap.values()) {
            jl.setText(" ");
        }

        jLabelBFDStatusXML.setText(" ");
        jLabelBFDStatusProto.setText(" ");
    }

    private void fillAuthResponseValidationText(Auth auth,
            byte[] hashedDemoXML, AuthRes authResult, String responseXML) {
        ValidationResult result = this.authResponseValidator
                .validateAuthResponse(auth, hashedDemoXML, authResult,
                        responseXML);
        this.jTextAreaResponseValidationResult
                .setText(this.jTextAreaResponseValidationResult.getText()
                        + "\n" + result.toString());
        if (!result.isDigitalSignatureVerified()) {
            JOptionPane
                    .showMessageDialog(this, "Signature Verification Failed",
                            "UID Authentication Demo Client",
                            JOptionPane.ERROR_MESSAGE);
        }
    }

    private DeviceCollectedBfdData constructBfdRequest() {

        String uid = jFormattedTextFieldAADHAAR1.getText();

        List<DeviceCollectedBfdData.BiometricData> listOfBiometrics = new ArrayList<>();

        DeviceCollectedBfdData request = new DeviceCollectedBfdData(uid,
                listOfBiometrics, createMeta());
        return request;

    }

    private void performBfd(DeviceCollectedBfdData rbdData, boolean useProto) {
        JOptionPane
                .showMessageDialog(this, "BFD is not supported",
                        "UID Authentication Demo Client",
                        JOptionPane.INFORMATION_MESSAGE);
    }

    public void drawFingerprintImage(Image image) {
        jLabelBiometric.setIcon(new ImageIcon(image.getScaledInstance(
                jLabelBiometric.getWidth(), jLabelBiometric.getHeight(),
                Image.SCALE_DEFAULT)));
    }

    /**
     * @param args the command line arguments
     */
    public static void main(String args[]) {

        try {
            // Set System L&F
            UIManager.setLookAndFeel(UIManager.getSystemLookAndFeelClassName());

        } catch (Exception e) {
            e.printStackTrace();
        }

        java.awt.EventQueue.invokeLater(new Runnable() {

            public void run() {
                try {
                    new SampleClientMainFrame().setVisible(true);

                } catch (URISyntaxException ex) {
                    Logger.getLogger(SampleClientMainFrame.class.getName())
                            .log(Level.SEVERE, null, ex);
                }
            }
        });
    }

	// Variables declaration - do not modify//GEN-BEGIN:variables
	private javax.swing.ButtonGroup buttonGroup1;
	private javax.swing.JButton jButton1;
	private javax.swing.JButton jButtonAuthenticate;
	private javax.swing.JButton jButtonBFDReset;
	private javax.swing.JButton jButtonClear;
	private javax.swing.JButton jButtonDSIGPublicKey;
	private javax.swing.JButton jButtonDecryptSignatureFile;
	private javax.swing.JButton jButtonGenerateOTP;
	private javax.swing.ButtonGroup jButtonGroupAddressMatchStrategy;
	private javax.swing.ButtonGroup jButtonGroupNameMatchStrategy;
	private javax.swing.JButton jButtonInitiateBFD;
	private javax.swing.JButton jButtonOTPDialogDone;
	private javax.swing.JButton jButtonPerformBFD;

	private javax.swing.JButton jButtonPickPublicKeyFile;
	private javax.swing.JButton jButtonPickPublicKeyFile1;
	private javax.swing.JButton jButtonResultValidationCopyToClipboard;
	private javax.swing.JButton jButtonResultValidationDone;
	private javax.swing.JButton jButtonSave;
	private javax.swing.JButton jButtonScan;
	private javax.swing.JButton jButtonScanLeftIndex;
	private javax.swing.JButton jButtonScanLeftLittle;
	private javax.swing.JButton jButtonScanLeftRing;
	private javax.swing.JButton jButtonScanLeftThumb;
	private javax.swing.JButton jButtonScanMiddle;
	private javax.swing.JButton jButtonScanRightIndex;
	private javax.swing.JButton jButtonScanRightLittle;
	private javax.swing.JButton jButtonScanRightMiddle;
	private javax.swing.JButton jButtonScanRightRing;
	private javax.swing.JButton jButtonScanRightThumb;
	private javax.swing.JButton jButtonSendOTPRequest;
	private javax.swing.JButton jButtonValidateResponse;
	private javax.swing.JCheckBox jCheckBoxBio;
	private javax.swing.JCheckBox jCheckBoxFIR;
	private javax.swing.JCheckBox jCheckBoxFMR;
	private javax.swing.JCheckBox jCheckBoxIIR;
	private javax.swing.JCheckBox jCheckBoxOtp;
	private javax.swing.JCheckBox jCheckBoxOtpViaEmail;
	private javax.swing.JCheckBox jCheckBoxOtpViaSMS;
	private javax.swing.JCheckBox jCheckBoxPa;
	private javax.swing.JCheckBox jCheckBoxPfa;
	private javax.swing.JCheckBox jCheckBoxPi;
	
	private javax.swing.JCheckBox jCheckBoxPin;
	private javax.swing.JComboBox jComboBiometricPosition;
	private javax.swing.JComboBox jComboBoxDOBType;
	private javax.swing.JComboBox jComboBoxLocationType;
	private javax.swing.JComboBox jComboBoxPidType;
	private javax.swing.JComboBox jComboBoxTokenType;
	private javax.swing.JComboBox jComboBoxUseSSK;
	private javax.swing.JComboBox jComboGender;
	private javax.swing.JDialog jDialogBFD;
	private javax.swing.JDialog jDialogPreferences;
	private javax.swing.JDialog jDialogResponseValidationResult;
	private javax.swing.JFormattedTextField jFormattedTextFieldAADHAAR1;
	private javax.swing.JPanel jFrameAddressDetails;
	private javax.swing.JPanel jFrameIdentificationDetails;
	private javax.swing.JLabel jLabeDistrict;
	private javax.swing.JLabel jLabel1;
	private javax.swing.JLabel jLabel10;
	private javax.swing.JLabel jLabel11;
	private javax.swing.JLabel jLabel12;
	private javax.swing.JLabel jLabel13;
	private javax.swing.JLabel jLabel14;
	private javax.swing.JLabel jLabel15;
	//3333
	private javax.swing.JLabel jLabelDe;
	private javax.swing.JLabel jLabel16;
	private javax.swing.JLabel jLabel17;
	private javax.swing.JLabel jLabel18;
	private javax.swing.JLabel jLabel19;
	private javax.swing.JLabel jLabel2;
	private javax.swing.JLabel jLabel20;
	private javax.swing.JLabel jLabel21;
	private javax.swing.JLabel jLabel22;
	private javax.swing.JLabel jLabel23;
	private javax.swing.JLabel jLabel24;
	private javax.swing.JLabel jLabel25;
	private javax.swing.JLabel jLabel26;
	private javax.swing.JLabel jLabel27;
	private javax.swing.JLabel jLabel28;
	private javax.swing.JLabel jLabel29;
	private javax.swing.JLabel jLabel3;
	private javax.swing.JLabel jLabel31;
	private javax.swing.JLabel jLabel32;
	private javax.swing.JLabel jLabel33;
	private javax.swing.JLabel jLabel34;
	private javax.swing.JLabel jLabel35;
	private javax.swing.JLabel jLabel4;
	private javax.swing.JLabel jLabel44;
	private javax.swing.JLabel jLabel45;
	private javax.swing.JLabel jLabel46;
	private javax.swing.JLabel jLabel47;
	private javax.swing.JLabel jLabel48;
	private javax.swing.JLabel jLabel49;
	private javax.swing.JLabel jLabel5;
	private javax.swing.JLabel jLabel50;
	private javax.swing.JLabel jLabel51;
	private javax.swing.JLabel jLabel52;
	private javax.swing.JLabel jLabel53;
	private javax.swing.JLabel jLabel6;
	private javax.swing.JLabel jLabel7;
	private javax.swing.JLabel jLabel8;
	private javax.swing.JLabel jLabel9;
	private javax.swing.JLabel jLabelAUA;
	private javax.swing.JLabel jLabelAUA1;
	private javax.swing.JLabel jLabelAadhaarNumber;
	private javax.swing.JLabel jLabelAge;
	private javax.swing.JLabel jLabelAuthRefCode;
	private javax.swing.JLabel jLabelAuthRefCodeValue;
	private javax.swing.JLabel jLabelAuthStatus;
	private javax.swing.JLabel jLabelAuthStatusProto;
	private javax.swing.JLabel jLabelAuthStatusTextProto;
	private javax.swing.JLabel jLabelAuthStatusTextXML;
	private javax.swing.JLabel jLabelBFDRankLeftIndex;
	private javax.swing.JLabel jLabelBFDRankLeftLittle;
	private javax.swing.JLabel jLabelBFDRankLeftMiddle;
	private javax.swing.JLabel jLabelBFDRankLeftRing;
	private javax.swing.JLabel jLabelBFDRankLeftThumb;
	private javax.swing.JLabel jLabelBFDRankRightIndex;
	private javax.swing.JLabel jLabelBFDRankRightLittle;
	private javax.swing.JLabel jLabelBFDRankRightMiddle;
	private javax.swing.JLabel jLabelBFDRankRightRing;
	private javax.swing.JLabel jLabelBFDRankRightThumb;
	private javax.swing.JLabel jLabelBFDStatusProto;
	private javax.swing.JLabel jLabelBFDStatusXML;
	private javax.swing.JLabel jLabelBiometric;
	private javax.swing.JLabel jLabelBiometricFile;
	private javax.swing.JLabel jLabelBiometricLeftIndex;
	private javax.swing.JLabel jLabelBiometricLeftLittle;
	private javax.swing.JLabel jLabelBiometricLeftMiddle;
	private javax.swing.JLabel jLabelBiometricLeftRing;
	private javax.swing.JLabel jLabelBiometricLeftThumb;
	private javax.swing.JLabel jLabelBiometricRightIndex;
	private javax.swing.JLabel jLabelBiometricRightLittle;
	private javax.swing.JLabel jLabelBiometricRightMiddle;
	private javax.swing.JLabel jLabelBiometricRightRing;
	private javax.swing.JLabel jLabelBiometricRightThumb;
	private javax.swing.JLabel jLabelBt;
	private javax.swing.JLabel jLabelBuilding;
	private javax.swing.JLabel jLabelCareof;
	private javax.swing.JLabel jLabelDob;
	private javax.swing.JLabel jLabelEmail;
	private javax.swing.JLabel jLabelGener;
	private javax.swing.JLabel jLabelLandmark;
	private javax.swing.JLabel jLabelLocality;
	private javax.swing.JLabel jLabelLocality1;
	private javax.swing.JLabel jLabelLogo;
	private javax.swing.JLabel jLabelName;
	private javax.swing.JLabel jLabelName1;
	private javax.swing.JLabel jLabelOtpRequestStatus;
	private javax.swing.JLabel jLabelPIN;
	private javax.swing.JLabel jLabelPIN1;
	private javax.swing.JLabel jLabelPfa;
	private javax.swing.JLabel jLabelPfa1;
	private javax.swing.JLabel jLabelPhone;
	private javax.swing.JLabel jLabelPincode;
	private javax.swing.JLabel jLabelProgressIndicator;
	private javax.swing.JLabel jLabelState;
	private javax.swing.JLabel jLabelStreet;
	private javax.swing.JLabel jLabelTerminalID;
	private javax.swing.JLabel jLabelTerminalID1;
	private javax.swing.JLabel jLabelToken;
	private javax.swing.JLabel jLabelTokenType;
	private javax.swing.JLabel jLabelUidMandatory;
	private javax.swing.JComboBox jLanguageCombo;
	private javax.swing.JMenuBar jMenuBar;
	private javax.swing.JMenu jMenuFile;
	private javax.swing.JMenuItem jMenuItem1;
	private javax.swing.JMenuItem jMenuItemPreferences;
	private javax.swing.JMenuItem jMenuItemResetSSK;
	private javax.swing.JMenu jMenuOptions;
	private javax.swing.JDialog jOTP;
	private javax.swing.JPanel jPanel1;
	private javax.swing.JPanel jPanel2;
	private javax.swing.JPanel jPanel3;
	private javax.swing.JPanel jPanel4;
	private javax.swing.JPanel jPanel5;
	private javax.swing.JPanel jPanelAddress;
	private javax.swing.JPanel jPanelAuthParameters;
	private javax.swing.JPanel jPanelAuthStatus;
	private javax.swing.JPanel jPanelBFD;
	private javax.swing.JPanel jPanelBiometric;
	private javax.swing.JPanel jPanelBiometricsOuter;
	private javax.swing.JPanel jPanelBiometricsOuter3;
	private javax.swing.JPanel jPanelBiometricsOuter4;
	private javax.swing.JPanel jPanelDeviceDetails;
	private javax.swing.JPanel jPanelIdentificationDetails;
	private javax.swing.JPanel jPanelKYR;
	private javax.swing.JPanel jPanelLocationDetails;
	private javax.swing.JPanel jPanelPfa;
	private javax.swing.JPanel jPanelPreferences;
	private javax.swing.JPanel jPanelUsesPreferences;
	private javax.swing.JPasswordField jPasswordFieldOTP;
	private javax.swing.JPasswordField jPasswordFieldPIN;
	private javax.swing.JPasswordField jPasswordSignature;
	//3333
	private javax.swing.JCheckBox jCheckBoxDe;
	private javax.swing.JRadioButton jRadioAddressFuzzy;
	private javax.swing.JRadioButton jRadioButtonAddressExactMatch;
	private javax.swing.JRadioButton jRadioButtonAddressPartialMatch;
	private javax.swing.JRadioButton jRadioButtonNameMatchExact;
	private javax.swing.JRadioButton jRadioButtonNameMatchPartial;
	private javax.swing.JRadioButton jRadioButtonPfaExactMatch;
	private javax.swing.JRadioButton jRadioButtonPfaPartialMatch;
	private javax.swing.JRadioButton jRadioFuzzyName;
	private javax.swing.JScrollPane jScrollPane1;
	private javax.swing.JScrollPane jScrollPane2;
	private javax.swing.JScrollPane jScrollPane3;
	private javax.swing.JSpinner jSpinnerNameMatchValue;
	private javax.swing.JSpinner jSpinnerNameMatchValueLocal;
	private javax.swing.JSpinner jSpinnerPaMatchValue;
	private javax.swing.JSpinner jSpinnerPfaMatchValue;
	private javax.swing.JSpinner jSpinnerPfaMatchValueLocal;
	private javax.swing.JTextArea jTextAreaFullAddressValue;
	private javax.swing.JTextArea jTextAreaFullAddressValueLocal;
	private javax.swing.JTextArea jTextAreaResponseValidationResult;
	private javax.swing.JTextField jTextFieldASALicense;
	private javax.swing.JTextField jTextFieldAge;
	private javax.swing.JTextField jTextFieldAua;
	private javax.swing.JTextField jTextFieldAuthServerURL;
	private javax.swing.JTextField jTextFieldBFDURL;
	private javax.swing.JTextField jTextFieldBuilding;
	private javax.swing.JTextField jTextFieldCareOf;
	private javax.swing.JTextField jTextFieldDSIGPublicKey;
	private javax.swing.JTextField jTextFieldDistrict;
	private javax.swing.JFormattedTextField jTextFieldDobDay;
	private javax.swing.JFormattedTextField jTextFieldDobMonth;
	private javax.swing.JFormattedTextField jTextFieldDobYear;
	private javax.swing.JTextField jTextFieldEmail;
	private javax.swing.JTextField jTextFieldFDC;
	private javax.swing.JTextField jTextFieldIDC;
	private javax.swing.JTextField jTextFieldLandmark;
	private javax.swing.JTextField jTextFieldLicenseKey;
	private javax.swing.JTextField jTextFieldLocality;
	private javax.swing.JTextField jTextFieldLocationValue;
	private javax.swing.JTextField jTextFieldName;
	private javax.swing.JTextField jTextFieldNameLocal;
	private javax.swing.JTextField jTextFieldOTPServerUrl;
	private javax.swing.JTextField jTextFieldPIP;
	private javax.swing.JTextField jTextFieldPOName;
	private javax.swing.JFormattedTextField jTextFieldPhone;
	private javax.swing.JFormattedTextField jTextFieldPincode;
	private javax.swing.JTextField jTextFieldPublicKeyFile;
	private javax.swing.JTextField jTextFieldServiceAgency;
	private javax.swing.JTextField jTextFieldSignatureAlias;
	private javax.swing.JTextField jTextFieldSignatureFile;
	private javax.swing.JTextField jTextFieldState;
	private javax.swing.JTextField jTextFieldStreet;
	private javax.swing.JTextField jTextFieldSubdist;
	private javax.swing.JTextField jTextFieldTerminalID;
	private javax.swing.JTextField jTextFieldToken;
	private javax.swing.JTextField jTextFieldUDC;
	private javax.swing.JTextField jTextFieldVtc;
	private javax.swing.ButtonGroup jbuttonGroupPfaMatchStrategy;
	private javax.swing.JLabel jLabelResConsent;
	private javax.swing.JCheckBox jCheckBoxRa;

	private javax.swing.JLabel jLabelKycRefCode;
	private javax.swing.JLabel jLabelKycRefCodeValue;
	private javax.swing.JLabel jLabelKYCServerURL;
	private javax.swing.JTextField jTextFieldKYCServerURL;
	/**
	 * new variables added for preference tab
	 */

	private javax.swing.JLabel jLabelDecryptSignatureFile;
	private javax.swing.JLabel jLabelDecryptPrivSignatureAlias;
	private javax.swing.JLabel jLabelDecryptSignaturePassword;

	private javax.swing.JTextField jTextFieldDecryptSignatureFile;
	private javax.swing.JTextField jTextFieldDecryptPrivSignatureAlias;
	private javax.swing.JPasswordField jPasswordFieldDecryptSignature;
	// End of variables declaration//GEN-END:variables

    private javax.swing.JButton jButtonCustomKYC;
    // Added for Mobile/Email ID consent and Local  Language required Consent
    private JCheckBox mecCheckbox;
    public JCheckBox lrCheckbox;
    private JLabel lblVer;
    private JLabel lblPfr;
    private JComboBox comboBoxVer;
    private JComboBox comboBoxPfr;

    private void resetBfdBiometrics() {
        Map<FingerPosition, javax.swing.JLabel> fingerPosToLabelMap = new HashMap<FingerPosition, JLabel>();
        jLabelBiometricLeftLittle.setIcon(null);
        jLabelBiometricLeftRing.setIcon(null);
        jLabelBiometricLeftMiddle.setIcon(null);
        jLabelBiometricLeftIndex.setIcon(null);
        jLabelBiometricLeftThumb.setIcon(null);
        jLabelBiometricRightThumb.setIcon(null);
        jLabelBiometricRightIndex.setIcon(null);
        jLabelBiometricRightMiddle.setIcon(null);
        jLabelBiometricRightRing.setIcon(null);
        jLabelBiometricRightLittle.setIcon(null);
    }

    public static class PinVerifier extends InputVerifier {

        public static final int PIN_MAX_LENGTH = 6;

        @Override
        public boolean verify(JComponent input) {
            JPasswordField password = (JPasswordField) input;
            return StringUtils.isNumeric(new String(password.getPassword()))
                    && password.getPassword().length == PIN_MAX_LENGTH;
        }
    }
}
