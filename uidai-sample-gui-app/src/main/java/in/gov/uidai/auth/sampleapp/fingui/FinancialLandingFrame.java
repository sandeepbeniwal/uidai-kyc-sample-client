/*
 * To change this template, choose Tools | Templates
 * and open the template in the editor.
 */
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
package in.gov.uidai.auth.sampleapp.fingui;

import java.awt.CardLayout;
import java.awt.Font;
import java.awt.Image;
import java.awt.image.BufferedImage;
import java.io.ByteArrayInputStream;
import java.io.File;
import java.io.FileReader;
import java.io.IOException;
import java.net.MalformedURLException;
import java.net.URISyntaxException;
import java.net.URL;
import java.util.ArrayList;
import java.util.List;
import java.util.Properties;
import java.util.logging.Level;
import java.util.logging.Logger;

import javax.imageio.ImageIO;
import javax.swing.ImageIcon;
import javax.swing.JFileChooser;
import javax.swing.JOptionPane;
import javax.xml.bind.JAXBException;

import org.apache.commons.lang.math.NumberUtils;

import in.gov.uidai.auth.aua.helper.AuthRequestCreator;
import in.gov.uidai.auth.aua.helper.DigitalSigner;
import in.gov.uidai.auth.aua.helper.OtpRequestCreator;
import in.gov.uidai.auth.aua.httpclient.KYCClient;
import in.gov.uidai.auth.aua.httpclient.OtpClient;
import in.gov.uidai.auth.device.helper.AuthAUADataCreator;
import in.gov.uidai.auth.device.helper.Encrypter;
import in.gov.uidai.auth.device.helper.PidCreator;
import in.gov.uidai.auth.device.model.AuthDataFromDeviceToAUA;
import in.gov.uidai.auth.device.model.DeviceCollectedAuthData;
import in.gov.uidai.auth.device.model.OtpDataFromDeviceToAUA;
import in.gov.uidai.auth.sampleapp.ErrorCodeDescriptions;
import in.gov.uidai.auth.sampleapp.common.FontManager;
import in.gov.uidai.auth.sampleapp.common.LanguageCodeFontStore;
import in.gov.uidai.auth.sampleapp.common.jasypt.utils.EncryptablePropertyUtils;
import in.gov.uidai.auth.sampleapp.converter.ConverterType;
import in.gov.uidai.auth.sampleapp.exception.ConverterNotFoundException;
import in.gov.uidai.authentication.common.types._2.LocationType;
import in.gov.uidai.authentication.common.types._2.Meta;
import in.gov.uidai.authentication.otp._2.Otp;
import in.gov.uidai.authentication.otp._2.OtpRes;
import in.gov.uidai.authentication.otp._2.OtpResult;
import in.gov.uidai.authentication.uid_auth_request._2.Auth;
import in.gov.uidai.authentication.uid_auth_request._2.DataType;
import in.gov.uidai.authentication.uid_auth_request._2.Uses;
import in.gov.uidai.authentication.uid_auth_request._2.UsesFlag;
import in.gov.uidai.authentication.uid_auth_response._2.AuthRes;
import in.gov.uidai.authentication.uid_auth_response._2.AuthResult;
import in.gov.uidai.kyc.client.DataDecryptor;
import in.gov.uidai.kyc.client.utils.XMLUtilities;
import in.gov.uidai.kyc.uid_kyc_response._2.KycRes;
import in.gov.uidai.kyc.uid_kyc_response._2.LDataType;
import in.gov.uidai.kyc.uid_kyc_response._2.PoaType;
import in.gov.uidai.kyc.uid_kyc_response._2.PoiType;
import in.gov.uidai.kyc.uid_kyc_response._2.UidDataType;



/**
 *
 * @author Sreemanth
 */
public class FinancialLandingFrame extends javax.swing.JFrame {

    public static final int DEFAULT_CONNECTION_RETRY_COUNT = 3;

	private Properties config = null;
    
    private AuthAUADataCreator authAUADataCreator = null;
    private KYCClient kYCClient = null;
    private OtpClient otpClient =null;
    
    private String uid;
    private String kycResponseXMLWithSignInfo;
    
    private List<DeviceCollectedAuthData.BiometricData> bioCaptures = new ArrayList<>();

    
    /**
     * Creates new form FinancialLandingFrame
     */
    public FinancialLandingFrame() {
        initComponents();
        try {
            config = EncryptablePropertyUtils.getEncryptableProperties(); 
            	//new Properties();
            config.load(new FileReader("authclient.properties"));
            initializeKycClient();
            FontManager.registerAllFont();
        } catch (IOException ex) {
            ex.printStackTrace();
            Logger.getLogger(FinancialLandingFrame.class.getName()).log(Level.SEVERE, null, ex);
            config = null;
        }

    }

    /**
     * This method is called from within the constructor to initialize the form.
     * WARNING: Do NOT modify this code. The content of this method is always
     * regenerated by the Form Editor.
     */
    @SuppressWarnings("unchecked")
    // <editor-fold defaultstate="collapsed" desc="Generated Code">//GEN-BEGIN:initComponents
    private void initComponents() {

        chooseApplicationButtonGroup = new javax.swing.ButtonGroup();
        authenticationTypeButtonGroup = new javax.swing.ButtonGroup();
        jOTP = new javax.swing.JDialog();
        jPanel2 = new javax.swing.JPanel();
        jPanel3 = new javax.swing.JPanel();
        jCheckBoxOtpViaSMS = new javax.swing.JCheckBox();
        jCheckBoxOtpViaEmail = new javax.swing.JCheckBox();
        jButtonSendOTPRequest = new javax.swing.JButton();
        jButtonOTPDialogDone = new javax.swing.JButton();
        jLabelOtpRequestStatus = new javax.swing.JLabel();
        jPanel1 = new javax.swing.JPanel();
        chooseApplicationPanel = new javax.swing.JPanel();
        bankLogoLabel = new javax.swing.JLabel();
        aadhaarLogoLabel = new javax.swing.JLabel();
        jLabel10 = new javax.swing.JLabel();
        contentPanel = new javax.swing.JPanel();
        applicationOptionsPanel = new javax.swing.JPanel();
        jRadioButton1 = new javax.swing.JRadioButton();
        jRadioButton2 = new javax.swing.JRadioButton();
        jRadioButton3 = new javax.swing.JRadioButton();
        jRadioButton4 = new javax.swing.JRadioButton();
        jRadioButton5 = new javax.swing.JRadioButton();
        jRadioButton6 = new javax.swing.JRadioButton();
        continueButton2 = new javax.swing.JButton();
        inputContentPanel = new javax.swing.JPanel();
        jLabel11 = new javax.swing.JLabel();
        jFormattedTextFieldAADHAARNo = new javax.swing.JFormattedTextField();
        try {
            jFormattedTextFieldAADHAARNo.setFormatterFactory(new javax.swing.text.DefaultFormatterFactory(new javax.swing.text.MaskFormatter("############")));
        } catch (java.text.ParseException ex) {
            ex.printStackTrace();
        }
        validationMessageLabel = new javax.swing.JLabel();
        jLabel12 = new javax.swing.JLabel();
        bioMetrictRadioButton = new javax.swing.JRadioButton();
        otpRadioButton = new javax.swing.JRadioButton();
        residentConsentCheckbox = new javax.swing.JCheckBox();
        kycResponseStatusPanel = new javax.swing.JPanel();
        statusLabel = new javax.swing.JLabel();
        kycErrorCodeLabel = new javax.swing.JLabel();
        authErrorCode = new javax.swing.JLabel();
        bioOTPPanel = new javax.swing.JPanel();
        bioMetricsCapturePanel = new javax.swing.JPanel();
        bioMetricsSelect = new javax.swing.JComboBox();
        biometricsScanButton = new javax.swing.JButton();
        bioImagePanel = new javax.swing.JPanel();
        bioImageLabel = new javax.swing.JLabel();
        otpPanel = new javax.swing.JPanel();
        otpPinLabel = new javax.swing.JLabel();
        otpPinTextField = new javax.swing.JPasswordField();
        jButton1 = new javax.swing.JButton();
        resetButton1 = new javax.swing.JButton();
        sendKYCRequestButton = new javax.swing.JButton();
        responeContentPanel = new javax.swing.JPanel();
        poiPanel = new javax.swing.JPanel();
        photoPanel = new javax.swing.JPanel();
        photoLabel = new javax.swing.JLabel();
        poiDetailsPanel = new javax.swing.JPanel();
        jPanel13 = new javax.swing.JPanel();
        aadhaarNumberLabel = new javax.swing.JLabel();
        jPanel14 = new javax.swing.JPanel();
        jLabel24 = new javax.swing.JLabel();
        residenNameTextField = new javax.swing.JTextField();
        jLabel25 = new javax.swing.JLabel();
        dobTextField = new javax.swing.JTextField();
        genderTextField = new javax.swing.JTextField();
        jLabel26 = new javax.swing.JLabel();
        jLabel27 = new javax.swing.JLabel();
        phoneNumberTextField = new javax.swing.JTextField();
        jLabel28 = new javax.swing.JLabel();
        emailTextField = new javax.swing.JTextField();
        poaPanel = new javax.swing.JPanel();
        jLabel29 = new javax.swing.JLabel();
        careOfTextField = new javax.swing.JTextField();
        jLabel30 = new javax.swing.JLabel();
        houseNoTextField = new javax.swing.JTextField();
        jLabel31 = new javax.swing.JLabel();
        landMarkTextField = new javax.swing.JTextField();
        jLabel32 = new javax.swing.JLabel();
        streetTextField = new javax.swing.JTextField();
        localityTextField = new javax.swing.JTextField();
        jLabel33 = new javax.swing.JLabel();
        jLabel34 = new javax.swing.JLabel();
        postOfficeTextField = new javax.swing.JTextField();
        subDistrictTextField = new javax.swing.JTextField();
        vtcNameTextField = new javax.swing.JTextField();
        jLabel35 = new javax.swing.JLabel();
        jLabel36 = new javax.swing.JLabel();
        districtTextField = new javax.swing.JTextField();
        jLabel37 = new javax.swing.JLabel();
        stateTextField = new javax.swing.JTextField();
        jLabel38 = new javax.swing.JLabel();
        jLabel39 = new javax.swing.JLabel();
        pincodeTextField = new javax.swing.JTextField();
        ouputTypeCombo = new javax.swing.JComboBox(ConverterType.getConverterTypes());
        saveAsButton = new javax.swing.JButton();
        responseResetButton = new javax.swing.JButton();
        poaLangPanel = new javax.swing.JPanel();
        jlangLabel40 = new javax.swing.JLabel();
        careOfLangTextField = new javax.swing.JTextField();
        jlangLabel141 = new javax.swing.JLabel();
        houseNoLangTextField = new javax.swing.JTextField();
        jlangLabel42 = new javax.swing.JLabel();
        jlangLabel43 = new javax.swing.JLabel();
        jlangLabel45 = new javax.swing.JLabel();
        jlangLabel44 = new javax.swing.JLabel();
        jlangLabel46 = new javax.swing.JLabel();
        jlangLabel47 = new javax.swing.JLabel();
        landMarkLangTextField = new javax.swing.JTextField();
        localityLangTextField = new javax.swing.JTextField();
        vtcNameLangTextField = new javax.swing.JTextField();
        streetLangTextField = new javax.swing.JTextField();
        postOfficeLangTextField = new javax.swing.JTextField();
        subDistrictLangTextField = new javax.swing.JTextField();
        jlangLabel48 = new javax.swing.JLabel();
        jlangLabel50 = new javax.swing.JLabel();
        districtLangTextField = new javax.swing.JTextField();
        stateLangTextField = new javax.swing.JTextField();
        jlangLabel151 = new javax.swing.JLabel();
        pincodeLangTextField = new javax.swing.JTextField();

        jOTP.setTitle("OTP Channels");

        jPanel2.setBackground(new java.awt.Color(255, 255, 255));

        jPanel3.setBackground(new java.awt.Color(255, 255, 255));
        jPanel3.setBorder(javax.swing.BorderFactory.createTitledBorder("Select channels for OTP delivery"));

        jCheckBoxOtpViaSMS.setBackground(new java.awt.Color(255, 255, 255));
        jCheckBoxOtpViaSMS.setText("via SMS");

        jCheckBoxOtpViaEmail.setBackground(new java.awt.Color(255, 255, 255));
        jCheckBoxOtpViaEmail.setText("via Email");

        javax.swing.GroupLayout jPanel3Layout = new javax.swing.GroupLayout(jPanel3);
        jPanel3.setLayout(jPanel3Layout);
        jPanel3Layout.setHorizontalGroup(
            jPanel3Layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
            .addGroup(jPanel3Layout.createSequentialGroup()
                .addContainerGap()
                .addGroup(jPanel3Layout.createParallelGroup(javax.swing.GroupLayout.Alignment.TRAILING, false)
                    .addComponent(jCheckBoxOtpViaEmail, javax.swing.GroupLayout.Alignment.LEADING, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE)
                    .addComponent(jCheckBoxOtpViaSMS, javax.swing.GroupLayout.Alignment.LEADING, javax.swing.GroupLayout.DEFAULT_SIZE, 214, Short.MAX_VALUE))
                .addContainerGap(236, Short.MAX_VALUE))
        );
        jPanel3Layout.setVerticalGroup(
            jPanel3Layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
            .addGroup(jPanel3Layout.createSequentialGroup()
                .addComponent(jCheckBoxOtpViaSMS)
                .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED, javax.swing.GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE)
                .addComponent(jCheckBoxOtpViaEmail)
                .addContainerGap())
        );

        jButtonSendOTPRequest.setText("Generate OTP");
        jButtonSendOTPRequest.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                jButtonSendOTPRequestActionPerformed(evt);
            }
        });

        jButtonOTPDialogDone.setText("Cancel");
        jButtonOTPDialogDone.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                jButtonOTPDialogDoneActionPerformed(evt);
            }
        });

        jLabelOtpRequestStatus.setText(".");

        javax.swing.GroupLayout jPanel2Layout = new javax.swing.GroupLayout(jPanel2);
        jPanel2.setLayout(jPanel2Layout);
        jPanel2Layout.setHorizontalGroup(
            jPanel2Layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
            .addGroup(jPanel2Layout.createSequentialGroup()
                .addContainerGap()
                .addGroup(jPanel2Layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
                    .addGroup(javax.swing.GroupLayout.Alignment.TRAILING, jPanel2Layout.createSequentialGroup()
                        .addComponent(jButtonOTPDialogDone)
                        .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED, 302, Short.MAX_VALUE)
                        .addComponent(jButtonSendOTPRequest))
                    .addComponent(jPanel3, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE)
                    .addComponent(jLabelOtpRequestStatus, javax.swing.GroupLayout.DEFAULT_SIZE, 468, Short.MAX_VALUE))
                .addContainerGap())
        );
        jPanel2Layout.setVerticalGroup(
            jPanel2Layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
            .addGroup(javax.swing.GroupLayout.Alignment.TRAILING, jPanel2Layout.createSequentialGroup()
                .addContainerGap()
                .addComponent(jPanel3, javax.swing.GroupLayout.PREFERRED_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.PREFERRED_SIZE)
                .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.UNRELATED)
                .addComponent(jLabelOtpRequestStatus, javax.swing.GroupLayout.DEFAULT_SIZE, 33, Short.MAX_VALUE)
                .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.UNRELATED)
                .addGroup(jPanel2Layout.createParallelGroup(javax.swing.GroupLayout.Alignment.BASELINE)
                    .addComponent(jButtonSendOTPRequest)
                    .addComponent(jButtonOTPDialogDone))
                .addGap(28, 28, 28))
        );

        javax.swing.GroupLayout jOTPLayout = new javax.swing.GroupLayout(jOTP.getContentPane());
        jOTP.getContentPane().setLayout(jOTPLayout);
        jOTPLayout.setHorizontalGroup(
            jOTPLayout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
            .addComponent(jPanel2, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE)
        );
        jOTPLayout.setVerticalGroup(
            jOTPLayout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
            .addComponent(jPanel2, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE)
        );

        setDefaultCloseOperation(javax.swing.WindowConstants.EXIT_ON_CLOSE);
        setIconImage(new javax.swing.ImageIcon(getClass().getResource("/logo3.jpg")).getImage());
        setIconImages(null);
        setResizable(false);

        jPanel1.setBackground(new java.awt.Color(111, 175, 238));
        jPanel1.setRequestFocusEnabled(false);

        chooseApplicationPanel.setBackground(new java.awt.Color(255, 255, 255));

        bankLogoLabel.setIcon(new javax.swing.ImageIcon(getClass().getResource("/banklogo.png"))); // NOI18N

        aadhaarLogoLabel.setIcon(new javax.swing.ImageIcon(getClass().getResource("/AadharLogoCopy.jpg"))); // NOI18N

        jLabel10.setFont(new java.awt.Font("Tahoma", 1, 26)); // NOI18N
        jLabel10.setForeground(new java.awt.Color(159, 17, 17));
        jLabel10.setHorizontalAlignment(javax.swing.SwingConstants.CENTER);
        jLabel10.setText("Aadhaar e-KYC Service");

        contentPanel.setBackground(new java.awt.Color(255, 255, 255));
        contentPanel.setPreferredSize(new java.awt.Dimension(926, 625));
        contentPanel.setLayout(new java.awt.CardLayout());

        applicationOptionsPanel.setBackground(new java.awt.Color(255, 255, 255));
        applicationOptionsPanel.setBorder(javax.swing.BorderFactory.createTitledBorder(null, "", javax.swing.border.TitledBorder.DEFAULT_JUSTIFICATION, javax.swing.border.TitledBorder.DEFAULT_POSITION, new java.awt.Font("Tahoma", 1, 12))); // NOI18N
        applicationOptionsPanel.setPreferredSize(new java.awt.Dimension(926, 625));

        jRadioButton1.setBackground(new java.awt.Color(255, 255, 255));
        chooseApplicationButtonGroup.add(jRadioButton1);
        jRadioButton1.setFont(new java.awt.Font("Tahoma", 0, 18)); // NOI18N
        jRadioButton1.setSelected(true);
        jRadioButton1.setText("Apply for a savings account");
        jRadioButton1.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                jRadioButton1ActionPerformed(evt);
            }
        });

        jRadioButton2.setBackground(new java.awt.Color(255, 255, 255));
        chooseApplicationButtonGroup.add(jRadioButton2);
        jRadioButton2.setFont(new java.awt.Font("Tahoma", 0, 18)); // NOI18N
        jRadioButton2.setText("Apply for a home loan");
        jRadioButton2.setToolTipText("");
        jRadioButton2.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                jRadioButton2ActionPerformed(evt);
            }
        });

        jRadioButton3.setBackground(new java.awt.Color(255, 255, 255));
        chooseApplicationButtonGroup.add(jRadioButton3);
        jRadioButton3.setFont(new java.awt.Font("Tahoma", 0, 18)); // NOI18N
        jRadioButton3.setText("Apply for a car loan");
        jRadioButton3.setToolTipText("");
        jRadioButton3.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                jRadioButton3ActionPerformed(evt);
            }
        });

        jRadioButton4.setBackground(new java.awt.Color(255, 255, 255));
        chooseApplicationButtonGroup.add(jRadioButton4);
        jRadioButton4.setFont(new java.awt.Font("Tahoma", 0, 18)); // NOI18N
        jRadioButton4.setText("Apply for an insurance policy");
        jRadioButton4.setToolTipText("");
        jRadioButton4.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                jRadioButton4ActionPerformed(evt);
            }
        });

        jRadioButton5.setBackground(new java.awt.Color(255, 255, 255));
        chooseApplicationButtonGroup.add(jRadioButton5);
        jRadioButton5.setFont(new java.awt.Font("Tahoma", 0, 18)); // NOI18N
        jRadioButton5.setText("Apply for a pension plan");
        jRadioButton5.setToolTipText("");
        jRadioButton5.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                jRadioButton5ActionPerformed(evt);
            }
        });

        jRadioButton6.setBackground(new java.awt.Color(255, 255, 255));
        chooseApplicationButtonGroup.add(jRadioButton6);
        jRadioButton6.setFont(new java.awt.Font("Tahoma", 0, 18)); // NOI18N
        jRadioButton6.setText("Apply for an investment product");
        jRadioButton6.setToolTipText("");
        jRadioButton6.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                jRadioButton6ActionPerformed(evt);
            }
        });

        continueButton2.setFont(new java.awt.Font("Tahoma", 0, 18)); // NOI18N
        continueButton2.setText("Continue");
        continueButton2.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                continueButton2ActionPerformed(evt);
            }
        });

        javax.swing.GroupLayout applicationOptionsPanelLayout = new javax.swing.GroupLayout(applicationOptionsPanel);
        applicationOptionsPanel.setLayout(applicationOptionsPanelLayout);
        applicationOptionsPanelLayout.setHorizontalGroup(
            applicationOptionsPanelLayout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
            .addGroup(applicationOptionsPanelLayout.createSequentialGroup()
                .addGap(190, 190, 190)
                .addGroup(applicationOptionsPanelLayout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
                    .addComponent(jRadioButton1, javax.swing.GroupLayout.Alignment.TRAILING)
                    .addComponent(jRadioButton2, javax.swing.GroupLayout.Alignment.TRAILING)
                    .addComponent(jRadioButton3, javax.swing.GroupLayout.Alignment.TRAILING)
                    .addComponent(jRadioButton4, javax.swing.GroupLayout.Alignment.TRAILING)
                    .addComponent(jRadioButton5, javax.swing.GroupLayout.Alignment.TRAILING)
                    .addComponent(jRadioButton6, javax.swing.GroupLayout.Alignment.TRAILING))
                .addContainerGap(443, Short.MAX_VALUE))
            .addGroup(javax.swing.GroupLayout.Alignment.TRAILING, applicationOptionsPanelLayout.createSequentialGroup()
                .addContainerGap(javax.swing.GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE)
                .addComponent(continueButton2)
                .addGap(314, 314, 314))
        );

        applicationOptionsPanelLayout.linkSize(javax.swing.SwingConstants.HORIZONTAL, new java.awt.Component[] {jRadioButton1, jRadioButton2, jRadioButton3, jRadioButton4, jRadioButton5, jRadioButton6});

        applicationOptionsPanelLayout.setVerticalGroup(
            applicationOptionsPanelLayout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
            .addGroup(applicationOptionsPanelLayout.createSequentialGroup()
                .addGap(64, 64, 64)
                .addComponent(jRadioButton1)
                .addGap(40, 40, 40)
                .addComponent(jRadioButton2)
                .addGap(44, 44, 44)
                .addComponent(jRadioButton3)
                .addGap(44, 44, 44)
                .addComponent(jRadioButton4)
                .addGap(44, 44, 44)
                .addComponent(jRadioButton5)
                .addGap(44, 44, 44)
                .addComponent(jRadioButton6)
                .addGap(29, 29, 29)
                .addComponent(continueButton2)
                .addGap(0, 91, Short.MAX_VALUE))
        );

        applicationOptionsPanelLayout.linkSize(javax.swing.SwingConstants.VERTICAL, new java.awt.Component[] {jRadioButton1, jRadioButton2, jRadioButton3, jRadioButton4, jRadioButton5, jRadioButton6});

        contentPanel.add(applicationOptionsPanel, "card1");

        inputContentPanel.setBackground(new java.awt.Color(255, 255, 255));
        inputContentPanel.setBorder(javax.swing.BorderFactory.createTitledBorder(null, "", javax.swing.border.TitledBorder.DEFAULT_JUSTIFICATION, javax.swing.border.TitledBorder.DEFAULT_POSITION, new java.awt.Font("Tahoma", 1, 12))); // NOI18N
        inputContentPanel.setPreferredSize(new java.awt.Dimension(926, 625));

        jLabel11.setFont(new java.awt.Font("Tahoma", 0, 18)); // NOI18N
        jLabel11.setText("Aadhaar number:");

        jFormattedTextFieldAADHAARNo.setFocusLostBehavior(javax.swing.JFormattedTextField.COMMIT);
        jFormattedTextFieldAADHAARNo.setFont(new java.awt.Font("Tahoma", 0, 18)); // NOI18N
        jFormattedTextFieldAADHAARNo.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                jFormattedTextFieldAADHAARNoActionPerformed(evt);
            }
        });

        validationMessageLabel.setVisible(false);
        validationMessageLabel.setFont(new java.awt.Font("Tahoma", 0, 18)); // NOI18N
        validationMessageLabel.setForeground(new java.awt.Color(255, 0, 0));
        validationMessageLabel.setText("Aadhaar number required.");

        jLabel12.setFont(new java.awt.Font("Tahoma", 0, 18)); // NOI18N
        jLabel12.setText("Authentication Type:");

        bioMetrictRadioButton.setBackground(new java.awt.Color(255, 255, 255));
        authenticationTypeButtonGroup.add(bioMetrictRadioButton);
        bioMetrictRadioButton.setFont(new java.awt.Font("Tahoma", 0, 18)); // NOI18N
        bioMetrictRadioButton.setSelected(true);
        bioMetrictRadioButton.setText("Biometric (Fingerprint) ");
        bioMetrictRadioButton.setToolTipText("");
        bioMetrictRadioButton.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                bioMetrictRadioButtonActionPerformed(evt);
            }
        });

        otpRadioButton.setBackground(new java.awt.Color(255, 255, 255));
        authenticationTypeButtonGroup.add(otpRadioButton);
        otpRadioButton.setFont(new java.awt.Font("Tahoma", 0, 18)); // NOI18N
        otpRadioButton.setText("OTP");
        otpRadioButton.setToolTipText("");
        otpRadioButton.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                otpRadioButtonActionPerformed(evt);
            }
        });

        residentConsentCheckbox.setBackground(new java.awt.Color(255, 255, 255));
        residentConsentCheckbox.setFont(new java.awt.Font("Tahoma", 0, 18)); // NOI18N
        residentConsentCheckbox.setSelected(true);
        residentConsentCheckbox.setText("Resident consent for authentication and e-KYC          ");
        residentConsentCheckbox.setActionCommand("Resident consent");
        residentConsentCheckbox.setHorizontalTextPosition(javax.swing.SwingConstants.LEADING);
        residentConsentCheckbox.setMargin(new java.awt.Insets(0, 0, 0, 0));
        residentConsentCheckbox.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                residentConsentCheckboxActionPerformed(evt);
            }
        });

        kycResponseStatusPanel.setBackground(new java.awt.Color(255, 255, 255));
        kycResponseStatusPanel.setBorder(javax.swing.BorderFactory.createTitledBorder(null, "Response Status", javax.swing.border.TitledBorder.DEFAULT_JUSTIFICATION, javax.swing.border.TitledBorder.DEFAULT_POSITION, new java.awt.Font("Tahoma", 0, 18))); // NOI18N

        kycErrorCodeLabel.setFont(new java.awt.Font("Tahoma", 0, 14)); // NOI18N

        authErrorCode.setFont(new java.awt.Font("Tahoma", 0, 14)); // NOI18N

        javax.swing.GroupLayout kycResponseStatusPanelLayout = new javax.swing.GroupLayout(kycResponseStatusPanel);
        kycResponseStatusPanel.setLayout(kycResponseStatusPanelLayout);
        kycResponseStatusPanelLayout.setHorizontalGroup(
            kycResponseStatusPanelLayout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
            .addGroup(kycResponseStatusPanelLayout.createSequentialGroup()
                .addContainerGap()
                .addGroup(kycResponseStatusPanelLayout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
                    .addComponent(kycErrorCodeLabel, javax.swing.GroupLayout.Alignment.TRAILING, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE)
                    .addGroup(kycResponseStatusPanelLayout.createSequentialGroup()
                        .addComponent(statusLabel, javax.swing.GroupLayout.PREFERRED_SIZE, 118, javax.swing.GroupLayout.PREFERRED_SIZE)
                        .addGap(0, 41, Short.MAX_VALUE))
                    .addComponent(authErrorCode, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE))
                .addContainerGap())
        );
        kycResponseStatusPanelLayout.setVerticalGroup(
            kycResponseStatusPanelLayout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
            .addGroup(kycResponseStatusPanelLayout.createSequentialGroup()
                .addContainerGap()
                .addComponent(statusLabel, javax.swing.GroupLayout.PREFERRED_SIZE, 93, javax.swing.GroupLayout.PREFERRED_SIZE)
                .addGap(18, 18, 18)
                .addComponent(kycErrorCodeLabel, javax.swing.GroupLayout.PREFERRED_SIZE, 90, javax.swing.GroupLayout.PREFERRED_SIZE)
                .addGap(18, 18, 18)
                .addComponent(authErrorCode, javax.swing.GroupLayout.DEFAULT_SIZE, 36, Short.MAX_VALUE)
                .addContainerGap())
        );

        bioOTPPanel.setLayout(new java.awt.CardLayout());

        bioMetricsCapturePanel.setBackground(new java.awt.Color(255, 255, 255));
        bioMetricsCapturePanel.setBorder(javax.swing.BorderFactory.createTitledBorder(null, "Fingerprint scan", javax.swing.border.TitledBorder.DEFAULT_JUSTIFICATION, javax.swing.border.TitledBorder.DEFAULT_POSITION, new java.awt.Font("Tahoma", 0, 18))); // NOI18N
        bioMetricsCapturePanel.setToolTipText("");
        bioMetricsCapturePanel.setPreferredSize(new java.awt.Dimension(500, 156));

        bioMetricsSelect.setFont(new java.awt.Font("Tahoma", 0, 18)); // NOI18N
        bioMetricsSelect.setModel(new javax.swing.DefaultComboBoxModel(new String[] { "Select finger", "UNKNOWN", "------------------", "LEFT_INDEX", "LEFT_LITTLE", "LEFT_MIDDLE", "LEFT_RING", "LEFT_THUMB", "------------------", "RIGHT_INDEX", "RIGHT_LITTLE", "RIGHT_MIDDLE", "RIGHT_RING", "RIGHT_THUMB " }));
        bioMetricsSelect.setSelectedIndex(1);
        bioMetricsSelect.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                bioMetricsSelectActionPerformed(evt);
            }
        });

        biometricsScanButton.setFont(new java.awt.Font("Tahoma", 0, 18)); // NOI18N
        biometricsScanButton.setText("Scan");
        biometricsScanButton.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                biometricsScanButtonActionPerformed(evt);
            }
        });

        bioImagePanel.setBackground(new java.awt.Color(255, 255, 204));
        bioImagePanel.setBorder(javax.swing.BorderFactory.createLineBorder(new java.awt.Color(255, 204, 51)));

        javax.swing.GroupLayout bioImagePanelLayout = new javax.swing.GroupLayout(bioImagePanel);
        bioImagePanel.setLayout(bioImagePanelLayout);
        bioImagePanelLayout.setHorizontalGroup(
            bioImagePanelLayout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
            .addComponent(bioImageLabel, javax.swing.GroupLayout.DEFAULT_SIZE, 100, Short.MAX_VALUE)
        );
        bioImagePanelLayout.setVerticalGroup(
            bioImagePanelLayout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
            .addComponent(bioImageLabel, javax.swing.GroupLayout.DEFAULT_SIZE, 100, Short.MAX_VALUE)
        );

        javax.swing.GroupLayout bioMetricsCapturePanelLayout = new javax.swing.GroupLayout(bioMetricsCapturePanel);
        bioMetricsCapturePanel.setLayout(bioMetricsCapturePanelLayout);
        bioMetricsCapturePanelLayout.setHorizontalGroup(
            bioMetricsCapturePanelLayout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
            .addGroup(bioMetricsCapturePanelLayout.createSequentialGroup()
                .addGap(41, 41, 41)
                .addComponent(bioMetricsSelect, javax.swing.GroupLayout.PREFERRED_SIZE, 146, javax.swing.GroupLayout.PREFERRED_SIZE)
                .addGap(18, 18, 18)
                .addComponent(biometricsScanButton)
                .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED, 69, Short.MAX_VALUE)
                .addComponent(bioImagePanel, javax.swing.GroupLayout.PREFERRED_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.PREFERRED_SIZE)
                .addGap(47, 47, 47))
        );
        bioMetricsCapturePanelLayout.setVerticalGroup(
            bioMetricsCapturePanelLayout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
            .addGroup(javax.swing.GroupLayout.Alignment.TRAILING, bioMetricsCapturePanelLayout.createSequentialGroup()
                .addContainerGap(28, Short.MAX_VALUE)
                .addGroup(bioMetricsCapturePanelLayout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
                    .addGroup(bioMetricsCapturePanelLayout.createParallelGroup(javax.swing.GroupLayout.Alignment.BASELINE)
                        .addComponent(bioMetricsSelect, javax.swing.GroupLayout.PREFERRED_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.PREFERRED_SIZE)
                        .addComponent(biometricsScanButton))
                    .addComponent(bioImagePanel, javax.swing.GroupLayout.PREFERRED_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.PREFERRED_SIZE))
                .addContainerGap())
        );

        bioOTPPanel.add(bioMetricsCapturePanel, "card2");

        otpPanel.setBackground(new java.awt.Color(255, 255, 255));
        otpPanel.setBorder(javax.swing.BorderFactory.createTitledBorder(null, "OTP", javax.swing.border.TitledBorder.DEFAULT_JUSTIFICATION, javax.swing.border.TitledBorder.DEFAULT_POSITION, new java.awt.Font("Tahoma", 0, 18))); // NOI18N

        otpPinLabel.setFont(new java.awt.Font("Tahoma", 0, 18)); // NOI18N
        otpPinLabel.setText("OTP pin:");

        otpPinTextField.setFont(new java.awt.Font("Tahoma", 0, 18)); // NOI18N

        jButton1.setFont(new java.awt.Font("Tahoma", 0, 18)); // NOI18N
        jButton1.setText("Generate OTP");
        jButton1.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                jButton1ActionPerformed(evt);
            }
        });

        javax.swing.GroupLayout otpPanelLayout = new javax.swing.GroupLayout(otpPanel);
        otpPanel.setLayout(otpPanelLayout);
        otpPanelLayout.setHorizontalGroup(
            otpPanelLayout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
            .addGroup(otpPanelLayout.createSequentialGroup()
                .addGap(26, 26, 26)
                .addGroup(otpPanelLayout.createParallelGroup(javax.swing.GroupLayout.Alignment.TRAILING)
                    .addGroup(otpPanelLayout.createSequentialGroup()
                        .addComponent(jButton1)
                        .addContainerGap(javax.swing.GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE))
                    .addGroup(otpPanelLayout.createSequentialGroup()
                        .addComponent(otpPinLabel, javax.swing.GroupLayout.PREFERRED_SIZE, 114, javax.swing.GroupLayout.PREFERRED_SIZE)
                        .addGap(41, 41, 41)
                        .addComponent(otpPinTextField, javax.swing.GroupLayout.PREFERRED_SIZE, 157, javax.swing.GroupLayout.PREFERRED_SIZE)
                        .addGap(154, 154, 154))))
        );
        otpPanelLayout.setVerticalGroup(
            otpPanelLayout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
            .addGroup(otpPanelLayout.createSequentialGroup()
                .addGap(20, 20, 20)
                .addGroup(otpPanelLayout.createParallelGroup(javax.swing.GroupLayout.Alignment.BASELINE)
                    .addComponent(otpPinLabel, javax.swing.GroupLayout.PREFERRED_SIZE, 33, javax.swing.GroupLayout.PREFERRED_SIZE)
                    .addComponent(otpPinTextField, javax.swing.GroupLayout.PREFERRED_SIZE, 33, javax.swing.GroupLayout.PREFERRED_SIZE))
                .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED, 28, Short.MAX_VALUE)
                .addComponent(jButton1)
                .addGap(29, 29, 29))
        );

        bioOTPPanel.add(otpPanel, "card3");

        resetButton1.setFont(new java.awt.Font("Tahoma", 0, 18)); // NOI18N
        resetButton1.setText("Reset");
        resetButton1.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                resetButton1ActionPerformed(evt);
            }
        });

        sendKYCRequestButton.setFont(new java.awt.Font("Tahoma", 0, 18)); // NOI18N
        sendKYCRequestButton.setActionCommand("Send KYC request");
        sendKYCRequestButton.setLabel("Send e-KYC request");
        sendKYCRequestButton.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                sendKYCRequestButtonActionPerformed(evt);
            }
        });

        javax.swing.GroupLayout inputContentPanelLayout = new javax.swing.GroupLayout(inputContentPanel);
        inputContentPanel.setLayout(inputContentPanelLayout);
        inputContentPanelLayout.setHorizontalGroup(
            inputContentPanelLayout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
            .addGroup(inputContentPanelLayout.createSequentialGroup()
                .addGap(153, 153, 153)
                .addGroup(inputContentPanelLayout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
                    .addGroup(inputContentPanelLayout.createSequentialGroup()
                        .addComponent(residentConsentCheckbox, javax.swing.GroupLayout.PREFERRED_SIZE, 453, javax.swing.GroupLayout.PREFERRED_SIZE)
                        .addContainerGap(javax.swing.GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE))
                    .addGroup(javax.swing.GroupLayout.Alignment.TRAILING, inputContentPanelLayout.createSequentialGroup()
                        .addGroup(inputContentPanelLayout.createParallelGroup(javax.swing.GroupLayout.Alignment.TRAILING)
                            .addGroup(inputContentPanelLayout.createSequentialGroup()
                                .addGap(0, 0, Short.MAX_VALUE)
                                .addComponent(resetButton1)
                                .addGap(35, 35, 35)
                                .addComponent(sendKYCRequestButton))
                            .addGroup(inputContentPanelLayout.createSequentialGroup()
                                .addGroup(inputContentPanelLayout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
                                    .addGroup(inputContentPanelLayout.createSequentialGroup()
                                        .addGroup(inputContentPanelLayout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
                                            .addComponent(jLabel12, javax.swing.GroupLayout.PREFERRED_SIZE, 175, javax.swing.GroupLayout.PREFERRED_SIZE)
                                            .addComponent(jLabel11, javax.swing.GroupLayout.PREFERRED_SIZE, 154, javax.swing.GroupLayout.PREFERRED_SIZE))
                                        .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED, javax.swing.GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE)
                                        .addGroup(inputContentPanelLayout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
                                            .addComponent(bioMetrictRadioButton)
                                            .addComponent(jFormattedTextFieldAADHAARNo, javax.swing.GroupLayout.PREFERRED_SIZE, 214, javax.swing.GroupLayout.PREFERRED_SIZE)
                                            .addComponent(validationMessageLabel))
                                        .addGap(18, 18, 18)
                                        .addComponent(otpRadioButton)
                                        .addGap(38, 38, 38))
                                    .addGroup(inputContentPanelLayout.createSequentialGroup()
                                        .addComponent(bioOTPPanel, javax.swing.GroupLayout.PREFERRED_SIZE, 0, Short.MAX_VALUE)
                                        .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED)))
                                .addComponent(kycResponseStatusPanel, javax.swing.GroupLayout.PREFERRED_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.PREFERRED_SIZE)))
                        .addGap(88, 88, 88))))
        );

        inputContentPanelLayout.linkSize(javax.swing.SwingConstants.HORIZONTAL, new java.awt.Component[] {resetButton1, sendKYCRequestButton});

        inputContentPanelLayout.linkSize(javax.swing.SwingConstants.HORIZONTAL, new java.awt.Component[] {bioMetrictRadioButton, jFormattedTextFieldAADHAARNo, validationMessageLabel});

        inputContentPanelLayout.setVerticalGroup(
            inputContentPanelLayout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
            .addGroup(inputContentPanelLayout.createSequentialGroup()
                .addGap(155, 155, 155)
                .addGroup(inputContentPanelLayout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
                    .addComponent(kycResponseStatusPanel, javax.swing.GroupLayout.PREFERRED_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.PREFERRED_SIZE)
                    .addGroup(inputContentPanelLayout.createSequentialGroup()
                        .addGroup(inputContentPanelLayout.createParallelGroup(javax.swing.GroupLayout.Alignment.BASELINE)
                            .addComponent(jLabel11, javax.swing.GroupLayout.PREFERRED_SIZE, 25, javax.swing.GroupLayout.PREFERRED_SIZE)
                            .addComponent(jFormattedTextFieldAADHAARNo, javax.swing.GroupLayout.PREFERRED_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.PREFERRED_SIZE))
                        .addGap(8, 8, 8)
                        .addComponent(validationMessageLabel, javax.swing.GroupLayout.PREFERRED_SIZE, 24, javax.swing.GroupLayout.PREFERRED_SIZE)
                        .addGap(18, 18, 18)
                        .addComponent(residentConsentCheckbox)
                        .addGap(24, 24, 24)
                        .addGroup(inputContentPanelLayout.createParallelGroup(javax.swing.GroupLayout.Alignment.BASELINE)
                            .addComponent(jLabel12, javax.swing.GroupLayout.PREFERRED_SIZE, 26, javax.swing.GroupLayout.PREFERRED_SIZE)
                            .addComponent(bioMetrictRadioButton)
                            .addComponent(otpRadioButton))
                        .addGap(18, 18, 18)
                        .addComponent(bioOTPPanel, javax.swing.GroupLayout.PREFERRED_SIZE, 176, javax.swing.GroupLayout.PREFERRED_SIZE)))
                .addGap(56, 56, 56)
                .addGroup(inputContentPanelLayout.createParallelGroup(javax.swing.GroupLayout.Alignment.BASELINE)
                    .addComponent(resetButton1)
                    .addComponent(sendKYCRequestButton))
                .addContainerGap(javax.swing.GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE))
        );

        inputContentPanelLayout.linkSize(javax.swing.SwingConstants.VERTICAL, new java.awt.Component[] {resetButton1, sendKYCRequestButton});

        inputContentPanelLayout.linkSize(javax.swing.SwingConstants.VERTICAL, new java.awt.Component[] {bioMetrictRadioButton, jFormattedTextFieldAADHAARNo, validationMessageLabel});

        contentPanel.add(inputContentPanel, "card2");

        responeContentPanel.setBackground(new java.awt.Color(255, 255, 255));
        responeContentPanel.setBorder(javax.swing.BorderFactory.createTitledBorder(null, "", javax.swing.border.TitledBorder.DEFAULT_JUSTIFICATION, javax.swing.border.TitledBorder.DEFAULT_POSITION, new java.awt.Font("Tahoma", 1, 12))); // NOI18N
        responeContentPanel.setFont(new java.awt.Font("Tahoma", 0, 3)); // NOI18N
        responeContentPanel.setPreferredSize(new java.awt.Dimension(926, 625));

        poiPanel.setBackground(new java.awt.Color(255, 255, 255));
        poiPanel.setBorder(javax.swing.BorderFactory.createTitledBorder(""));

        photoPanel.setBackground(new java.awt.Color(255, 255, 255));
        photoPanel.setBorder(javax.swing.BorderFactory.createTitledBorder(null, "POI", javax.swing.border.TitledBorder.DEFAULT_JUSTIFICATION, javax.swing.border.TitledBorder.DEFAULT_POSITION, new java.awt.Font("Tahoma", 1, 14))); // NOI18N

        photoLabel.setBackground(new java.awt.Color(255, 255, 255));

        javax.swing.GroupLayout photoPanelLayout = new javax.swing.GroupLayout(photoPanel);
        photoPanel.setLayout(photoPanelLayout);
        photoPanelLayout.setHorizontalGroup(
            photoPanelLayout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
            .addGroup(photoPanelLayout.createSequentialGroup()
                .addContainerGap()
                .addComponent(photoLabel, javax.swing.GroupLayout.DEFAULT_SIZE, 183, Short.MAX_VALUE)
                .addContainerGap())
        );
        photoPanelLayout.setVerticalGroup(
            photoPanelLayout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
            .addGroup(photoPanelLayout.createSequentialGroup()
                .addComponent(photoLabel, javax.swing.GroupLayout.PREFERRED_SIZE, 167, javax.swing.GroupLayout.PREFERRED_SIZE)
                .addGap(0, 0, Short.MAX_VALUE))
        );

        poiDetailsPanel.setBackground(new java.awt.Color(255, 255, 255));

        jPanel13.setBackground(new java.awt.Color(255, 255, 255));

        aadhaarNumberLabel.setBackground(new java.awt.Color(255, 255, 255));
        aadhaarNumberLabel.setFont(new java.awt.Font("Tahoma", 1, 18)); // NOI18N
        aadhaarNumberLabel.setHorizontalAlignment(javax.swing.SwingConstants.LEFT);
        aadhaarNumberLabel.setIcon(new javax.swing.ImageIcon(getClass().getResource("/aadhaar_verified.png"))); // NOI18N

        javax.swing.GroupLayout jPanel13Layout = new javax.swing.GroupLayout(jPanel13);
        jPanel13.setLayout(jPanel13Layout);
        jPanel13Layout.setHorizontalGroup(
            jPanel13Layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
            .addGroup(jPanel13Layout.createSequentialGroup()
                .addContainerGap()
                .addComponent(aadhaarNumberLabel, javax.swing.GroupLayout.DEFAULT_SIZE, 236, Short.MAX_VALUE)
                .addContainerGap())
        );
        jPanel13Layout.setVerticalGroup(
            jPanel13Layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
            .addGroup(jPanel13Layout.createSequentialGroup()
                .addComponent(aadhaarNumberLabel)
                .addGap(0, 1, Short.MAX_VALUE))
        );

        jPanel14.setBackground(new java.awt.Color(255, 255, 255));
        jPanel14.setBorder(javax.swing.BorderFactory.createTitledBorder(null, "POI", javax.swing.border.TitledBorder.DEFAULT_JUSTIFICATION, javax.swing.border.TitledBorder.DEFAULT_POSITION, new java.awt.Font("Tahoma", 1, 14))); // NOI18N

        jLabel24.setFont(new java.awt.Font("Tahoma", 0, 12)); // NOI18N
        jLabel24.setText("Resident Name");

        residenNameTextField.setDisabledTextColor(new java.awt.Color(0, 0, 0));
        residenNameTextField.setEnabled(false);
        residenNameTextField.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                residenNameTextFieldActionPerformed(evt);
            }
        });

        jLabel25.setFont(new java.awt.Font("Tahoma", 0, 12)); // NOI18N
        jLabel25.setText("Date of Birth");

        dobTextField.setDisabledTextColor(new java.awt.Color(0, 0, 0));
        dobTextField.setEnabled(false);
        dobTextField.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                dobTextFieldActionPerformed(evt);
            }
        });

        genderTextField.setDisabledTextColor(new java.awt.Color(0, 0, 0));
        genderTextField.setEnabled(false);
        genderTextField.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                genderTextFieldActionPerformed(evt);
            }
        });

        jLabel26.setFont(new java.awt.Font("Tahoma", 0, 12)); // NOI18N
        jLabel26.setText("Gender");

        jLabel27.setFont(new java.awt.Font("Tahoma", 0, 12)); // NOI18N
        jLabel27.setText("Phone No");

        phoneNumberTextField.setDisabledTextColor(new java.awt.Color(0, 0, 0));
        phoneNumberTextField.setEnabled(false);
        phoneNumberTextField.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                phoneNumberTextFieldActionPerformed(evt);
            }
        });

        jLabel28.setFont(new java.awt.Font("Tahoma", 0, 12)); // NOI18N
        jLabel28.setText("Email Id");

        emailTextField.setDisabledTextColor(new java.awt.Color(0, 0, 0));
        emailTextField.setEnabled(false);
        emailTextField.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                emailTextFieldActionPerformed(evt);
            }
        });

        javax.swing.GroupLayout jPanel14Layout = new javax.swing.GroupLayout(jPanel14);
        jPanel14.setLayout(jPanel14Layout);
        jPanel14Layout.setHorizontalGroup(
            jPanel14Layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
            .addGroup(jPanel14Layout.createSequentialGroup()
                .addGap(26, 26, 26)
                .addGroup(jPanel14Layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
                    .addGroup(jPanel14Layout.createSequentialGroup()
                        .addComponent(jLabel28, javax.swing.GroupLayout.PREFERRED_SIZE, 95, javax.swing.GroupLayout.PREFERRED_SIZE)
                        .addGap(56, 56, 56)
                        .addComponent(emailTextField, javax.swing.GroupLayout.PREFERRED_SIZE, 283, javax.swing.GroupLayout.PREFERRED_SIZE))
                    .addGroup(jPanel14Layout.createSequentialGroup()
                        .addGroup(jPanel14Layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
                            .addComponent(jLabel25, javax.swing.GroupLayout.PREFERRED_SIZE, 95, javax.swing.GroupLayout.PREFERRED_SIZE)
                            .addComponent(jLabel24, javax.swing.GroupLayout.PREFERRED_SIZE, 95, javax.swing.GroupLayout.PREFERRED_SIZE))
                        .addGap(56, 56, 56)
                        .addGroup(jPanel14Layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
                            .addComponent(residenNameTextField, javax.swing.GroupLayout.PREFERRED_SIZE, 283, javax.swing.GroupLayout.PREFERRED_SIZE)
                            .addComponent(dobTextField, javax.swing.GroupLayout.PREFERRED_SIZE, 283, javax.swing.GroupLayout.PREFERRED_SIZE)))
                    .addGroup(jPanel14Layout.createSequentialGroup()
                        .addGroup(jPanel14Layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
                            .addComponent(jLabel26, javax.swing.GroupLayout.PREFERRED_SIZE, 95, javax.swing.GroupLayout.PREFERRED_SIZE)
                            .addComponent(jLabel27, javax.swing.GroupLayout.PREFERRED_SIZE, 95, javax.swing.GroupLayout.PREFERRED_SIZE))
                        .addGap(56, 56, 56)
                        .addGroup(jPanel14Layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
                            .addComponent(genderTextField, javax.swing.GroupLayout.PREFERRED_SIZE, 283, javax.swing.GroupLayout.PREFERRED_SIZE)
                            .addComponent(phoneNumberTextField, javax.swing.GroupLayout.PREFERRED_SIZE, 283, javax.swing.GroupLayout.PREFERRED_SIZE))))
                .addContainerGap(20, Short.MAX_VALUE))
        );
        jPanel14Layout.setVerticalGroup(
            jPanel14Layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
            .addGroup(jPanel14Layout.createSequentialGroup()
                .addComponent(jLabel24)
                .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.UNRELATED)
                .addComponent(jLabel25)
                .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.UNRELATED)
                .addComponent(jLabel26)
                .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.UNRELATED)
                .addComponent(jLabel27)
                .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.UNRELATED)
                .addComponent(jLabel28))
            .addGroup(jPanel14Layout.createSequentialGroup()
                .addComponent(residenNameTextField, javax.swing.GroupLayout.PREFERRED_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.PREFERRED_SIZE)
                .addGap(5, 5, 5)
                .addComponent(dobTextField, javax.swing.GroupLayout.PREFERRED_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.PREFERRED_SIZE)
                .addGap(5, 5, 5)
                .addComponent(genderTextField, javax.swing.GroupLayout.PREFERRED_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.PREFERRED_SIZE)
                .addGap(5, 5, 5)
                .addComponent(phoneNumberTextField, javax.swing.GroupLayout.PREFERRED_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.PREFERRED_SIZE)
                .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED)
                .addComponent(emailTextField, javax.swing.GroupLayout.PREFERRED_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.PREFERRED_SIZE))
        );

        javax.swing.GroupLayout poiDetailsPanelLayout = new javax.swing.GroupLayout(poiDetailsPanel);
        poiDetailsPanel.setLayout(poiDetailsPanelLayout);
        poiDetailsPanelLayout.setHorizontalGroup(
            poiDetailsPanelLayout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
            .addGroup(poiDetailsPanelLayout.createSequentialGroup()
                .addGap(124, 124, 124)
                .addComponent(jPanel13, javax.swing.GroupLayout.PREFERRED_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.PREFERRED_SIZE)
                .addContainerGap(javax.swing.GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE))
            .addGroup(poiDetailsPanelLayout.createSequentialGroup()
                .addContainerGap()
                .addComponent(jPanel14, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE)
                .addContainerGap())
        );
        poiDetailsPanelLayout.setVerticalGroup(
            poiDetailsPanelLayout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
            .addGroup(poiDetailsPanelLayout.createSequentialGroup()
                .addComponent(jPanel13, javax.swing.GroupLayout.PREFERRED_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.PREFERRED_SIZE)
                .addGap(2, 2, 2)
                .addComponent(jPanel14, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE))
        );

        javax.swing.GroupLayout poiPanelLayout = new javax.swing.GroupLayout(poiPanel);
        poiPanel.setLayout(poiPanelLayout);
        poiPanelLayout.setHorizontalGroup(
            poiPanelLayout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
            .addGroup(poiPanelLayout.createSequentialGroup()
                .addContainerGap()
                .addComponent(photoPanel, javax.swing.GroupLayout.PREFERRED_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.PREFERRED_SIZE)
                .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED)
                .addComponent(poiDetailsPanel, javax.swing.GroupLayout.PREFERRED_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.PREFERRED_SIZE)
                .addContainerGap(javax.swing.GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE))
        );
        poiPanelLayout.setVerticalGroup(
            poiPanelLayout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
            .addGroup(javax.swing.GroupLayout.Alignment.TRAILING, poiPanelLayout.createSequentialGroup()
                .addGap(2, 2, 2)
                .addGroup(poiPanelLayout.createParallelGroup(javax.swing.GroupLayout.Alignment.TRAILING, false)
                    .addComponent(photoPanel, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE)
                    .addComponent(poiDetailsPanel, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE))
                .addGap(2, 2, 2))
        );

        poaPanel.setBackground(new java.awt.Color(255, 255, 255));
        poaPanel.setBorder(javax.swing.BorderFactory.createTitledBorder(null, "POA", javax.swing.border.TitledBorder.DEFAULT_JUSTIFICATION, javax.swing.border.TitledBorder.DEFAULT_POSITION, new java.awt.Font("Tahoma", 1, 14))); // NOI18N
        poaPanel.setPreferredSize(new java.awt.Dimension(868, 199));

        jLabel29.setFont(new java.awt.Font("Tahoma", 0, 12)); // NOI18N
        jLabel29.setText("Care of");

        careOfTextField.setDisabledTextColor(new java.awt.Color(0, 0, 0));
        careOfTextField.setEnabled(false);
        careOfTextField.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                careOfTextFieldActionPerformed(evt);
            }
        });

        jLabel30.setFont(new java.awt.Font("Tahoma", 0, 12)); // NOI18N
        jLabel30.setText("House No");

        houseNoTextField.setDisabledTextColor(new java.awt.Color(0, 0, 0));
        houseNoTextField.setEnabled(false);
        houseNoTextField.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                houseNoTextFieldActionPerformed(evt);
            }
        });

        jLabel31.setFont(new java.awt.Font("Tahoma", 0, 12)); // NOI18N
        jLabel31.setText("Landmark");

        landMarkTextField.setDisabledTextColor(new java.awt.Color(0, 0, 0));
        landMarkTextField.setEnabled(false);

        jLabel32.setFont(new java.awt.Font("Tahoma", 0, 12)); // NOI18N
        jLabel32.setText("Street");

        streetTextField.setDisabledTextColor(new java.awt.Color(0, 0, 0));
        streetTextField.setEnabled(false);

        localityTextField.setDisabledTextColor(new java.awt.Color(0, 0, 0));
        localityTextField.setEnabled(false);
        localityTextField.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                localityTextFieldActionPerformed(evt);
            }
        });

        jLabel33.setFont(new java.awt.Font("Tahoma", 0, 12)); // NOI18N
        jLabel33.setText("Post Office");
        jLabel33.setMaximumSize(new java.awt.Dimension(36, 14));
        jLabel33.setMinimumSize(new java.awt.Dimension(36, 14));
        jLabel33.setPreferredSize(new java.awt.Dimension(36, 14));

        jLabel34.setFont(new java.awt.Font("Tahoma", 0, 12)); // NOI18N
        jLabel34.setText("Locality");

        postOfficeTextField.setDisabledTextColor(new java.awt.Color(0, 0, 0));
        postOfficeTextField.setEnabled(false);

        subDistrictTextField.setDisabledTextColor(new java.awt.Color(0, 0, 0));
        subDistrictTextField.setEnabled(false);

        vtcNameTextField.setDisabledTextColor(new java.awt.Color(0, 0, 0));
        vtcNameTextField.setEnabled(false);

        jLabel35.setFont(new java.awt.Font("Tahoma", 0, 12)); // NOI18N
        jLabel35.setText("VTC Name");

        jLabel36.setFont(new java.awt.Font("Tahoma", 0, 12)); // NOI18N
        jLabel36.setText("Sub District");

        districtTextField.setDisabledTextColor(new java.awt.Color(0, 0, 0));
        districtTextField.setEnabled(false);
        districtTextField.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                districtTextFieldActionPerformed(evt);
            }
        });

        jLabel37.setFont(new java.awt.Font("Tahoma", 0, 12)); // NOI18N
        jLabel37.setText("District");

        stateTextField.setDisabledTextColor(new java.awt.Color(0, 0, 0));
        stateTextField.setEnabled(false);
        stateTextField.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                stateTextFieldActionPerformed(evt);
            }
        });

        jLabel38.setFont(new java.awt.Font("Tahoma", 0, 12)); // NOI18N
        jLabel38.setText("State");

        jLabel39.setFont(new java.awt.Font("Tahoma", 0, 12)); // NOI18N
        jLabel39.setText("Pincode");

        pincodeTextField.setDisabledTextColor(new java.awt.Color(0, 0, 0));
        pincodeTextField.setEnabled(false);
        pincodeTextField.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                pincodeTextFieldActionPerformed(evt);
            }
        });

        javax.swing.GroupLayout poaPanelLayout = new javax.swing.GroupLayout(poaPanel);
        poaPanel.setLayout(poaPanelLayout);
        poaPanelLayout.setHorizontalGroup(
            poaPanelLayout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
            .addGroup(poaPanelLayout.createSequentialGroup()
                .addGap(19, 19, 19)
                .addGroup(poaPanelLayout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
                    .addGroup(poaPanelLayout.createParallelGroup(javax.swing.GroupLayout.Alignment.TRAILING, false)
                        .addComponent(jLabel31, javax.swing.GroupLayout.Alignment.LEADING, javax.swing.GroupLayout.DEFAULT_SIZE, 93, Short.MAX_VALUE)
                        .addGroup(poaPanelLayout.createSequentialGroup()
                            .addGroup(poaPanelLayout.createParallelGroup(javax.swing.GroupLayout.Alignment.TRAILING)
                                .addComponent(jLabel34, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE)
                                .addComponent(jLabel29, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE))
                            .addGap(9, 9, 9)))
                    .addComponent(jLabel35, javax.swing.GroupLayout.PREFERRED_SIZE, 93, javax.swing.GroupLayout.PREFERRED_SIZE)
                    .addComponent(jLabel37, javax.swing.GroupLayout.PREFERRED_SIZE, 84, javax.swing.GroupLayout.PREFERRED_SIZE))
                .addGap(18, 18, Short.MAX_VALUE)
                .addGroup(poaPanelLayout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING, false)
                    .addGroup(poaPanelLayout.createSequentialGroup()
                        .addGroup(poaPanelLayout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING, false)
                            .addComponent(careOfTextField, javax.swing.GroupLayout.Alignment.TRAILING, javax.swing.GroupLayout.DEFAULT_SIZE, 282, Short.MAX_VALUE)
                            .addComponent(landMarkTextField, javax.swing.GroupLayout.Alignment.TRAILING, javax.swing.GroupLayout.DEFAULT_SIZE, 282, Short.MAX_VALUE)
                            .addComponent(localityTextField, javax.swing.GroupLayout.Alignment.TRAILING))
                        .addGap(63, 63, 63)
                        .addGroup(poaPanelLayout.createParallelGroup(javax.swing.GroupLayout.Alignment.TRAILING, false)
                            .addComponent(jLabel32, javax.swing.GroupLayout.Alignment.LEADING, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE)
                            .addComponent(jLabel30, javax.swing.GroupLayout.Alignment.LEADING, javax.swing.GroupLayout.DEFAULT_SIZE, 80, Short.MAX_VALUE)
                            .addComponent(jLabel33, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE)))
                    .addGroup(javax.swing.GroupLayout.Alignment.TRAILING, poaPanelLayout.createSequentialGroup()
                        .addGroup(poaPanelLayout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
                            .addComponent(districtTextField, javax.swing.GroupLayout.PREFERRED_SIZE, 282, javax.swing.GroupLayout.PREFERRED_SIZE)
                            .addComponent(vtcNameTextField, javax.swing.GroupLayout.PREFERRED_SIZE, 282, javax.swing.GroupLayout.PREFERRED_SIZE))
                        .addGap(64, 64, 64)
                        .addGroup(poaPanelLayout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
                            .addComponent(jLabel36, javax.swing.GroupLayout.DEFAULT_SIZE, 97, Short.MAX_VALUE)
                            .addComponent(jLabel38, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE))))
                .addGap(18, 18, 18)
                .addGroup(poaPanelLayout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
                    .addGroup(poaPanelLayout.createSequentialGroup()
                        .addComponent(stateTextField, javax.swing.GroupLayout.PREFERRED_SIZE, 162, javax.swing.GroupLayout.PREFERRED_SIZE)
                        .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.UNRELATED)
                        .addComponent(jLabel39, javax.swing.GroupLayout.PREFERRED_SIZE, 49, javax.swing.GroupLayout.PREFERRED_SIZE)
                        .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED)
                        .addComponent(pincodeTextField, javax.swing.GroupLayout.PREFERRED_SIZE, 64, javax.swing.GroupLayout.PREFERRED_SIZE))
                    .addGroup(poaPanelLayout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING, false)
                        .addComponent(subDistrictTextField, javax.swing.GroupLayout.DEFAULT_SIZE, 289, Short.MAX_VALUE)
                        .addComponent(houseNoTextField)
                        .addComponent(streetTextField)
                        .addComponent(postOfficeTextField)))
                .addGap(23, 23, 23))
        );
        poaPanelLayout.setVerticalGroup(
            poaPanelLayout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
            .addGroup(poaPanelLayout.createSequentialGroup()
                .addGroup(poaPanelLayout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING, false)
                    .addComponent(jLabel30, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE)
                    .addComponent(careOfTextField)
                    .addComponent(houseNoTextField)
                    .addComponent(jLabel29, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE))
                .addGap(5, 5, 5)
                .addGroup(poaPanelLayout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING, false)
                    .addGroup(javax.swing.GroupLayout.Alignment.TRAILING, poaPanelLayout.createParallelGroup(javax.swing.GroupLayout.Alignment.BASELINE)
                        .addComponent(streetTextField, javax.swing.GroupLayout.PREFERRED_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.PREFERRED_SIZE)
                        .addComponent(jLabel32, javax.swing.GroupLayout.PREFERRED_SIZE, 19, javax.swing.GroupLayout.PREFERRED_SIZE))
                    .addComponent(landMarkTextField)
                    .addComponent(jLabel31, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE))
                .addGap(5, 5, 5)
                .addGroup(poaPanelLayout.createParallelGroup(javax.swing.GroupLayout.Alignment.TRAILING)
                    .addComponent(localityTextField, javax.swing.GroupLayout.PREFERRED_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.PREFERRED_SIZE)
                    .addGroup(poaPanelLayout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING, false)
                        .addComponent(jLabel33, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE)
                        .addComponent(postOfficeTextField))
                    .addComponent(jLabel34, javax.swing.GroupLayout.PREFERRED_SIZE, 17, javax.swing.GroupLayout.PREFERRED_SIZE))
                .addGap(5, 5, 5)
                .addGroup(poaPanelLayout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING, false)
                    .addGroup(poaPanelLayout.createSequentialGroup()
                        .addGroup(poaPanelLayout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
                            .addComponent(subDistrictTextField, javax.swing.GroupLayout.PREFERRED_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.PREFERRED_SIZE)
                            .addGroup(poaPanelLayout.createSequentialGroup()
                                .addGap(2, 2, 2)
                                .addComponent(jLabel36, javax.swing.GroupLayout.PREFERRED_SIZE, 17, javax.swing.GroupLayout.PREFERRED_SIZE)))
                        .addGap(4, 4, 4)
                        .addGroup(poaPanelLayout.createParallelGroup(javax.swing.GroupLayout.Alignment.TRAILING, false)
                            .addGroup(poaPanelLayout.createParallelGroup(javax.swing.GroupLayout.Alignment.BASELINE)
                                .addComponent(stateTextField, javax.swing.GroupLayout.PREFERRED_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.PREFERRED_SIZE)
                                .addComponent(districtTextField, javax.swing.GroupLayout.PREFERRED_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.PREFERRED_SIZE)
                                .addComponent(jLabel39)
                                .addComponent(pincodeTextField, javax.swing.GroupLayout.PREFERRED_SIZE, 20, javax.swing.GroupLayout.PREFERRED_SIZE))
                            .addGroup(poaPanelLayout.createSequentialGroup()
                                .addComponent(jLabel38, javax.swing.GroupLayout.PREFERRED_SIZE, 18, javax.swing.GroupLayout.PREFERRED_SIZE)
                                .addGap(3, 3, 3)))
                        .addGap(14, 14, 14))
                    .addGroup(poaPanelLayout.createSequentialGroup()
                        .addGap(1, 1, 1)
                        .addGroup(poaPanelLayout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING, false)
                            .addComponent(vtcNameTextField)
                            .addComponent(jLabel35, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE))
                        .addGap(5, 5, 5)
                        .addComponent(jLabel37, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE)
                        .addContainerGap())))
        );

        ouputTypeCombo.setFont(new java.awt.Font("Tahoma", 0, 14)); // NOI18N
        ouputTypeCombo.setPreferredSize(new java.awt.Dimension(119, 23));
        ouputTypeCombo.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                ouputTypeComboActionPerformed(evt);
            }
        });

        saveAsButton.setFont(new java.awt.Font("Tahoma", 0, 14)); // NOI18N
        saveAsButton.setText("Save");
        saveAsButton.setPreferredSize(new java.awt.Dimension(119, 23));
        saveAsButton.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                saveAsButtonActionPerformed(evt);
            }
        });

        responseResetButton.setFont(new java.awt.Font("Tahoma", 0, 14)); // NOI18N
        responseResetButton.setText("New e-KYC");
        responseResetButton.setPreferredSize(new java.awt.Dimension(119, 23));
        responseResetButton.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                responseResetButtonActionPerformed(evt);
            }
        });

        poaLangPanel.setBackground(new java.awt.Color(255, 255, 255));
        poaLangPanel.setBorder(javax.swing.BorderFactory.createTitledBorder(null, "Local Language", javax.swing.border.TitledBorder.DEFAULT_JUSTIFICATION, javax.swing.border.TitledBorder.DEFAULT_POSITION, new java.awt.Font("Tahoma", 1, 14))); // NOI18N
        poaLangPanel.setPreferredSize(new java.awt.Dimension(868, 199));

        jlangLabel40.setFont(new java.awt.Font("Tahoma", 0, 12)); // NOI18N
        jlangLabel40.setText("Care of");

        careOfLangTextField.setBackground(new java.awt.Color(240, 240, 240));
        careOfLangTextField.setFont(new java.awt.Font("Tahoma", 1, 11)); // NOI18N
        careOfLangTextField.setDisabledTextColor(new java.awt.Color(0, 0, 0));
        careOfLangTextField.setEnabled(false);
        careOfLangTextField.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                careOfLangTextFieldActionPerformed(evt);
            }
        });

        jlangLabel141.setFont(new java.awt.Font("Tahoma", 0, 12)); // NOI18N
        jlangLabel141.setText("House No");

        houseNoLangTextField.setBackground(new java.awt.Color(240, 240, 240));
        houseNoLangTextField.setFont(new java.awt.Font("Tahoma", 1, 11)); // NOI18N
        houseNoLangTextField.setDisabledTextColor(new java.awt.Color(0, 0, 0));
        houseNoLangTextField.setEnabled(false);
        houseNoLangTextField.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                houseNoLangTextFieldActionPerformed(evt);
            }
        });

        jlangLabel42.setFont(new java.awt.Font("Tahoma", 0, 12)); // NOI18N
        jlangLabel42.setText("Landmark");

        jlangLabel43.setFont(new java.awt.Font("Tahoma", 0, 12)); // NOI18N
        jlangLabel43.setText("Street");

        jlangLabel45.setFont(new java.awt.Font("Tahoma", 0, 12)); // NOI18N
        jlangLabel45.setText("Locality");

        jlangLabel44.setFont(new java.awt.Font("Tahoma", 0, 12)); // NOI18N
        jlangLabel44.setText("Post Office");

        jlangLabel46.setFont(new java.awt.Font("Tahoma", 0, 12)); // NOI18N
        jlangLabel46.setText("VTC Name");

        jlangLabel47.setFont(new java.awt.Font("Tahoma", 0, 12)); // NOI18N
        jlangLabel47.setText("Sub District");

        landMarkLangTextField.setBackground(new java.awt.Color(240, 240, 240));
        landMarkLangTextField.setDisabledTextColor(new java.awt.Color(0, 0, 0));
        landMarkLangTextField.setEnabled(false);

        localityLangTextField.setBackground(new java.awt.Color(240, 240, 240));
        localityLangTextField.setDisabledTextColor(new java.awt.Color(0, 0, 0));
        localityLangTextField.setEnabled(false);

        vtcNameLangTextField.setBackground(new java.awt.Color(240, 240, 240));
        vtcNameLangTextField.setDisabledTextColor(new java.awt.Color(0, 0, 0));
        vtcNameLangTextField.setEnabled(false);
        vtcNameLangTextField.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                vtcNameLangTextFieldActionPerformed(evt);
            }
        });

        streetLangTextField.setBackground(new java.awt.Color(240, 240, 240));
        streetLangTextField.setDisabledTextColor(new java.awt.Color(0, 0, 0));
        streetLangTextField.setEnabled(false);

        postOfficeLangTextField.setBackground(new java.awt.Color(240, 240, 240));
        postOfficeLangTextField.setDisabledTextColor(new java.awt.Color(0, 0, 0));
        postOfficeLangTextField.setEnabled(false);
        postOfficeLangTextField.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                postOfficeLangTextFieldActionPerformed(evt);
            }
        });

        subDistrictLangTextField.setBackground(new java.awt.Color(240, 240, 240));
        subDistrictLangTextField.setDisabledTextColor(new java.awt.Color(0, 0, 0));
        subDistrictLangTextField.setEnabled(false);

        jlangLabel48.setFont(new java.awt.Font("Tahoma", 0, 12)); // NOI18N
        jlangLabel48.setText("District");

        jlangLabel50.setFont(new java.awt.Font("Tahoma", 0, 12)); // NOI18N
        jlangLabel50.setText("State");

        districtLangTextField.setBackground(new java.awt.Color(240, 240, 240));
        districtLangTextField.setDisabledTextColor(new java.awt.Color(0, 0, 0));
        districtLangTextField.setEnabled(false);

        stateLangTextField.setBackground(new java.awt.Color(240, 240, 240));
        stateLangTextField.setDisabledTextColor(new java.awt.Color(0, 0, 0));
        stateLangTextField.setEnabled(false);

        jlangLabel151.setFont(new java.awt.Font("Tahoma", 0, 12)); // NOI18N
        jlangLabel151.setText("Pincode");

        pincodeLangTextField.setBackground(new java.awt.Color(240, 240, 240));
        pincodeLangTextField.setDisabledTextColor(new java.awt.Color(0, 0, 0));
        pincodeLangTextField.setEnabled(false);
        pincodeLangTextField.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                pincodeLangTextFieldActionPerformed(evt);
            }
        });

        javax.swing.GroupLayout poaLangPanelLayout = new javax.swing.GroupLayout(poaLangPanel);
        poaLangPanel.setLayout(poaLangPanelLayout);
        poaLangPanelLayout.setHorizontalGroup(
            poaLangPanelLayout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
            .addGroup(poaLangPanelLayout.createSequentialGroup()
                .addGap(18, 18, 18)
                .addGroup(poaLangPanelLayout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
                    .addComponent(jlangLabel45)
                    .addComponent(jlangLabel46)
                    .addComponent(jlangLabel42)
                    .addComponent(jlangLabel40, javax.swing.GroupLayout.PREFERRED_SIZE, 58, javax.swing.GroupLayout.PREFERRED_SIZE)
                    .addComponent(jlangLabel48, javax.swing.GroupLayout.PREFERRED_SIZE, 67, javax.swing.GroupLayout.PREFERRED_SIZE))
                .addGroup(poaLangPanelLayout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
                    .addGroup(poaLangPanelLayout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
                        .addGroup(poaLangPanelLayout.createSequentialGroup()
                            .addGap(48, 48, 48)
                            .addComponent(landMarkLangTextField, javax.swing.GroupLayout.PREFERRED_SIZE, 281, javax.swing.GroupLayout.PREFERRED_SIZE))
                        .addGroup(javax.swing.GroupLayout.Alignment.TRAILING, poaLangPanelLayout.createSequentialGroup()
                            .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED)
                            .addGroup(poaLangPanelLayout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
                                .addComponent(localityLangTextField, javax.swing.GroupLayout.Alignment.TRAILING, javax.swing.GroupLayout.PREFERRED_SIZE, 281, javax.swing.GroupLayout.PREFERRED_SIZE)
                                .addComponent(vtcNameLangTextField, javax.swing.GroupLayout.Alignment.TRAILING, javax.swing.GroupLayout.PREFERRED_SIZE, 281, javax.swing.GroupLayout.PREFERRED_SIZE)
                                .addComponent(districtLangTextField, javax.swing.GroupLayout.Alignment.TRAILING, javax.swing.GroupLayout.PREFERRED_SIZE, 281, javax.swing.GroupLayout.PREFERRED_SIZE))))
                    .addGroup(poaLangPanelLayout.createSequentialGroup()
                        .addGap(48, 48, 48)
                        .addComponent(careOfLangTextField, javax.swing.GroupLayout.PREFERRED_SIZE, 281, javax.swing.GroupLayout.PREFERRED_SIZE)))
                .addGap(59, 59, 59)
                .addGroup(poaLangPanelLayout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
                    .addComponent(jlangLabel141, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE)
                    .addComponent(jlangLabel43, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE)
                    .addComponent(jlangLabel47, javax.swing.GroupLayout.DEFAULT_SIZE, 102, Short.MAX_VALUE)
                    .addComponent(jlangLabel44, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE)
                    .addComponent(jlangLabel50, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE))
                .addGap(16, 16, 16)
                .addGroup(poaLangPanelLayout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
                    .addGroup(javax.swing.GroupLayout.Alignment.TRAILING, poaLangPanelLayout.createSequentialGroup()
                        .addComponent(stateLangTextField, javax.swing.GroupLayout.PREFERRED_SIZE, 147, javax.swing.GroupLayout.PREFERRED_SIZE)
                        .addGap(18, 18, 18)
                        .addComponent(jlangLabel151)
                        .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.UNRELATED)
                        .addComponent(pincodeLangTextField, javax.swing.GroupLayout.PREFERRED_SIZE, 67, javax.swing.GroupLayout.PREFERRED_SIZE))
                    .addComponent(streetLangTextField, javax.swing.GroupLayout.Alignment.TRAILING, javax.swing.GroupLayout.PREFERRED_SIZE, 287, javax.swing.GroupLayout.PREFERRED_SIZE)
                    .addComponent(houseNoLangTextField, javax.swing.GroupLayout.Alignment.TRAILING, javax.swing.GroupLayout.PREFERRED_SIZE, 287, javax.swing.GroupLayout.PREFERRED_SIZE)
                    .addComponent(postOfficeLangTextField, javax.swing.GroupLayout.Alignment.TRAILING, javax.swing.GroupLayout.PREFERRED_SIZE, 287, javax.swing.GroupLayout.PREFERRED_SIZE)
                    .addComponent(subDistrictLangTextField, javax.swing.GroupLayout.Alignment.TRAILING, javax.swing.GroupLayout.PREFERRED_SIZE, 287, javax.swing.GroupLayout.PREFERRED_SIZE))
                .addGap(25, 25, 25))
        );
        poaLangPanelLayout.setVerticalGroup(
            poaLangPanelLayout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
            .addGroup(poaLangPanelLayout.createSequentialGroup()
                .addGroup(poaLangPanelLayout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING, false)
                    .addComponent(houseNoLangTextField)
                    .addComponent(jlangLabel40, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE)
                    .addComponent(jlangLabel141)
                    .addComponent(careOfLangTextField, javax.swing.GroupLayout.PREFERRED_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.PREFERRED_SIZE))
                .addGap(5, 5, 5)
                .addGroup(poaLangPanelLayout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
                    .addGroup(poaLangPanelLayout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING, false)
                        .addComponent(streetLangTextField, javax.swing.GroupLayout.DEFAULT_SIZE, 21, Short.MAX_VALUE)
                        .addComponent(jlangLabel42, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE)
                        .addComponent(jlangLabel43))
                    .addComponent(landMarkLangTextField, javax.swing.GroupLayout.Alignment.TRAILING, javax.swing.GroupLayout.PREFERRED_SIZE, 21, javax.swing.GroupLayout.PREFERRED_SIZE))
                .addGap(5, 5, 5)
                .addGroup(poaLangPanelLayout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
                    .addGroup(javax.swing.GroupLayout.Alignment.TRAILING, poaLangPanelLayout.createParallelGroup(javax.swing.GroupLayout.Alignment.BASELINE)
                        .addComponent(postOfficeLangTextField, javax.swing.GroupLayout.PREFERRED_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.PREFERRED_SIZE)
                        .addComponent(jlangLabel44)
                        .addComponent(localityLangTextField, javax.swing.GroupLayout.PREFERRED_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.PREFERRED_SIZE))
                    .addComponent(jlangLabel45, javax.swing.GroupLayout.PREFERRED_SIZE, 19, javax.swing.GroupLayout.PREFERRED_SIZE))
                .addGap(5, 5, 5)
                .addGroup(poaLangPanelLayout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING, false)
                    .addComponent(subDistrictLangTextField)
                    .addComponent(jlangLabel46, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE)
                    .addComponent(jlangLabel47, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE)
                    .addComponent(vtcNameLangTextField))
                .addGap(5, 5, 5)
                .addGroup(poaLangPanelLayout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING, false)
                    .addComponent(districtLangTextField, javax.swing.GroupLayout.Alignment.TRAILING, javax.swing.GroupLayout.PREFERRED_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.PREFERRED_SIZE)
                    .addGroup(poaLangPanelLayout.createParallelGroup(javax.swing.GroupLayout.Alignment.BASELINE)
                        .addComponent(stateLangTextField)
                        .addComponent(jlangLabel151)
                        .addComponent(pincodeLangTextField)
                        .addComponent(jlangLabel48, javax.swing.GroupLayout.PREFERRED_SIZE, 18, javax.swing.GroupLayout.PREFERRED_SIZE)
                        .addComponent(jlangLabel50, javax.swing.GroupLayout.PREFERRED_SIZE, 20, javax.swing.GroupLayout.PREFERRED_SIZE)))
                .addGap(5, 5, 5))
        );

        javax.swing.GroupLayout responeContentPanelLayout = new javax.swing.GroupLayout(responeContentPanel);
        responeContentPanel.setLayout(responeContentPanelLayout);
        responeContentPanelLayout.setHorizontalGroup(
            responeContentPanelLayout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
            .addGroup(responeContentPanelLayout.createSequentialGroup()
                .addGroup(responeContentPanelLayout.createParallelGroup(javax.swing.GroupLayout.Alignment.TRAILING, false)
                    .addComponent(poaPanel, javax.swing.GroupLayout.DEFAULT_SIZE, 915, Short.MAX_VALUE)
                    .addComponent(poiPanel, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE))
                .addContainerGap(javax.swing.GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE))
            .addGroup(javax.swing.GroupLayout.Alignment.TRAILING, responeContentPanelLayout.createSequentialGroup()
                .addContainerGap(javax.swing.GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE)
                .addComponent(ouputTypeCombo, javax.swing.GroupLayout.PREFERRED_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.PREFERRED_SIZE)
                .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.UNRELATED)
                .addComponent(saveAsButton, javax.swing.GroupLayout.PREFERRED_SIZE, 107, javax.swing.GroupLayout.PREFERRED_SIZE)
                .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED)
                .addComponent(responseResetButton, javax.swing.GroupLayout.PREFERRED_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.PREFERRED_SIZE)
                .addGap(14, 14, 14))
            .addGroup(javax.swing.GroupLayout.Alignment.TRAILING, responeContentPanelLayout.createSequentialGroup()
                .addComponent(poaLangPanel, javax.swing.GroupLayout.DEFAULT_SIZE, 915, Short.MAX_VALUE)
                .addContainerGap())
        );

        responeContentPanelLayout.linkSize(javax.swing.SwingConstants.HORIZONTAL, new java.awt.Component[] {ouputTypeCombo, responseResetButton, saveAsButton});

        responeContentPanelLayout.setVerticalGroup(
            responeContentPanelLayout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
            .addGroup(responeContentPanelLayout.createSequentialGroup()
                .addGap(1, 1, 1)
                .addComponent(poiPanel, javax.swing.GroupLayout.PREFERRED_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.PREFERRED_SIZE)
                .addGap(10, 10, 10)
                .addComponent(poaPanel, javax.swing.GroupLayout.PREFERRED_SIZE, 163, javax.swing.GroupLayout.PREFERRED_SIZE)
                .addGap(5, 5, 5)
                .addComponent(poaLangPanel, javax.swing.GroupLayout.PREFERRED_SIZE, 168, javax.swing.GroupLayout.PREFERRED_SIZE)
                .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED)
                .addGroup(responeContentPanelLayout.createParallelGroup(javax.swing.GroupLayout.Alignment.BASELINE)
                    .addComponent(ouputTypeCombo, javax.swing.GroupLayout.PREFERRED_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.PREFERRED_SIZE)
                    .addComponent(saveAsButton, javax.swing.GroupLayout.PREFERRED_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.PREFERRED_SIZE)
                    .addComponent(responseResetButton, javax.swing.GroupLayout.PREFERRED_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.PREFERRED_SIZE))
                .addContainerGap(javax.swing.GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE))
        );

        responeContentPanelLayout.linkSize(javax.swing.SwingConstants.VERTICAL, new java.awt.Component[] {ouputTypeCombo, responseResetButton, saveAsButton});

        contentPanel.add(responeContentPanel, "card3");

        javax.swing.GroupLayout chooseApplicationPanelLayout = new javax.swing.GroupLayout(chooseApplicationPanel);
        chooseApplicationPanel.setLayout(chooseApplicationPanelLayout);
        chooseApplicationPanelLayout.setHorizontalGroup(
            chooseApplicationPanelLayout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
            .addGroup(chooseApplicationPanelLayout.createSequentialGroup()
                .addGap(56, 56, 56)
                .addGroup(chooseApplicationPanelLayout.createParallelGroup(javax.swing.GroupLayout.Alignment.TRAILING, false)
                    .addGroup(chooseApplicationPanelLayout.createSequentialGroup()
                        .addComponent(bankLogoLabel)
                        .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED, javax.swing.GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE)
                        .addComponent(jLabel10, javax.swing.GroupLayout.PREFERRED_SIZE, 377, javax.swing.GroupLayout.PREFERRED_SIZE)
                        .addGap(204, 204, 204)
                        .addComponent(aadhaarLogoLabel))
                    .addComponent(contentPanel, javax.swing.GroupLayout.PREFERRED_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.PREFERRED_SIZE))
                .addContainerGap(javax.swing.GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE))
        );
        chooseApplicationPanelLayout.setVerticalGroup(
            chooseApplicationPanelLayout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
            .addGroup(chooseApplicationPanelLayout.createSequentialGroup()
                .addGroup(chooseApplicationPanelLayout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
                    .addGroup(chooseApplicationPanelLayout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING, false)
                        .addComponent(aadhaarLogoLabel, javax.swing.GroupLayout.PREFERRED_SIZE, 0, Short.MAX_VALUE)
                        .addComponent(jLabel10, javax.swing.GroupLayout.DEFAULT_SIZE, 51, Short.MAX_VALUE))
                    .addComponent(bankLogoLabel))
                .addGap(8, 8, 8)
                .addComponent(contentPanel, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.PREFERRED_SIZE)
                .addGap(3, 3, 3))
        );

        javax.swing.GroupLayout jPanel1Layout = new javax.swing.GroupLayout(jPanel1);
        jPanel1.setLayout(jPanel1Layout);
        jPanel1Layout.setHorizontalGroup(
            jPanel1Layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
            .addComponent(chooseApplicationPanel, javax.swing.GroupLayout.PREFERRED_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.PREFERRED_SIZE)
        );
        jPanel1Layout.setVerticalGroup(
            jPanel1Layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
            .addComponent(chooseApplicationPanel, javax.swing.GroupLayout.PREFERRED_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.PREFERRED_SIZE)
        );

        javax.swing.GroupLayout layout = new javax.swing.GroupLayout(getContentPane());
        getContentPane().setLayout(layout);
        layout.setHorizontalGroup(
            layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
            .addComponent(jPanel1, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE)
        );
        layout.setVerticalGroup(
            layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
            .addComponent(jPanel1, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE)
        );

        pack();
    }// </editor-fold>//GEN-END:initComponents

    private void resetButton1ActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_resetButton1ActionPerformed
        resetFields();
    }//GEN-LAST:event_resetButton1ActionPerformed

    private void sendKYCRequestButtonActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_sendKYCRequestButtonActionPerformed
        
        if(jFormattedTextFieldAADHAARNo.getText().trim().isEmpty()){
            validationMessageLabel.setVisible(true);
        }else{
            System.out.println("processing kyc request");
            validationMessageLabel.setVisible(false);
            sendKYCRequest();
        }
        
    }//GEN-LAST:event_sendKYCRequestButtonActionPerformed

    private void saveAsButtonActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_saveAsButtonActionPerformed
        JFileChooser fileChooser = new JFileChooser();
        String[] saveFileTypes = ConverterType.getConverterTypes();
        String selectFileType = saveFileTypes[ouputTypeCombo
                .getSelectedIndex()];
        File toSavefile = new File(uid + "." + selectFileType.toLowerCase());
        fileChooser.setSelectedFile(toSavefile);
        int returnValue = fileChooser.showSaveDialog(this);
        if (returnValue == JFileChooser.APPROVE_OPTION) {
            File file = fileChooser.getSelectedFile();
            try {
                saveFile(file, selectFileType.toLowerCase());
                JOptionPane.showMessageDialog(this, "Saved succesfully",
                        "KYC Demo Client", JOptionPane.INFORMATION_MESSAGE);
            } catch (IOException e) {
                e.printStackTrace();
                JOptionPane.showMessageDialog(this,
                        "Saving file to system has issue",
                        "KYC Demo Client:Error", JOptionPane.ERROR_MESSAGE);
            } catch (ConverterNotFoundException e) {
                e.printStackTrace();
                JOptionPane.showMessageDialog(this,
                        "This type of saving not yet supported",
                        "KYC Demo Client:Error", JOptionPane.ERROR_MESSAGE);
            } catch (Exception e) {
                e.printStackTrace();
                JOptionPane.showMessageDialog(this, "Conversion Error",
                        "KYC Demo Client:Error", JOptionPane.ERROR_MESSAGE);

            }

        }

    }//GEN-LAST:event_saveAsButtonActionPerformed

    private void responseResetButtonActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_responseResetButtonActionPerformed
        CardLayout cardLayout = (CardLayout)contentPanel.getLayout();
        cardLayout.first(contentPanel);
    }//GEN-LAST:event_responseResetButtonActionPerformed

    private void ouputTypeComboActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_ouputTypeComboActionPerformed
        // TODO add your handling code here:
    }//GEN-LAST:event_ouputTypeComboActionPerformed

    private void bioMetrictRadioButtonActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_bioMetrictRadioButtonActionPerformed
        otpPinTextField.setText("");
        CardLayout layout = (CardLayout)bioOTPPanel.getLayout();
        layout.first(bioOTPPanel);
        
    }//GEN-LAST:event_bioMetrictRadioButtonActionPerformed

    private void bioMetricsSelectActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_bioMetricsSelectActionPerformed
        // TODO add your handling code here:
    }//GEN-LAST:event_bioMetricsSelectActionPerformed

    private void biometricsScanButtonActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_biometricsScanButtonActionPerformed
		JOptionPane.showMessageDialog(this, "Biometric authentication is not supported.",
                "UID Authentication Demo Client", JOptionPane.INFORMATION_MESSAGE);
    }//GEN-LAST:event_biometricsScanButtonActionPerformed

    private void residenNameTextFieldActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_residenNameTextFieldActionPerformed
        // TODO add your handling code here:
    }//GEN-LAST:event_residenNameTextFieldActionPerformed

    private void dobTextFieldActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_dobTextFieldActionPerformed
        // TODO add your handling code here:
    }//GEN-LAST:event_dobTextFieldActionPerformed

    private void genderTextFieldActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_genderTextFieldActionPerformed
        // TODO add your handling code here:
    }//GEN-LAST:event_genderTextFieldActionPerformed

    private void phoneNumberTextFieldActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_phoneNumberTextFieldActionPerformed
        // TODO add your handling code here:
    }//GEN-LAST:event_phoneNumberTextFieldActionPerformed

    private void emailTextFieldActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_emailTextFieldActionPerformed
        // TODO add your handling code here:
    }//GEN-LAST:event_emailTextFieldActionPerformed

    private void continueButton2ActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_continueButton2ActionPerformed
        resetFields();
        CardLayout cardLayout = (CardLayout) contentPanel.getLayout();
        cardLayout.next(contentPanel);
        
    }//GEN-LAST:event_continueButton2ActionPerformed

    private void jRadioButton3ActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_jRadioButton3ActionPerformed
        // TODO add your handling code here:
    }//GEN-LAST:event_jRadioButton3ActionPerformed

    private void jFormattedTextFieldAADHAARNoActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_jFormattedTextFieldAADHAARNoActionPerformed
        // TODO add your handling code here:
    }//GEN-LAST:event_jFormattedTextFieldAADHAARNoActionPerformed

    private void careOfTextFieldActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_careOfTextFieldActionPerformed
        // TODO add your handling code here:
    }//GEN-LAST:event_careOfTextFieldActionPerformed

    private void jTextField25ActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_jTextField25ActionPerformed
        // TODO add your handling code here:
    }//GEN-LAST:event_jTextField25ActionPerformed

    private void localityTextFieldActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_localityTextFieldActionPerformed
        // TODO add your handling code here:
    }//GEN-LAST:event_localityTextFieldActionPerformed

    private void jRadioButton1ActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_jRadioButton1ActionPerformed
        // TODO add your handling code here:
    }//GEN-LAST:event_jRadioButton1ActionPerformed

    private void jRadioButton4ActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_jRadioButton4ActionPerformed
        // TODO add your handling code here:
    }//GEN-LAST:event_jRadioButton4ActionPerformed

    private void jRadioButton2ActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_jRadioButton2ActionPerformed
        // TODO add your handling code here:
    }//GEN-LAST:event_jRadioButton2ActionPerformed

    private void jRadioButton5ActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_jRadioButton5ActionPerformed
        // TODO add your handling code here:
    }//GEN-LAST:event_jRadioButton5ActionPerformed

    private void jRadioButton6ActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_jRadioButton6ActionPerformed
        // TODO add your handling code here:
    }//GEN-LAST:event_jRadioButton6ActionPerformed

    private void residentConsentCheckboxActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_residentConsentCheckboxActionPerformed
        // TODO add your handling code here:
    }//GEN-LAST:event_residentConsentCheckboxActionPerformed

    private void otpRadioButtonActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_otpRadioButtonActionPerformed
        // clearing other 
        bioMetricsSelect.setSelectedIndex(1);
        bioCaptures.clear();
        CardLayout layout = (CardLayout)bioOTPPanel.getLayout();
        layout.last(bioOTPPanel);
        
    }//GEN-LAST:event_otpRadioButtonActionPerformed

    private void jButtonSendOTPRequestActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_jButtonSendOTPRequestActionPerformed
		jLabelOtpRequestStatus.setText("Requesting OTP ...");

		String channel = getPreferredChannel();

		OtpDataFromDeviceToAUA auaData = new OtpDataFromDeviceToAUA(jFormattedTextFieldAADHAARNo.getText(), 
                        config.getProperty("terminalId"), channel);

		OtpRequestCreator requestCreator = new OtpRequestCreator();
		Otp otp = requestCreator.createOtpRequest(config.getProperty("auaCode"), config.getProperty("sa"),
				config.getProperty("licenseKey"), auaData);
		try {
			OtpRes res = otpClient.generateOtp(otp).getOtpRes();
			if (res.getRet().equals(OtpResult.N)) {
				jLabelOtpRequestStatus.setText("Failed (Reason: " + res.getErr() + " (" + ErrorCodeDescriptions.getDescription(res.getErr()) + "), "
						+ " Code: " + (res.getCode()) + ")");
				jLabelOtpRequestStatus.setToolTipText("Failed (Reason: " + res.getErr() + " (" + ErrorCodeDescriptions.getDescription(res.getErr()) + "), "
						+ " Code: " + (res.getCode()) + ")");
			} else {
				jLabelOtpRequestStatus.setText("Success (Code:" + (res.getCode()) + ")");
			}
		} catch (Exception e) {
			jLabelOtpRequestStatus.setText(e.getMessage());
		}
        // TODO add your handling code here:
    }//GEN-LAST:event_jButtonSendOTPRequestActionPerformed
    private String getPreferredChannel() {
        String channel = "";
        if (jCheckBoxOtpViaEmail.isSelected() && jCheckBoxOtpViaSMS.isSelected()) {
            channel = OtpDataFromDeviceToAUA.BOTH_EMAIL_SMS_CHANNEL;
        } else if (jCheckBoxOtpViaEmail.isSelected()) {
            channel = OtpDataFromDeviceToAUA.EMAIL_CHANNEL;
        } else if (jCheckBoxOtpViaSMS.isSelected()) {
            channel = OtpDataFromDeviceToAUA.SMS_CHANNEL;
        }
        return channel;
    }
    private void jButtonOTPDialogDoneActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_jButtonOTPDialogDoneActionPerformed
        jCheckBoxOtpViaEmail.setSelected(false);
        jCheckBoxOtpViaSMS.setSelected(false);
        jLabelOtpRequestStatus.setText("");
    }//GEN-LAST:event_jButtonOTPDialogDoneActionPerformed

    private void jButton1ActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_jButton1ActionPerformed
        if (jFormattedTextFieldAADHAARNo.getText().trim().isEmpty()) {
            validationMessageLabel.setVisible(true);
        } else {
            jOTP.setModal(true);
            jOTP.setBounds(100, 100, 620, 230);
            jOTP.setVisible(true);
        }        // TODO add your handling code here:
    }//GEN-LAST:event_jButton1ActionPerformed

    private void careOfLangTextFieldActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_careOfLangTextFieldActionPerformed
        // TODO add your handling code here:
    }//GEN-LAST:event_careOfLangTextFieldActionPerformed

    private void houseNoLangTextFieldActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_houseNoLangTextFieldActionPerformed
        // TODO add your handling code here:
    }//GEN-LAST:event_houseNoLangTextFieldActionPerformed

    private void postOfficeLangTextFieldActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_postOfficeLangTextFieldActionPerformed
        // TODO add your handling code here:
    }//GEN-LAST:event_postOfficeLangTextFieldActionPerformed

    private void districtTextFieldActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_districtTextFieldActionPerformed
        // TODO add your handling code here:
    }//GEN-LAST:event_districtTextFieldActionPerformed

    private void pincodeTextFieldActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_pincodeTextFieldActionPerformed
        // TODO add your handling code here:
    }//GEN-LAST:event_pincodeTextFieldActionPerformed

    private void pincodeLangTextFieldActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_pincodeLangTextFieldActionPerformed
        // TODO add your handling code here:
    }//GEN-LAST:event_pincodeLangTextFieldActionPerformed

    private void stateTextFieldActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_stateTextFieldActionPerformed
        // TODO add your handling code here:
    }//GEN-LAST:event_stateTextFieldActionPerformed

    private void vtcNameLangTextFieldActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_vtcNameLangTextFieldActionPerformed
        // TODO add your handling code here:
    }//GEN-LAST:event_vtcNameLangTextFieldActionPerformed

    private void houseNoTextFieldActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_houseNoTextFieldActionPerformed
        // TODO add your handling code here:
    }//GEN-LAST:event_houseNoTextFieldActionPerformed

        //<editor-fold defaultstate="collapsed" desc="Sending KYC Request">
    private void sendKYCRequest() {
        this.repaint();
        DeviceCollectedAuthData authData = contructKYCRequest();
        if (config == null) {
            JOptionPane.showMessageDialog(this, "Unable to load configuration properties",
                    "UID KYC Demo Client", JOptionPane.ERROR_MESSAGE);
            return;
        }
        // Retry Count added for test connection
        String kycServerURL = config.getProperty("kycServerUrl");
        int retryCount = NumberUtils.toInt(config.getProperty("connectionRetryCount"),DEFAULT_CONNECTION_RETRY_COUNT);
		for (int i = 0; i < retryCount; i++) {
			try {
				new java.net.URL(kycServerURL).openConnection().connect();
				break;// if successful break;
			} catch (Exception e) {
				System.out.println("Tried "+ i+" time :"+e.getMessage());
				// if exception got retry count times then throw error
				if (i == (retryCount - 1)) {
					e.printStackTrace();
					JOptionPane.showMessageDialog(this,
							"Server not reachable.\n Retried " + retryCount
									+ " times", "UID KYC Demo Client",
							JOptionPane.ERROR_MESSAGE);
					return;
				}
			}
		}
        if (!(new File(config.getProperty("publicKeyFile"))).exists()) {
            JOptionPane.showMessageDialog(this, "Public key file not found.\nVerify the file path in Edit -> Preferences",
                    "UID KYC Demo Client", JOptionPane.ERROR_MESSAGE);
            return;
        }

        if (!(new File(config.getProperty("publicKeyFileDSIG"))).exists()) {
            JOptionPane.showMessageDialog(this, "Signature file not found.\nVerify the file path in Edit -> Preferences",
                    "UID KYC Demo Client", JOptionPane.ERROR_MESSAGE);
            return;
        }

        if (!this.residentConsentCheckbox.isSelected()) {
            JOptionPane.showMessageDialog(this, "Cannot send the KYC request without Residnet Consent ",
                    "UID KYC Demo Client", JOptionPane.ERROR_MESSAGE);
            System.out.print("Show message");
            return;
        }
       try{
           
        Uses uses = createUsesElement();

        AuthDataFromDeviceToAUA auaData = authAUADataCreator.prepareAUAData(authData.getUid(), 
                config.getProperty("terminalId"), authData.getDeviceMetaData(), PidCreator.createXmlPid(authData), DataType.X);
        Auth auth = AuthRequestCreator.createAuthRequest(config.getProperty("auaCode"), config.getProperty("sa"), 
                config.getProperty("licenseKey"), uses, null/*token*/, auaData, authData.getDeviceMetaData());
        
        String kycResponseXML = kYCClient.kycTrans(auth, config.getProperty("auaCode"),
                residentConsentCheckbox.isSelected(),config.getProperty("asaLicenseKey"), uses, "");
        kycResponseXMLWithSignInfo = kycResponseXML;
        populateResponse(kycResponseXML);
           
       }catch(Exception ex){
           ex.printStackTrace();
           JOptionPane.showMessageDialog(this, "Error: " + ex.getMessage(), "UID Authentication Demo Client", JOptionPane.ERROR_MESSAGE);
       }
    }
    
    private void populateResponse(String kycResponseXML) throws JAXBException {
        KycRes kycRes = (KycRes) XMLUtilities.parseXML(KycRes.class, kycResponseXML);

        if (AuthResult.Y.toString().equalsIgnoreCase(kycRes.getRet().toString())) {
            kycErrorCodeLabel.setText("");
            kycErrorCodeLabel.setToolTipText("");
            statusLabel.setIcon(new ImageIcon(getClass().getResource("/success.png")));
            //Show Response Panel
            CardLayout cardLayout = (CardLayout) contentPanel.getLayout();
            cardLayout.next(contentPanel);

        } else {
            statusLabel.setIcon(new ImageIcon(getClass().getResource("/failure.png")));
            kycErrorCodeLabel.setText("<html><body style=\"width:120px\"><b>e-KYC Error code:</b>" + kycRes.getErr() + " (" + ErrorCodeDescriptions.getDescription(kycRes.getErr()) + ")</body></html>");

            byte[] authBytes = kycRes.getRar();
            if(authBytes != null){
                AuthRes authRes = (AuthRes) XMLUtilities.parseXML(AuthRes.class, new String(authBytes));
                if (AuthResult.N.toString().equalsIgnoreCase(authRes.getRet().toString())) {
                    authErrorCode.setText("<html><body style=\"width:120px\"><b>Auth Error code: </b>" + authRes.getErr() + " (" + ErrorCodeDescriptions.getDescription(authRes.getErr()) + ")</body></html>");
                }
            }
        }

        // populate response in response panel
        if (kycRes.getUidData() != null) {
            UidDataType uidData = kycRes.getUidData();
            aadhaarNumberLabel.setText(uidData.getUid());
            PoiType poi = uidData.getPoi();

            dobTextField.setText(poi.getDob());
            emailTextField.setText(poi.getEmail());
            genderTextField.setText(poi.getGender().toString());
            residenNameTextField.setText(poi.getName());
            phoneNumberTextField.setText(poi.getPhone());


            //poa details
            PoaType poa = uidData.getPoa();
            careOfTextField.setText(poa.getCo());
            districtTextField.setText(poa.getDist());
            houseNoTextField.setText(poa.getHouse());
            localityTextField.setText(poa.getLoc());
            landMarkTextField.setText(poa.getLm());
            pincodeTextField.setText(poa.getPc());
            postOfficeTextField.setText(poa.getPo());
            stateTextField.setText(poa.getState());
            streetTextField.setText(poa.getStreet());
            subDistrictTextField.setText(poa.getSubdist());
            vtcNameTextField.setText(poa.getVtc());

            byte[] photo = uidData.getPht();
            Image image = readImage(photo);
            photoLabel.setIcon(new ImageIcon(image));
            
            
            // poa language level details by siva.
            LDataType ldataType = uidData.getLData();
            if (ldataType != null) {
            	
            	String languageCode = ldataType.getLang();
				Font localeFont = new Font("Tahoma",Font.PLAIN,10);
				if (languageCode != null) {
					String fontName = LanguageCodeFontStore
							.getFontNameByLanguageCode(languageCode);
					System.out.println(fontName);
					localeFont = new Font(fontName,Font.PLAIN,9);
				}	
            	
            careOfLangTextField.setText(ldataType.getCo());
            careOfLangTextField.setFont(localeFont);
            
            districtLangTextField.setText(ldataType.getDist());
            districtLangTextField.setFont(localeFont);
            
            houseNoLangTextField.setText(ldataType.getHouse());
            houseNoLangTextField.setFont(localeFont);
            
            localityLangTextField.setText(ldataType.getLoc());
            localityLangTextField.setFont(localeFont);
            
            landMarkLangTextField.setText(ldataType.getLm());
            landMarkLangTextField.setFont(localeFont);
            
            pincodeLangTextField.setText(ldataType.getPc());
            pincodeLangTextField.setFont(new Font("Tahoma",Font.PLAIN,11));
            
            postOfficeLangTextField.setText(ldataType.getPo());
            postOfficeLangTextField.setFont(localeFont);
            
            stateLangTextField.setText(ldataType.getState());
            stateLangTextField.setFont(localeFont);
            
            streetLangTextField.setText(ldataType.getStreet());
            streetLangTextField.setFont(localeFont);
            
            subDistrictLangTextField.setText(ldataType.getSubdist());
            subDistrictLangTextField.setFont(localeFont);
            
            vtcNameLangTextField.setText(ldataType.getVtc());
            vtcNameLangTextField.setFont(localeFont);
            } 


        }
    }
    
    private Image readImage(byte[] imageBytes) {
        byte[] faceByteIso = org.apache.commons.codec.binary.Base64
                .decodeBase64(imageBytes);
        try {
            BufferedImage bufImage = ImageIO.read(new ByteArrayInputStream(
                    faceByteIso));
            return bufImage.getScaledInstance(-1, 270,
                    Image.SCALE_AREA_AVERAGING);
        } catch (IOException e) {
            e.printStackTrace();
        }
        return null;
    }

    private Uses createUsesElement() {

        Uses uses = new Uses();
        uses.setBio(UsesFlag.valueOf(bioMetrictRadioButton.isSelected() ? "Y" : "N"));
        uses.setOtp(UsesFlag.valueOf(otpRadioButton.isSelected() ? "Y" : "N"));
        uses.setPi(UsesFlag.N);
        uses.setPa(UsesFlag.N);
        uses.setPfa(UsesFlag.N);
        uses.setPin(UsesFlag.N);

        String biometricTypes = "";

        if (bioMetrictRadioButton.isSelected()) {
            biometricTypes += "FMR";
        }

        uses.setBt(biometricTypes);
        return uses;
    }

    private DeviceCollectedAuthData contructKYCRequest() {
        DeviceCollectedAuthData data = new DeviceCollectedAuthData();
        String aadhaarNumber= jFormattedTextFieldAADHAARNo.getText();
        this.uid = aadhaarNumber;
        data.setUid(aadhaarNumber);
        
        data.setFullAddress("");
        Meta meta = createMeta();
        data.setDeviceMetaData(meta);
        if(!bioCaptures.isEmpty()){
            data.setBiometrics(bioCaptures);            
        }
        String dynamicPin = new String(otpPinTextField.getPassword()).trim();
        if(dynamicPin != null){
            data.setDynamicPin(dynamicPin);
        }
        return data;
    }
    
    private Meta createMeta(){
        Meta meta = new Meta();
        meta.setFdc(config.getProperty("fdc"));
        meta.setIdc(config.getProperty("idc"));
        meta.setLot(LocationType.valueOf(config.getProperty("lot")));
        meta.setLov(config.getProperty("lov"));
        meta.setPip(config.getProperty("publicIP"));
        meta.setUdc(config.getProperty("udc"));
        
        return meta;
    }
    
    //</editor-fold>
	private void saveFile(File toSaveFile, String fileType) throws Exception {
        JOptionPane.showMessageDialog(this, "Operation not supported.",
                "UID Authentication Demo Client", JOptionPane.INFORMATION_MESSAGE);
    }

    private void resetFields(){
        bioCaptures.clear();
        bioImageLabel.setIcon(null);
        jFormattedTextFieldAADHAARNo.setText("");
        residentConsentCheckbox.setSelected(true);
        bioMetricsSelect.setSelectedIndex(1);
        bioMetrictRadioButton.setSelected(true);
        statusLabel.setIcon(null);
        kycErrorCodeLabel.setText("");
        authErrorCode.setText("");
        validationMessageLabel.setVisible(false);
        // clearing otp pin
        otpPinTextField.setText("");
        // Resetting to default Biometrics card
        CardLayout layout = (CardLayout)bioOTPPanel.getLayout();
        layout.first(bioOTPPanel);

    }
    
    private void initializeKycClient() {
        try {
            String useSSK = config.getProperty("useSSK");
            boolean useSSKFlag = "yes".equalsIgnoreCase(useSSK) ? true : false;
            authAUADataCreator = new AuthAUADataCreator(new Encrypter(config.getProperty("publicKeyFile")), useSSKFlag);
            kYCClient = new KYCClient(new URL(config.getProperty("kycServerUrl")).toURI());
            otpClient = new OtpClient(new URL(config.getProperty("otpServerUrl")).toURI());
            
            DigitalSigner ds = null;
            DataDecryptor dd = null;
            if ("true".equalsIgnoreCase(config.getProperty("useDongle"))) {
                if (config.getProperty("safeSignConfPath") != null && config.getProperty("donglePin") != null) {
                     ds = new DigitalSigner(config.getProperty("safeSignConfPath"), config.getProperty("donglePin").toCharArray());
                } else {
                    System.out.println("Your are using USE_DONGLE please set SAFE_SING_CFG_PATH and ");
                }
            }else{
               	ds = new DigitalSigner(config.getProperty("signKeyStore"),config.getProperty("signaturePassword").toCharArray(),
			config.getProperty("signatureAlias"));

            }
            dd = new DataDecryptor(config.getProperty("signKeyStore"), config.getProperty("signaturePassword").toCharArray(), config.getProperty("publicKeyFileDSIG"));
            
            kYCClient.setDigitalSignator(ds);
            otpClient.setDigitalSignator(ds);
            otpClient.setAsaLicenseKey(config.getProperty("asaLicenseKey"));
            kYCClient.setDataDecryptor(dd);
            kYCClient.setAsaLicenseKey(config.getProperty("asaLicenseKey"));
        } catch (MalformedURLException ex) {
            ex.printStackTrace();
            Logger.getLogger(FinancialLandingFrame.class.getName()).log(Level.SEVERE, null, ex);
        } catch (URISyntaxException ex) {
            ex.printStackTrace();
            Logger.getLogger(FinancialLandingFrame.class.getName()).log(Level.SEVERE, null, ex);
        }
    }

	public void drawFingerprintImage(Image image) {
		bioImageLabel.setIcon(new ImageIcon(image.getScaledInstance(bioImageLabel.getWidth(), bioImageLabel.getHeight(),
				Image.SCALE_DEFAULT)));
	}
        

    /**
     * @param args the command line arguments
     */
    public static void main(String args[]) {
        /* Set the Nimbus look and feel */
        //<editor-fold defaultstate="collapsed" desc=" Look and feel setting code (optional) ">
        /* If Nimbus (introduced in Java SE 6) is not available, stay with the default look and feel.
         * For details see http://download.oracle.com/javase/tutorial/uiswing/lookandfeel/plaf.html 
         */
        try {
            for (javax.swing.UIManager.LookAndFeelInfo info : javax.swing.UIManager.getInstalledLookAndFeels()) {
                if ("Windows".equals(info.getName())) {
                    javax.swing.UIManager.setLookAndFeel(info.getClassName());
                    break;
                }
            }
        } catch (ClassNotFoundException ex) {
            java.util.logging.Logger.getLogger(FinancialLandingFrame.class.getName()).log(java.util.logging.Level.SEVERE, null, ex);
        } catch (InstantiationException ex) {
            java.util.logging.Logger.getLogger(FinancialLandingFrame.class.getName()).log(java.util.logging.Level.SEVERE, null, ex);
        } catch (IllegalAccessException ex) {
            java.util.logging.Logger.getLogger(FinancialLandingFrame.class.getName()).log(java.util.logging.Level.SEVERE, null, ex);
        } catch (javax.swing.UnsupportedLookAndFeelException ex) {
            java.util.logging.Logger.getLogger(FinancialLandingFrame.class.getName()).log(java.util.logging.Level.SEVERE, null, ex);
        }
        //</editor-fold>
        
        /* Create and display the form */
        java.awt.EventQueue.invokeLater(new Runnable() {
            public void run() {
                new FinancialLandingFrame().setVisible(true);
            }
        });
    }
    // Variables declaration - do not modify//GEN-BEGIN:variables
    javax.swing.JLabel aadhaarLogoLabel;
    javax.swing.JLabel aadhaarNumberLabel;
    javax.swing.JPanel applicationOptionsPanel;
    javax.swing.JLabel authErrorCode;
    javax.swing.ButtonGroup authenticationTypeButtonGroup;
    javax.swing.JLabel bankLogoLabel;
    javax.swing.JLabel bioImageLabel;
    javax.swing.JPanel bioImagePanel;
    javax.swing.JPanel bioMetricsCapturePanel;
    javax.swing.JComboBox bioMetricsSelect;
    javax.swing.JRadioButton bioMetrictRadioButton;
    javax.swing.JPanel bioOTPPanel;
    javax.swing.JButton biometricsScanButton;
    javax.swing.JTextField careOfLangTextField;
    javax.swing.JTextField careOfTextField;
    javax.swing.ButtonGroup chooseApplicationButtonGroup;
    javax.swing.JPanel chooseApplicationPanel;
    javax.swing.JPanel contentPanel;
    javax.swing.JButton continueButton2;
    javax.swing.JTextField districtLangTextField;
    javax.swing.JTextField districtTextField;
    javax.swing.JTextField dobTextField;
    javax.swing.JTextField emailTextField;
    javax.swing.JTextField genderTextField;
    javax.swing.JTextField houseNoLangTextField;
    javax.swing.JTextField houseNoTextField;
    javax.swing.JPanel inputContentPanel;
    javax.swing.JButton jButton1;
    javax.swing.JButton jButtonOTPDialogDone;
    javax.swing.JButton jButtonSendOTPRequest;
    javax.swing.JCheckBox jCheckBoxOtpViaEmail;
    javax.swing.JCheckBox jCheckBoxOtpViaSMS;
    javax.swing.JFormattedTextField jFormattedTextFieldAADHAARNo;
    javax.swing.JLabel jLabel10;
    javax.swing.JLabel jLabel11;
    javax.swing.JLabel jLabel12;
    javax.swing.JLabel jLabel24;
    javax.swing.JLabel jLabel25;
    javax.swing.JLabel jLabel26;
    javax.swing.JLabel jLabel27;
    javax.swing.JLabel jLabel28;
    javax.swing.JLabel jLabel29;
    javax.swing.JLabel jLabel30;
    javax.swing.JLabel jLabel31;
    javax.swing.JLabel jLabel32;
    javax.swing.JLabel jLabel33;
    javax.swing.JLabel jLabel34;
    javax.swing.JLabel jLabel35;
    javax.swing.JLabel jLabel36;
    javax.swing.JLabel jLabel37;
    javax.swing.JLabel jLabel38;
    javax.swing.JLabel jLabel39;
    javax.swing.JLabel jLabelOtpRequestStatus;
    javax.swing.JDialog jOTP;
    javax.swing.JPanel jPanel1;
    javax.swing.JPanel jPanel13;
    javax.swing.JPanel jPanel14;
    javax.swing.JPanel jPanel2;
    javax.swing.JPanel jPanel3;
    javax.swing.JRadioButton jRadioButton1;
    javax.swing.JRadioButton jRadioButton2;
    javax.swing.JRadioButton jRadioButton3;
    javax.swing.JRadioButton jRadioButton4;
    javax.swing.JRadioButton jRadioButton5;
    javax.swing.JRadioButton jRadioButton6;
    javax.swing.JLabel jlangLabel141;
    javax.swing.JLabel jlangLabel151;
    javax.swing.JLabel jlangLabel40;
    javax.swing.JLabel jlangLabel42;
    javax.swing.JLabel jlangLabel43;
    javax.swing.JLabel jlangLabel44;
    javax.swing.JLabel jlangLabel45;
    javax.swing.JLabel jlangLabel46;
    javax.swing.JLabel jlangLabel47;
    javax.swing.JLabel jlangLabel48;
    javax.swing.JLabel jlangLabel50;
    javax.swing.JLabel kycErrorCodeLabel;
    javax.swing.JPanel kycResponseStatusPanel;
    javax.swing.JTextField landMarkLangTextField;
    javax.swing.JTextField landMarkTextField;
    javax.swing.JTextField localityLangTextField;
    javax.swing.JTextField localityTextField;
    javax.swing.JPanel otpPanel;
    javax.swing.JLabel otpPinLabel;
    javax.swing.JPasswordField otpPinTextField;
    javax.swing.JRadioButton otpRadioButton;
    javax.swing.JComboBox ouputTypeCombo;
    javax.swing.JTextField phoneNumberTextField;
    javax.swing.JLabel photoLabel;
    javax.swing.JPanel photoPanel;
    javax.swing.JTextField pincodeLangTextField;
    javax.swing.JTextField pincodeTextField;
    javax.swing.JPanel poaLangPanel;
    javax.swing.JPanel poaPanel;
    javax.swing.JPanel poiDetailsPanel;
    javax.swing.JPanel poiPanel;
    javax.swing.JTextField postOfficeLangTextField;
    javax.swing.JTextField postOfficeTextField;
    javax.swing.JButton resetButton1;
    javax.swing.JTextField residenNameTextField;
    javax.swing.JCheckBox residentConsentCheckbox;
    javax.swing.JPanel responeContentPanel;
    javax.swing.JButton responseResetButton;
    javax.swing.JButton saveAsButton;
    javax.swing.JButton sendKYCRequestButton;
    javax.swing.JTextField stateLangTextField;
    javax.swing.JTextField stateTextField;
    javax.swing.JLabel statusLabel;
    javax.swing.JTextField streetLangTextField;
    javax.swing.JTextField streetTextField;
    javax.swing.JTextField subDistrictLangTextField;
    javax.swing.JTextField subDistrictTextField;
    javax.swing.JLabel validationMessageLabel;
    javax.swing.JTextField vtcNameLangTextField;
    javax.swing.JTextField vtcNameTextField;
    // End of variables declaration//GEN-END:variables
}
