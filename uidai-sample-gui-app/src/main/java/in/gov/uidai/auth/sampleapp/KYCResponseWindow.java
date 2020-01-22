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
/**
 *
 */
package in.gov.uidai.auth.sampleapp;

import java.awt.Color;
import java.awt.Font;
import java.awt.Image;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.awt.image.BufferedImage;
import java.io.ByteArrayInputStream;
import java.io.File;
import java.io.IOException;

import javax.imageio.ImageIO;
import javax.swing.Box;
import javax.swing.GroupLayout;
import javax.swing.JButton;
import javax.swing.JComboBox;
import javax.swing.JFileChooser;
import javax.swing.JFrame;
import javax.swing.JOptionPane;
import javax.swing.JPanel;
import javax.swing.JScrollPane;
import javax.swing.UIManager;

import in.gov.uidai.auth.sampleapp.common.FontManager;
import in.gov.uidai.auth.sampleapp.common.LanguageCodeFontStore;
import in.gov.uidai.auth.sampleapp.converter.ConverterType;
import in.gov.uidai.auth.sampleapp.exception.ConverterNotFoundException;
import in.gov.uidai.kyc.uid_kyc_response._2.KycRes;
import in.gov.uidai.kyc.uid_kyc_response._2.LDataType;
import in.gov.uidai.kyc.uid_kyc_response._2.PoaType;
import in.gov.uidai.kyc.uid_kyc_response._2.PoiType;
import in.gov.uidai.kyc.uid_kyc_response._2.UidDataType;

/**
 *
 */
public class KYCResponseWindow {

    public static final int DEFAULT_IMAGE_SIZE = 200;
    //private JFrame aWindow = new JFrame("KYC response details");
    public JFrame aWindow = new JFrame("KYC response details");
    //frame.setDefaultCloseOperation(JFrame.EXIT_ON_CLOSE);
    JScrollPane scrollPane = new JScrollPane();
    Box box = Box.createVerticalBox();
    private KycRes kycRes;
    private String kycResponseXMLWithSignInfo;

    private Image image;
    private String uid = "XXXXXXXXXXXX";

    private String[] saveFileTypes = ConverterType.getConverterTypes();

    static {
        try {
            UIManager.setLookAndFeel(UIManager.getSystemLookAndFeelClassName());
            FontManager.registerAllFont();
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    public KYCResponseWindow(KycRes kycResponse,
            String kycResponseXMLWithSignInfo) {
        this.kycRes = kycResponse;
        this.kycResponseXMLWithSignInfo = kycResponseXMLWithSignInfo;
        aWindow.setIconImage(new javax.swing.ImageIcon(getClass().getResource(
                "/logo3.jpg")).getImage());
        if (kycResponse.getUidData() != null) {
            this.uid = kycResponse.getUidData().getUid();
            initialize();
            init();
        }
    }

    private void initialize() {
        jLabelUID = new javax.swing.JLabel(uid);
        jLabelUID.setFont(new java.awt.Font("Tahoma", 1, 16));
        jLabelUID.setIcon(new javax.swing.ImageIcon(getClass().getResource(
                "/aadhaar_verified.png")));

        jLabelLogo = new javax.swing.JLabel();
        jLabelLogo.setIcon(new javax.swing.ImageIcon(getClass().getResource(
                "/aadhaar_verified.png")));
        UidDataType uidData = kycRes.getUidData();
        if (uidData != null) {
            PoiType poi = uidData.getPoi();
            jLabelName = new javax.swing.JLabel("Resident Name");
            jTextFieldName = new javax.swing.JTextField(poi.getName());
            jTextFieldName.setEnabled(false);
            jTextFieldName.setDisabledTextColor(Color.BLACK);
            jLabelDOB = new javax.swing.JLabel("Date of Birth");
            jTextFieldDOB = new javax.swing.JTextField(poi.getDob());
            jTextFieldDOB.setEnabled(false);
            jTextFieldDOB.setDisabledTextColor(Color.BLACK);
            jLabelGender = new javax.swing.JLabel("Gender");
            jTextFieldGender = new javax.swing.JTextField(poi.getGender()
                    .toString());
            jTextFieldGender.setEnabled(false);
            jTextFieldGender.setDisabledTextColor(Color.BLACK);
            jLabelMobile = new javax.swing.JLabel("Phone No");
            jTextFieldMobile = new javax.swing.JTextField(poi.getPhone());
            jTextFieldMobile.setEnabled(false);
            jTextFieldMobile.setDisabledTextColor(Color.BLACK);
            jLabelEmail = new javax.swing.JLabel("Email Id");
            jTextFieldEmail = new javax.swing.JTextField(poi.getEmail());
            jTextFieldEmail.setEnabled(false);
            jTextFieldEmail.setDisabledTextColor(Color.BLACK);

            PoaType poa = uidData.getPoa();
            jLabelCo = new javax.swing.JLabel("Care of");
            jTextFieldCo = new javax.swing.JTextField(poa.getCo());
            jTextFieldCo.setEnabled(false);
            jTextFieldCo.setDisabledTextColor(Color.BLACK);
            jLabelHouse = new javax.swing.JLabel("House no");
            jTextFieldHouse = new javax.swing.JTextField(poa.getHouse());
            jTextFieldHouse.setEnabled(false);
            jTextFieldHouse.setDisabledTextColor(Color.BLACK);
            jLabelLm = new javax.swing.JLabel("Landmark");
            jTextFieldLm = new javax.swing.JTextField(poa.getLm());
            jTextFieldLm.setEnabled(false);
            jTextFieldLm.setDisabledTextColor(Color.BLACK);
            jLabelLc = new javax.swing.JLabel("Locality");
            jTextFieldLc = new javax.swing.JTextField(poa.getLoc());
            jTextFieldLc.setEnabled(false);
            jTextFieldLc.setDisabledTextColor(Color.BLACK);
            jLabelVtc = new javax.swing.JLabel("Vtc");
            jTextFieldVtc = new javax.swing.JTextField(poa.getVtc());
            jTextFieldVtc.setEnabled(false);
            jTextFieldVtc.setDisabledTextColor(Color.BLACK);
            jLabelSubDist = new javax.swing.JLabel("Sub district");
            jTextFieldSubDist = new javax.swing.JTextField(poa.getSubdist());
            jTextFieldSubDist.setEnabled(false);
            jTextFieldSubDist.setDisabledTextColor(Color.BLACK);
            jLabelDist = new javax.swing.JLabel("District");
            jTextFieldDist = new javax.swing.JTextField(poa.getDist());
            jTextFieldDist.setEnabled(false);
            jTextFieldDist.setDisabledTextColor(Color.BLACK);
            jLabelState = new javax.swing.JLabel("State");
            jTextFieldState = new javax.swing.JTextField(poa.getState());
            jTextFieldState.setEnabled(false);
            jTextFieldState.setDisabledTextColor(Color.BLACK);
            jLabelPc = new javax.swing.JLabel("Pincode");
            jTextFieldPc = new javax.swing.JTextField(poa.getPc());
            jTextFieldPc.setEnabled(false);
            jTextFieldPc.setDisabledTextColor(Color.BLACK);
            jLabelPo = new javax.swing.JLabel("PostOffice");
            jTextFieldPo = new javax.swing.JTextField(poa.getPo());
            jTextFieldPo.setEnabled(false);
            jTextFieldPo.setDisabledTextColor(Color.BLACK);
            jLabelStreet = new javax.swing.JLabel("Street");
            jTextFieldStreet = new javax.swing.JTextField(poa.getStreet());
            jTextFieldStreet.setEnabled(false);
            jTextFieldStreet.setDisabledTextColor(Color.BLACK);

            LDataType ldataType = uidData.getLData();
            if (ldataType != null) {
                String languageCode = ldataType.getLang();
                Font localeFont = new Font("Tahoma", Font.PLAIN, 12);
                if (languageCode != null) {
                    String fontName = LanguageCodeFontStore
                            .getFontNameByLanguageCode(languageCode);
                    System.out.println(fontName);
                    localeFont = new Font(fontName, Font.PLAIN, 12);
                }

                jLabelangCo = new javax.swing.JLabel("Language Code");
                jTextFieldlangCo = new javax.swing.JTextField(ldataType
                        .getLang());
                jTextFieldlangCo.setEnabled(false);
                jTextFieldlangCo.setDisabledTextColor(Color.BLACK);
                jLabellangName = new javax.swing.JLabel("Resident Name");
                jTextFieldlangName = new javax.swing.JTextField();
                jTextFieldlangName.setFont(localeFont);
                jTextFieldlangName.setText(ldataType.getName());
                jTextFieldlangName.setEnabled(false);
                jTextFieldlangName.setDisabledTextColor(Color.BLACK);

                jLabellaCo = new javax.swing.JLabel("Care of");
                jTextFieldlaCo = new javax.swing.JTextField(ldataType.getCo());
                jTextFieldlaCo.setFont(localeFont);
                jTextFieldlaCo.setEnabled(false);
                jTextFieldlaCo.setDisabledTextColor(Color.BLACK);
                jLabellangHouse = new javax.swing.JLabel("House no");
                jTextFieldlangHouse = new javax.swing.JTextField(ldataType
                        .getHouse());
                jTextFieldlangHouse.setFont(localeFont);
                jTextFieldlangHouse.setEnabled(false);
                jTextFieldlangHouse.setDisabledTextColor(Color.BLACK);
                jLabellangLm = new javax.swing.JLabel("Landmark");
                jTextFieldlangLm = new javax.swing.JTextField(ldataType.getLm());
                jTextFieldlangLm.setFont(localeFont);
                jTextFieldlangLm.setEnabled(false);
                jTextFieldlangLm.setDisabledTextColor(Color.BLACK);
                jLabellangLc = new javax.swing.JLabel("Locality");
                jTextFieldlangLc = new javax.swing.JTextField(ldataType.getLoc());
                jTextFieldlangLc.setFont(localeFont);
                jTextFieldlangLc.setEnabled(false);
                jTextFieldlangLc.setDisabledTextColor(Color.BLACK);
                jLabellangVtc = new javax.swing.JLabel("Vtc");
                jTextFieldlangVtc = new javax.swing.JTextField(ldataType
                        .getVtc());
                jTextFieldlangVtc.setFont(localeFont);
                jTextFieldlangVtc.setEnabled(false);
                jTextFieldlangVtc.setDisabledTextColor(Color.BLACK);
                jLabellangSubDist = new javax.swing.JLabel("Sub district");
                jTextFieldlangSubDist = new javax.swing.JTextField(ldataType
                        .getSubdist());
                jTextFieldlangSubDist.setFont(localeFont);
                jTextFieldlangSubDist.setEnabled(false);
                jTextFieldlangSubDist.setDisabledTextColor(Color.BLACK);
                jLabellangDist = new javax.swing.JLabel("District");
                jTextFieldlangDist = new javax.swing.JTextField(ldataType
                        .getDist());
                jTextFieldlangDist.setFont(localeFont);
                jTextFieldlangDist.setEnabled(false);
                jTextFieldlangDist.setDisabledTextColor(Color.BLACK);
                jLabellangState = new javax.swing.JLabel("State");
                jTextFieldlangState = new javax.swing.JTextField(ldataType
                        .getState());
                jTextFieldlangState.setFont(localeFont);
                jTextFieldlangState.setEnabled(false);
                jTextFieldlangState.setDisabledTextColor(Color.BLACK);
                jLabellangPc = new javax.swing.JLabel("Pincode");
                jTextFieldlangPc = new javax.swing.JTextField(ldataType.getPc());
                jTextFieldlangPc.setFont(localeFont);
                jTextFieldlangPc.setEnabled(false);
                jTextFieldlangPc.setDisabledTextColor(Color.BLACK);
                jLabellangPo = new javax.swing.JLabel("PostOffice");
                jTextFieldlangPo = new javax.swing.JTextField(ldataType.getPo());
                jTextFieldlangPo.setFont(localeFont);
                jTextFieldlangPo.setEnabled(false);
                jTextFieldlangPo.setDisabledTextColor(Color.BLACK);
                jLabellangStreet = new javax.swing.JLabel("Street");
                jTextFieldlangStreet = new javax.swing.JTextField(ldataType
                        .getStreet());
                jTextFieldlangStreet.setFont(localeFont);
                jTextFieldlangStreet.setEnabled(false);
                jTextFieldlangStreet.setDisabledTextColor(Color.BLACK);
            }
            saveAsButton = new JButton("Save as");
            // Action Listener for Save as feature.
            saveAsButton.addActionListener(new ActionListener() {
                @Override
                public void actionPerformed(ActionEvent e) {
                    processSaveAs();
                }
            });

            jComboSaveFileType = new JComboBox(saveFileTypes);

            byte[] photo = uidData.getPht();
            readImage(photo);

        }
        jPanelPhoto = new PhotoDisplayPanel(image);
        jPanelPhoto.setBackground(new java.awt.Color(255, 255, 255));
        jPanelPhoto.setBorder(javax.swing.BorderFactory.createTitledBorder(
                null, "Photo",
                javax.swing.border.TitledBorder.DEFAULT_JUSTIFICATION,
                javax.swing.border.TitledBorder.DEFAULT_POSITION,
                new java.awt.Font("Tahoma", 1, 10))); // NOI18N

        jPanelPOIDetails = new javax.swing.JPanel();
        jPanelPOIDetails.setBackground(new java.awt.Color(255, 255, 255));
        jPanelPOIDetails.setBorder(javax.swing.BorderFactory
                .createTitledBorder(null, "Identity",
                        javax.swing.border.TitledBorder.DEFAULT_JUSTIFICATION,
                        javax.swing.border.TitledBorder.DEFAULT_POSITION,
                        new java.awt.Font("Tahoma", 1, 10))); // NOI18N

        jPanelPoi = new javax.swing.JPanel();
        jPanelPoi.setBackground(new java.awt.Color(255, 255, 255));
        jPanelPoi.setBorder(javax.swing.BorderFactory.createTitledBorder(null,
                "POI ", javax.swing.border.TitledBorder.DEFAULT_JUSTIFICATION,
                javax.swing.border.TitledBorder.DEFAULT_POSITION,
                new java.awt.Font("Tahoma", 1, 10))); // NOI18N

        jFrameAddressDetails = new javax.swing.JPanel();
        jFrameAddressDetails.setBackground(new java.awt.Color(255, 255, 255));
        jFrameAddressDetails.setBorder(javax.swing.BorderFactory
                .createTitledBorder(null, "POA ",
                        javax.swing.border.TitledBorder.DEFAULT_JUSTIFICATION,
                        javax.swing.border.TitledBorder.DEFAULT_POSITION,
                        new java.awt.Font("Tahoma", 1, 10))); // NOI18N

        jFramelangAddressDetails = new javax.swing.JPanel();
        jFramelangAddressDetails
                .setBackground(new java.awt.Color(255, 255, 255));
        jFramelangAddressDetails.setBorder(javax.swing.BorderFactory
                .createTitledBorder(null, "Local Language ",
                        javax.swing.border.TitledBorder.DEFAULT_JUSTIFICATION,
                        javax.swing.border.TitledBorder.DEFAULT_POSITION,
                        new java.awt.Font("Tahoma", 1, 10))); // NOI18N

        // Action buttons
        jPanelActionButtons = new JPanel();
        jPanelActionButtons.setBackground(new Color(255, 255, 255));

        jFrameResponseDetails = new javax.swing.JPanel();
        jFrameResponseDetails.setBackground(new java.awt.Color(255, 255, 255));
        jFrameResponseDetails.setBorder(javax.swing.BorderFactory
                .createTitledBorder(null, "Response Details ",
                        javax.swing.border.TitledBorder.DEFAULT_JUSTIFICATION,
                        javax.swing.border.TitledBorder.DEFAULT_POSITION,
                        new java.awt.Font("Tahoma", 1, 10))); // NOI18N

        jFrameUID = new javax.swing.JPanel();
        jFrameUID.setBackground(new java.awt.Color(255, 255, 255));
        jFrameUID.setBorder(javax.swing.BorderFactory.createTitledBorder(null,
                "Aadhaar Number ",
                javax.swing.border.TitledBorder.DEFAULT_JUSTIFICATION,
                javax.swing.border.TitledBorder.DEFAULT_POSITION,
                new java.awt.Font("Tahoma", 1, 10))); // NOI18N

        jPanelUID = new javax.swing.JPanel();
        jPanelUID.setBackground(new java.awt.Color(255, 255, 255));
        jPanelUID.setBorder(javax.swing.BorderFactory.createTitledBorder(null,
                "POI", javax.swing.border.TitledBorder.DEFAULT_JUSTIFICATION,
                javax.swing.border.TitledBorder.DEFAULT_POSITION,
                new java.awt.Font("Tahoma", 1, 10))); // NOI18N

    }

    private void processSaveAs() {
        System.out.println("saved..");
        // JLabel label = new JLabel();
        // final JComponent inputs[] = new JComponent[]{label};
        // JOptionPane.showMessageDialog(aWindow,inputs,"KYC Demo Client:Save as",JOptionPane.PLAIN_MESSAGE);

        JFileChooser fileChooser = new JFileChooser();
        String selectFileType = saveFileTypes[jComboSaveFileType
                .getSelectedIndex()];
        File toSavefile = new File(uid + "." + selectFileType.toLowerCase());
        fileChooser.setSelectedFile(toSavefile);
        int returnValue = fileChooser.showSaveDialog(aWindow);
        if (returnValue == JFileChooser.APPROVE_OPTION) {
            File file = fileChooser.getSelectedFile();
            try {
                saveFile(file, selectFileType.toLowerCase());
                JOptionPane.showMessageDialog(aWindow, "Saved succesfully",
                        "KYC Demo Client", JOptionPane.INFORMATION_MESSAGE);
            } catch (IOException e) {
                e.printStackTrace();
                JOptionPane.showMessageDialog(aWindow,
                        "Saving file to system has issue",
                        "KYC Demo Client:Error", JOptionPane.ERROR_MESSAGE);
            } catch (ConverterNotFoundException e) {
                e.printStackTrace();
                JOptionPane.showMessageDialog(aWindow,
                        "This type of saving not yet supported",
                        "KYC Demo Client:Error", JOptionPane.ERROR_MESSAGE);
            } catch (Exception e) {
                e.printStackTrace();
                JOptionPane.showMessageDialog(aWindow, "Conversion Error",
                        "KYC Demo Client:Error", JOptionPane.ERROR_MESSAGE);
            }
        }
    }

    private void saveFile(File toSaveFile, String fileType) throws Exception {
        throw new ConverterNotFoundException();
    }

    private void init() {
        javax.swing.GroupLayout jPanelPOIDetailsLayout = new javax.swing.GroupLayout(
                jPanelPOIDetails);
        jPanelPOIDetails.setLayout(jPanelPOIDetailsLayout);
        jPanelPOIDetailsLayout
                .setHorizontalGroup(jPanelPOIDetailsLayout
                        .createParallelGroup(
                                javax.swing.GroupLayout.Alignment.LEADING)
                        .addGroup(
                                jPanelPOIDetailsLayout
                                        .createSequentialGroup()
                                        .addGroup(
                                                jPanelPOIDetailsLayout
                                                        .createParallelGroup(
                                                                javax.swing.GroupLayout.Alignment.TRAILING)
                                                        .addComponent(
                                                                jLabelName)
                                                        .addComponent(jLabelDOB)
                                                        .addComponent(
                                                                jLabelGender)
                                                        .addComponent(
                                                                jLabelMobile)
                                                        .addComponent(
                                                                jLabelEmail))
                                        .addPreferredGap(
                                                javax.swing.LayoutStyle.ComponentPlacement.RELATED)
                                        .addGroup(
                                                jPanelPOIDetailsLayout
                                                        .createParallelGroup(
                                                                javax.swing.GroupLayout.Alignment.LEADING)
                                                        .addComponent(
                                                                jTextFieldName,
                                                                javax.swing.GroupLayout.PREFERRED_SIZE,
                                                                400,
                                                                javax.swing.GroupLayout.PREFERRED_SIZE)
                                                        .addComponent(
                                                                jTextFieldDOB,
                                                                javax.swing.GroupLayout.PREFERRED_SIZE,
                                                                400,
                                                                javax.swing.GroupLayout.PREFERRED_SIZE)
                                                        .addComponent(
                                                                jTextFieldGender,
                                                                javax.swing.GroupLayout.PREFERRED_SIZE,
                                                                400,
                                                                javax.swing.GroupLayout.PREFERRED_SIZE)
                                                        .addComponent(
                                                                jTextFieldMobile,
                                                                javax.swing.GroupLayout.PREFERRED_SIZE,
                                                                400,
                                                                javax.swing.GroupLayout.PREFERRED_SIZE)
                                                        .addComponent(
                                                                jTextFieldEmail,
                                                                javax.swing.GroupLayout.PREFERRED_SIZE,
                                                                400,
                                                                javax.swing.GroupLayout.PREFERRED_SIZE))
                                        .addPreferredGap(
                                                javax.swing.LayoutStyle.ComponentPlacement.RELATED)));

        jPanelPOIDetailsLayout
                .setVerticalGroup(jPanelPOIDetailsLayout
                        .createParallelGroup(
                                javax.swing.GroupLayout.Alignment.LEADING)
                        .addGroup(
                                jPanelPOIDetailsLayout
                                        .createSequentialGroup()
                                        .addGroup(
                                                jPanelPOIDetailsLayout
                                                        .createParallelGroup(
                                                                javax.swing.GroupLayout.Alignment.BASELINE)
                                                        .addComponent(
                                                                jTextFieldName,
                                                                javax.swing.GroupLayout.PREFERRED_SIZE,
                                                                javax.swing.GroupLayout.DEFAULT_SIZE,
                                                                javax.swing.GroupLayout.PREFERRED_SIZE)
                                                        .addComponent(
                                                                jLabelName))
                                        .addGap(5, 5, 5)
                                        .addPreferredGap(
                                                javax.swing.LayoutStyle.ComponentPlacement.RELATED)
                                        .addGroup(
                                                jPanelPOIDetailsLayout
                                                        .createParallelGroup(
                                                                javax.swing.GroupLayout.Alignment.BASELINE)
                                                        .addComponent(
                                                                jTextFieldDOB,
                                                                javax.swing.GroupLayout.PREFERRED_SIZE,
                                                                javax.swing.GroupLayout.DEFAULT_SIZE,
                                                                javax.swing.GroupLayout.PREFERRED_SIZE)
                                                        .addComponent(jLabelDOB))
                                        .addGap(5, 5, 5)
                                        .addPreferredGap(
                                                javax.swing.LayoutStyle.ComponentPlacement.RELATED)
                                        .addGroup(
                                                jPanelPOIDetailsLayout
                                                        .createParallelGroup(
                                                                javax.swing.GroupLayout.Alignment.BASELINE)
                                                        .addComponent(
                                                                jTextFieldGender,
                                                                javax.swing.GroupLayout.PREFERRED_SIZE,
                                                                javax.swing.GroupLayout.DEFAULT_SIZE,
                                                                javax.swing.GroupLayout.PREFERRED_SIZE)
                                                        .addComponent(
                                                                jLabelGender))
                                        .addGap(5, 5, 5)
                                        .addPreferredGap(
                                                javax.swing.LayoutStyle.ComponentPlacement.RELATED)
                                        .addGroup(
                                                jPanelPOIDetailsLayout
                                                        .createParallelGroup(
                                                                javax.swing.GroupLayout.Alignment.BASELINE)
                                                        .addComponent(
                                                                jTextFieldMobile,
                                                                javax.swing.GroupLayout.PREFERRED_SIZE,
                                                                javax.swing.GroupLayout.DEFAULT_SIZE,
                                                                javax.swing.GroupLayout.PREFERRED_SIZE)
                                                        .addComponent(
                                                                jLabelMobile))
                                        .addGap(5, 5, 5)
                                        .addPreferredGap(
                                                javax.swing.LayoutStyle.ComponentPlacement.RELATED)
                                        .addGroup(
                                                jPanelPOIDetailsLayout
                                                        .createParallelGroup(
                                                                javax.swing.GroupLayout.Alignment.BASELINE)
                                                        .addComponent(
                                                                jTextFieldEmail,
                                                                javax.swing.GroupLayout.PREFERRED_SIZE,
                                                                javax.swing.GroupLayout.DEFAULT_SIZE,
                                                                javax.swing.GroupLayout.PREFERRED_SIZE)
                                                        .addComponent(
                                                                jLabelEmail))
                                        .addGap(5, 5, 5)
                                        .addPreferredGap(
                                                javax.swing.LayoutStyle.ComponentPlacement.RELATED)
                                        ./*addContainerGap()*/addGap(5, 5, 5)));

        javax.swing.GroupLayout jPanelUidLayout = new javax.swing.GroupLayout(
                jFrameUID);
        jFrameUID.setLayout(jPanelUidLayout);
        jPanelUidLayout.setHorizontalGroup(jPanelUidLayout.createParallelGroup(
                javax.swing.GroupLayout.Alignment.LEADING).addGroup(
                        jPanelUidLayout.createSequentialGroup().addGap(5, 5, 5)
                                .addComponent(jLabelUID).addGap(5, 5, 5)));
        jPanelUidLayout.setVerticalGroup(jPanelUidLayout.createParallelGroup(
                javax.swing.GroupLayout.Alignment.LEADING).addGroup(
                        jPanelUidLayout.createSequentialGroup().addGroup(
                                jPanelUidLayout.createParallelGroup(
                                        javax.swing.GroupLayout.Alignment.LEADING)
                                        .addComponent(jLabelUID))));

        javax.swing.GroupLayout jPanelUIDLayout = new javax.swing.GroupLayout(
                jPanelUID);
        jPanelUID.setLayout(jPanelUIDLayout);
        jPanelUIDLayout.setHorizontalGroup(jPanelUIDLayout
                .createParallelGroup(
                        javax.swing.GroupLayout.Alignment.LEADING).addGroup(
                        jPanelUIDLayout.createSequentialGroup().addGroup(
                                jPanelUIDLayout.createParallelGroup(
                                        javax.swing.GroupLayout.Alignment.CENTER)
                                        .addComponent(jFrameUID).addComponent(
                                        jPanelPOIDetails)).addContainerGap()));

        jPanelUIDLayout
                .setVerticalGroup(jPanelUIDLayout
                        .createParallelGroup(
                                javax.swing.GroupLayout.Alignment.LEADING)
                        .addGroup(
                                jPanelUIDLayout
                                        .createSequentialGroup()
                                        .addGroup(
                                                jPanelUIDLayout
                                                        .createParallelGroup(
                                                                javax.swing.GroupLayout.Alignment.CENTER)
                                                        .addComponent(jFrameUID))
                                        .addGap(5, 5, 5)
                                        .addGroup(
                                                jPanelUIDLayout
                                                        .createParallelGroup(
                                                                javax.swing.GroupLayout.Alignment.LEADING)
                                                        .addComponent(
                                                                jPanelPOIDetails))
                                        .addGap(5, 5, 5)));

        javax.swing.GroupLayout jPanelPoiLayout = new javax.swing.GroupLayout(
                jPanelPoi);
        jPanelPoi.setLayout(jPanelPoiLayout);
        jPanelPoiLayout
                .setHorizontalGroup(jPanelPoiLayout
                        .createParallelGroup(
                                javax.swing.GroupLayout.Alignment.TRAILING)
                        .addGroup(
                                jPanelPoiLayout
                                        .createSequentialGroup()
                                        /*.addContainerGap()*/
                                        .addGap(1, 1, 1)
                                        .addComponent(jPanelPhoto)
                                        .addPreferredGap(
                                                javax.swing.LayoutStyle.ComponentPlacement.UNRELATED)
                                        .addComponent(jPanelUID)
                                        .addContainerGap()));
        jPanelPoiLayout.setVerticalGroup(jPanelPoiLayout.createParallelGroup(
                javax.swing.GroupLayout.Alignment.LEADING).addGroup(
                        jPanelPoiLayout.createSequentialGroup().addGroup(
                                jPanelPoiLayout.createParallelGroup(
                                        javax.swing.GroupLayout.Alignment.BASELINE).addGap(1, 1, 1)
                                        .addComponent(jPanelPhoto).addComponent(
                                        jPanelUID)).addGap(1, 1, 1)/*addPreferredGap(
						javax.swing.LayoutStyle.ComponentPlacement.RELATED)*/));

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
                                                                jLabelDist)
                                                        .addComponent(jLabelCo)
                                                        .addComponent(jLabelLm)
                                                        .addComponent(jLabelLc)
                                                        .addComponent(jLabelVtc))
                                        .addPreferredGap(
                                                javax.swing.LayoutStyle.ComponentPlacement.RELATED)
                                        .addGroup(
                                                jFrameAddressDetailsLayout
                                                        .createParallelGroup(
                                                                javax.swing.GroupLayout.Alignment.LEADING)
                                                        .addComponent(
                                                                jTextFieldDist,
                                                                javax.swing.GroupLayout.Alignment.TRAILING,
                                                                javax.swing.GroupLayout.DEFAULT_SIZE,
                                                                214,
                                                                Short.MAX_VALUE)
                                                        .addComponent(
                                                                jTextFieldCo,
                                                                javax.swing.GroupLayout.DEFAULT_SIZE,
                                                                300,
                                                                Short.MAX_VALUE)
                                                        .addComponent(
                                                                jTextFieldLm,
                                                                javax.swing.GroupLayout.DEFAULT_SIZE,
                                                                300,
                                                                Short.MAX_VALUE)
                                                        .addComponent(
                                                                jTextFieldLc,
                                                                javax.swing.GroupLayout.DEFAULT_SIZE,
                                                                300,
                                                                Short.MAX_VALUE)
                                                        .addComponent(
                                                                jTextFieldVtc,
                                                                javax.swing.GroupLayout.DEFAULT_SIZE,
                                                                300,
                                                                Short.MAX_VALUE))
                                        .addGroup(
                                                jFrameAddressDetailsLayout
                                                        .createParallelGroup(
                                                                javax.swing.GroupLayout.Alignment.LEADING)
                                                        .addGroup(
                                                                jFrameAddressDetailsLayout
                                                                        .createSequentialGroup()
                                                                        .addGap(
                                                                                5,
                                                                                5,
                                                                                5)
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
                                                                                                                                jLabelHouse)
                                                                                                                        .addComponent(
                                                                                                                                jLabelPo))
                                                                                                        .addPreferredGap(
                                                                                                                javax.swing.LayoutStyle.ComponentPlacement.RELATED)))
                                                                        .addGroup(
                                                                                jFrameAddressDetailsLayout
                                                                                        .createParallelGroup(
                                                                                                javax.swing.GroupLayout.Alignment.LEADING)
                                                                                        .addComponent(
                                                                                                jTextFieldStreet,
                                                                                                javax.swing.GroupLayout.DEFAULT_SIZE,
                                                                                                300,
                                                                                                Short.MAX_VALUE)
                                                                                        .addGroup(
                                                                                                javax.swing.GroupLayout.Alignment.TRAILING,
                                                                                                jFrameAddressDetailsLayout
                                                                                                        .createSequentialGroup()
                                                                                                        .addComponent(
                                                                                                                jTextFieldState,
                                                                                                                javax.swing.GroupLayout.PREFERRED_SIZE,
                                                                                                                150,
                                                                                                                javax.swing.GroupLayout.PREFERRED_SIZE)
                                                                                                        .addPreferredGap(
                                                                                                                javax.swing.LayoutStyle.ComponentPlacement.UNRELATED)
                                                                                                        .addComponent(
                                                                                                                jLabelPc)
                                                                                                        .addPreferredGap(
                                                                                                                javax.swing.LayoutStyle.ComponentPlacement.RELATED)
                                                                                                        .addComponent(
                                                                                                                jTextFieldPc,
                                                                                                                javax.swing.GroupLayout.PREFERRED_SIZE,
                                                                                                                120,
                                                                                                                javax.swing.GroupLayout.PREFERRED_SIZE))
                                                                                        .addComponent(
                                                                                                jTextFieldHouse,
                                                                                                javax.swing.GroupLayout.Alignment.TRAILING,
                                                                                                javax.swing.GroupLayout.DEFAULT_SIZE,
                                                                                                218,
                                                                                                Short.MAX_VALUE)
                                                                                        .addComponent(
                                                                                                jTextFieldPo,
                                                                                                javax.swing.GroupLayout.DEFAULT_SIZE,
                                                                                                300,
                                                                                                Short.MAX_VALUE)))
                                                        .addGroup(
                                                                jFrameAddressDetailsLayout
                                                                        .createSequentialGroup()
                                                                        .addGap(
                                                                                5,
                                                                                5,
                                                                                5)
                                                                        .addComponent(
                                                                                jLabelSubDist)
                                                                        .addPreferredGap(
                                                                                javax.swing.LayoutStyle.ComponentPlacement.UNRELATED)
                                                                        .addComponent(
                                                                                jTextFieldSubDist,
                                                                                javax.swing.GroupLayout.DEFAULT_SIZE,
                                                                                300,
                                                                                Short.MAX_VALUE)))
                                        .addContainerGap()));
        jFrameAddressDetailsLayout
                .setVerticalGroup(jFrameAddressDetailsLayout
                        .createParallelGroup(
                                javax.swing.GroupLayout.Alignment.LEADING)
                        .addGroup(
                                jFrameAddressDetailsLayout
                                        .createSequentialGroup()
                                        /*.addContainerGap()*/
                                        .addGap(1, 1, 1)
                                        .addGroup(
                                                jFrameAddressDetailsLayout
                                                        .createParallelGroup(
                                                                javax.swing.GroupLayout.Alignment.BASELINE)
                                                        .addComponent(
                                                                jTextFieldCo,
                                                                javax.swing.GroupLayout.PREFERRED_SIZE,
                                                                javax.swing.GroupLayout.DEFAULT_SIZE,
                                                                javax.swing.GroupLayout.PREFERRED_SIZE)
                                                        .addComponent(jLabelCo)
                                                        .addComponent(
                                                                jTextFieldHouse,
                                                                javax.swing.GroupLayout.PREFERRED_SIZE,
                                                                javax.swing.GroupLayout.DEFAULT_SIZE,
                                                                javax.swing.GroupLayout.PREFERRED_SIZE)
                                                        .addComponent(
                                                                jLabelHouse))
                                        .addPreferredGap(
                                                javax.swing.LayoutStyle.ComponentPlacement.RELATED)
                                        .addGroup(
                                                jFrameAddressDetailsLayout
                                                        .createParallelGroup(
                                                                javax.swing.GroupLayout.Alignment.BASELINE)
                                                        .addComponent(jLabelLm)
                                                        .addComponent(
                                                                jTextFieldLm,
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
                                                        .addComponent(jLabelLc)
                                                        .addComponent(
                                                                jTextFieldLc,
                                                                javax.swing.GroupLayout.PREFERRED_SIZE,
                                                                javax.swing.GroupLayout.DEFAULT_SIZE,
                                                                javax.swing.GroupLayout.PREFERRED_SIZE)
                                                        .addComponent(jLabelPo)
                                                        .addComponent(
                                                                jTextFieldPo,
                                                                javax.swing.GroupLayout.PREFERRED_SIZE,
                                                                javax.swing.GroupLayout.DEFAULT_SIZE,
                                                                javax.swing.GroupLayout.PREFERRED_SIZE))
                                        .addPreferredGap(
                                                javax.swing.LayoutStyle.ComponentPlacement.RELATED)
                                        .addGroup(
                                                jFrameAddressDetailsLayout
                                                        .createParallelGroup(
                                                                javax.swing.GroupLayout.Alignment.BASELINE)
                                                        .addComponent(jLabelVtc)
                                                        .addComponent(
                                                                jTextFieldVtc,
                                                                javax.swing.GroupLayout.PREFERRED_SIZE,
                                                                javax.swing.GroupLayout.DEFAULT_SIZE,
                                                                javax.swing.GroupLayout.PREFERRED_SIZE)
                                                        .addComponent(
                                                                jLabelSubDist)
                                                        .addComponent(
                                                                jTextFieldSubDist,
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
                                                                jTextFieldPc,
                                                                javax.swing.GroupLayout.PREFERRED_SIZE,
                                                                javax.swing.GroupLayout.DEFAULT_SIZE,
                                                                javax.swing.GroupLayout.PREFERRED_SIZE)
                                                        .addComponent(jLabelPc)
                                                        .addComponent(
                                                                jTextFieldState,
                                                                javax.swing.GroupLayout.PREFERRED_SIZE,
                                                                javax.swing.GroupLayout.DEFAULT_SIZE,
                                                                javax.swing.GroupLayout.PREFERRED_SIZE)
                                                        .addComponent(
                                                                jLabelState)
                                                        .addComponent(
                                                                jLabelDist)
                                                        .addComponent(
                                                                jTextFieldDist,
                                                                javax.swing.GroupLayout.PREFERRED_SIZE,
                                                                javax.swing.GroupLayout.DEFAULT_SIZE,
                                                                javax.swing.GroupLayout.PREFERRED_SIZE))
                                        .addGap(1, 1, 1)/*addContainerGap(
												javax.swing.GroupLayout.DEFAULT_SIZE,
												Short.MAX_VALUE)*/));

        // ********************************************Local lang
        // Details*******************************
        if (kycRes.getUidData() != null
                && kycRes.getUidData().getLData() != null) {

            javax.swing.GroupLayout jFramelangAddressDetailsLayout = new javax.swing.GroupLayout(
                    jFramelangAddressDetails);
            jFramelangAddressDetails.setLayout(jFramelangAddressDetailsLayout);
            jFramelangAddressDetailsLayout
                    .setHorizontalGroup(jFramelangAddressDetailsLayout
                            .createParallelGroup(
                                    javax.swing.GroupLayout.Alignment.LEADING)
                            .addGroup(
                                    jFramelangAddressDetailsLayout
                                            .createSequentialGroup()
                                            .addContainerGap()
                                            /*.addGap(1,1,1)*/
                                            .addGroup(
                                                    jFramelangAddressDetailsLayout
                                                            .createParallelGroup(
                                                                    javax.swing.GroupLayout.Alignment.TRAILING)
                                                            .addComponent(
                                                                    jLabellangDist)
                                                            .addComponent(
                                                                    jLabelangCo)
                                                            .addComponent(
                                                                    jLabellaCo)
                                                            .addComponent(
                                                                    jLabellangLm)
                                                            .addComponent(
                                                                    jLabellangLc)
                                                            .addComponent(
                                                                    jLabellangVtc))
                                            .addPreferredGap(
                                                    javax.swing.LayoutStyle.ComponentPlacement.RELATED)
                                            .addGroup(
                                                    jFramelangAddressDetailsLayout
                                                            .createParallelGroup(
                                                                    javax.swing.GroupLayout.Alignment.LEADING)
                                                            .addComponent(
                                                                    jTextFieldlangDist,
                                                                    javax.swing.GroupLayout.Alignment.TRAILING,
                                                                    javax.swing.GroupLayout.DEFAULT_SIZE,
                                                                    214,
                                                                    Short.MAX_VALUE)
                                                            .addComponent(
                                                                    jTextFieldlangCo,
                                                                    javax.swing.GroupLayout.DEFAULT_SIZE,
                                                                    300,
                                                                    Short.MAX_VALUE)
                                                            .addComponent(
                                                                    jTextFieldlaCo,
                                                                    javax.swing.GroupLayout.DEFAULT_SIZE,
                                                                    300,
                                                                    Short.MAX_VALUE)
                                                            .addComponent(
                                                                    jTextFieldlangLm,
                                                                    javax.swing.GroupLayout.DEFAULT_SIZE,
                                                                    300,
                                                                    Short.MAX_VALUE)
                                                            .addComponent(
                                                                    jTextFieldlangLc,
                                                                    javax.swing.GroupLayout.DEFAULT_SIZE,
                                                                    300,
                                                                    Short.MAX_VALUE)
                                                            .addComponent(
                                                                    jTextFieldlangVtc,
                                                                    javax.swing.GroupLayout.DEFAULT_SIZE,
                                                                    300,
                                                                    Short.MAX_VALUE))
                                            .addGroup(
                                                    jFramelangAddressDetailsLayout
                                                            .createParallelGroup(
                                                                    javax.swing.GroupLayout.Alignment.LEADING)
                                                            .addGroup(
                                                                    jFramelangAddressDetailsLayout
                                                                            .createSequentialGroup()
                                                                            .addGap(
                                                                                    5,
                                                                                    5,
                                                                                    5)
                                                                            .addGroup(
                                                                                    jFramelangAddressDetailsLayout
                                                                                            .createParallelGroup(
                                                                                                    javax.swing.GroupLayout.Alignment.LEADING)
                                                                                            .addComponent(
                                                                                                    jLabellangState,
                                                                                                    javax.swing.GroupLayout.Alignment.TRAILING)
                                                                                            .addGroup(
                                                                                                    javax.swing.GroupLayout.Alignment.TRAILING,
                                                                                                    jFramelangAddressDetailsLayout
                                                                                                            .createSequentialGroup()
                                                                                                            .addGroup(
                                                                                                                    jFramelangAddressDetailsLayout
                                                                                                                            .createParallelGroup(
                                                                                                                                    javax.swing.GroupLayout.Alignment.TRAILING)
                                                                                                                            .addComponent(
                                                                                                                                    jLabellangStreet)
                                                                                                                            .addComponent(
                                                                                                                                    jLabellangHouse)
                                                                                                                            .addComponent(
                                                                                                                                    jLabellangName)
                                                                                                                            .addComponent(
                                                                                                                                    jLabellangPo))
                                                                                                            .addPreferredGap(
                                                                                                                    javax.swing.LayoutStyle.ComponentPlacement.RELATED)))
                                                                            .addGroup(
                                                                                    jFramelangAddressDetailsLayout
                                                                                            .createParallelGroup(
                                                                                                    javax.swing.GroupLayout.Alignment.LEADING)
                                                                                            .addComponent(
                                                                                                    jTextFieldlangStreet,
                                                                                                    javax.swing.GroupLayout.DEFAULT_SIZE,
                                                                                                    300,
                                                                                                    Short.MAX_VALUE)
                                                                                            .addGroup(
                                                                                                    javax.swing.GroupLayout.Alignment.TRAILING,
                                                                                                    jFramelangAddressDetailsLayout
                                                                                                            .createSequentialGroup()
                                                                                                            .addComponent(
                                                                                                                    jTextFieldlangState,
                                                                                                                    javax.swing.GroupLayout.PREFERRED_SIZE,
                                                                                                                    150,
                                                                                                                    javax.swing.GroupLayout.PREFERRED_SIZE)
                                                                                                            .addPreferredGap(
                                                                                                                    javax.swing.LayoutStyle.ComponentPlacement.UNRELATED)
                                                                                                            .addComponent(
                                                                                                                    jLabellangPc)
                                                                                                            .addPreferredGap(
                                                                                                                    javax.swing.LayoutStyle.ComponentPlacement.RELATED)
                                                                                                            .addComponent(
                                                                                                                    jTextFieldlangPc,
                                                                                                                    javax.swing.GroupLayout.PREFERRED_SIZE,
                                                                                                                    120,
                                                                                                                    javax.swing.GroupLayout.PREFERRED_SIZE))
                                                                                            .addComponent(
                                                                                                    jTextFieldlangHouse,
                                                                                                    javax.swing.GroupLayout.Alignment.TRAILING,
                                                                                                    javax.swing.GroupLayout.DEFAULT_SIZE,
                                                                                                    218,
                                                                                                    Short.MAX_VALUE)
                                                                                            .addComponent(
                                                                                                    jTextFieldlangName,
                                                                                                    javax.swing.GroupLayout.Alignment.TRAILING,
                                                                                                    javax.swing.GroupLayout.DEFAULT_SIZE,
                                                                                                    218,
                                                                                                    Short.MAX_VALUE)
                                                                                            .addComponent(
                                                                                                    jTextFieldlangPo,
                                                                                                    javax.swing.GroupLayout.DEFAULT_SIZE,
                                                                                                    300,
                                                                                                    Short.MAX_VALUE)))
                                                            .addGroup(
                                                                    jFramelangAddressDetailsLayout
                                                                            .createSequentialGroup()
                                                                            .addGap(
                                                                                    5,
                                                                                    5,
                                                                                    5)
                                                                            .addComponent(
                                                                                    jLabellangSubDist)
                                                                            .addPreferredGap(
                                                                                    javax.swing.LayoutStyle.ComponentPlacement.UNRELATED)
                                                                            .addComponent(
                                                                                    jTextFieldlangSubDist,
                                                                                    javax.swing.GroupLayout.DEFAULT_SIZE,
                                                                                    300,
                                                                                    Short.MAX_VALUE)))
                                            .addContainerGap()));
            jFramelangAddressDetailsLayout
                    .setVerticalGroup(jFramelangAddressDetailsLayout
                            .createParallelGroup(
                                    javax.swing.GroupLayout.Alignment.LEADING)
                            .addGroup(
                                    jFramelangAddressDetailsLayout
                                            .createSequentialGroup()
                                            /*.addContainerGap()*/
                                            .addGap(1, 1, 1)
                                            .addGroup(
                                                    jFramelangAddressDetailsLayout
                                                            .createParallelGroup(
                                                                    javax.swing.GroupLayout.Alignment.BASELINE)
                                                            .addComponent(
                                                                    jTextFieldlangCo,
                                                                    javax.swing.GroupLayout.PREFERRED_SIZE,
                                                                    javax.swing.GroupLayout.DEFAULT_SIZE,
                                                                    javax.swing.GroupLayout.PREFERRED_SIZE)
                                                            .addComponent(
                                                                    jLabelangCo)
                                                            .addComponent(
                                                                    jTextFieldlangName,
                                                                    javax.swing.GroupLayout.PREFERRED_SIZE,
                                                                    javax.swing.GroupLayout.DEFAULT_SIZE,
                                                                    javax.swing.GroupLayout.PREFERRED_SIZE)
                                                            .addComponent(
                                                                    jLabellangName))
                                            .addPreferredGap(
                                                    javax.swing.LayoutStyle.ComponentPlacement.RELATED)
                                            .addGroup(
                                                    jFramelangAddressDetailsLayout
                                                            .createParallelGroup(
                                                                    javax.swing.GroupLayout.Alignment.BASELINE)
                                                            .addComponent(
                                                                    jTextFieldlaCo,
                                                                    javax.swing.GroupLayout.PREFERRED_SIZE,
                                                                    javax.swing.GroupLayout.DEFAULT_SIZE,
                                                                    javax.swing.GroupLayout.PREFERRED_SIZE)
                                                            .addComponent(
                                                                    jLabellaCo)
                                                            .addComponent(
                                                                    jTextFieldlangHouse,
                                                                    javax.swing.GroupLayout.PREFERRED_SIZE,
                                                                    javax.swing.GroupLayout.DEFAULT_SIZE,
                                                                    javax.swing.GroupLayout.PREFERRED_SIZE)
                                                            .addComponent(
                                                                    jLabellangHouse))
                                            .addPreferredGap(
                                                    javax.swing.LayoutStyle.ComponentPlacement.RELATED)
                                            .addGroup(
                                                    jFramelangAddressDetailsLayout
                                                            .createParallelGroup(
                                                                    javax.swing.GroupLayout.Alignment.BASELINE)
                                                            .addComponent(
                                                                    jLabellangLm)
                                                            .addComponent(
                                                                    jTextFieldlangLm,
                                                                    javax.swing.GroupLayout.PREFERRED_SIZE,
                                                                    javax.swing.GroupLayout.DEFAULT_SIZE,
                                                                    javax.swing.GroupLayout.PREFERRED_SIZE)
                                                            .addComponent(
                                                                    jTextFieldlangStreet,
                                                                    javax.swing.GroupLayout.PREFERRED_SIZE,
                                                                    javax.swing.GroupLayout.DEFAULT_SIZE,
                                                                    javax.swing.GroupLayout.PREFERRED_SIZE)
                                                            .addComponent(
                                                                    jLabellangStreet))
                                            .addPreferredGap(
                                                    javax.swing.LayoutStyle.ComponentPlacement.RELATED)
                                            .addGroup(
                                                    jFramelangAddressDetailsLayout
                                                            .createParallelGroup(
                                                                    javax.swing.GroupLayout.Alignment.BASELINE)
                                                            .addComponent(
                                                                    jLabellangLc)
                                                            .addComponent(
                                                                    jTextFieldlangLc,
                                                                    javax.swing.GroupLayout.PREFERRED_SIZE,
                                                                    javax.swing.GroupLayout.DEFAULT_SIZE,
                                                                    javax.swing.GroupLayout.PREFERRED_SIZE)
                                                            .addComponent(
                                                                    jLabellangPo)
                                                            .addComponent(
                                                                    jTextFieldlangPo,
                                                                    javax.swing.GroupLayout.PREFERRED_SIZE,
                                                                    javax.swing.GroupLayout.DEFAULT_SIZE,
                                                                    javax.swing.GroupLayout.PREFERRED_SIZE))
                                            .addPreferredGap(
                                                    javax.swing.LayoutStyle.ComponentPlacement.RELATED)
                                            .addGroup(
                                                    jFramelangAddressDetailsLayout
                                                            .createParallelGroup(
                                                                    javax.swing.GroupLayout.Alignment.BASELINE)
                                                            .addComponent(
                                                                    jLabellangVtc)
                                                            .addComponent(
                                                                    jTextFieldlangVtc,
                                                                    javax.swing.GroupLayout.PREFERRED_SIZE,
                                                                    javax.swing.GroupLayout.DEFAULT_SIZE,
                                                                    javax.swing.GroupLayout.PREFERRED_SIZE)
                                                            .addComponent(
                                                                    jLabellangSubDist)
                                                            .addComponent(
                                                                    jTextFieldlangSubDist,
                                                                    javax.swing.GroupLayout.PREFERRED_SIZE,
                                                                    javax.swing.GroupLayout.DEFAULT_SIZE,
                                                                    javax.swing.GroupLayout.PREFERRED_SIZE))
                                            .addPreferredGap(
                                                    javax.swing.LayoutStyle.ComponentPlacement.RELATED)
                                            .addGroup(
                                                    jFramelangAddressDetailsLayout
                                                            .createParallelGroup(
                                                                    javax.swing.GroupLayout.Alignment.BASELINE)
                                                            .addComponent(
                                                                    jTextFieldlangPc,
                                                                    javax.swing.GroupLayout.PREFERRED_SIZE,
                                                                    javax.swing.GroupLayout.DEFAULT_SIZE,
                                                                    javax.swing.GroupLayout.PREFERRED_SIZE)
                                                            .addComponent(
                                                                    jLabellangPc)
                                                            .addComponent(
                                                                    jTextFieldlangState,
                                                                    javax.swing.GroupLayout.PREFERRED_SIZE,
                                                                    javax.swing.GroupLayout.DEFAULT_SIZE,
                                                                    javax.swing.GroupLayout.PREFERRED_SIZE)
                                                            .addComponent(
                                                                    jLabellangState)
                                                            .addComponent(
                                                                    jLabellangDist)
                                                            .addComponent(
                                                                    jTextFieldlangDist,
                                                                    javax.swing.GroupLayout.PREFERRED_SIZE,
                                                                    javax.swing.GroupLayout.DEFAULT_SIZE,
                                                                    javax.swing.GroupLayout.PREFERRED_SIZE))
                                            /*.addContainerGap(
													javax.swing.GroupLayout.DEFAULT_SIZE,
													Short.MAX_VALUE)*/.addGap(1, 1, 1)));

        }
        // *************************************END*****************************************************

        // FIXME -- is this code required?
        javax.swing.GroupLayout jPanelResponseLayout = new javax.swing.GroupLayout(
                jFrameResponseDetails);
        jFrameResponseDetails.setLayout(jPanelResponseLayout);
        jPanelResponseLayout
                .setHorizontalGroup(jPanelResponseLayout
                        .createParallelGroup(
                                javax.swing.GroupLayout.Alignment.LEADING)
                        .addGroup(
                                jPanelResponseLayout.createSequentialGroup()
                                        .addContainerGap().addComponent(
                                                jFrameAddressDetails))
                        .addGap(24, 24, 24)
                        .addGroup(
                                jPanelResponseLayout.createSequentialGroup()
                                        .addContainerGap().addComponent(
                                                jFramelangAddressDetails))
                        .addGap(24, 24, 24)
                        .addGroup(
                                jPanelResponseLayout
                                        .createSequentialGroup()
                                        .addGroup(
                                                jPanelResponseLayout
                                                        .createParallelGroup(
                                                                javax.swing.GroupLayout.Alignment.LEADING)
                                                        .addComponent(jPanelPoi))
                                        .addContainerGap(
                                                javax.swing.GroupLayout.DEFAULT_SIZE,
                                                Short.MAX_VALUE)));
        jPanelResponseLayout
                .setVerticalGroup(jPanelResponseLayout
                        .createParallelGroup(
                                javax.swing.GroupLayout.Alignment.LEADING)
                        .addGroup(
                                jPanelResponseLayout
                                        .createSequentialGroup()
                                        .addGroup(
                                                jPanelResponseLayout
                                                        .createParallelGroup(
                                                                javax.swing.GroupLayout.Alignment.BASELINE)
                                                        .addComponent(
                                                                jFrameAddressDetails)
                                                        .addComponent(
                                                                jFramelangAddressDetails)
                                                        .addComponent(jPanelPoi))));
        // end FIXME -- is this code required?

        // action buttons
        GroupLayout jPanelActionButtonsLayout = new GroupLayout(
                jPanelActionButtons);
        jPanelActionButtons.setLayout(jPanelActionButtonsLayout);

        // horizontal group
        jPanelActionButtonsLayout
                .setHorizontalGroup(jPanelActionButtonsLayout
                        .createParallelGroup(GroupLayout.Alignment.TRAILING)
                        .addGroup(
                                jPanelActionButtonsLayout
                                        .createSequentialGroup()
                                        .addGap(50)
                                        .addComponent(jComboSaveFileType)
                                        .addPreferredGap(
                                                javax.swing.LayoutStyle.ComponentPlacement.RELATED,
                                                javax.swing.GroupLayout.DEFAULT_SIZE,
                                                Short.MAX_VALUE).addComponent(
                                                saveAsButton)));

        // vertical group
        jPanelActionButtonsLayout.setVerticalGroup(jPanelActionButtonsLayout
                .createParallelGroup(GroupLayout.Alignment.TRAILING).addGroup(
                jPanelActionButtonsLayout.createParallelGroup()
                        .addComponent(jComboSaveFileType).addComponent(
                        saveAsButton)));

        // action buttons end
        javax.swing.GroupLayout jPanelAddressLayout = new javax.swing.GroupLayout(
                jFrameResponseDetails);
        jFrameResponseDetails.setLayout(jPanelAddressLayout);
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
                                                        .addGap(50)
                                                        .addComponent(
                                                                jFramelangAddressDetails,
                                                                javax.swing.GroupLayout.PREFERRED_SIZE,
                                                                javax.swing.GroupLayout.DEFAULT_SIZE,
                                                                javax.swing.GroupLayout.PREFERRED_SIZE)
                                                        .addGap(50)
                                                        .addComponent(
                                                                jPanelActionButtons,
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
                                                                                                jPanelPoi))
                                                                        .addContainerGap()))));

        jPanelAddressLayout
                .setVerticalGroup(jPanelAddressLayout
                        .createParallelGroup(
                                javax.swing.GroupLayout.Alignment.LEADING)
                        .addGroup(
                                javax.swing.GroupLayout.Alignment.TRAILING,
                                jPanelAddressLayout
                                        .createSequentialGroup()
                                        .addComponent(
                                                jPanelPoi,
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
                                                                jFrameAddressDetails,
                                                                javax.swing.GroupLayout.PREFERRED_SIZE,
                                                                javax.swing.GroupLayout.DEFAULT_SIZE,
                                                                javax.swing.GroupLayout.PREFERRED_SIZE))
                                        .addGroup(
                                                jPanelAddressLayout
                                                        .createParallelGroup(
                                                                javax.swing.GroupLayout.Alignment.BASELINE)
                                                        .addComponent(
                                                                jFramelangAddressDetails,
                                                                javax.swing.GroupLayout.PREFERRED_SIZE,
                                                                javax.swing.GroupLayout.DEFAULT_SIZE,
                                                                javax.swing.GroupLayout.PREFERRED_SIZE))
                                        .addPreferredGap(
                                                javax.swing.LayoutStyle.ComponentPlacement.RELATED)
                                        .addGroup(
                                                jPanelAddressLayout
                                                        .createParallelGroup(
                                                                javax.swing.GroupLayout.Alignment.BASELINE)
                                                        .addComponent(
                                                                jPanelActionButtons,
                                                                javax.swing.GroupLayout.PREFERRED_SIZE,
                                                                javax.swing.GroupLayout.DEFAULT_SIZE,
                                                                javax.swing.GroupLayout.PREFERRED_SIZE))
                                        .addPreferredGap(
                                                javax.swing.LayoutStyle.ComponentPlacement.RELATED)));

        // aWindow.setBounds(250, 250, 865, 650);
        aWindow.setBounds(230, 230, 850, 730);
        aWindow.setResizable(true);
        aWindow.setDefaultCloseOperation(JFrame.HIDE_ON_CLOSE);
        /*aWindow.add(jFrameResponseDetails);
		aWindow.setResizable(true);
		aWindow.add(jFrameResponseDetails);
		scrollPane.setVerticalScrollBarPolicy(JScrollPane.VERTICAL_SCROLLBAR_ALWAYS); 
		scrollPane.getVerticalScrollBar().setUnitIncrement(15);
	    scrollPane.setViewportView(jFrameResponseDetails);
		aWindow.add(scrollPane);
		aWindow.pack();
         */
        aWindow.add(jFrameResponseDetails);
        aWindow.setLocationRelativeTo(null);
        aWindow.setVisible(true);

    }

    private void readImage(byte[] imageBytes) {
        //byte[] faceByteIso = org.apache.commons.codec.binary.Base64
        //	.decodeBase64(imageBytes);
        BufferedImage bufImage = null;
        try {
            if (bufImage == null) {
                byte[] faceByteIso = org.apache.commons.codec.binary.Base64.decodeBase64(imageBytes);
//				byte[] faceByteIso= imageBytes;
                bufImage = ImageIO.read(new ByteArrayInputStream(
                        imageBytes));
                this.image = bufImage.getScaledInstance(-1, 270,
                        Image.SCALE_AREA_AVERAGING);
            } // this.image = Scalr.resize(bufImage, DEFAULT_IMAGE_SIZE);
            else {
                this.image = bufImage.getScaledInstance(-1, 270,
                        Image.SCALE_AREA_AVERAGING);
            }
        } catch (IOException e) {
            e.printStackTrace();
        }
    }

    private javax.swing.JPanel jFrameResponseDetails;
    private javax.swing.JPanel jPanelPOIDetails;
    private javax.swing.JLabel jLabelUID;
    private javax.swing.JLabel jLabelLogo;

    private javax.swing.JLabel jLabelName;
    private javax.swing.JTextField jTextFieldName;
    private javax.swing.JLabel jLabelDOB;
    private javax.swing.JTextField jTextFieldDOB;
    private javax.swing.JLabel jLabelGender;
    private javax.swing.JTextField jTextFieldGender;
    private javax.swing.JLabel jLabelMobile;
    private javax.swing.JTextField jTextFieldMobile;
    private javax.swing.JLabel jLabelEmail;
    private javax.swing.JTextField jTextFieldEmail;

    private javax.swing.JLabel jLabelCo;
    private javax.swing.JTextField jTextFieldCo;
    private javax.swing.JLabel jLabelHouse;
    private javax.swing.JTextField jTextFieldHouse;
    private javax.swing.JLabel jLabelLm;
    private javax.swing.JTextField jTextFieldLm;
    private javax.swing.JLabel jLabelLc;
    private javax.swing.JTextField jTextFieldLc;
    private javax.swing.JLabel jLabelVtc;
    private javax.swing.JTextField jTextFieldVtc;
    private javax.swing.JLabel jLabelSubDist;
    private javax.swing.JTextField jTextFieldSubDist;
    private javax.swing.JLabel jLabelDist;
    private javax.swing.JTextField jTextFieldDist;
    private javax.swing.JLabel jLabelState;
    private javax.swing.JTextField jTextFieldState;
    private javax.swing.JLabel jLabelPc;
    private javax.swing.JTextField jTextFieldPc;
    private javax.swing.JLabel jLabelPo;
    private javax.swing.JTextField jTextFieldPo;
    private javax.swing.JTextField jTextFieldStreet;
    private javax.swing.JLabel jLabelStreet;

    private javax.swing.JPanel jPanelPoi;
    private javax.swing.JPanel jPanelPhoto;

    private javax.swing.JPanel jFrameAddressDetails;
    private javax.swing.JPanel jFrameUID;
    private javax.swing.JPanel jPanelUID;
    private javax.swing.JPanel jFramelangAddressDetails;

    private javax.swing.JPanel jPanelActionButtons;
    private JButton saveAsButton;
    private JComboBox jComboSaveFileType;

    private javax.swing.JLabel jLabelangCo;
    private javax.swing.JTextField jTextFieldlangCo;
    private javax.swing.JLabel jLabellangName;
    private javax.swing.JTextField jTextFieldlangName;
    private javax.swing.JLabel jLabellaCo;
    private javax.swing.JTextField jTextFieldlaCo;
    private javax.swing.JLabel jLabellangHouse;
    private javax.swing.JTextField jTextFieldlangHouse;
    private javax.swing.JLabel jLabellangLm;
    private javax.swing.JTextField jTextFieldlangLm;
    private javax.swing.JLabel jLabellangLc;
    private javax.swing.JTextField jTextFieldlangLc;
    private javax.swing.JLabel jLabellangVtc;
    private javax.swing.JTextField jTextFieldlangVtc;
    private javax.swing.JLabel jLabellangSubDist;
    private javax.swing.JTextField jTextFieldlangSubDist;
    private javax.swing.JLabel jLabellangDist;
    private javax.swing.JTextField jTextFieldlangDist;
    private javax.swing.JLabel jLabellangState;
    private javax.swing.JTextField jTextFieldlangState;
    private javax.swing.JLabel jLabellangPc;
    private javax.swing.JTextField jTextFieldlangPc;
    private javax.swing.JLabel jLabellangPo;
    private javax.swing.JTextField jTextFieldlangPo;
    private javax.swing.JLabel jLabellangStreet;
    private javax.swing.JTextField jTextFieldlangStreet;

}
