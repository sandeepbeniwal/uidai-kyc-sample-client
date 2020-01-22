<?xml version="1.0" encoding="UTF-8"?>
<xsl:stylesheet version="1.1"
	xmlns:xsl="http://www.w3.org/1999/XSL/Transform" xmlns:fo="http://www.w3.org/1999/XSL/Format"
	xmlns:base64="in.gov.uidai.base64.CustomBase64Utils"
	exclude-result-prefixes="fo">
	<xsl:output method="xml" version="1.0" omit-xml-declaration="no"
		indent="yes" />
	<xsl:param name="imageData" select="KycRes/UidData/Pht" />
	<xsl:param name="resourcePath" />
<!--    
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
 -->
	<xsl:template match="/">
		<fo:root xmlns:fo="http://www.w3.org/1999/XSL/Format">
			<fo:layout-master-set>
				<fo:simple-page-master master-name="simpleA4"
					page-height="29.7cm" page-width="21cm">
					<fo:region-body margin="2cm" />
					<fo:region-before margin="1cm"></fo:region-before>
					<fo:region-after margin="1cm"></fo:region-after>
				</fo:simple-page-master>
			</fo:layout-master-set>
			<fo:page-sequence master-reference="simpleA4">
				<fo:static-content flow-name="xsl-region-before">
					<fo:block> UIDAI eKYC</fo:block>
				</fo:static-content>
				<fo:static-content flow-name="xsl-region-after">
					<fo:block>-0-</fo:block>
				</fo:static-content>
				<fo:flow flow-name="xsl-region-body">
					<fo:block font-size="16pt" font-weight="bold" space-after="5mm">
						UIDAI e-KYC Resident Details					
					</fo:block>
					<fo:block font-size="10pt" space-after="5mm">
						<xsl:apply-templates select="KycRes/UidData/Poi"></xsl:apply-templates>
					</fo:block>
					<fo:block font-size="10pt" space-after="5mm">
						<xsl:apply-templates select="KycRes/UidData/Poa"></xsl:apply-templates>
					</fo:block>
				</fo:flow>
			</fo:page-sequence>
		</fo:root>
	</xsl:template>

	<xsl:template match="Poi">
		<fo:table table-layout="fixed" width="100%" border-collapse="separate"
			border="solid 1px black" background-repeat="no-repeat"
			background-position-horizontal="8cm" background-position-vertical="5cm">
			<xsl:attribute name="background-image">
				<xsl:text>url("</xsl:text>
				<xsl:value-of select="$resourcePath"></xsl:value-of>
				<xsl:text>aadhaar_verified.png")</xsl:text>
			</xsl:attribute>
			<fo:table-column column-width="6cm" />
			<fo:table-column column-width="4cm" />
			<fo:table-column column-width="5cm" />
			<fo:table-body>
				<fo:table-row>
					<fo:table-cell number-rows-spanned="6">
						<fo:block>
							<fo:external-graphic>
								<xsl:attribute name="src">
									<xsl:text>url('data:image/jpg;base64,</xsl:text>
									<xsl:value-of select="base64:decode($imageData)"></xsl:value-of>
									<xsl:text>')</xsl:text>
								</xsl:attribute>
							</fo:external-graphic>
							
							
						    <fo:external-graphic>
								<xsl:attribute name="src">
									<xsl:value-of select="concat('url(data:image/jpg;base64,',$imageData,')')"/>
								</xsl:attribute>
	   						</fo:external-graphic>
	   						
	   						
						</fo:block>
					</fo:table-cell>
					<fo:table-cell padding-before=".2cm">
						<fo:block>
							UID :
						</fo:block>
					</fo:table-cell>
					<fo:table-cell padding-before=".2cm">
						<fo:block>
							<xsl:value-of select="/KycRes/UidData/@uid" />
						</fo:block>
					</fo:table-cell>

				</fo:table-row>
				<fo:table-row>
					<fo:table-cell padding-before=".2cm">
						<fo:block>
							Resident Name :
						</fo:block>
					</fo:table-cell>
					<fo:table-cell padding-before=".2cm">
						<fo:block>
							<xsl:value-of select="@name" />
						</fo:block>
					</fo:table-cell>
				</fo:table-row>
				<fo:table-row>
					<fo:table-cell padding-before=".2cm">
						<fo:block>
							Date of Birth :
						</fo:block>
					</fo:table-cell>
					<fo:table-cell padding-before=".2cm">
						<fo:block>
							<xsl:value-of select="@dob" />
						</fo:block>
					</fo:table-cell>
				</fo:table-row>
				<fo:table-row>
					<fo:table-cell padding-before=".2cm">
						<fo:block>
							Gender :
						</fo:block>
					</fo:table-cell>
					<fo:table-cell padding-before=".2cm">
						<fo:block>
							<xsl:value-of select="@gender" />
						</fo:block>
					</fo:table-cell>
				</fo:table-row>
				<fo:table-row>
					<fo:table-cell padding-before=".2cm">
						<fo:block>
							Phone No :
						</fo:block>
					</fo:table-cell>
					<fo:table-cell padding-before=".2cm">
						<fo:block>
							<xsl:value-of select="@phone" />
						</fo:block>
					</fo:table-cell>
				</fo:table-row>
				<fo:table-row>
					<fo:table-cell padding-before=".2cm">
						<fo:block>
							Email Id :
						</fo:block>
					</fo:table-cell>
					<fo:table-cell padding-before=".2cm">
						<fo:block>
							<xsl:value-of select="@email" />
						</fo:block>
					</fo:table-cell>
				</fo:table-row>
			</fo:table-body>
		</fo:table>
	</xsl:template>
	<xsl:template match="Poa">
		<fo:table table-layout="fixed" width="100%" border-collapse="separate"
			border="solid 1px black">
			<fo:table-column column-width="3cm" />
			<fo:table-column column-width="5cm" />
			<fo:table-column column-width="3cm" />
			<fo:table-column column-width="5cm" />
			<fo:table-body>
				<fo:table-row>
					<fo:table-cell padding-before=".2cm">
						<fo:block>
							Care of :
						</fo:block>
					</fo:table-cell>
					<fo:table-cell padding-before=".2cm">
						<fo:block>
							<xsl:value-of select="@co" />
						</fo:block>
					</fo:table-cell>
					<fo:table-cell padding-before=".2cm">
						<fo:block>
							House no :
						</fo:block>
					</fo:table-cell>
					<fo:table-cell padding-before=".2cm">
						<fo:block>
							<xsl:value-of select="@house" />
						</fo:block>
					</fo:table-cell>
				</fo:table-row>
				<fo:table-row>
					<fo:table-cell padding-before=".2cm">
						<fo:block>
							Landmark :
						</fo:block>
					</fo:table-cell>
					<fo:table-cell padding-before=".2cm">
						<fo:block>
							<xsl:value-of select="@lm" />
						</fo:block>
					</fo:table-cell>
					<fo:table-cell padding-before=".2cm">
						<fo:block>
							Street :
						</fo:block>
					</fo:table-cell>
					<fo:table-cell padding-before=".2cm">
						<fo:block>
							<xsl:value-of select="@street" />
						</fo:block>
					</fo:table-cell>
				</fo:table-row>
				<fo:table-row>
					<fo:table-cell padding-before=".2cm">
						<fo:block>
							Locality :
						</fo:block>
					</fo:table-cell>
					<fo:table-cell padding-before=".2cm">
						<fo:block>
							<xsl:value-of select="@loc" />
						</fo:block>
					</fo:table-cell>
					<fo:table-cell padding-before=".2cm">
						<fo:block>
							Post Office :
						</fo:block>
					</fo:table-cell>
					<fo:table-cell padding-before=".2cm">
						<fo:block>
							<xsl:value-of select="@po" />
						</fo:block>
					</fo:table-cell>
				</fo:table-row>
				<fo:table-row>
					<fo:table-cell padding-before=".2cm">
						<fo:block>
							Vtc :
						</fo:block>
					</fo:table-cell>
					<fo:table-cell padding-before=".2cm">
						<fo:block>
							<xsl:value-of select="@vtc" />
						</fo:block>
					</fo:table-cell>
					<fo:table-cell padding-before=".2cm">
						<fo:block>
							Sub district :
						</fo:block>
					</fo:table-cell>
					<fo:table-cell padding-before=".2cm">
						<fo:block>
							<xsl:value-of select="@subdist" />
						</fo:block>
					</fo:table-cell>
				</fo:table-row>
				<fo:table-row>
					<fo:table-cell padding-before=".2cm">
						<fo:block>
							District :
						</fo:block>
					</fo:table-cell>
					<fo:table-cell padding-before=".2cm">
						<fo:block>
							<xsl:value-of select="@dist" />
						</fo:block>
					</fo:table-cell>
					<fo:table-cell padding-before=".2cm">
						<fo:table table-layout="fixed" width="100%"
							border-collapse="separate">
							<fo:table-column column-width="1.2cm" />
							<fo:table-column column-width="4cm" />
							<fo:table-column column-width="1.5cm" />
							<fo:table-column column-width="1cm" />

							<fo:table-body>
								<fo:table-row>
									<fo:table-cell>
										<fo:block>
											State :
									</fo:block>
									</fo:table-cell>
									<fo:table-cell>
										<fo:block>
											<xsl:value-of select="@state" />
										</fo:block>
									</fo:table-cell>
									<fo:table-cell>
										<fo:block>
											Pincode :
									</fo:block>
									</fo:table-cell>
									<fo:table-cell>
										<fo:block>
											<xsl:value-of select="@pc" />
										</fo:block>
									</fo:table-cell>
								</fo:table-row>
							</fo:table-body>
						</fo:table>
					</fo:table-cell>
				</fo:table-row>
			</fo:table-body>
		</fo:table>
	</xsl:template>

</xsl:stylesheet>
