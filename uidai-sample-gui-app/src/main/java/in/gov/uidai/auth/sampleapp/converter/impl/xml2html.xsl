<?xml version="1.0"?>
<xsl:stylesheet xmlns:xsl="http://www.w3.org/1999/XSL/Transform"
	xmlns:base64="in.gov.uidai.base64.CustomBase64Utils" version="1.0" xmlns:ascii="in.gov.uidai.auth.sampleapp.common.UnicodeUitls">
	<xsl:param name="imageData" select="/KycRes/UidData/Pht" />
	
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
		<html>
			<head>
				<title> UIDAI eKYC</title>
			</head>
			<style type="text/css">

				html, body, div, span, applet, object, iframe,
				h1,
				h2, h3, h4, h5, h6, p, blockquote, pre,
				a, abbr, acronym, address,
				big, cite, code,
				del, dfn, em, font, img, ins, kbd, q, s, samp,
				small, strike, strong, sub, sup, tt, var,
				b, u, i, center,
				dl, dt, dd,
				ol, ul, li,
				fieldset, form, label, legend,
				table, caption, tbody,
				tfoot, thead, tr, th, td {
				margin: 0;
				padding: 0;
				border: 0;
				outline: 0;
				}

				body {
				margin: 0;
				padding: 0;
				text-align:left;
				font-family:Arial;
				font-size:12px;
				background-color:#fff;
				}

				/* Client Daliy Reports */

				.wrapper{
				background-color:#FFFFFF;
				margin:0 auto;
				max-width:1260px;
				text-align:left;
				width:1004px;
				}

				.container{
				overflow:hidden;
				border:1px
				solid #000;
				margin-top:5px;
				}
				.logo{
				text-transform: uppercase;
				text-align: center;
				}
				.header{
				overflow:hidden;
				border-bottom:1px solid
				#000;
				min-height:60px;

				}
				.header iframe{
				height:100px;
				width:99%;
				overflow:hidden;
				}


				.footer iframe{
				height:200px;
				width:99%;
				overflow:hidden;
				}

				.footer{
				min-height:60px;
				border-top:1px solid #000;
				padding:5px;
				}

				.main_view{
				clear:both;
				overflow:hidden;
				border-bottom:1px solid #000;
				}

				.main_view .personal_details{
				float:left;
				width:84%;
				border-right:1px solid #000;
				}

				.main_view
				.photo_details{
				float:left;
				width:15%;
				}

				.each_pat{
				overflow:hidden;
				border-bottom:1px solid #000;
				clear:both;
				}
				.each_pat.last{
				border:none;
				}

				.each_pat p{
				float:left;
				overflow:hidden;
				}

				.each_pat.three_area p.one_view,
				.each_pat.two_area p.one_view{
				width:435px;
				border-right:1px solid #000;
				}

				.each_pat.two_area
				p.two_view{
				width:385px;
				padding-left:10px;
				}


				.each_pat.three_area
				p.two_view{
				width:190px;
				border-right:1px solid #000;
				padding-left:10px;
				}

				.each_pat.three_area p.three_view{
				width:190px;
				padding-left:10px;
				}

				.each_pat label,
				.offical_details label{
				font-weight:bold;
				padding:8px 10px 8px 5px;
				float:left;
				display:block;
				}

				.each_pat span,
				.offical_details span{
				padding:8px;
				float:left;
				display:block;
				}

				.main_view .photo_details img{
				width:160px;
				padding-top: 40px;
				}

				.offical_details{
				clear:both;
				overflow:hidden;
				}

				.offical_details
				.sign_details{
				padding:5px 0px 10px 0px;
				overflow:hidden;
				clear:both;
				}
			</style>

			<body>
				<h1>UIDAI e-KYC Resident Details</h1>

				<div class="main_view">
					<div class="header"></div>
					<div class="personal_details">

						<div class="each_pat">
							<label> Name in full : </label>
							<span>
								<xsl:value-of select="/KycRes/UidData/Poi/@name" />
							</span>
						</div>

						<div class="two_area each_pat">
							<p class="one_view">
								<label> Date Of Birth (yyyy-mm-dd) : </label>
								<span>
									<xsl:value-of select="/KycRes/UidData/Poi/@dob" />
								</span>
							</p>
							<p class="two_view">
								<label> Gender : </label>
								<span>
									<xsl:value-of select="/KycRes/UidData/Poi/@gender" />
								</span>
							</p>
						</div>
						<div class="two_area each_pat">

							<p class="one_view">
								<label> Mobile No : </label>
								<span>
									<xsl:value-of select="/KycRes/UidData/Poi/@phone" />
								</span>
							</p>
							<p class="two_view">
								<label> Email ID: </label>
								<span>
									<xsl:value-of select="/KycRes/UidData/Poi/@email" />
								</span>
							</p>
						</div>


						<div class="each_pat">
							<label> Proof of Address Details </label>
							<span>
							</span>
						</div>


						<div class="three_area each_pat">
							<p class="one_view">
								<label> Care of : </label>
								<span>
									<xsl:value-of select="/KycRes/UidData/Poa/@co" />
								</span>
							</p>

							<p class="two_view">
								<label> Building : </label>
								<span>
									<xsl:value-of select="/KycRes/UidData/Poa/@house" />
								</span>
							</p>

							<p class="three_view">
								<label> Street : </label>
								<span>
									<xsl:value-of select="/KycRes/UidData/Poa/@street" />
								</span>
							</p>
						</div>

						<div class="two_area each_pat">
							<p class="one_view">
								<label> Landmark : </label>
								<span>
									<xsl:value-of select="/KycRes/UidData/Poa/@lm" />
								</span>
							</p>

							<p class="two_view">
								<label> Locality : </label>
								<span>
									<xsl:value-of select="/KycRes/UidData/Poa/@loc" />
								</span>
							</p>
						</div>
						<div class="each_pat">
							<label> Village: </label>
							<span>
								<xsl:value-of select="/KycRes/UidData/Poa/@vtc" />
							</span>
						</div>
						<div class="three_area each_pat">
							<p class="one_view">
								<label> District: </label>
								<span>
									<xsl:value-of select="/KycRes/UidData/Poa/@dist" />
								</span>
							</p>

							<p class="two_view">
								<label> State : </label>
								<span>
									<xsl:value-of select="/KycRes/UidData/Poa/@state" />
								</span>
							</p>

							<p class="three_view">
								<label> Pincode : </label>
								<span>
									<xsl:value-of select="/KycRes/UidData/Poa/@pc" />
								</span>
							</p>
						</div>



						<div class="two_area each_pat last">
							<p class="one_view">
								<label>Post Offfice : </label>
								<span>
									<xsl:value-of select="/KycRes/UidData/Poa/@po" />
								</span>
							</p>

							<p class="two_view">
								<label> Aadhaar No : </label>
								<span>
									<xsl:value-of select="/KycRes/UidData/@uid" />
								</span>
							</p>
						</div>
					</div>
					<div class="photo_details">
						<center>
							<img>
								<!-- <xsl:attribute name="src">
									<xsl:text>data:image/jpg;base64,</xsl:text>
									<xsl:value-of select="base64:decode($imageData)"></xsl:value-of>
								</xsl:attribute> -->
								<xsl:attribute name="src">
								<xsl:value-of select="concat('url(data:image/jpg;base64,',$imageData,')')"/>
								</xsl:attribute>
							</img>
						</center>
					</div>
					<div class="each_pat">
							<label> Details in Local Language</label>
							<span>
							</span>
						</div>
						<div class="each_pat">
							<label> Name in full : </label>
							<span>
								<xsl:value-of select="ascii:unicode(/KycRes/UidData/LData/@name)" />
							</span>
						</div>
						<div class="each_pat">
							<label> Proof of Address Details </label>
							<span>
							</span>
						</div>
						<div class="three_area each_pat">
							<p class="one_view">
								<label> Care of : </label>
								<span>
									<xsl:value-of select="ascii:unicode(/KycRes/UidData/LData/@co)" />
								</span>
							</p>

							<p class="two_view">
								<label> Building : </label>
								<span>
									<xsl:value-of select="ascii:unicode(/KycRes/UidData/LData/@house)" />
								</span>
							</p>

							<p class="three_view">
								<label> Street : </label>
								<span>
									<xsl:value-of select="ascii:unicode(/KycRes/UidData/LData/@street)" />
								</span>
							</p>
						</div>
						<div class="two_area each_pat">
							<p class="one_view">
								<label> Landmark : </label>
								<span>
									<xsl:value-of select="ascii:unicode(/KycRes/UidData/LData/@lm)" />
								</span>
							</p>

							<p class="two_view">
								<label> Locality : </label>
								<span>
									<xsl:value-of select="ascii:unicode(/KycRes/UidData/LData/@lc)" />
								</span>
							</p>
						</div>		
						<div class="each_pat">
							<label> Village: </label>
							<span>
								<xsl:value-of select="ascii:unicode(/KycRes/UidData/LData/@vtc)" />
							</span>
						</div>
						<div class="three_area each_pat">
							<p class="one_view">
								<label> District: </label>
								<span>
									<xsl:value-of select="ascii:unicode(/KycRes/UidData/LData/@dist)" />
								</span>
							</p>

							<p class="two_view">
								<label> State : </label>
								<span>
									<xsl:value-of select="ascii:unicode(/KycRes/UidData/LData/@state)" />
								</span>
							</p>

							<p class="three_view">
								<label> Pincode : </label>
								<span>
									<xsl:value-of select="ascii:unicode(/KycRes/UidData/LData/@pc)" />
								</span>
							</p>
						</div>
						<div class="two_area each_pat last">
							<p class="one_view">
								<label>Post Offfice : </label>
								<span>
									<xsl:value-of select="ascii:unicode(/KycRes/UidData/LData/@po)" />
								</span>
							</p>

							<p class="two_view">
								<label> Aadhaar No : </label>
								<span>
									<xsl:value-of select="/KycRes/UidData/@uid" />
								</span>
							</p>
						</div>
				</div>
			</body>
		</html>
	</xsl:template>
</xsl:stylesheet>