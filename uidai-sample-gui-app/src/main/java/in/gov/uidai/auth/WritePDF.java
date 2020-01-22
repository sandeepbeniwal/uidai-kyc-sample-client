package in.gov.uidai.auth;

import java.io.File;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;

import org.bouncycastle.util.encoders.Base64;



public class WritePDF {
	
	public static void main(String[] args) {
		
	}
	public static void writePdfData(byte[] eadharPDF, File f) {

		try {
			if(!f.exists()) f.createNewFile();
			FileOutputStream f1 = new FileOutputStream(f);
			f1.write(Base64.decode(eadharPDF));
			f1.close();
		} catch (FileNotFoundException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (IOException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		
	}

}
