import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PublicKey;
import java.security.SignatureException;
import java.security.cert.CertificateException;
import java.security.cert.CertificateExpiredException;
import java.security.cert.CertificateFactory;
import java.security.cert.CertificateNotYetValidException;
import java.security.cert.X509Certificate;

public class VerifyCertificate {
	
	private static X509Certificate caCertificate;
	private static X509Certificate userCertificate;
	
	public VerifyCertificate(X509Certificate caCertificate, X509Certificate userCertificate) {
		VerifyCertificate.caCertificate = caCertificate;
		VerifyCertificate.userCertificate = userCertificate;
	}

	public static void main(String[] args) throws Exception {
		boolean flag = true;
		String caFileName = args[0];
		String userFileName = args[1];
		X509Certificate caCertificate = print(caFileName);
		X509Certificate userCertificate = print(userFileName);
	    System.out.println("CA's DN: " + caCertificate.getSubjectDN());
	    System.out.println("user's DN: " + userCertificate.getSubjectDN());
		PublicKey caPublicKey = caCertificate.getPublicKey();
		try {
			verifyCertificate(caCertificate, caPublicKey);
		}
		catch(Exception e) { //print the error message
			flag = false;
			System.out.println("CA's certificate is not signed correctly");
		}
		try {
			verifyValidityDate(caCertificate, caPublicKey);
		}
		catch(Exception e) {
			flag = false;
			System.out.println("CA's certificate is not currently valid");
		}
		try {
			verifyCertificate(userCertificate, caPublicKey);
		}
		catch(Exception e) {
			flag = false;
			System.out.println("user's certificate is not signed correctly");
		}
		try {
			verifyValidityDate(userCertificate, caPublicKey);
		}
		catch(Exception e) {
			flag = false;
			System.out.println("user's certificate is not currently valid");
		}
		if (flag == true) {
			System.out.println("Pass");
		}
		}


	public void startVerify(){
		boolean flag = true; // give "pass" only if the flag is "true"
		X509Certificate caCertificate = VerifyCertificate.caCertificate;
		X509Certificate userCertificate = VerifyCertificate.userCertificate;
	    System.out.println("CA's DN: " + caCertificate.getSubjectDN()); //print out the DN
	    System.out.println("user's DN: " + userCertificate.getSubjectDN());
		PublicKey caPublicKey = caCertificate.getPublicKey();
		try {
			verifyCertificate(caCertificate, caPublicKey);
		}
		catch(Exception e) { //print the error message
			flag = false;
			System.out.println("CA's certificate is not signed correctly");
		}
		try {
			verifyValidityDate(caCertificate, caPublicKey);
		}
		catch(Exception e) {
			flag = false;
			System.out.println("CA's certificate is not currently valid");
		}
		try {
			verifyCertificate(userCertificate, caPublicKey);
		}
		catch(Exception e) {
			flag = false;
			System.out.println("user's certificate is not signed correctly");
		}
		try {
			verifyValidityDate(userCertificate, caPublicKey);
		}
		catch(Exception e) {
			flag = false;
			System.out.println("user's certificate is not currently valid");
		}
		if (flag == true) {
			System.out.println("Pass");
		}
		}
	
	public static X509Certificate print(String filename) throws FileNotFoundException, CertificateException {
		FileInputStream fileInput = new FileInputStream(filename);
		CertificateFactory certificateFactory = CertificateFactory.getInstance("X.509");  
		X509Certificate X509certificate = (X509Certificate) certificateFactory.generateCertificate(fileInput);

		if (X509certificate.toString() == null) {
			System.out.println("Fail. There is no DN");
			System.exit(0);
		}
		return X509certificate;		
	}
	
	public static void verifyCertificate(X509Certificate certificate, PublicKey publicKey) throws InvalidKeyException, CertificateException, NoSuchAlgorithmException, NoSuchProviderException, SignatureException {
		certificate.verify(publicKey);
	}

    public static void verifyValidityDate(X509Certificate certificate, PublicKey publicKey) throws CertificateExpiredException, CertificateNotYetValidException {
		certificate.checkValidity();
	}
	
}
