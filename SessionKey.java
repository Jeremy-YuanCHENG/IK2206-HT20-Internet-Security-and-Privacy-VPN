import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import java.security.NoSuchAlgorithmException;



public class SessionKey {

	private SecretKey secretKey;   //attribute, whose type is SecretKey
	
	
	public SessionKey(Integer keylength) throws NoSuchAlgorithmException {
		KeyGenerator keyGenerator = KeyGenerator.getInstance("AES");
		keyGenerator.init(keylength);
		this.secretKey = keyGenerator.generateKey(); //put the generated key into the attribute
		//constructor doesn't need a return
	}
	
	public SessionKey(byte[] keybytes) {
		this.secretKey = new SecretKeySpec(keybytes, 0, keybytes.length, "AES"); //transform "byte[]" into "SecretKey"
	}

	public SecretKey getSecretKey() {  
		return secretKey;
	}
	

    public byte[] getKeyBytes() {
    	return secretKey.getEncoded(); //encode the "SecretKey" into a "byte[]"
	}
}