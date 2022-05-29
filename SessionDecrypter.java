import java.io.InputStream;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;

import javax.crypto.Cipher;
import javax.crypto.CipherInputStream;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.spec.IvParameterSpec;


public class SessionDecrypter {
	
    private SessionKey originalKey;
    private IvParameterSpec ivValue;
    private Cipher cipher;
    

	public SessionDecrypter(byte[] keybytes, byte[] ivbytes){
		this.originalKey = new SessionKey(keybytes);
		this.ivValue = new IvParameterSpec(ivbytes);
	}
	
	public CipherInputStream openCipherInputStream(InputStream input) throws NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException, InvalidAlgorithmParameterException {
		this.cipher = Cipher.getInstance("AES/CTR/NoPadding");
		cipher.init(Cipher.DECRYPT_MODE, originalKey.getSecretKey(), ivValue);
		return new CipherInputStream(input, cipher);
	}
}
