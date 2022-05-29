import java.io.OutputStream;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;

import javax.crypto.Cipher;
import javax.crypto.CipherOutputStream;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.spec.IvParameterSpec;



public class SessionEncrypter {

	private SessionKey sessionKey;
	private IvParameterSpec ivValue;
	private Cipher cipher;

	public SessionEncrypter(Integer keylength) throws NoSuchAlgorithmException {
		this.sessionKey = new SessionKey(keylength);
		byte[] iv = new byte[16];
		SecureRandom secureRandom = new SecureRandom();
		secureRandom.nextBytes(iv);
		this.ivValue = new IvParameterSpec(iv);
	}

	public SessionEncrypter(byte[] keybytes, byte[] ivbytes) {
		this.sessionKey = new SessionKey(keybytes);
		this.ivValue = new IvParameterSpec(ivbytes);
	}

	public CipherOutputStream openCipherOutputStream(OutputStream output) throws NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException, InvalidAlgorithmParameterException {
		this.cipher = Cipher.getInstance("AES/CTR/NoPadding");
		cipher.init(Cipher.ENCRYPT_MODE, sessionKey.getSecretKey(), ivValue);
		return new CipherOutputStream(output, cipher);
	}

	public byte[] getKeyBytes() {
		return this.sessionKey.getSecretKey().getEncoded();
	}

	public byte[] getIVBytes() {
		return this.ivValue.getIV();
	}

}
