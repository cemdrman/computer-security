import java.security.KeyPairGenerator;
import java.security.KeyPair;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;

public class CryptoHelper {

	/**
	 * Question-1
	 * 
	 * @param keyAlgorithm
	 * @param numBits
	 * @return Public-Private Key
	 */
	public KeyPair generateKeyPair(String keyAlgorithm, int numBits) {

		try {
			// Get the public/private key pair
			KeyPairGenerator keyGen = KeyPairGenerator.getInstance(keyAlgorithm);
			keyGen.initialize(numBits);
			KeyPair keyPair = keyGen.genKeyPair();
			System.out.println("Generating key/value pair using " + keyPair.getPrivate().getAlgorithm() + " algorithm");
			return keyPair;
		} catch (NoSuchAlgorithmException e) {
			System.out.println("Exception");
			System.out.println("No such algorithm: " + keyAlgorithm);
		}
		return null;
	}
	
	/**
	 * Question-2
	 * 
	 * @param keyAlgorithm
	 */
	public SecretKey generateSymmetricKey() {
		KeyGenerator generator = null;
		try {
			generator = KeyGenerator.getInstance("AES");
		} catch (NoSuchAlgorithmException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		SecretKey key = generator.generateKey();
		return key;
	}

	/**
	 * 
	 * @return Initialization Vector
	 */
	public byte[] generateIV() {
		SecureRandom random = new SecureRandom();
		byte[] iv = new byte[16];
		random.nextBytes(iv);
		return iv;
	}	

}
