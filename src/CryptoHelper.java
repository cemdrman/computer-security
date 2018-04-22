import java.security.KeyPairGenerator;
import java.security.Key;
import java.security.KeyPair;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;

import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;

public class CryptoHelper {

	/**
	 * Question-1
	 * @param keyAlgorithm
	 * @param numBits
	 * @return Public-Private Key
	 */
	public KeyPair generatePublicPrivateKeys(String keyAlgorithm, int numBits) {
		
		try {
			// Get the public/private key pair
			KeyPairGenerator keyGen = KeyPairGenerator.getInstance(keyAlgorithm);
			keyGen.initialize(numBits);
			KeyPair keyPair = keyGen.genKeyPair();

			System.out.println("\n" + "Generating key/value pair using " + keyPair.getPrivate().getAlgorithm() + " algorithm");

			return keyPair;

		} catch (NoSuchAlgorithmException e) {
			System.out.println("Exception");
			System.out.println("No such algorithm: " + keyAlgorithm);
		}
		return null;
	}
	
	public Key generateSymmetricKey() throws NoSuchAlgorithmException {
		KeyGenerator generator = KeyGenerator.getInstance( "AES" );
		SecretKey key = generator.generateKey();
		return key;
	}
	
	public byte [] generateIV() {
		SecureRandom random = new SecureRandom();
		byte [] iv = new byte [16];
		random.nextBytes( iv );
		return iv;
	}
	
	public void generateKey(String keyAlgorithm) {

        try {

            KeyGenerator keyGen = KeyGenerator.getInstance(keyAlgorithm);
            SecretKey key = keyGen.generateKey();

            System.out.println(
                    "\n" +
                    "Generating symmetric key using " +
                    key.getAlgorithm() + 
                    " algorithm");

            // Get the bytes of the key
            byte[] keyBytes = key.getEncoded();
            int numBytes = keyBytes.length;

            System.out.println(
                    "  The number of bytes in the key = " +
                    numBytes + ".");

            // The bytes can be converted back to a SecretKey
            SecretKey key2 = new SecretKeySpec(keyBytes, keyAlgorithm);
            System.out.println(
                "  Are both symmetric keys equal? " + key.equals(key2));

        } catch (NoSuchAlgorithmException e) {

            System.out.println("Exception");
            System.out.println("No such algorithm: " + keyAlgorithm);

        }

    }


}
