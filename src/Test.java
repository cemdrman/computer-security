import java.security.Key;
import java.security.KeyPair;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.util.Base64;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;

public class Test {

	public static void main(String[] args) throws Exception {
		// Generate a 1024-bit RSA key pair
		CryptoHelper cryptoGenerater = new CryptoHelper();
		KeyPair keyPair = cryptoGenerater.generatePublicPrivateKeys("RSA", 1024);
		
		PrivateKey privateKey = keyPair.getPrivate();
		PublicKey publicKey = keyPair.getPublic();
		System.out.println("Private Key : " + privateKey.getEncoded());
		System.out.println("Public  Key : " + publicKey.getEncoded());
		Base64.Encoder encoder = Base64.getEncoder();
		System.out.println("private:" + encoder.encodeToString(privateKey.getEncoded()));
		System.out.println("public :" + encoder.encodeToString(publicKey.getEncoded()));
		
		//--Question-2
		
		SecretKey secretKey = cryptoGenerater.generateSymmetricKey(); 	
		System.out.println("Symetric Key:" + secretKey.getEncoded());
		
		 // encrypt the message
        byte[] encrypted = encrypt(publicKey, "cem");     
		System.out.println("Encrypted Symetric Key: " + encrypted );
		
		byte[] decrypted = decrypt(privateKey, encrypted);
		
		System.out.println("Decrypted Symetric Key: " + decrypted );
		
		
		
	}
	
	
	
	public static byte[] encrypt(PublicKey publicKey, String secretKey) throws Exception {
        Cipher cipher = Cipher.getInstance("RSA");  
        cipher.init(Cipher.ENCRYPT_MODE, publicKey); 
        return cipher.doFinal(secretKey.getBytes());  
    }
    
    public static byte[] decrypt(PrivateKey privateKey, byte [] encrypted) throws Exception {
        Cipher cipher = Cipher.getInstance("RSA");  
        cipher.init(Cipher.DECRYPT_MODE, privateKey);        
        return cipher.doFinal(encrypted);
    }

}
