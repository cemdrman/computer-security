import java.security.KeyPair;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Signature;
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
        byte[] encrypted = encrypt(publicKey, "cemdirmanfenerbahçe");     
		System.out.println("Encrypted Symetric Key: " + encrypted );
		
		byte[] decrypted = decrypt(privateKey, encrypted);
		
		System.out.println("Decrypted Symetric Key: " + decrypted );
		
		
		
		//--Question-3
		String longMessage = "really long message, but you cant see this message.";
		
		Signature signature = Signature.getInstance("SHA256withRSA");
		//encrypting it with KA-
		signature.initSign(privateKey);
		/* Supply the Signature Object the Data to Be Signed */		
		signature.update(longMessage.getBytes());
		byte[] signatureBytes = signature.sign();
		System.out.println("Singature:" + signatureBytes);

		signature.initVerify(publicKey);
		signature.update(longMessage.getBytes());

	    System.out.println("Is verifyed: " + signature.verify(signatureBytes));
	}
	
	
	
	public static byte[] encrypt(PublicKey publicKey, String secretKey) throws Exception {
        Cipher cipher = Cipher.getInstance("RSA");  
        //SecretKeySpec k = new SecretKeySpec(publicKey.getEncoded(), "AES");
        cipher.init(Cipher.ENCRYPT_MODE, publicKey); 
        return cipher.doFinal(secretKey.getBytes());
    }
    
    public static byte[] decrypt(PrivateKey privateKey, byte [] encrypted) throws Exception {
        Cipher cipher = Cipher.getInstance("RSA");  
        //SecretKeySpec k = new SecretKeySpec(privateKey.getEncoded(), "AES");
        cipher.init(Cipher.DECRYPT_MODE, privateKey);        
        return cipher.doFinal(encrypted);
    }

}
