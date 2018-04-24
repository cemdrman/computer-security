import java.security.InvalidKeyException;
import java.security.KeyPair;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Signature;
import java.util.Base64;
import javax.crypto.Cipher;
import javax.crypto.Mac;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

public class Test {
	
	private static Base64.Encoder encoder = Base64.getEncoder();
	
	public static void main(String[] args) throws Exception {
		
		CryptoHelper cryptoGenerater = new CryptoHelper();
		// --Question-1
		// Generate a 1024-bit RSA key pair
		System.out.println("--Question - 1");
		KeyPair keyPair = cryptoGenerater.generateKeyPair("RSA", 1024);
		PrivateKey privateKey = keyPair.getPrivate();
		PublicKey publicKey = keyPair.getPublic();		
		System.out.println("Private Key : " + privateKey.getEncoded());
		System.out.println("Public  Key : " + publicKey.getEncoded());		
		System.out.println("Private:" + encoder.encodeToString(privateKey.getEncoded()));
		System.out.println("Public :" + encoder.encodeToString(publicKey.getEncoded()));
		// --Question-2
		System.out.println("--Question - 2");
		SecretKey secretKey = cryptoGenerater.generateSymmetricKey();
		System.out.println("Symetric Key:" + secretKey.getEncoded());
		// encrypt the message
		byte[] encrypted = encrypt(publicKey, "cemdirmanfenerbahçe");		
		byte[] decrypted = decrypt(privateKey, encrypted);
		System.out.println("Encrypted Symetric Key: " + encrypted);
		System.out.println("Decrypted Symetric Key: " + decrypted);

		// --Question-3
		System.out.println("--Question - 3");
		String longMessage = "really long message, but you cant see this message.";
		Signature signature = Signature.getInstance("SHA256withRSA");
		// encrypting it with KA-
		signature.initSign(privateKey);
		/* Supply the Signature Object the Data to Be Signed */
		signature.update(longMessage.getBytes());
		byte[] signatureBytes = signature.sign();
		System.out.println("Singature:" + signatureBytes);
		signature.initVerify(publicKey);
		signature.update(longMessage.getBytes());
		System.out.println("Is verifyed: " + signature.verify(signatureBytes));

		// --Question-4
		System.out.println("--Question - 4");
		hmac(longMessage);
		
		// --Question-5
		System.out.println("--Question - 5");
		byte[] iv = cryptoGenerater.generateIV();
		IvParameterSpec ivspec = new IvParameterSpec(iv);
		Cipher ci = Cipher.getInstance("AES/CBC/PKCS5Padding");
		//I have already secret key and iv
		ci.init(Cipher.ENCRYPT_MODE, secretKey, ivspec);
		//Encrypting a message
		String plainText = "this text is plain text for testing";
		byte[] input = plainText.getBytes("UTF-8");
	    byte[] encoded = ci.doFinal(input);
	    System.out.println("Encoded PlainText: " + encoded);
	    //Decrypting Back to a message
	    ci.init(Cipher.DECRYPT_MODE, secretKey, ivspec);
	    String decrytedPlainText = new String(ci.doFinal(encoded), "UTF-8");
	    System.out.println(decrytedPlainText);
	    
		
	}		

	public static byte[] encrypt(PublicKey publicKey, String secretKey) throws Exception {
		Cipher cipher = Cipher.getInstance("RSA");
		// SecretKeySpec k = new SecretKeySpec(publicKey.getEncoded(), "AES");
		cipher.init(Cipher.ENCRYPT_MODE, publicKey);
		return cipher.doFinal(secretKey.getBytes());
	}

	public static byte[] decrypt(PrivateKey privateKey, byte[] encrypted) throws Exception {
		Cipher cipher = Cipher.getInstance("RSA");
		// SecretKeySpec k = new SecretKeySpec(privateKey.getEncoded(), "AES");
		cipher.init(Cipher.DECRYPT_MODE, privateKey);
		return cipher.doFinal(encrypted);
	}

	public static void hmac(String message) {
		String secret = "secret";
		Mac sha256_HMAC;
		try {
			sha256_HMAC = Mac.getInstance("HmacSHA256");
			SecretKeySpec secret_key = new SecretKeySpec(secret.getBytes(), "HmacSHA256");
			sha256_HMAC.init(secret_key);
			String hash = Base64.getEncoder().encodeToString(sha256_HMAC.doFinal(message.getBytes()));
			System.out.println(hash);
		} catch (NoSuchAlgorithmException e) {e.printStackTrace();} 
		  catch (InvalidKeyException e) {e.printStackTrace();}
	}

}
