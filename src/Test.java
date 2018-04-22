import java.security.Key;
import java.security.KeyPair;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.util.Base64;

public class Test {

	public static void main(String[] args) {
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
		//--
		
		
		try {
			String plaintext = "This is really secret message.";
			System.out.println( plaintext );
			Key secretKey = cryptoGenerater.generateSymmetricKey();
			
		} catch (NoSuchAlgorithmException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} 		
	}

}
