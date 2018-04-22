import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

public class HashingUtil {

	/**
	 * 
	 * @param message
	 * @return hash
	 */
	public static byte[] hashingWithSHA(String message) {
		MessageDigest digest = null;
		try {
			digest = MessageDigest.getInstance("SHA-256");
		} catch (NoSuchAlgorithmException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		byte[] hash = digest.digest(message.getBytes(StandardCharsets.UTF_8));
		return hash;
	}
}
