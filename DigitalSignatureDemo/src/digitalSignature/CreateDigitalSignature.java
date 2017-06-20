package digitalSignature;
import java.io.BufferedInputStream;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.Signature;
import java.security.SignatureException;
import java.util.HashMap;
import java.util.Map;

public class CreateDigitalSignature {

	public static void main(String[] args) throws NoSuchAlgorithmException, NoSuchProviderException,
			InvalidKeyException, SignatureException, IOException {

		// 1. Generate public-private key 
		Map<String, Key> keys = generateKeys();

		// 2. Digitally sign the file with private key
		byte[] sign = sign(keys.get("privateKey"));

		// 3. Persist the sign and public key 
		saveSignAndPublicKey(keys.get("publicKey"), sign);

	}

	/**
	 * The method generate public-private key. 
	 * This involved 3 steps, Instantiate, initialize and create
	 * @return
	 * @throws NoSuchAlgorithmException
	 * @throws NoSuchProviderException
	 */
	private static Map<String, Key> generateKeys() throws NoSuchAlgorithmException, NoSuchProviderException {

		Map<String, Key> keys = new HashMap<>();

		/**
		 * Instantiate key-pair generator object using KeyPairGenerator
		 * getInstance has two form: String algorithm  or provider(this guarantee that the implementation of an algorithm)
		 */
		KeyPairGenerator keyGen = KeyPairGenerator.getInstance("DSA", "SUN");

		
		/**
		 * Keysize for a DSA key generator is the key length (in bits)
		 * Instance of SecureRandom that uses the SHA1PRNG algorithm, as provided by the built-in SUN provide
		 */
		SecureRandom random = SecureRandom.getInstance("SHA1PRNG", "SUN");
		keyGen.initialize(1024, random);
		
		/**
		 * Generate private & public key
		 */
		KeyPair keyPair = keyGen.generateKeyPair();
		PrivateKey privateKey = keyPair.getPrivate();
		PublicKey publicKey = keyPair.getPublic();

		keys.put("privateKey", privateKey);
		keys.put("publicKey", publicKey);

		return keys;

	}

	/**
	 * Method sign file with private key generated
	 * @param key
	 * @return
	 * @throws NoSuchAlgorithmException
	 * @throws NoSuchProviderException
	 * @throws InvalidKeyException
	 * @throws SignatureException
	 * @throws IOException
	 */
	private static byte[] sign(Key key) throws NoSuchAlgorithmException, NoSuchProviderException,
			InvalidKeyException, SignatureException, IOException {

		/**
		 * Instantiate and initiate the Signature class
		 */
		Signature dsa = Signature.getInstance("SHA1withDSA", "SUN");
		dsa.initSign((PrivateKey) key);
		
		/**
		 * Read in the data a buffer at a time and will supply it to the Signature object by calling the update method
		 */
		byte[] buffer = new byte[1024];
		int len;
		try (BufferedInputStream br = new BufferedInputStream(new FileInputStream("C:\\Users\\manas.das\\Desktop\\Name.txt"))) {

			while ((len = br.read(buffer)) >= 0) {
				dsa.update(buffer, 0, len);
			}
		}
		
		/**
		 * Generate the Signature
		 */
		byte[] realSig = dsa.sign();

		return realSig;
	}

	/**
	 * Method save the Signature and the Public Key in Files
	 * @param key
	 * @param signedFileInByte
	 * @throws IOException
	 */
	private static void saveSignAndPublicKey(Key key, byte[] signedFileInByte) throws IOException {

		/**
		 * Save the sign in a file
		 */
		try (FileOutputStream savedSign = new FileOutputStream("C:\\Users\\manas.das\\Desktop\\mysign")) {

			savedSign.write(signedFileInByte);
		}

		/**
		 * Save the public key
		 */
		byte[] publickey = key.getEncoded();
		try (FileOutputStream keyfos = new FileOutputStream("C:\\Users\\manas.das\\Desktop\\mypublickey")) {

			keyfos.write(publickey);
		}

	}

}
