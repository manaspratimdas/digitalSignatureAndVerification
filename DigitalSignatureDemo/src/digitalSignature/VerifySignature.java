package digitalSignature;

import java.io.BufferedInputStream;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.security.InvalidKeyException;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PublicKey;
import java.security.Signature;
import java.security.SignatureException;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.X509EncodedKeySpec;

public class VerifySignature {

	public static void main(String[] args) throws FileNotFoundException, IOException, NoSuchAlgorithmException,
			NoSuchProviderException, InvalidKeySpecException, InvalidKeyException, SignatureException {

		// Get the public key
		PublicKey publickey = getPublicKey();

		// get the signature
		byte[] sign2Verify = getSignature2Verify();

		// verify the file with public key and signature
		verifySignature(publickey, sign2Verify);

	}

	/**
	 * Generate the public key
	 * 
	 * @return
	 * @throws IOException
	 * @throws FileNotFoundException
	 * @throws NoSuchAlgorithmException
	 * @throws NoSuchProviderException
	 * @throws InvalidKeySpecException
	 */
	private static PublicKey getPublicKey() throws IOException, FileNotFoundException, NoSuchAlgorithmException,
			NoSuchProviderException, InvalidKeySpecException {

		/**
		 * Read the file used to store public key and store in an byte array
		 */
		byte[] encKey = null;
		try (FileInputStream keyFile = new FileInputStream("C:\\Users\\manas.das\\Desktop\\mypublickey")) {

			encKey = new byte[keyFile.available()];
			keyFile.read(encKey);
		}

		/**
		 * Key specification required-assuming that the key was encoded
		 * according to the X.509 standard-(built-in DSA key-pair generator
		 * supplied by the SUN provider)
		 */
		X509EncodedKeySpec pubKeySpec = null;
		if (encKey != null) {
			pubKeySpec = new X509EncodedKeySpec(encKey);
		}

		/**
		 * KeyFactory class in order to instantiate a DSA public key from its
		 * encoding
		 */
		KeyFactory keyFactory = KeyFactory.getInstance("DSA", "SUN");

		/**
		 * KeyFactory object to generate a PublicKey from the key specification
		 */
		PublicKey pubKey = keyFactory.generatePublic(pubKeySpec);

		return pubKey;
	}

	
	/**
	 * Method return the signature after reading the file
	 * @return
	 * @throws FileNotFoundException
	 * @throws IOException
	 */
	private static byte[] getSignature2Verify() throws FileNotFoundException, IOException {

		byte[] sign2Verify = null;
		try (FileInputStream signFile = new FileInputStream("C:\\Users\\manas.das\\Desktop\\mysign")) {

			sign2Verify = new byte[signFile.available()];
			signFile.read(sign2Verify);
		}

		return sign2Verify;

	}

	/**
	 * Method to verify signature
	 * @param pubKey
	 * @param sign2Verify
	 * @throws NoSuchAlgorithmException
	 * @throws NoSuchProviderException
	 * @throws InvalidKeyException
	 * @throws SignatureException
	 * @throws IOException
	 */
	private static void verifySignature(PublicKey pubKey, byte[] sign2Verify) throws NoSuchAlgorithmException,
			NoSuchProviderException, InvalidKeyException, SignatureException, IOException {

		/**
		 *  Signature object that uses the same signature algorithm as was used to generate the signature
		 */
		Signature sig = Signature.getInstance("SHA1withDSA", "SUN");

		/**
		 * initialize the Signature object
		 */
		sig.initVerify(pubKey);

		/**
		 * Read in the data a buffer at a time and will supply it to the
		 * Signature object by calling the update method
		 */
		byte[] buffer = new byte[1024];
		int len;
		try (BufferedInputStream br = new BufferedInputStream(
				new FileInputStream("C:\\Users\\manas.das\\Desktop\\Name.txt"))) {

			while ((len = br.read(buffer)) >= 0) {
				sig.update(buffer, 0, len);
			}
		}

		/**
		 * Verify the signature
		 */
		boolean verifies = sig.verify(sign2Verify);

		System.out.println("signature verifies: " + verifies);

	}

}
