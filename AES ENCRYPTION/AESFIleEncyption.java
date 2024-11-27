package AESCFileEncryptionProject.java;
import javax.crypto.Cipher;   //allows you to specify the encryption algorithm (in this case, AES), the encryption mode (e.g., CBC), and the padding scheme (e.g., PKCS5Padding).

import javax.crypto.KeyGenerator; //Generates symmetric encryption keys (such as AES keys) in Java
import javax.crypto.SecretKey; //Represents a symmetric key (in this case, an AES key) that can be used in encryption and decryption operations.
import javax.crypto.spec.IvParameterSpec; //Specifies an Initialization Vector (IV), which is a block of random data that ensures unique encryption results for each encryption session, even with the same key and input.
import javax.crypto.spec.SecretKeySpec; //Represents the AES encryption key in a specified format. It allows you to convert raw bytes into a SecretKey object, which is needed to initialize the cipher.
import java.io.File;
import java.io.FileInputStream;  //Allows reading bytes from a file input stream
import java.io.FileOutputStream; 
// Provides a more flexible API for handling files and paths, including methods to read/write entire files or paths.
import java.nio.file.Files;
import java.security.MessageDigest; //Implements a one-way hash function for generating a hash (in this case, SHA-256) of input data, such as a passphrase.
import java.util.Base64; //Provides methods for encoding and decoding data to and from Base64, a common encoding scheme used in cryptographic operations.

public class AESFIleEncyption {
	private static final String ALGORITHM = "AES";
    private static final String TRANSFORMATION = "AES/CBC/PKCS5Padding";
    private static final int BLOCK_SIZE = 16; //AES requires data to be processed in blocks of 16 bytes,

    // Generate a 256-bit SHA key
    public static SecretKeySpec getKey(String myKey) throws Exception {
        MessageDigest sha = MessageDigest.getInstance("SHA-256");
        byte[] key = myKey.getBytes("UTF-8");
        key = sha.digest(key);
        return new SecretKeySpec(key, ALGORITHM);
    }
    public static byte[] generateIv() {
        byte[] iv = new byte[BLOCK_SIZE];
        new java.security.SecureRandom().nextBytes(iv); //even if an attacker knows part of the output or the internal state, they should not be able to predict any other part of the sequence.
        return iv; //fills the iv byte array with random bytes.
    }
    public static void encryptFile(String inputFile, String outputFile, SecretKeySpec secretKey) throws Exception {
        Cipher cipher = Cipher.getInstance(TRANSFORMATION); //not yet initialised
        byte[] iv = generateIv(); // Generates an initialization vector (IV), which ensures that identical plaintext inputs produce different ciphertexts each time they’re encrypted.
        IvParameterSpec ivParameterSpec = new IvParameterSpec(iv);
        cipher.init(Cipher.ENCRYPT_MODE, secretKey, ivParameterSpec); // Cipher is now ready for encryption with the specified key and IV.

        byte[] inputBytes = Files.readAllBytes(new File(inputFile).toPath());
        byte[] outputBytes = cipher.doFinal(inputBytes); //encrypted data

        try (FileOutputStream outputStream = new FileOutputStream(outputFile)) {
            outputStream.write(iv); // Write the IV at the start of the file used for decryption
            outputStream.write(outputBytes); //encrypted file
        }
    }
    public static void decryptFile(String inputFile, String outputFile, SecretKeySpec secretKey) throws Exception {
        FileInputStream inputStream = new FileInputStream(inputFile);

        byte[] iv = new byte[BLOCK_SIZE];
        inputStream.read(iv); // Read IV from the start of the file
        IvParameterSpec ivParameterSpec = new IvParameterSpec(iv);

        byte[] fileContent = inputStream.readAllBytes(); //Reads the remaining bytes of inputFile (i.e., the encrypted content) into fileContent.

        Cipher cipher = Cipher.getInstance(TRANSFORMATION);
        cipher.init(Cipher.DECRYPT_MODE, secretKey, ivParameterSpec);

        byte[] outputBytes = cipher.doFinal(fileContent); //storing the decrypted plaintext in outputBytes.
        // Byte array outputBytes contains the decrypted file data.

        try (FileOutputStream outputStream = new FileOutputStream(outputFile)) {
            outputStream.write(outputBytes);
        }
    }

	public static void main(String[] args) {
		// TODO Auto-generated method stub
		 try {
	            String key = "mySecretKey12345"; // Change it to any key you prefer
	            SecretKeySpec secretKey = getKey(key);

	            String inputFile = "testfile.png"; // File to encrypt
	            String encryptedFile = "encryptedfile.png";
	            String decryptedFile = "decryptedfile.png";
	            
	           

	            // Encrypt the file
	            encryptFile(inputFile, encryptedFile, secretKey);
	            System.out.println("File Encrypted Successfully.");

	            // Decrypt the file
	            decryptFile(encryptedFile, decryptedFile, secretKey);
	            System.out.println("File Decrypted Successfully.");

	        } catch (Exception e) {
	            e.printStackTrace();
	        }
	}

}
