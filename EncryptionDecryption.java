package projectcrypto;

import java.security.*;
import javax.crypto.*;
import javax.crypto.spec.SecretKeySpec;
import java.util.Scanner;

public class EncryptionDecryption {
    private static final String ALGORITHM = "AES";
    private static final String RSA_ALGORITHM = "RSA";
    private static Key aesKey;

    public static void main(String[] args) throws Exception {
        Scanner scanner = new Scanner(System.in);
        System.out.println("Enter data to encrypt: ");
        String data = scanner.nextLine();

        // Encrypt the data using AES
        aesKey = new SecretKeySpec("mysecretkey12345".getBytes(), ALGORITHM);
        Cipher aesCipher = Cipher.getInstance(ALGORITHM);
        aesCipher.init(Cipher.ENCRYPT_MODE, aesKey);
        byte[] aesEncryptedData = aesCipher.doFinal(data.getBytes());
        System.out.println("AES Encrypted data: " + new String(aesEncryptedData));

        // Encrypt the AES key using RSA
        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance(RSA_ALGORITHM);
        keyPairGenerator.initialize(2048);
        KeyPair keyPair = keyPairGenerator.generateKeyPair();
        PublicKey publicKey = keyPair.getPublic();
        PrivateKey privateKey = keyPair.getPrivate();

        Cipher rsaCipher = Cipher.getInstance(RSA_ALGORITHM);
        rsaCipher.init(Cipher.ENCRYPT_MODE, publicKey);
        byte[] rsaEncryptedAesKey = rsaCipher.doFinal(aesKey.getEncoded());
        System.out.println("Encrypted AES key: " + new String(rsaEncryptedAesKey));

        // Decrypt the AES key using RSA
        rsaCipher.init(Cipher.DECRYPT_MODE, privateKey);
        byte[] decryptedAesKey = rsaCipher.doFinal(rsaEncryptedAesKey);
        SecretKey aesKey = new SecretKeySpec(decryptedAesKey, ALGORITHM);

        // Decrypt the data using AES
        aesCipher.init(Cipher.DECRYPT_MODE, aesKey);
        byte[] aesDecryptedData = aesCipher.doFinal(aesEncryptedData);
        System.out.println("AES Decrypted data: " + new String(aesDecryptedData));
    }
}