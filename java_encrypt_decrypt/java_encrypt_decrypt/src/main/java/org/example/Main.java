package org.example;
import org.bouncycastle.openpgp.PGPException;
import java.io.IOException;
import java.security.NoSuchProviderException;
import java.util.logging.Logger;


public class Main {
    private static final Logger logger = Logger.getLogger(Main.class.getName());
    private static final PGPDecryptionService decryptionService = new PGPDecryptionService();
    private static final PGPEncryptionService encryptionService = new PGPEncryptionService();

    public static void main(String[] args) {
        PGPDecryptionService();
        performEncryption();
    }

    private static void PGPDecryptionService() {
        String encryptedFile = "C:/Users/yashvardhan.rathore_/Downloads/sample_bta2.csv.pgp";
        String privateKeyFile = "C:/Users/yashvardhan.rathore_/Downloads/private_key.asc";
        String outputFolder = "C:/Users/yashvardhan.rathore_/Documents";
        char[] passphrase = "SIM4Eight".toCharArray();

        try {
            logger.info("Starting decryption process");
            decryptionService.decryptFile(encryptedFile, privateKeyFile, passphrase, outputFolder);
            logger.info("Decryption completed successfully.");
            System.out.println("Decryption successful!");
        } catch (IOException | NoSuchProviderException | PGPException e) {
            logger.severe("Error during decryption: " + e.getMessage());
            System.out.println("Decryption failed: " + e.getMessage());
        }
    }

    private static void performEncryption() {
        String inputFileName = "C:/Users/yashvardhan.rathore_/Downloads/sample_data.csv";
        String publicKeyFile = "C:/Users/yashvardhan.rathore_/Downloads/public_key.asc";
        String outputFileName = "C:/Users/yashvardhan.rathore_/Downloads";
        boolean armor = true;
        boolean withIntegrityCheck = true;

        try {
            logger.info("Starting encryption process...");
            encryptionService.encryptFile(outputFileName, inputFileName, publicKeyFile, armor, withIntegrityCheck);
            logger.info("Encryption completed successfully.");
            System.out.println("Encryption successful!");
        } catch (IOException | NoSuchProviderException | PGPException e) {
            logger.severe("Error during encryption: " + e.getMessage());
            System.out.println("Encryption failed: " + e.getMessage());
        }
    }
}