package org.example;

import org.bouncycastle.openpgp.*;
import org.bouncycastle.openpgp.jcajce.JcaPGPObjectFactory;
import org.bouncycastle.openpgp.operator.jcajce.*;
import org.bouncycastle.openpgp.operator.PBESecretKeyDecryptor;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.util.io.Streams;

import java.io.*;
import java.nio.file.*;
import java.security.Security;
import java.util.Iterator;
import java.util.logging.Logger;
import java.security.NoSuchProviderException;


public class PGPDecryptionService {

    private static final Logger logger = Logger.getLogger(PGPDecryptionService.class.getName());

    static {
        if (Security.getProvider("BC") == null) {
            Security.addProvider(new BouncyCastleProvider());
            logger.info("BouncyCastle provider added.");
        }
    }

    public void decryptFile(String encryptedInputFileName, String privateKeyFileName, char[] passphrase, String outputFolder)
            throws IOException, PGPException, NoSuchProviderException {

        logger.info("Starting decryption process...");
        logger.info("Encrypted Input File: " + encryptedInputFileName);
        logger.info("Private Key File: " + privateKeyFileName);
        logger.info("Output File: " + outputFolder);
        logger.info("Passphrase Length: " + passphrase.length);

        InputStream encryptedInputStream = new BufferedInputStream(new FileInputStream(encryptedInputFileName));
        InputStream keyInputStream = new BufferedInputStream(new FileInputStream(privateKeyFileName));

        encryptedInputStream.mark(0);
        PGPObjectFactory pgpF = new PGPObjectFactory(PGPUtil.getDecoderStream(encryptedInputStream), new JcaKeyFingerprintCalculator());

        Object firstObject = pgpF.nextObject();
        PGPEncryptedDataList enc;
        if (firstObject instanceof PGPEncryptedDataList) {
            enc = (PGPEncryptedDataList) firstObject;
            logger.info("PGPEncryptedDataList identified in first object.");
        } else {
            enc = (PGPEncryptedDataList) pgpF.nextObject();
            logger.info("PGP marker found; moving to encrypted data list.");
        }

        Iterator<PGPEncryptedData> encryptedDataObjects = enc.getEncryptedDataObjects();
        PGPPrivateKey privateKey = null;
        PGPPublicKeyEncryptedData encryptedData = null;
        PGPSecretKeyRingCollection pgpSecretKeyRingCollection =
                new PGPSecretKeyRingCollection(PGPUtil.getDecoderStream(keyInputStream), new JcaKeyFingerprintCalculator());

        while (privateKey == null && encryptedDataObjects.hasNext()) {
            encryptedData = (PGPPublicKeyEncryptedData) encryptedDataObjects.next();
            PGPSecretKey secretKey = pgpSecretKeyRingCollection.getSecretKey(encryptedData.getKeyID());

            if (secretKey == null) {
                logger.warning("No matching secret key found for key ID: " + encryptedData.getKeyID());
                continue;
            }
            logger.info("Matching secret key found.");

            PBESecretKeyDecryptor decryptor = new JcePBESecretKeyDecryptorBuilder().setProvider("BC").build(passphrase);
            privateKey = secretKey.extractPrivateKey(decryptor);
            logger.info("Private key successfully extracted.");
        }

        if (privateKey == null) {
            throw new IllegalArgumentException("Private key not found for decryption.");
        }

        logger.info("Initializing decrypted data stream...");

        InputStream clear = encryptedData.getDataStream(new JcePublicKeyDataDecryptorFactoryBuilder()
                .setProvider("BC").build(privateKey));
        JcaPGPObjectFactory plainFact = new JcaPGPObjectFactory(clear);
        Object message = plainFact.nextObject();
        logger.info("Decrypted message received: " + message.getClass().getName());

        if (message instanceof PGPCompressedData) {
            PGPCompressedData compressedData = (PGPCompressedData) message;
            logger.info("Compressed data identified, decompressing...");
            JcaPGPObjectFactory pgpFact = new JcaPGPObjectFactory(compressedData.getDataStream());
            message = pgpFact.nextObject();
        }

        if (message instanceof PGPLiteralData) {
            PGPLiteralData literalData = (PGPLiteralData) message;
            logger.info("Literal data identified, writing to output file...");

            // Extract the original filename from the PGPLiteralData
            String originalFileName = literalData.getFileName();
            if (originalFileName.isEmpty()) {
                originalFileName = "decrypted_file";
            }
            // Build the output file path within the specified folder (removing .pgp if present)
            Path outputFilePath = Paths.get(outputFolder, originalFileName.replaceFirst("\\.pgp$", ""));
            logger.info("Decrypted file will be saved as: " + outputFilePath);

            InputStream unc = literalData.getInputStream();
            OutputStream fOut = Files.newOutputStream(outputFilePath, StandardOpenOption.CREATE);
            Streams.pipeAll(unc, fOut);
            fOut.close();
            logger.info("Decryption completed successfully. File saved at: " + outputFilePath);
        } else {
            throw new PGPException("Unexpected PGP message type: " + message.getClass().getName());
        }

        if (encryptedData.isIntegrityProtected()) {
            if (encryptedData.verify()) {
                logger.info("Data integrity check passed.");
            } else {
                logger.warning("Data integrity check failed.");
            }
        } else {
            logger.warning("No integrity check present.");
        }
    }
}
