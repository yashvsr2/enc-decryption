package org.example;

import org.bouncycastle.bcpg.ArmoredOutputStream;
import org.bouncycastle.bcpg.CompressionAlgorithmTags;
import org.bouncycastle.openpgp.*;
import org.bouncycastle.openpgp.operator.jcajce.JcaKeyFingerprintCalculator;
import org.bouncycastle.openpgp.operator.jcajce.JcePGPDataEncryptorBuilder;
import org.bouncycastle.openpgp.operator.jcajce.JcePublicKeyKeyEncryptionMethodGenerator;

import java.io.*;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.NoSuchProviderException;
import java.security.SecureRandom;
import java.util.logging.Level;
import java.util.logging.Logger;

public class PGPEncryptionService {

    private static final Logger logger = Logger.getLogger(PGPEncryptionService.class.getName());

    public void encryptFile(String outputFolder, String inputFileName, String pubKeyFileName, boolean armor, boolean withIntegrityCheck)
            throws IOException, NoSuchProviderException, PGPException {

        logger.info("Starting file encryption...");
        logger.info("Input File: " + inputFileName);
        logger.info("Public Key File: " + pubKeyFileName);
        logger.info("Output Folder: " + outputFolder);
        logger.info("Armor: " + armor + ", Integrity Check: " + withIntegrityCheck);

        // Extract the filename from the input file path and append .pgp
        String inputFileNameOnly = Paths.get(inputFileName).getFileName().toString();
        String outputFileName = inputFileNameOnly + ".pgp";
        Path outputFilePath = Paths.get(outputFolder, outputFileName);
        logger.info("Encrypted file will be saved as: " + outputFilePath);

        try (OutputStream out = new BufferedOutputStream(new FileOutputStream(outputFilePath.toFile()));
             InputStream publicKeyInputStream = new BufferedInputStream(new FileInputStream(pubKeyFileName))) {

            OutputStream finalOut = armor ? new ArmoredOutputStream(out) : out;
            logger.info("Output stream prepared" + (armor ? " with armor." : "."));

            PGPPublicKey publicKey = getEncryptionKey(publicKeyInputStream);
            if (publicKey == null) {
                throw new IllegalArgumentException("No encryption key found in the public key file.");
            }
            logger.info("Encryption key extracted successfully.");

            byte[] compressedData = compressFile(inputFileName);
            logger.info("Input file compressed successfully.");

            encryptData(finalOut, compressedData, publicKey, withIntegrityCheck);
            logger.info("File encrypted and written to output successfully.");
        } catch (Exception e) {
            logger.log(Level.SEVERE, "Error during encryption", e);
            throw e;
        }
    }

    private PGPPublicKey getEncryptionKey(InputStream publicKeyInputStream) throws IOException, PGPException {
        logger.info("Extracting public key from the provided key file...");
        PGPPublicKeyRingCollection pgpPubRings = new PGPPublicKeyRingCollection(
                PGPUtil.getDecoderStream(publicKeyInputStream), new JcaKeyFingerprintCalculator());

        for (PGPPublicKeyRing keyRing : pgpPubRings) {
            for (PGPPublicKey key : keyRing) {
                if (key.isEncryptionKey()) {
                    logger.info("Encryption key found.");
                    return key;
                }
            }
        }
        logger.warning("No encryption key found in the provided key file.");
        return null;
    }

    private byte[] compressFile(String inputFileName) throws IOException, PGPException {
        logger.info("Compressing the input file: " + inputFileName);
        try (ByteArrayOutputStream bOut = new ByteArrayOutputStream()) {
            PGPCompressedDataGenerator compressor = new PGPCompressedDataGenerator(CompressionAlgorithmTags.ZIP);
            try (OutputStream compressedOut = compressor.open(bOut)) {
                PGPUtil.writeFileToLiteralData(compressedOut, PGPLiteralData.BINARY, new File(inputFileName));
            }
            return bOut.toByteArray();
        }
    }

    private void encryptData(OutputStream out, byte[] data, PGPPublicKey publicKey, boolean withIntegrityCheck)
            throws IOException, PGPException {

        logger.info("Initializing encryption...");
        PGPEncryptedDataGenerator encGen = new PGPEncryptedDataGenerator(
                new JcePGPDataEncryptorBuilder(PGPEncryptedData.CAST5)
                        .setWithIntegrityPacket(withIntegrityCheck)
                        .setSecureRandom(new SecureRandom())
                        .setProvider("BC"));

        encGen.addMethod(new JcePublicKeyKeyEncryptionMethodGenerator(publicKey).setProvider("BC"));

        try (OutputStream encryptedOut = encGen.open(out, data.length)) {
            logger.info("Writing encrypted data to the output file...");
            encryptedOut.write(data);
        }
    }
}

