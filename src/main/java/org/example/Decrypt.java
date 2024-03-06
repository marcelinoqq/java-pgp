package org.example;

import org.bouncycastle.openpgp.*;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.openpgp.jcajce.JcaPGPObjectFactory;
import org.bouncycastle.openpgp.operator.PBESecretKeyDecryptor;
import org.bouncycastle.openpgp.operator.jcajce.JcaKeyFingerprintCalculator;
import org.bouncycastle.openpgp.operator.jcajce.JcePBESecretKeyDecryptorBuilder;
import org.bouncycastle.openpgp.operator.jcajce.JcePublicKeyDataDecryptorFactoryBuilder;

import java.io.*;
import java.security.Security;
import java.util.Iterator;
import java.util.Objects;
import java.util.logging.Level;
import java.util.logging.Logger;

public class Decrypt {

    private static final Logger LOGGER = Logger.getLogger(Decrypt.class.getName());
    private static final String INPUT_DIRECTORY = "C:\\Users\\kmarcelino\\Desktop\\bbac\\encrypted_files";
    private static final String OUTPUT_DIRECTORY = "C:\\Users\\kmarcelino\\Desktop\\bbac\\decrypted_files";
    private static final String PRIVATE_KEY_PATH = "C:\\Users\\kmarcelino\\Desktop\\bbac\\BBACPrivate.asc.gpg";

    public static void main(String[] args) {
        Security.addProvider(new BouncyCastleProvider());
        LOGGER.info("\nTest with Java version: " + Runtime.version() +
                " BouncyCastle Version: " + Security.getProvider("BC") + "\n");

        File inputDir = new File(INPUT_DIRECTORY);
        File[] encryptedFiles = Objects.requireNonNull(inputDir.listFiles((dir, name) -> name.endsWith(".gpg")));

        for (File encryptedFile : encryptedFiles) {
            decryptAndSave(encryptedFile);
        }
    }

    private static void decryptAndSave(File encryptedFile) {
        try {
            String outputFileName = getOutputFileName(encryptedFile);
            byte[] encryptedData = readBytesFromFile(encryptedFile);
            byte[] decryptedData = decrypt(getDecodedInputStream(encryptedData), new FileInputStream(PRIVATE_KEY_PATH),
                    "ENC(AFV3c5ub8vKIzyvZZRkexaLwQDJUsFPAGCPergT3pm+hSIVoIF+L6g==)".toCharArray());

            writeBytesToFile(outputFileName, decryptedData);

            LOGGER.info("Decrypted and saved to: " + outputFileName);
        } catch (IOException | PGPException e) {
            LOGGER.log(Level.SEVERE, "Error during decryption and saving for file: " + encryptedFile.getName(), e);
        }
    }

    private static String getOutputFileName(File encryptedFile) {
        return OUTPUT_DIRECTORY + File.separator + encryptedFile.getName().replace(".gpg", "_decrypted.txt");
    }

    public static byte[] readBytesFromFile(File file) throws IOException {
        return getBytes(file);
    }

    static byte[] getBytes(File file) throws IOException {
        try (FileInputStream fileInputStream = new FileInputStream(file)) {
            long fileSize = file.length();
            if (fileSize > Integer.MAX_VALUE) {
                throw new IOException("File is too large to read into a byte array");
            }

            int fileLength = (int) fileSize;
            byte[] bytes = new byte[fileLength];
            int bytesRead = fileInputStream.read(bytes);

            if (bytesRead < fileLength) {
                throw new IOException("Could not read the entire file");
            }

            return bytes;
        }
    }

    public static void writeBytesToFile(String fileName, byte[] data) throws IOException {
        try (FileOutputStream fileOutputStream = new FileOutputStream(fileName)) {
            fileOutputStream.write(data);
        }
    }

    public static byte[] decrypt(InputStream encryptedStream, InputStream keyIn, char[] password)
            throws IOException, PGPException {
        try (InputStream decodedKeyStream = getDecodedInputStream(keyIn.readAllBytes());
             ByteArrayOutputStream out = new ByteArrayOutputStream()) {

            JcaPGPObjectFactory pgpF = new JcaPGPObjectFactory(encryptedStream);
            PGPEncryptedDataList enc = (PGPEncryptedDataList) pgpF.nextObject();

            Iterator<PGPEncryptedData> it = enc.getEncryptedDataObjects();
            PGPPrivateKey sKey = null;
            PGPPublicKeyEncryptedData pbe = null;

            PGPSecretKeyRingCollection pgpSec = new PGPSecretKeyRingCollection(decodedKeyStream, new JcaKeyFingerprintCalculator());

            while (sKey == null && it.hasNext()) {
                pbe = (PGPPublicKeyEncryptedData) it.next();
                sKey = findSecretKey(pgpSec, pbe.getKeyID(), password);
            }

            if (sKey == null) {
                throw new PGPException("Secret key for message not found.");
            }

            try (InputStream clear = pbe.getDataStream(new JcePublicKeyDataDecryptorFactoryBuilder().setProvider("BC").build(sKey))) {
                JcaPGPObjectFactory plainFact = new JcaPGPObjectFactory(clear);
                PGPCompressedData cData = (PGPCompressedData) plainFact.nextObject();
                JcaPGPObjectFactory pgpFact = new JcaPGPObjectFactory(cData.getDataStream());
                PGPLiteralData ld = (PGPLiteralData) pgpFact.nextObject();
                InputStream unc = ld.getInputStream();

                unc.transferTo(out);
            }

            return out.toByteArray();
        }
    }

    private static PGPPrivateKey findSecretKey(PGPSecretKeyRingCollection pgpSec, long keyID, char[] pass)
            throws PGPException {
        PGPSecretKey pgpSecKey = pgpSec.getSecretKey(keyID);

        if (pgpSecKey == null) {
            return null;
        }

        PBESecretKeyDecryptor decryptor = new JcePBESecretKeyDecryptorBuilder().setProvider("BC").build(pass);

        return pgpSecKey.extractPrivateKey(decryptor);
    }

    public static InputStream getDecodedInputStream(byte[] data) throws IOException {
        return PGPUtil.getDecoderStream(new ByteArrayInputStream(data));
    }
}
