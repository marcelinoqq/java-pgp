package org.example;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.openpgp.*;
import org.bouncycastle.openpgp.jcajce.JcaPGPObjectFactory;
import org.bouncycastle.openpgp.operator.PBESecretKeyDecryptor;
import org.bouncycastle.openpgp.operator.PGPDataEncryptorBuilder;
import org.bouncycastle.openpgp.operator.jcajce.*;
import org.bouncycastle.openpgp.operator.jcajce.JcePGPDataEncryptorBuilder;

import java.io.*;
import java.security.Security;
import java.util.Iterator;
import java.util.Objects;
import java.util.logging.Level;
import java.util.logging.Logger;

import static org.example.Decrypt.getBytes;

public class Encrypt {

    private static final Logger LOGGER = Logger.getLogger(Encrypt.class.getName());
    private static final String INPUT_DIRECTORY = "C:\\Users\\kmarcelino\\Desktop\\bbac\\decrypted_files";
    private static final String OUTPUT_DIRECTORY = "C:\\Users\\kmarcelino\\Desktop\\bbac\\encrypted_files";
    private static final String PUBLIC_KEY_FILE = "C:\\Users\\kmarcelino\\Desktop\\bbac\\BBACPublic.asc";
    private static final String PRIVATE_KEY_FILE = "C:\\Users\\kmarcelino\\Desktop\\bbac\\BBACPrivate.asc";

    public static void main(String[] args) {
        Security.addProvider(new BouncyCastleProvider());
        LOGGER.info("\nTest with Java version: " + Runtime.version() +
                " BouncyCastle Version: " + Security.getProvider("BC") + "\n");

        File inputDir = new File(INPUT_DIRECTORY);
        File[] files = Objects.requireNonNull(inputDir.listFiles());

        for (File file : files) {
            if (file.getName().endsWith(".txt")) {
                encryptAndSave(file);
            } else if (file.getName().endsWith(".gpg")) {
                decryptAndSave(file);
            }
        }
    }

    private static void encryptAndSave(File plaintextFile) {
        try {
            String outputFileName = OUTPUT_DIRECTORY + File.separator +
                    plaintextFile.getName().replace(".txt", "_encrypted.gpg");

            byte[] plaintextData = readBytesFromFile(plaintextFile);
            byte[] encryptedData = encrypt(
                    plaintextData,
                    new FileInputStream(PUBLIC_KEY_FILE),
                    "ENC(AFV3c5ub8vKIzyvZZRkexaLwQDJUsFPAGCPergT3pm+hSIVoIF+L6g==)".toCharArray()
            );

            writeBytesToFile(outputFileName, encryptedData);

            LOGGER.info("Encrypted and saved to: " + outputFileName);
        } catch (IOException | PGPException e) {
            LOGGER.log(Level.SEVERE, "Error during encryption and saving", e);
        }
    }

    private static void decryptAndSave(File encryptedFile) {
        try {
            String outputFileName = OUTPUT_DIRECTORY + File.separator +
                    encryptedFile.getName().replace(".gpg", "_decrypted.txt");

            byte[] encryptedData = readBytesFromFile(encryptedFile);
            byte[] decryptedData = decrypt(
                    new ByteArrayInputStream(encryptedData),
                    new FileInputStream(PRIVATE_KEY_FILE),
                    "ENC(AFV3c5ub8vKIzyvZZRkexaLwQDJUsFPAGCPergT3pm+hSIVoIF+L6g==)".toCharArray()
            );

            writeBytesToFile(outputFileName, decryptedData);

            LOGGER.info("Decrypted and saved to: " + outputFileName);
        } catch (IOException | PGPException e) {
            LOGGER.log(Level.SEVERE, "Error during decryption and saving", e);
        }
    }

    public static byte[] encrypt(byte[] data, InputStream publicKeyIn, char[] password)
            throws IOException, PGPException {
        try (ByteArrayOutputStream out = new ByteArrayOutputStream();
             ByteArrayInputStream ignored = new ByteArrayInputStream(readBytesFromFile(new File(PRIVATE_KEY_FILE)))) {

            LOGGER.info("Public Key Content: " + new String(readBytesFromFile(new File(PUBLIC_KEY_FILE))));

            PGPPublicKeyRingCollection pgpPub = new PGPPublicKeyRingCollection(publicKeyIn, new JcaKeyFingerprintCalculator());
            Iterator<PGPPublicKeyRing> keyRingIter = pgpPub.getKeyRings();

            PGPPublicKey key = null;
            while (key == null && keyRingIter.hasNext()) {
                PGPPublicKeyRing keyRing = keyRingIter.next();
                Iterator<PGPPublicKey> keyIter = keyRing.getPublicKeys();
                while (key == null && keyIter.hasNext()) {
                    PGPPublicKey k = keyIter.next();
                    if (k.isEncryptionKey()) {
                        key = k;
                    }
                }
            }

            if (key == null) {
                throw new IllegalArgumentException("Public key for encryption not found.");
            }

            // Debug: Print information about the found public key
            LOGGER.info("Found public key: " + key.getKeyID() + ", Algorithm: " + key.getAlgorithm());

            JcePGPDataEncryptorBuilder encryptorBuilder = new JcePGPDataEncryptorBuilder(PGPEncryptedData.AES_256)
                    .setWithIntegrityPacket(true)
                    .setSecureRandom(((PGPDataEncryptorBuilder) Security.getProvider("BC")).getSecureRandom())
                    .setProvider("BC");

            PGPEncryptedDataGenerator encryptedDataGenerator = new PGPEncryptedDataGenerator(encryptorBuilder);
            JcePublicKeyKeyEncryptionMethodGenerator keyEncryptionMethodGenerator = new JcePublicKeyKeyEncryptionMethodGenerator(key)
                    .setProvider("BC");

            encryptedDataGenerator.addMethod(keyEncryptionMethodGenerator);
            OutputStream encryptedOut = encryptedDataGenerator.open(out, data.length);

            encryptedOut.write(data);
            encryptedOut.close();

            return out.toByteArray();
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

    public static byte[] readBytesFromFile(File file) throws IOException {
        return getBytes(file);
    }

    public static void writeBytesToFile(String fileName, byte[] data) throws IOException {
        try (FileOutputStream fileOutputStream = new FileOutputStream(fileName)) {
            fileOutputStream.write(data);
        }
    }

    public static InputStream getDecodedInputStream(byte[] data) throws IOException {
        return PGPUtil.getDecoderStream(new ByteArrayInputStream(data));
    }
}
