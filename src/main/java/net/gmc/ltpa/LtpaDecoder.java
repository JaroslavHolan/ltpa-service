package net.gmc.ltpa;

import sun.misc.BASE64Decoder;

import javax.crypto.Cipher;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.DESedeKeySpec;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.security.*;
import java.security.spec.KeySpec;
import java.sql.Date;
import java.text.SimpleDateFormat;
import java.util.Arrays;
import java.util.StringTokenizer;


public class LtpaDecoder {
    private String ltpa3DESKey = "Z+Iq9Fx3fgNoHgzPDhDJgMtf84EEqaGZZqY4rz+IY/o=";
    private String ltpaPassword = "pass";
    private String ltpaPlaintext;

    private String sUserInfo = "";
    private Date dExpiry;
    private String sFullToken = "";
    private String sSignature = "";
    private static final String DES_DECRIPTING_ALGORITHM = "DESede/CBC/NoPadding"; // ECB PKCS5Padding

    public static void main(String[] args) {
        String tokenCipher = "LHBxotSyuQq+pHsDRaZnyBUFM14tlCg9SXZkorCz31IG66xi4nQwl97S4IMxaOPR3c0HArab668KGStJOAhz4Hb" +
                "QyY/sxjU549lNOD01lk2alHGqSH3X9MxnHO2kKn3ZUbJ69Z6KAbgF7DhtgVVAg1xefLP2SSyIa1R5WYOsOYXHU73PbjKXyVQsIoA" +
                "lB+CPIG+oTHuIcv4c36S7bofP2wRa6q4On7U+9Ol8vCugal+qb+sk7cS7wVWDClkazQeq5lULMrfsdMcjeW/BuXdBQir5/tPN9RA" +
                "1omJ6A48WTwhNoyQ24aGtmNIlFeRX1ybsQTJFp2D70/4WMlBZ2cUuJg==";

        try {
            LtpaDecoder decoder = new LtpaDecoder(tokenCipher);
            System.out.println("UserInfo: " + decoder.getUserInfo());
            System.out.println("Expiry: " + decoder.getExpiryDate());
            System.out.println("Full token: " + decoder.getFullToken());
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    public LtpaDecoder(String fulltoken) throws Exception {
        byte[] secretKey = getSecretKey(ltpa3DESKey, ltpaPassword);
        ltpaPlaintext = new String(decryptLtpaToken(fulltoken, secretKey));


        System.out.println("LTPA plain text = " + ltpaPlaintext);
        //extractTokenData(ltpaPlaintext);
    }

    private void extractTokenData(String token) {
        System.out.println("\n");
        StringTokenizer st = new StringTokenizer(token, "%");

        sUserInfo = st.nextToken();
        String sExpires = st.nextToken();
        sSignature = st.nextToken();
        dExpiry = new Date(Long.parseLong(sExpires));
        sFullToken = token;
    }

    public String getSignature() {
        return sSignature;
    }

    public String getFullToken() {
        return sFullToken;
    }

    public String getUserInfo() {
        return sUserInfo;
    }

    public String getLtpaPlainText() {
        return ltpaPlaintext;
    }

    public String getExpiryDate() {
        SimpleDateFormat sdf = new SimpleDateFormat("yyyy-MM-dd HH:mm:ss z");
        return sdf.format(dExpiry);
    }

    private byte[] getSecretKey(String shared3DES, String password) throws Exception {
        MessageDigest md = MessageDigest.getInstance("SHA");
        md.update(password.getBytes());
        byte[] hash3DES = new byte[24];
        System.arraycopy(md.digest(), 0, hash3DES, 0, 20);
        Arrays.fill(hash3DES, 20, 24, (byte) 0);
        // decrypt the real key and return it
        BASE64Decoder base64decoder = new BASE64Decoder();
        byte[] ciphertext = base64decoder.decodeBuffer(shared3DES);
        return decrypt(ciphertext, hash3DES);
    }

    private byte[] getSecretKey2(String ltpa3DESKey, String ltpaPassword) throws Exception {
        MessageDigest md = MessageDigest.getInstance("SHA");
        md.update(ltpaPassword.getBytes());
        byte[] hash3DES = new byte[24];
        System.arraycopy(md.digest(), 0, hash3DES, 0, 20);
        Arrays.fill(hash3DES, 20, 24, (byte) 0);

        Cipher cipher = Cipher.getInstance(DES_DECRIPTING_ALGORITHM);
        final KeySpec keySpec = new DESedeKeySpec(hash3DES);
        final SecretKey secretKey = SecretKeyFactory.getInstance("DESede").generateSecret(keySpec);

        cipher.init(Cipher.DECRYPT_MODE, secretKey);

        BASE64Decoder base64decoder = new BASE64Decoder();
        byte[] decodedBase64 = base64decoder.decodeBuffer(ltpa3DESKey);
        byte[] secret = cipher.doFinal(decodedBase64);

        return secret;
    }

    public byte[] decryptLtpaToken(String encryptedLtpaToken, byte[] key) throws Exception {
        BASE64Decoder base64decoder = new BASE64Decoder();
        final byte[] ltpaByteArray = base64decoder.decodeBuffer(encryptedLtpaToken);
        return decrypt(ltpaByteArray, key);
    }

    public byte[] decryptLtpaToken2(String ltpaToken, byte[] secretKey) throws Exception {
        BASE64Decoder base64decoder = new BASE64Decoder();
        byte[] ltpaTokenBytes = base64decoder.decodeBuffer(ltpaToken);
        byte[] decrypted = decrypt2(ltpaTokenBytes, secretKey, DES_DECRIPTING_ALGORITHM);
        return decrypted;
    }

    private byte[] decrypt2(byte[] token, byte[] key, String algorithm) throws Exception {
        SecretKey sKey;

        if (algorithm.indexOf("AES") != -1) {
            sKey = new SecretKeySpec(key, 0, 16, "AES");
        } else {
            DESedeKeySpec kSpec = new DESedeKeySpec(key);
            SecretKeyFactory kFact = SecretKeyFactory.getInstance("DESede");
            sKey = kFact.generateSecret(kSpec);
        }

        Cipher cipher = createCipher(sKey, key, algorithm);

        return cipher.doFinal(token);
    }

    private Cipher createCipher(SecretKey sKey, byte[] key, String algorithm) throws NoSuchPaddingException,
            NoSuchAlgorithmException, InvalidAlgorithmParameterException, InvalidKeyException {
        Cipher cipher = Cipher.getInstance(algorithm);
        if (algorithm.indexOf("ECB") == -1) {
            if (algorithm.indexOf("AES") != -1) {
                IvParameterSpec ivs16 = generateIvParameterSpec(key, 16);
                cipher.init(Cipher.DECRYPT_MODE, sKey, ivs16);
            } else {
                IvParameterSpec ivs8 = generateIvParameterSpec(key, 8);
                cipher.init(Cipher.DECRYPT_MODE, sKey, ivs8);
            }
        } else {
            cipher.init(Cipher.DECRYPT_MODE, sKey);
        }
        return cipher;
    }

    private IvParameterSpec generateIvParameterSpec(byte key[], int size) {
        byte[] row = new byte[size];

        for (int i = 0; i < size; i++) {
            row[i] = key[i];
        }

        return new IvParameterSpec(row);
    }

    public byte[] decrypt(byte[] ciphertext, byte[] key) throws Exception {
        final Cipher cipher = Cipher.getInstance("DESede/ECB/NoPadding");  // PKCS5Padding
        final KeySpec keySpec = new DESedeKeySpec(key);
        final Key secretKey = SecretKeyFactory.getInstance("TripleDES").generateSecret(keySpec);

        cipher.init(Cipher.DECRYPT_MODE, secretKey);

        int length = ciphertext.length;
        System.out.println("length = " + length);

        return cipher.doFinal(ciphertext);
    }
}