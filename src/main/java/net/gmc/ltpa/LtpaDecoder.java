package net.gmc.ltpa;

import sun.misc.BASE64Decoder;

import javax.crypto.Cipher;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.DESedeKeySpec;
import java.security.Key;
import java.security.MessageDigest;
import java.security.spec.KeySpec;
import java.sql.Date;
import java.text.SimpleDateFormat;
import java.util.Arrays;
import java.util.StringTokenizer;


//The shared 3DES key is itself encrypted using the SHA hash value of the LTPA password (padded with 0x0 upto 24 bytes).

public class LtpaDecoder {
    private String ltpa3DESKey = "QqeSTtiKQhjU6MPqS02U5ADZi65HQf+4ZqY4rz+IY/o\\=";
    private String ltpaPassword = "pass";

    private String sUserInfo = "";
    private Date dExpiry;
    private String sFullToken = "";
    private String sSignature = "";

    public static void main(String[] args) {
        String tokenCipher = "AAECAzU3YjQ1MWM0NTdiNDY5MzRNeSBUZXN0IFVzZXKJ2NS4iw2JTsJywolTa5pa6Y5kAA==";

        try {
            LtpaDecoder t = new LtpaDecoder(tokenCipher);
            System.out.println("UserInfo: " + t.getUserInfo());
            System.out.println("Expiry: " + t.getExpiryDate());
            System.out.println("Full token: " + t.getFullToken());
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    public LtpaDecoder(String fulltoken) throws Exception {
        byte[] secretKey = getSecretKey(this.ltpa3DESKey, this.ltpaPassword);
        String ltpaPlaintext = new String(decryptLtpaToken(fulltoken, secretKey));

        extractTokenData(ltpaPlaintext);
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

    public byte[] decryptLtpaToken(String encryptedLtpaToken, byte[] key) throws Exception {
        BASE64Decoder base64decoder = new BASE64Decoder();
        final byte[] ltpaByteArray = base64decoder.decodeBuffer(encryptedLtpaToken);
        return decrypt(ltpaByteArray, key);
    }

    public byte[] decrypt(byte[] ciphertext, byte[] key) throws Exception {
        final Cipher cipher = Cipher.getInstance("DESede/ECB/PKCS5Padding");
        final KeySpec keySpec = new DESedeKeySpec(key);
        final Key secretKey = SecretKeyFactory.getInstance("TripleDES").generateSecret(keySpec);

        cipher.init(Cipher.DECRYPT_MODE, secretKey);
        return cipher.doFinal(ciphertext);
    }
}