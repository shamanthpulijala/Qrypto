// Benchmark corpus: Java cryptographic patterns
// Expected detections marked with comments

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.spec.IvParameterSpec;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.MessageDigest;
import java.security.Signature;

public class CryptoExamples {

    // EXPECTED: RSA, vulnerable, public-key (key generation)
    public static void generateRSA() throws Exception {
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA");
        kpg.initialize(2048);
        KeyPair kp = kpg.generateKeyPair();
    }

    // EXPECTED: ECDSA, vulnerable, signature
    public static void signData() throws Exception {
        Signature sig = Signature.getInstance("SHA256withECDSA");
        sig.initSign(privateKey);
        sig.update(data);
        byte[] signature = sig.sign();
    }

    // EXPECTED: AES-256, adequate, symmetric
    public static void encryptAES() throws Exception {
        Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
        cipher.init(Cipher.ENCRYPT_MODE, key, new IvParameterSpec(iv));
    }

    // EXPECTED: SHA-256, adequate, hash
    public static void hashSHA256() throws Exception {
        MessageDigest md = MessageDigest.getInstance("SHA-256");
        byte[] digest = md.digest(data);
    }

    // EXPECTED: MD5, classical-weak, hash (critical severity)
    public static void hashMD5() throws Exception {
        MessageDigest md = MessageDigest.getInstance("MD5");
        byte[] digest = md.digest(data);
    }

    // EXPECTED: DES, classical-weak, symmetric (critical severity)
    public static void encryptDES() throws Exception {
        Cipher cipher = Cipher.getInstance("DES/ECB/PKCS5Padding");
        cipher.init(Cipher.ENCRYPT_MODE, key);
    }
}
