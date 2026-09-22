package org.ntro.enterprise.security;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.MessageDigest;
import javax.crypto.Cipher;
import javax.crypto.KeyAgreement;
import javax.crypto.spec.SecretKeySpec;
import javax.crypto.spec.IvParameterSpec;

public class EnterpriseCryptoService {

    public KeyPair generateIdentityPair() throws Exception {
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA");
        kpg.initialize(2048);
        return kpg.generateKeyPair();
    }

    public KeyPair generateEcSession() throws Exception {
        KeyPairGenerator ecKpg = KeyPairGenerator.getInstance("EC");
        ecKpg.initialize(256);
        return ecKpg.generateKeyPair();
    }

    public byte[] performKeyExchange(KeyPair myPair, KeyPair peerPair) throws Exception {
        KeyAgreement ka = KeyAgreement.getInstance("ECDH");
        ka.init(myPair.getPrivate());
        ka.doPhase(peerPair.getPublic(), true);
        return ka.generateSecret();
    }

    public byte[] encryptPayload(byte[] plaintext, byte[] key, byte[] iv) throws Exception {
        SecretKeySpec keySpec = new SecretKeySpec(key, 0, 16, "AES");
        IvParameterSpec ivSpec = new IvParameterSpec(iv);
        Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
        cipher.init(Cipher.ENCRYPT_MODE, keySpec, ivSpec);
        return cipher.doFinal(plaintext);
    }

    public byte[] hashTransaction(byte[] message) throws Exception {
        MessageDigest md = MessageDigest.getInstance("SHA-256");
        return md.digest(message);
    }
}
