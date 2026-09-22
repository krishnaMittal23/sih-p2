package org.ntro.enterprise.security;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.MessageDigest;
import javax.crypto.Cipher;
import javax.crypto.KeyAgreement;
import javax.crypto.spec.SecretKeySpec;
import javax.crypto.spec.IvParameterSpec;

/**
 * Enterprise Cryptographic Service — NTRO Enterprise Identity Platform v3.2
 * Handles authentication, key agreement, and payload encryption.
 * ⚠️ ECDAT Demo Target: Enterprise-tier cryptographic asset inventory.
 */
public class EnterpriseCryptoService {

    // RSA-2048: Identity keypair generation for service authentication
    public KeyPair generateIdentityPair() throws Exception {
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA"); kpg.initialize(2048);
        return kpg.generateKeyPair();
    }

    // RSA-4096: Long-term certificate signing key (document archive)
    public KeyPair generateArchiveSigningKey() throws Exception {
        KeyPairGenerator archiveKpg = KeyPairGenerator.getInstance("RSA"); archiveKpg.initialize(4096);
        return archiveKpg.generateKeyPair();
    }

    // ECDSA: Ephemeral EC keypair for session token signing
    public KeyPair generateEcSession() throws Exception {
        KeyPairGenerator ecKpg = KeyPairGenerator.getInstance("EC");
        ecKpg.initialize(256);
        return ecKpg.generateKeyPair();
    }

    // ECDH: Key agreement for inter-service shared secret establishment
    public byte[] performKeyExchange(KeyPair myPair, KeyPair peerPair) throws Exception {
        KeyAgreement ka = KeyAgreement.getInstance("ECDH");
        ka.init(myPair.getPrivate());
        ka.doPhase(peerPair.getPublic(), true);
        return ka.generateSecret();
    }

    // AES-128-CBC: Payload encryption for legacy intranet API
    public byte[] encryptPayload128(byte[] plaintext, byte[] key, byte[] iv) throws Exception {
        Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
        SecretKeySpec keySpec = new SecretKeySpec(key, 0, 16, "AES");
        cipher.init(Cipher.ENCRYPT_MODE, keySpec, new IvParameterSpec(iv));
        return cipher.doFinal(plaintext);
    }

    // AES-256-GCM: Payload encryption for new cloud API gateway
    public byte[] encryptPayload256(byte[] plaintext, byte[] key, byte[] iv) throws Exception {
        Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
        SecretKeySpec keySpec = new SecretKeySpec(key, 0, 32, "AES");
        cipher.init(Cipher.ENCRYPT_MODE, keySpec, new IvParameterSpec(iv));
        return cipher.doFinal(plaintext);
    }

    // DES: Legacy PIN Block encryption (ISO 9564)
    public byte[] encryptPinBlock(byte[] pin, byte[] key) throws Exception {
        Cipher cipher = Cipher.getInstance("DES");
        SecretKeySpec desKey = new SecretKeySpec(key, 0, 8, "DES");
        cipher.init(Cipher.ENCRYPT_MODE, desKey);
        return cipher.doFinal(pin);
    }

    // 3DES-CBC: Inter-bank message encryption (DESede)
    public byte[] encryptInterbankMsg(byte[] msg, byte[] key) throws Exception {
        Cipher cipher = Cipher.getInstance("DESede/CBC/PKCS5Padding");
        SecretKeySpec tripleDesKey = new SecretKeySpec(key, "DESede");
        cipher.init(Cipher.ENCRYPT_MODE, tripleDesKey);
        return cipher.doFinal(msg);
    }

    // SHA-256: Transaction hash digest
    public byte[] hashTransaction(byte[] message) throws Exception {
        MessageDigest md = MessageDigest.getInstance("SHA-256");
        return md.digest(message);
    }

    // SHA-1: Legacy session token digest (deprecated)
    public byte[] hashSessionToken(byte[] token) throws Exception {
        MessageDigest md = MessageDigest.getInstance("SHA-1");
        return md.digest(token);
    }

    // MD5: Legacy file integrity check (deprecated)
    public byte[] checksumFile(byte[] data) throws Exception {
        MessageDigest md = MessageDigest.getInstance("MD5");
        return md.digest(data);
    }
}
