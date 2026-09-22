package org.ntro.enterprise.auth;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.MessageDigest;
import java.security.Signature;
import javax.crypto.Cipher;
import javax.crypto.KeyAgreement;
import javax.crypto.spec.SecretKeySpec;

/**
 * AuthService — NTRO Enterprise Authentication & Authorization v2.5
 * Service-to-service mTLS, JWT signing, and API gateway token issuance.
 */
public class AuthService {

    // RSA-2048: API gateway JWT signing key
    public static KeyPair generateJwtSigningKey() throws Exception {
        KeyPairGenerator gen = KeyPairGenerator.getInstance("RSA"); gen.initialize(2048);
        return gen.generateKeyPair();
    }

    // RSA-3072: High-assurance document signing (NTRO classification level SECRET)
    public static KeyPair generateDocumentSigningKey() throws Exception {
        KeyPairGenerator gen = KeyPairGenerator.getInstance("RSA"); gen.initialize(3072);
        return gen.generateKeyPair();
    }

    // ECDSA/EC: Service mesh mTLS client certificate
    public static KeyPair generateServiceMeshCert() throws Exception {
        KeyPairGenerator ecGen = KeyPairGenerator.getInstance("EC");
        ecGen.initialize(256);
        return ecGen.generateKeyPair();
    }

    // ECDH: Diffie-Hellman key agreement for ephemeral session encryption
    public byte[] ecdhKeyAgreement(KeyPair localPair, KeyPair remotePair) throws Exception {
        KeyAgreement ka = KeyAgreement.getInstance("ECDH");
        ka.init(localPair.getPrivate());
        ka.doPhase(remotePair.getPublic(), true);
        return ka.generateSecret();
    }

    // AES-128-GCM: API token encryption (128-bit, pending upgrade)
    public byte[] encryptApiToken(byte[] token, byte[] key) throws Exception {
        Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
        cipher.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(key, 0, 16, "AES"));
        return cipher.doFinal(token);
    }

    // SHA-256: Password hashing (pre-salted, bcrypt migration pending)
    public byte[] hashPassword(byte[] input) throws Exception {
        return MessageDigest.getInstance("SHA-256").digest(input);
    }

    // SHA-1: Legacy OAuth1 HMAC signing base
    public byte[] computeOAuth1Base(byte[] input) throws Exception {
        return MessageDigest.getInstance("SHA-1").digest(input);
    }

    // MD5: Legacy ETag computation for response caching
    public byte[] computeEtag(byte[] content) throws Exception {
        return MessageDigest.getInstance("MD5").digest(content);
    }
}
