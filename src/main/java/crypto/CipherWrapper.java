package crypto;

import javax.crypto.Cipher;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.lang.reflect.Constructor;
import java.lang.reflect.Field;
import java.lang.reflect.Modifier;
import java.security.MessageDigest;
import java.util.Map;

public class CipherWrapper {
    private CipherAlgorithm algorithm;
    private CipherOperationMode opMode;
    private int ivSize;

    private int keySize;

    public CipherWrapper(CipherAlgorithm algorithm, CipherOperationMode opMode){
        this.algorithm = algorithm;
        this.opMode = opMode;

        switch (algorithm) {
            case DES:
                this.keySize = 8;
                this.ivSize = 8;
                break;
            case AES128:
                this.keySize = 16;
                this.ivSize = 16;
                break;
            case AES192:
                this.keySize = 24;
                this.ivSize = 16;
                break;
            case AES256:
                this.keySize = 32;
                this.ivSize = 16;
                break;
        }
    }

    public byte[] encrypt(byte[] clean, String pass) throws Exception {

        String algString = (this.algorithm == CipherAlgorithm.DES) ? "DES" : "AES";
        String cypherTransform = algString + "/" + this.opMode.toString() + "/PKCS5Padding";

        Cipher cipher = Cipher.getInstance(cypherTransform);
        MessageDigest md = MessageDigest.getInstance("SHA-256");

        final byte[][] keyAndIV = EVP_BytesToKey(this.keySize, cipher.getBlockSize(), md, pass.getBytes(), 1);
        SecretKeySpec key = new SecretKeySpec(keyAndIV[0], algString);
        IvParameterSpec iv = new IvParameterSpec(keyAndIV[1]);

        if(this.opMode != CipherOperationMode.ECB)
            cipher.init(Cipher.ENCRYPT_MODE, key, iv);
        else
            cipher.init(Cipher.ENCRYPT_MODE, key);

        return cipher.doFinal(clean);
    }

    public byte[] decrypt(byte[] encryptedBytes, String pass) throws Exception {

        String algString = (this.algorithm == CipherAlgorithm.DES) ? "DES" : "AES";
        String cypherTransform = algString + "/" + this.opMode.toString() + "/PKCS5Padding";

        Cipher cipher = Cipher.getInstance(cypherTransform);
        MessageDigest md = MessageDigest.getInstance("SHA-256");

        final byte[][] keyAndIV = EVP_BytesToKey(this.keySize, cipher.getBlockSize(), md, pass.getBytes(), 1);
        SecretKeySpec key = new SecretKeySpec(keyAndIV[0], algString);
        IvParameterSpec iv = new IvParameterSpec(keyAndIV[1]);

        if(this.opMode != CipherOperationMode.ECB)
            cipher.init(Cipher.DECRYPT_MODE, key, iv);
        else
            cipher.init(Cipher.DECRYPT_MODE, key);

        return cipher.doFinal(encryptedBytes);
    }

    public static void init(){

        //This is so shitty...
        String errorString = "Failed manually overriding key-length permissions.";
        int newMaxKeyLength;
        try {
            if ((newMaxKeyLength = Cipher.getMaxAllowedKeyLength("AES")) < 256) {
                Class c = Class.forName("javax.crypto.CryptoAllPermissionCollection");
                Constructor con = c.getDeclaredConstructor();
                con.setAccessible(true);
                Object allPermissionCollection = con.newInstance();
                Field f = c.getDeclaredField("all_allowed");
                f.setAccessible(true);
                f.setBoolean(allPermissionCollection, true);

                c = Class.forName("javax.crypto.CryptoPermissions");
                con = c.getDeclaredConstructor();
                con.setAccessible(true);
                Object allPermissions = con.newInstance();
                f = c.getDeclaredField("perms");
                f.setAccessible(true);
                ((Map) f.get(allPermissions)).put("*", allPermissionCollection);

                c = Class.forName("javax.crypto.JceSecurityManager");
                f = c.getDeclaredField("defaultPolicy");
                f.setAccessible(true);
                Field mf = Field.class.getDeclaredField("modifiers");
                mf.setAccessible(true);
                mf.setInt(f, f.getModifiers() & ~Modifier.FINAL);
                f.set(null, allPermissions);

                newMaxKeyLength = Cipher.getMaxAllowedKeyLength("AES");
            }
        } catch (Exception e) {
            throw new RuntimeException(errorString, e);
        }
        if (newMaxKeyLength < 256)
            throw new RuntimeException(errorString);
    }

    public static byte[][] EVP_BytesToKey(int key_len, int iv_len, MessageDigest md, byte[] data, int count) {
        byte[][] both = new byte[2][];
        byte[] key = new byte[key_len];
        int key_ix = 0;
        byte[] iv = new byte[iv_len];
        int iv_ix = 0;
        both[0] = key;
        both[1] = iv;
        byte[] md_buf = null;
        int nkey = key_len;
        int niv = iv_len;
        int i = 0;
        if (data == null) {
            return both;
        }
        int addmd = 0;
        for (;;) {
            md.reset();
            if (addmd++ > 0) {
                md.update(md_buf);
            }
            md.update(data);
            md_buf = md.digest();
            for (i = 1; i < count; i++) {
                md.reset();
                md.update(md_buf);
                md_buf = md.digest();
            }
            i = 0;
            if (nkey > 0) {
                for (;;) {
                    if (nkey == 0)
                        break;
                    if (i == md_buf.length)
                        break;
                    key[key_ix++] = md_buf[i];
                    nkey--;
                    i++;
                }
            }
            if (niv > 0 && i != md_buf.length) {
                for (;;) {
                    if (niv == 0)
                        break;
                    if (i == md_buf.length)
                        break;
                    iv[iv_ix++] = md_buf[i];
                    niv--;
                    i++;
                }
            }
            if (nkey == 0 && niv == 0) {
                break;
            }
        }
        for (i = 0; i < md_buf.length; i++) {
            md_buf[i] = 0;
        }
        return both;
    }

    public CipherAlgorithm getAlgorithm() {
        return algorithm;
    }

    public CipherOperationMode getOperationMode() {
        return opMode;
    }

}
