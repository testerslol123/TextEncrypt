package testers.com.textencrypt;

import org.bouncycastle.crypto.BlockCipher;
import org.bouncycastle.crypto.BufferedBlockCipher;
import org.bouncycastle.crypto.CipherParameters;
import org.bouncycastle.crypto.DataLengthException;
import org.bouncycastle.crypto.InvalidCipherTextException;
import org.bouncycastle.crypto.engines.AESEngine;
import org.bouncycastle.crypto.engines.CAST6Engine;
import org.bouncycastle.crypto.engines.CamelliaEngine;
import org.bouncycastle.crypto.engines.RC6Engine;
import org.bouncycastle.crypto.engines.RijndaelEngine;
import org.bouncycastle.crypto.engines.SerpentEngine;
import org.bouncycastle.crypto.engines.Shacal2Engine;
import org.bouncycastle.crypto.engines.ThreefishEngine;
import org.bouncycastle.crypto.engines.TwofishEngine;
import org.bouncycastle.crypto.modes.CBCBlockCipher;
import org.bouncycastle.crypto.paddings.BlockCipherPadding;
import org.bouncycastle.crypto.paddings.PKCS7Padding;
import org.bouncycastle.crypto.paddings.PaddedBufferedBlockCipher;
import org.bouncycastle.crypto.params.KeyParameter;
import org.bouncycastle.crypto.params.ParametersWithIV;
import org.bouncycastle.crypto.params.TweakableBlockCipherParameters;
import org.springframework.security.crypto.keygen.KeyGenerators;
//import org.springframework.security.crypto.keygen.KeyGenerators;

import java.io.UnsupportedEncodingException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.KeySpec;

import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;

public class Encryptor {

    private int blockSize;
    private byte[] ivData;
    private BlockCipherPadding padding;
    private SecretKeyFactory factory;
    private String salt;
    private KeySpec spec;
    private SecretKey tmp;
    private KeyParameter keyParam;

    private Object[] Algs = {new AESEngine(), null, new TwofishEngine(), new CamelliaEngine(), new SerpentEngine(), new CAST6Engine(), new RC6Engine(), null, new Shacal2Engine()};

    public void setParameters(int KeySize, int alg) throws NoSuchAlgorithmException, InvalidKeySpecException
    {
        this.blockSize = 128;
        padding = new PKCS7Padding();
    }

    public void setEncParameters(int alg, String pwd, int KeySize, String mode) throws NoSuchAlgorithmException, InvalidKeySpecException
    {
        System.out.println(KeySize);
        SecureRandom r = null;

        this.ivData = new byte[128/8];
        r = new SecureRandom();
        r.nextBytes(this.ivData);

        factory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA512");

        salt = KeyGenerators.string().generateKey();
        spec = new PBEKeySpec (pwd.toCharArray(), salt.getBytes(), 65536, KeySize);
        tmp = factory.generateSecret(spec);
        keyParam = new KeyParameter(tmp.getEncoded());

    }

    public void setDecParameters(byte[] Encrypted, int alg, String pwd, int KeySize, String mode) throws InvalidKeySpecException, NoSuchAlgorithmException
    {

        this.ivData = new byte[128/8];
        System.arraycopy(Encrypted, 0, this.ivData, 0, 128/8);

        byte[] salt = new byte[16];
        System.arraycopy(Encrypted, Encrypted.length - 16 , salt, 0, 16);

        factory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA512");

        spec = new PBEKeySpec (pwd.toCharArray(), salt, 65536, KeySize);
        tmp = factory.generateSecret(spec);
        keyParam = new KeyParameter(tmp.getEncoded());

    }

    public byte[] CBCEncrypt(byte[] input, int alg) throws NoSuchAlgorithmException, InvalidKeySpecException, NoSuchPaddingException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException, UnsupportedEncodingException, DataLengthException, IllegalStateException, InvalidCipherTextException
    {
        CipherParameters cipherParams = null;
        cipherParams = new ParametersWithIV(keyParam, ivData);

        BufferedBlockCipher cipher = new PaddedBufferedBlockCipher(new CBCBlockCipher((BlockCipher) new SerpentEngine()), padding);
        cipher.reset();
        cipher.init(true, cipherParams);

        byte[] output = new byte[cipher.getOutputSize(input.length)];

        int bytesWrittenOut = cipher.processBytes(input, 0, input.length, output, 0);
        bytesWrittenOut += cipher.doFinal(output, bytesWrittenOut);

        byte[] bytesAll = new byte[ivData.length + output.length + salt.getBytes().length];
        System.arraycopy(ivData, 0, bytesAll, 0, ivData.length);
        System.arraycopy(output, 0, bytesAll, ivData.length, output.length);
        System.arraycopy(salt.getBytes(), 0, bytesAll, ivData.length + output.length, salt.getBytes().length);

        return bytesAll;
    }

    public byte[] CBCDecrypt(byte[] Encrypted, int alg) throws UnsupportedEncodingException, NoSuchAlgorithmException, InvalidKeySpecException, DataLengthException, IllegalStateException, InvalidCipherTextException
    {

        byte[] salt = new byte[16];
        System.arraycopy(Encrypted, Encrypted.length - 16 , salt, 0, 16);

        byte[] rawEnc = new byte[Encrypted.length - 16];
        System.arraycopy(Encrypted, 0 , rawEnc, 0, Encrypted.length - 16);

        CipherParameters cipherParams = null;
        cipherParams = new ParametersWithIV(keyParam, this.ivData);

        BufferedBlockCipher cipher = new PaddedBufferedBlockCipher(new CBCBlockCipher((BlockCipher) new SerpentEngine()), padding);
        cipher.reset();
        cipher.init(false, cipherParams);

        byte[] output = new byte[cipher.getOutputSize(rawEnc.length - blockSize/8)];

        int bytesWrittenin = cipher.processBytes(rawEnc, blockSize/8, rawEnc.length - blockSize/8, output, 0);
        bytesWrittenin += cipher.doFinal(output, bytesWrittenin);

        byte[] Dec = new byte[bytesWrittenin];
        System.arraycopy(output, 0, Dec, 0, bytesWrittenin);

        return Dec;
    }
}
