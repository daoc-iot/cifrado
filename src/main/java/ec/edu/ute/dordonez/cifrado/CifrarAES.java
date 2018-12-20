
package ec.edu.ute.dordonez.cifrado;

import java.io.UnsupportedEncodingException;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.Base64;
import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

/**
 *
 * @author dordonez@ute.edu.ec
 */
public class CifrarAES {
    public static final String DEFAULT_KEY = "1234567890123456";
    public static final String DEFAULT_TEXT ="Pablito clavó un clavito, qué clase de clavito clavó Pablito !!!!!";
    
    /*
    Devuelve "original" codificado con "key" e "iv", en formato de Base64 (ISO-8859-1).
    "iv" es un aleatorio de 16 bytes y se devuelve al inicio de la String codificada
    en 24 caracteres
    */
    public String cifrar(byte[] original, byte[] key) throws NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException, UnsupportedEncodingException, InvalidAlgorithmParameterException, IllegalBlockSizeException, BadPaddingException {
        SecureRandom random = new SecureRandom();
        byte[] iv = new byte[16];
        random.nextBytes(iv);
        IvParameterSpec ivParSpec = new IvParameterSpec(iv);
        SecretKeySpec skeySpec = new SecretKeySpec(key, "AES");
        Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
        cipher.init(Cipher.ENCRYPT_MODE, skeySpec, ivParSpec);
        byte[] cifrado = cipher.doFinal(original);
        String strIv = Base64.getEncoder().encodeToString(iv);
        String strCifrado = Base64.getEncoder().encodeToString(cifrado);
        return strIv + strCifrado;
    }
    
    public byte[] descifrar(String cifrado, byte[] key) throws NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException, UnsupportedEncodingException, InvalidAlgorithmParameterException, IllegalBlockSizeException, BadPaddingException {
        byte[] iv = Base64.getDecoder().decode(cifrado.substring(0, 24));
        byte[] payload = Base64.getDecoder().decode(cifrado.substring(24));
        IvParameterSpec ivParSpec = new IvParameterSpec(iv);
        SecretKeySpec skeySpec = new SecretKeySpec(key, "AES");
        Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
        cipher.init(Cipher.DECRYPT_MODE, skeySpec, ivParSpec);
        byte[] original = cipher.doFinal(payload);
        return original;
    }    
    
    public static void main(String[] args) throws Exception {
        CifrarAES esta = new CifrarAES();
        String paraCifrar = DEFAULT_TEXT;
        String cifrado = esta.cifrar(paraCifrar.getBytes("UTF-8"), DEFAULT_KEY.getBytes("UTF-8"));
        System.out.println(cifrado);
        byte[] original = esta.descifrar(cifrado, DEFAULT_KEY.getBytes("UTF-8"));
        System.out.println(new String(original, "UTF-8"));
    }
}
