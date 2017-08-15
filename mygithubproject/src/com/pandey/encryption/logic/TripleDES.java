package com.pandey.encryption.logic;

import java.io.UnsupportedEncodingException;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Arrays;
import java.util.Base64;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

public class TripleDES {

	
	public final static String KEY="!@@!YEDNAPRAMUKJAR^&%)"; 
	
	/**
	 * @param data is the plain text sent to get encrypted.
	 * @return Base64 Encoded String
	 * @throws Exception: It can throw: NoSuchAlgorithmException, UnsupportedEncodingException, 
     *  NoSuchPaddingException, InvalidKeyException, InvalidAlgorithmParameterException, IllegalBlockSizeException, BadPaddingException
	 */
    public String encrypt(String data) throws Exception  {
    	//Creating a key for the digest from external key.
        final MessageDigest md = MessageDigest.getInstance("SHA1");
        final byte[] digestOfPassword = md.digest(KEY.getBytes("utf-8"));
        //Copying 24 bytes to an Array
        final byte[] keyBytes = Arrays.copyOf(digestOfPassword, 24);
        // Picking the Last 16 bytes
        for (int j = 0, k = 8; j < 16;) {
            keyBytes[k++] = keyBytes[j++];
        }
        // Fetching Triple DES SecretKey
        final SecretKey key = new SecretKeySpec(keyBytes, "DESede");
        // Create 8 byte iv
        final IvParameterSpec iv = new IvParameterSpec(new byte[8]);
        // Set Mode to CBC and padding
        final Cipher cipher = Cipher.getInstance("DESede/CBC/PKCS5Padding");
        cipher.init(Cipher.ENCRYPT_MODE, key, iv);
        //Encrypt the data
        final byte[] cipherText = cipher.doFinal(data.getBytes("utf-8"));
        // return after base64 encoding 
        return Base64.getEncoder().encodeToString(cipherText);
    }
    /**
	 * @param data is the base64 encoded text sent to get decrypted.
	 * @return Plain String
	 * @throws Exception: It can throw: NoSuchAlgorithmException, UnsupportedEncodingException, 
     *  NoSuchPaddingException, InvalidKeyException, InvalidAlgorithmParameterException, IllegalBlockSizeException, BadPaddingException
	 */
    public String decrypt(String data) throws Exception {
    	//converts into Base64 encoded string to Byte array
    	byte[] message = Base64.getDecoder().decode(data);
        final MessageDigest md = MessageDigest.getInstance("SHA1");
        final byte[] digestOfPassword = md.digest(KEY.getBytes("utf-8"));
      //Copying 24 bytes to an Array
        final byte[] keyBytes = Arrays.copyOf(digestOfPassword, 24);
        for (int j = 0, k = 8; j < 16;) {
            keyBytes[k++] = keyBytes[j++];
        }
        // Fetching Triple DES SecretKey
        final SecretKey key = new SecretKeySpec(keyBytes, "DESede");
        // Create 8 byte iv
        final IvParameterSpec iv = new IvParameterSpec(new byte[8]);
        // Set Mode to CBC and padding
        final Cipher decipher = Cipher.getInstance("DESede/CBC/PKCS5Padding");
        decipher.init(Cipher.DECRYPT_MODE, key, iv);
        // Decrypt the data
        final byte[] plainText = decipher.doFinal(message);
        // return after converting to plain Text
        return new String(plainText, "UTF-8");
    }
    
    
    public static void main(String[] args) throws Exception {
        String text = "||Rajkumar|Pandey||";
        System.out.println("Plain Text:"+text);
        String codedtext = new TripleDES().encrypt(text);
        System.out.println("base64encoded:"+codedtext);
        String decodedtext = new TripleDES().decrypt(codedtext);
        System.out.println("Decrypted:"+decodedtext); 
    }

}