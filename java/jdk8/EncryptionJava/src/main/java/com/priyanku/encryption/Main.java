/*
 * Licensed to Priyanku Biswas
 * June 2022
 * This project can encrypt and decrypt text based on a master code like {2A517BA1-9DA5-4259-AE1D-711B2571B415}
 */
package com.priyanku.encryption;

import java.io.UnsupportedEncodingException;
import java.nio.charset.StandardCharsets;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.spec.AlgorithmParameterSpec;
import java.util.Base64;

import javax.crypto.Cipher;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

public class Main {

	//Don't change below value of pwd.
	private static String pwd="!cvZ8"+"0M3jmP!t"+"LLfZ\\3f"+"jm,J/";
	
	//This keeps changing from application to application
	private String masterName = "";
	
	public Main(String masterName) {
		super();
		this.masterName = masterName;
	}

	public static void main(String[] args) {

		//Below one is the string encrypted with the Master code
		String encryptedPasswordString = args[0];  

		// Below one is the master code like {2A517BA.....
		Main obj = new Main(args[1]);
		try
		{
			String decrypted = obj.decrypt(encryptedPasswordString);					 
			System.out.println(decrypted); 
        }
		catch (Exception e){
            e.printStackTrace();
        }
		
		try
		{
			String encrypted = obj.encrypt("jk");	
					
			System.out.println(encrypted); 
        }
		catch (Exception e){
            e.printStackTrace();
        }
	}

	public String encrypt(String plainTextPasswordString ) {
		return enRfc2898DeriveBytes(
				plainTextPasswordString.getBytes(StandardCharsets.UTF_8),
				pwd,
				masterName.getBytes(StandardCharsets.UTF_8));
	}

	public String decrypt(String encryptedPasswordString ) {
		return deRfc2898DeriveBytes( 
				Base64.getDecoder().decode(encryptedPasswordString),
				pwd,
				masterName.getBytes(StandardCharsets.UTF_8));
	}

	private String enRfc2898DeriveBytes(byte[] data,String fPassword,byte[] fSalt){
	    Rfc2898DeriveBytes keyGenerator = null;
	    try {
	        keyGenerator = new Rfc2898DeriveBytes(fPassword, fSalt, 1000);
	    }
	    catch (InvalidKeyException e1) { 
	        e1.printStackTrace();
	    } catch (NoSuchAlgorithmException e1) {
	        e1.printStackTrace();
	    } catch (UnsupportedEncodingException e1) {
	        e1.printStackTrace();
	    } 
	    byte[] bKey = keyGenerator.getBytes(32);
	    byte[] bIv = keyGenerator.getBytes(16);
	     
	    try {
	        SecretKeySpec sekey = new SecretKeySpec(bKey, "AES");
	        AlgorithmParameterSpec param = new IvParameterSpec(bIv);
	         
	        Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
	        cipher.init(Cipher.ENCRYPT_MODE,sekey,param);
	        byte[] encrypted = cipher.doFinal(data);
	        
	        return Base64.getEncoder().encodeToString(encrypted);
	    } catch (Exception e) {
	        e.printStackTrace();
	        return null;
	    }
	}
	
	private String deRfc2898DeriveBytes(byte[] data,String fPassword,byte[] fSalt){
	    Rfc2898DeriveBytes keyGenerator = null;
	    try {
	        keyGenerator = new Rfc2898DeriveBytes(fPassword, fSalt, 1000);
	    }
	    catch (InvalidKeyException e1) { 
	        e1.printStackTrace();
	    } catch (NoSuchAlgorithmException e1) {
	        e1.printStackTrace();
	    } catch (UnsupportedEncodingException e1) {
	        e1.printStackTrace();
	    } 
	    byte[] bKey = keyGenerator.getBytes(32);
	    byte[] bIv = keyGenerator.getBytes(16);
	     
	    try {
	        SecretKeySpec sekey = new SecretKeySpec(bKey, "AES");
	        AlgorithmParameterSpec param = new IvParameterSpec(bIv);
	         
	        Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
	        cipher.init(Cipher.DECRYPT_MODE,sekey,param);
	        byte[] decrypted = cipher.doFinal(data);
	        
	        return new String(decrypted, StandardCharsets.UTF_8);
	    } catch (Exception e) {
	        e.printStackTrace();
	        return null;
	    }
	}
}
