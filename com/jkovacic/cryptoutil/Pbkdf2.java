/*
Copyright 2012, Jernej Kovacic

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

   http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/ 

package com.jkovacic.cryptoutil;

import java.security.*;
import javax.crypto.*;
import javax.crypto.spec.*;
import java.util.*;


/**
 * Password Based Key Derivation Function class, implementing the standard PKCS #5 2.0
 * specified by the RFC 2898: http://tools.ietf.org/html/rfc2898
 * 
 * It is possible to set the key derivation parameters (HMAC algorithm, number of iterations, salt),
 * if they are not specified, recommended default settings are applied: HMAC-SHA1, 10000 iterations
 * and a hard coded salt.
 *  
 * Test vectors to test the class are defined by the RFC 6070:
 * http://tools.ietf.org/html/rfc6070
 * 
 * @author Jernej Kovacic
 */
public class Pbkdf2 
{
	// MD5 hash of "com.jkovacic.cryptoutil.Pbkdf2", 
	// calculated at: http://md5-hash-online.waraxe.us/
	private static final byte[] DEFAULT_SALT = ByteHex.toBytes("79:c0:5b:84:b7:a8:9e:10:78:dc:35:05:bd:34:6b:23".toCharArray());
	private static final int DEFAULT_ITERATIONS = 10000;
	private static final DigestAlgorithm DEFAULT_HMAC = DigestAlgorithm.SHA1;
	
	private DigestAlgorithm hmac = null;
	private byte[] salt = null;
	private int iter = 0;
	
	private Mac mac = null;
	
	/**
	 * Constructor
	 * 
	 * @param hmac - HMAC algorithm
	 * @param salt
	 * @param iterations - number of iterations
	 */
	public Pbkdf2(DigestAlgorithm hmac, byte[] salt, int iterations)
	{
		setParams(hmac, salt, iterations);
	}
	
	/**
	 * Constructor
	 * 
	 * Default parameters are set: HMAC-SHA1, 10000 iterations and a hard coded salt
	 */
	public Pbkdf2()
	{
		setParams(DEFAULT_HMAC, DEFAULT_SALT, DEFAULT_ITERATIONS);
	}
	
	/**
	 * Constructor 
	 * 
	 * Default number of iterations (10000) and a default hard coded salt are set
	 * 
	 * @param hmac - HMAC algorithm
	 */
	public Pbkdf2(DigestAlgorithm hmac)
	{
		setParams(hmac, DEFAULT_SALT, DEFAULT_ITERATIONS);
	}
	
	/**
	 * Constructor
	 * 
	 * Default HMAC algorithm (HMAC-SHA1) and number of iterations (10000) are set. 
	 * 
	 * @param salt
	 */
	public Pbkdf2(byte[] salt)
	{
		setParams(DEFAULT_HMAC, salt, DEFAULT_ITERATIONS);
	}
	
	/**
	 * Constructor 
	 * 
	 * Default HMAC algorithm (HMAC-SHA1) and salt (a hard coded value) are set
	 * 
	 * @param iterations - number of iterations
	 */
	public Pbkdf2(int iterations)
	{
		setParams(DEFAULT_HMAC, DEFAULT_SALT, iterations);
	}
	
	/**
	 * Constructor
	 * 
	 * Default number of iterations (10000) is set
	 * 
	 * @param hmac - HMAC algorithm
	 * @param salt
	 */
	public Pbkdf2(DigestAlgorithm hmac, byte[] salt)
	{
		setParams(hmac, salt, DEFAULT_ITERATIONS);
	}
	
	/**
	 * Constructor
	 * 
	 * Default salt (a hard coded value) is set
	 * 
	 * @param hmac - HMAC algorithm
	 * @param iterations - number of iterations
	 */
	public Pbkdf2(DigestAlgorithm hmac, int iterations)
	{
		setParams(hmac, DEFAULT_SALT, iterations);
	}
	
	/**
	 * Constructor
	 * 
	 * Default HMAC algorithm (HMAC-SHA1) is set
	 * 
	 * @param salt
	 * @param iterations - number of iterations
	 */
	public Pbkdf2(byte[] salt, int iterations)
	{
		setParams(DEFAULT_HMAC, salt, iterations);
	}
	
	/*
	 * Sets key derivation parameters.
	 * If any parameter is null, its default value will be set.
	 *  
	 * @param hmac - HMAC algorithm
	 * @param salt
	 * @param iterations - number of iterations
	 */
	private void setParams(DigestAlgorithm hmac, byte[] salt, int iterations)
	{
		this.hmac = ( null!=hmac ? hmac : DEFAULT_HMAC );
		this.salt = ( null!=salt ? salt : DEFAULT_SALT );
		this.iter = ( iterations>0 ? iterations : DEFAULT_ITERATIONS );
	}
	
	/**
	 * @return HMAC algorithm used at key generation
	 */
	public DigestAlgorithm getHmac()
	{
		return hmac;
	}
	
	/**
	 * @return salt used at key generation
	 */
	public byte[] getSalt()
	{
		return salt;
	}
	
	/**
	 * @return number of iterations used at key generation
	 */
	public int getIterations()
	{
		return iter;
	}
	
	/**
	 * @param hmac - HMAC algorithm
	 */
	public void setHmac(DigestAlgorithm hmac)
	{
		setParams(hmac, this.salt, this.iter);
	}
	
	/**
	 * @param salt
	 */
	public void setSalt(byte[] salt)
	{
		setParams(this.hmac, salt, this.iter);
	}
	
	/**
	 * @param iterations - number of iterations
	 */
	public void setIterations(int iterations)
	{
		setParams(this.hmac, this.salt, iterations);
	}
	
	/**
	 * @return class's default HMAC algorithm
	 */
	public static DigestAlgorithm getDefaultHmac()
	{
		return DEFAULT_HMAC;
	}
	
	/**
	 * @return class's default salt
	 */
	public static byte[] getDefaultSalt()
	{
		return DEFAULT_SALT;
	}
	
	/**
	 * @return class's default number of iterations
	 */
	public static int getDefaultIterations()
	{
		return DEFAULT_ITERATIONS;
	}
	
	/*
	 * Implementation of a "pseudo random function" (a term from the standard).
	 * In practice, a HMAC is calculated. 
	 * 
	 * @param text - input to the HMAC function
	 * 
	 * @return HMAC value of the 'text'
	 */
	private byte[] prf(byte[] text)
	{
		mac.reset();
		
		return mac.doFinal(text);
	}
	
	/*
	 * A utility function to "convert" an int value into an array of bytes
	 *  
	 * @param n - int value to be "converted"
	 * 
	 * @return - byte array representing 'n'
	 */
	private byte[] int2bytes(int n)
	{
		// allocate the byte array
		byte[] retVal = new byte[4];
		
		// The last byte is a remainder of division by 256.
		// Then divide the number ny 256 and repeat the process.
		// As 256 is a power of 2, it is possible to speed up 
		// the calculations using bitwise operations.
		int a = n;
		for ( int i=0; i<4; i++ )
		{
			retVal[3-i] = (byte) (a & 0xff);
			a >>= 8;
		}
		
		return retVal;
	}
	
	/**
	 * Derives a key with the desired number of bytes from the given pass phrase.
	 * Key derivation parameters must be set beforehand.
	 * 
	 * @param passPhrase - pass phrase
	 * @param dklen - desired key length (in bytes)
	 * 
	 * @return key of the specified length or 'null' if any parameter is invalid
	 */
	public byte[] getKey(byte[] passPhrase, int dklen)
	{
		/*
		 * The key derivation process is described in detail at RFC 2898:
		 * http://tools.ietf.org/html/rfc2898
		 */
		
		// sanity check
		if ( null==passPhrase || 0==passPhrase.length || dklen<=0 )
		{
			return null;
		}
		
		// instantiate a HMAC class
		try
		{
			mac =  Mac.getInstance("Hmac" + hmac.getCompact());
		}
		catch ( NoSuchAlgorithmException ex )
		{ 
			return null;
		}
		
		// The HMAC secret (a pass phrase) is the same at all iterations
		// so the HMAC can be initialized only once. 
		// It must be reset during each iteration, though.
		SecretKeySpec secret = new SecretKeySpec(passPhrase, mac.getAlgorithm());
		try
		{
			mac.init(secret);
		}
		catch ( InvalidKeyException ex )
		{
			return null;
		}
		
		/*
		 * Key generation is split into several steps, as at each step only
		 * hlen bytes (length of the chosen HMAC algorithm's output) can be generated
		 */
		int hlen = mac.getMacLength();
		if ( hlen <=0 )
		{
			return null;
		}
		
		byte[] retVal = new byte[dklen];
		Arrays.fill(retVal, (byte) 0);
		
		int n = dklen / hlen;
		int r = dklen % hlen;
		
		// Derive n (or n+1) segments of the key
		for ( int i=0; i<=n; i++ )
		{
			if ( i==n && 0==r )
			{
				break;  // out of for i
			}
			
			byte[] t = new byte[hlen];
			Arrays.fill(t, (byte) 0);
			
			// Initial "text" to the HMAC consists of the salt and its length (4 bytes)
			byte[] tempText = new byte[salt.length + 4];
			byte[] quartet = int2bytes(i+1);
			System.arraycopy(salt, 0, tempText, 0, salt.length);
			System.arraycopy(quartet, 0, tempText, salt.length, 4);
			
			/*
			 * At each iteration a HMAC of the tempText is calculated and xor'ed
			 * to the key segment.
			 */
			for ( int c=0; c<iter; c++ )
			{
				byte[] ui = prf(tempText);
				for ( int ctr=0; ctr<hlen; ctr++ )
				{
					t[ctr] ^= ui[ctr];
				}
				
				/*
				 * Result of the PRF is input to the same function in the next iteration.
				 * Since 'tempText' is not needed anymore, its allocation memory will be "used"
				 * to hold input to PRF for the next iteration.
				 * At the first iteration,'tempText' will probably not be of the appropriate size.
				 * This is handled by the if clause.
				 */
				if ( hlen==tempText.length )
				{
					System.arraycopy(ui, 0, tempText, 0, hlen);
				}
				else
				{
					tempText = ui;
				}
			}  // for c
			
			// At the last iteration, probably not all bytes will be used.
			int copylen = ( i<n ? hlen : r );
			System.arraycopy(t, 0, retVal, i*hlen, copylen);
		}  // for i
		
		
		return retVal;
	}

}
