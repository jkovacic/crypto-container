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

import java.util.*;

import com.jkovacic.cryptoutil.*;

/*
 * A class with some basic tests, intended to provide
 * a brief demonstration of the library.
 * 
 * It performs all PBKDF2 test vectors specified at the RFC 6070:
 * http://tools.ietf.org/html/rfc6070 
 * 
 * @author Jernej Kovacic
 */
public class PBKDF2Test 
{
	/*
	 * Prepares test vectors for HMAC-SHA1 based PBKDF as specified by the RFC 6070:
	 * http://tools.ietf.org/html/rfc6070
	 */
	private static List<TestItem> prepareTestVectors()
	{
		List<TestItem> retVal = new LinkedList<TestItem>();
		
		TestItem item = new TestItem();
		
		item.password = "password".getBytes();
		item.salt = "salt".getBytes();
		item.iter = 1;
		item.keylen = 20;
		item.expected = "0c:60:c8:0f:96:1f:0e:71:f3:a9:b5:24:af:60:12:06:2f:e0:37:a6";
		retVal.add(item);
		
		item = new TestItem(item);
		item.iter = 2;
		item.expected = "ea:6c:01:4d:c7:2d:6f:8c:cd:1e:d9:2a:ce:1d:41:f0:d8:de:89:57";
		retVal.add(item);
		
		item = new TestItem(item);
		item.iter = 4096;
		item.expected = "4b:00:79:01:b7:65:48:9a:be:ad:49:d9:26:f7:21:d0:65:a4:29:c1";
		retVal.add(item);
		
		item = new TestItem(item);
		item.iter = 16777216;
		item.expected = "ee:fe:3d:61:cd:4d:a4:e4:e9:94:5b:3d:6b:a2:15:8c:26:34:e9:84";
		retVal.add(item);
		
		item = new TestItem();
		item.password = "passwordPASSWORDpassword".getBytes();
		item.salt = "saltSALTsaltSALTsaltSALTsaltSALTsalt".getBytes();
		item.iter = 4096;
		item.keylen = 25;
		item.expected = "3d:2e:ec:4f:e4:1c:84:9b:80:c8:d8:36:62:c0:e4:4a:8b:29:1a:96:4c:f2:f0:70:38";
		retVal.add(item);
		
		item = new TestItem();
		item.password = "pass\u0000word".getBytes();
		item.salt = "sa\u0000lt".getBytes();
		item.iter = 4096;
		item.keylen = 16;
		item.expected = "56:fa:6a:a7:55:48:09:9d:cc:37:d7:f0:34:25:e0:c3";
		retVal.add(item);
		
		return retVal;
	}
	
	public static void main(String[] args)
	{
		Pbkdf2 gen = new Pbkdf2(DigestAlgorithm.SHA1);
		List<TestItem> testVector = prepareTestVectors();
		
		int passed = 0;
		
		// For each item of the test vector, generate a key from the specified parameters
		// and compare it to the expected one.
		for ( TestItem i : testVector )
		{
			System.out.println("Password: \"" + new String(i.password) + "\"");
			System.out.println("Salt: \"" + new String(i.salt) + "\"");
			System.out.println("Iterations: " + i.iter + "\tkey length: " + i.keylen);
			
			gen.setSalt(i.salt);
			gen.setIterations(i.iter);
			byte[] key = gen.getKey(i.password, i.keylen);
			String kstr = new String(ByteHex.toHex(key, false));
			
			System.out.println("Generated key: " + kstr);
			System.out.println("Expected key:  " + i.expected);
			 
			if ( kstr.equalsIgnoreCase(i.expected) )
			{
				System.out.println("Keys MATCH");
				passed++;
			}
			else
			{
				System.out.println("Keys DO NOT match");
			}
			System.out.println();
		}
		
		System.out.println( testVector.size() + " tests performed, " + passed + " tests passed");
	}
}


/*
 * A utility class to hold test vector elements
 * 
 * @author Jernej Kovacic
 */
class TestItem
{
	/*
	 * Default constructor
	 */
	TestItem() 
	{
		
	}
	
	/*
	 * Copy constructor
	 * 
	 * @param obj - object whose members will be copied ('cloned') to this one
	 */
	TestItem(TestItem obj)
	{ 
		this.password = obj.password.clone();
		this.salt = obj.salt.clone();
		this.iter = obj.iter;
		this.keylen = obj.keylen;
	}
	
	// Passphrase
	byte[] password = null;;
	
	// HMAC salt
	byte[] salt = null;
	
	// Number of iterations
	int iter = 0;
	
	// Key length
	int keylen= 0;
	
	// Expected key as defined by RFC 6070
	String expected = null;
}
