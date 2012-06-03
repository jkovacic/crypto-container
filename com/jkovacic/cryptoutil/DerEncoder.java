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

import java.util.*;

/**
 * A class to prepare a DER encoded structure.
 * 
 * DER encoding is based on ASN.1 specification which is available at:
 * http://www.itu.int/ITU-T/studygroups/com17/languages/X.690-0207.pdf
 * 
 * Usage:
 * - Instantiate the class using its default constructor
 * - Append the values using appendXXX() function. XXX defines the ASN.1 type
 *   that will be encoded into the DER structure
 * - When all values have been appended, create the DER structure by calling encode().
 *   The initial ASN.1 structure will automatically be generated at the start of the DER structure
 *   The values will be encoded in the same order as appended to the class.
 *   
 * Even after encode() has been called, it is possible to append additional
 * data and create another DER structure, containing previous and new data.
 * It is not possible to retrieve and remove already appended data.
 *  
 * @author Jernej Kovacic
 */
public class DerEncoder extends DerAb 
{
	private List<SequenceItem> sequence = null;

	/**
	 * Constructor
	 */
	public DerEncoder()
	{
		this.sequence = new LinkedList<SequenceItem>();
	}
	
	/**
	 * @param octetStream - octet stream array to be appended to the DER structure
	 */
	public void appendOctetStream(byte[] octetStream)
	{
		// sanity check
		if ( null==octetStream )
		{
			return;
		}
		
		SequenceItem os = new SequenceItem();
		os.type = Asn1Types.OCTET_STRING;
		os.contents = octetStream;
		
		sequence.add(os);
	}
	
	/**
	 * Converts an integer value into an array of bytes and appends it into the DER structure.
	 * Sign of the value is preserved. If the value is positive and the converted byte array's 
	 * most significant bit equals 1, an additional zero-byte will be prepended to preserve the sign.
	 * 
	 * @param val - int value to be encoded into the DER structure
	 */
	public void appendInt(int val)
	{
		
		SequenceItem si = new SequenceItem();
		si.type = Asn1Types.INTEGER;
		
		int log = 0; 	// number of bytes to encode the integer (analogy to log256(val))
		
		// determination of log strongly depends on val's sign
		if ( 0==val || -1==val )
		{
			/*
			 * 0 (all zeroes in binary) and -1 (all ones in binary)
			 * are two special cases...
			 */
			log = 1;
		}
		if ( val>=0 )
		{
			/*
			 * The quartet of bytes representing val (an int value) starts with at least one zero bit.
			 * When the bitwise shift to right is performed (equivalent to division by a power of 2),
			 * it will be prepended with even more zeros and once such a bit-shifted value will reach 0.
			 * So, the number of shifting by 8 bytes to right will determine the "log256(val)". 
			 */
			int tempVal  = val;
			while ( tempVal>0 )
			{
				tempVal >>>= 8;
				log++;
			}
			
			/*
			 * If the first non-zero byte's MSB is 1, such a "contracted" number would be considered 
			 * negative by ASN.1 parsers. To prevent this, an additional zero-byte must be prepended to it.
			 * To achieve this, log will be increased by 1.
			 */
			
			// 0x80 is 1, followed by 7 zeros, shifting it by log-1 bytes and bit AND
			// will check the MSB of the first non-zero (i.e. log^th) byte:
			if ( 0 != (val & ( 0x80 << (8*(log-1)) ) ) )
			{
				log++;
			}
		}
		else
		{
			/*
			 * Negative int values start with at least one zero bit. The left most non-one byte
			 * (i.e at least one of its bit equals 0) must be found first. To find it, start with
			 * a 'tempVal' equaling -1 (equivalent to 0xffffffff) and perform bit shifting to left 
			 * (it will replace the "missing" right bits with zero bits), until bitwise AND comparison 
			 * equals this temporary int, meaning that the left side remainder of the 'val' consists of
			 *  ones only. 
			 */
			int tempVal = 0xffffffff;
			log = 0;
			
			while ( log<4 && tempVal!=(val & tempVal) )
			{
				tempVal <<= 8;
				log++;
			}
			
			/*
			 * If the first non-one byte's MSB is 0, such a "contracted" number would be considered
			 * as positive by ASN.1 parsers. To prevent this, an additional one-byte must be prepended to it.
			 * To achieve this, log will be increased by 1.
			 */
			
			// To check MSB of the first non-one byte, just bit shift it to left for
			// (4-log) bytes and check the sign.
			if ( (val << (8*(4-log)) ) >= 0 )
			{
				log++;
			}
		}
		
		// Should not occur (as 0 and -1 were handled separately) but just in case.... 
		// Even if 'val' equals 0, one byte will be needed
		if ( 0==log )
		{
			log++;
		}
				
		// Allocate the necessary number of bytes
		si.contents = new byte[log];
		
		// And populate it with integer's byte values
		long temp = (long) (val & 0xffffffff);
		for ( int i=0; i<log; i++ )
		{
			si.contents[log-i-1] = (byte) (temp & 0xff);
			temp >>= 8;
		}
		
		sequence.add(si);
	}
	
	/*
	 * Determines the total length of the data item within a DER structure.
	 * The total length consists of the actual data payload and its prefix
	 * (indicating the ASN.1 type and the payload length)  
	 * 
	 * @param item - data item whose total length is to be determined
	 * 
	 * @return - total length of the data item
	 */
	private int itemLength(byte[] item)
	{
		// sanity check
		if ( null==item )
		{
			return -1;
		}
		
		int len = item.length;
		int retVal = len + 2; // 1 for type id + 1 for the first byte of len
		
		/*
		 * If 'len' is longer than 127 bytes, determine the actual "length" (in bytes)
		 * of the 'len' and update the 'retVal'
		 */
		if ( len>127 )
		{
			while ( len>0xFF )
			{
				len >>>= 8;
				retVal++;
			}
			
			retVal++;
		}
		
		return retVal;
	}
	
	/*
	 * Encodes the length into the appropriate array of bytes.
	 * If 'len' is equal or less than 127, an "array" of one byte with the value of 'len' will be returned.
	 * If 'len' is greater than 127, the MSB of the first byte will be set to 1, the remaining bits will
	 * indicate the number of additional bytes. The first byte will be followed by this number of bytes
	 * with the 'len' "encoded" 
	 * 
	 * @param len - length to be encoded
	 * 
	 * @return a byte array with the encoded 'len' or null if 'len' is not positive
	 */
	private byte[] encodeLen(int len)
	{
		if ( len<=0 )
		{
			return null;
		}
		
		byte[] retVal = null;
		if ( len<=127 )
		{
			/*
			 * If 'len' is 127 bytes or shorter, just return an "array" 
			 * with one byte, with the value of 'len'
			 */
			retVal = new byte[1];
			retVal[0] = (byte) (len & 0xff);
		}
		else
		{
			/*
			 * Otherwise the first byte will determine the number of bytes that actually 
			 * hold the value of 'len'
			 */
			// number of bytes that follow the first one:
			int log = 1;
			int temp = len;
			while ( temp>0xff )
			{
				temp >>>= 8;
				log++;
			}
			
			retVal = new byte[log+1];
			
			/*
			 * The first byte will carry the number of bytes that follow.
			 * Its MSB must be set to 1.
			 */ 
			retVal[0] = (byte) (log & 0xff | 0x80);
			
			// Extract individual bytes from the int value and append them to the retVal
			// Use bitwise operators to speed up the process
			temp = len;
			for ( int i=0; i<log; i++ )
			{
				retVal[retVal.length-i-1] = (byte) (temp & 0xff);
				temp >>>= 8;
			}
		}
		
		return retVal;
	}
	
	/**
	 * Encodes the previously appended data into a DER structure
	 * 
	 * @return byte array with the DER structure
	 */
	public byte[] encode()
	{
		// Get a sum of total lengths (incl. prefixes) of all elements
		int len = 0;
		for ( SequenceItem seq : sequence )
		{
			len += itemLength(seq.contents);
		}
		
		// Length of the initial DER sequence
		byte[] lenVec = encodeLen(len);
		
		// And allocate the output buffer
		byte[] retVal = new byte[len + lenVec.length + 1];
		
		// The first few bytes are reserved to indicate a DER structure and its length
		retVal[0] = (byte) (Asn1Types.SEQUENCE.getValue() & 0xff);
		System.arraycopy(lenVec, 0, retVal, 1, lenVec.length);
		
		// For each element...
		int pos = lenVec.length + 1;
		for ( SequenceItem item : sequence )
		{
			// ...indicate its ASN.1 type,...
			retVal[pos++] = (byte) (item.type.getValue() & 0xff);
			
			// ... indicate its payload's length...
			lenVec = encodeLen(item.contents.length);
			System.arraycopy(lenVec, 0, retVal, pos, lenVec.length);
			pos += lenVec.length;
			
			// ... and finally copy the actual data 
			System.arraycopy(item.contents, 0, retVal, pos, item.contents.length);
			pos += item.contents.length;
		}
		
		return retVal;
	}
	
	/*
	 * A convenience internal structure holding information about
	 * each element's ASN.1 type and its contents
	 *  
	 * @author Jernej Kovacic
	 */
	private class SequenceItem
	{
		public Asn1Types type = null;
		public byte[] contents = null;
	}
	
}
