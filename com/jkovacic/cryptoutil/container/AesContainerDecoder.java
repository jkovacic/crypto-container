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

package com.jkovacic.cryptoutil.container;

import com.jkovacic.cryptoutil.*;

/**
 * A specialized class, derived from DerDecoder, used to process
 * DER encoded contents of AesContainer
 * 
 * Typical procedure to parse the container's contents from a DER encoded input
 * requires several steps:
 * - instantiate an AesContainerDecoder using its constructor and pass it a DER encoded structure
 * - call parse() to start decoding from DER
 * - availability of container's contents may be checked by calling isCompleted()
 * - obtain the cipher text and its HMAC finger print by calling getText() and getHmac(), respectively 
 * 
 * @author Jernej Kovacic
 */
public class AesContainerDecoder extends DerDecoder 
{
	private byte[] text = null;				// encrypted actual data
	private byte[] fingerPrint = null;		// HMAC of the original plain text
	private boolean ready = false;			// has parsing completed successfully?

	/**
	 * Constructor
	 *  
	 * @param container - contents of the AesContainer to be decoded
	 */
	public AesContainerDecoder(byte[] container)
	{
		super(container);
		this.ready = false;
	}
	
	/**
	 * Parses the container's DER structure and prepares encrypted data 
	 * and its HMAC to be retrieved by getText() and getHmac(), respectively
	 * 
	 * @return true/false, indicating success of parsing
	 */
	public boolean parse()
	{
		ready = false;
		try
		{
			// parse the sequence
			SequenceRange seq = parseSequence();
			if ( null == seq )
			{
				return false;
			}
			
			// ...and check that nothing follows the initial sequence
			if ( true==moreData(seq.seqstart + seq.seqlen) )
			{
				return false;
			}
			
			// version (must be 0)
			seq = parseInteger();
			if ( null==seq )
			{
				return false;
			}
			
			int version = toInt(seq);
			if ( 0 != version )
			{
				return false;
			}
			
			// get encrypted text
			seq = parseOctetString();
			if ( null == seq )
			{
				return false;
			}
			text = toByteArray(seq);
			
			// and its HMAC
			seq= parseOctetString();
			if ( null==seq )
			{
				return false;
			}
			fingerPrint = toByteArray(seq);
			
			if ( true==moreData() )
			{
				return false;
			}
			
			// if reaching this point, everything was OK,
			// parsed data may be considered as ready
			ready = true;
		}
		catch ( DerException ex )
		{
			return false;
		}
		
		return ready;
	}
	
	/**
	 * @return are encrypted data and its HMAC ready to be retrieved by getText() and getHmac(), respectively
	 */
	public boolean isCompleted()
	{
		return ready;
	}
	
	/**
	 * @return encrypted data or 'null' if not available
	 */
	public byte[] getText()
	{
		return ( true==ready ? text : null );
	}
	
	/**
	 * @return plain text's HMAC value or 'null' if not available
	 */
	public byte[] getHmac()
	{
		return ( true==ready ? fingerPrint: null );
	}
}
