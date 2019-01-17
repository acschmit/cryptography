/**
 *
 * The MIT License (MIT)
 *
 * Copyright (c) 2015 Albert C Schmitt
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 */
package org.albertschmitt.crypto.common;

import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertTrue;

import org.junit.Before;
import org.junit.Test;

public class Base64Test
{

	private static final int ARRY_SIZE = 256;
	private byte[] bytes_in = new byte[ARRY_SIZE];

	@Before
	public void setUp() throws Exception
	{
		// Generate array of all bytes 0 - 255 to ensure comprehensive test.
		bytes_in = new byte[ARRY_SIZE];
		for (int i = 0; i <= ARRY_SIZE - 1; i++)
		{
			bytes_in[i] = (byte) i;
		}
	}

	@Test
	public void testEncodeToChar_And_DecodeCharArray()
	{
		// Test conversion with line separator.
		char[] chars_out = Base64.encodeToChar(bytes_in, true);
		assertNotNull(chars_out);

		// Verify that the line breaks are in the expected places.
		boolean bOK = chars_out[76] == '\r' && chars_out[77] == '\n' && chars_out[154] == '\r' && chars_out[155] == '\n'
					  && chars_out[232] == '\r' && chars_out[233] == '\n' && chars_out[310] == '\r' && chars_out[311] == '\n';
		assertTrue(bOK);

		// Convert back to byte array.
		byte[] bytes_out = Base64.decode(chars_out);
		assertArrayEquals(bytes_in, bytes_out);

		// Test conversion again without line separator.
		chars_out = Base64.encodeToChar(bytes_in, false);
		// TBD: Verify there are no line breaks in output.

		assertNotNull(chars_out);

		// Convert back to byte array.
		bytes_out = Base64.decode(chars_out);
		assertArrayEquals(bytes_in, bytes_out);
	}

	// @Test
	// public void testDecodeFastCharArray()
	// {
	// fail("Not yet implemented"); // TODO
	// }
	//
	// @Test
	// public void testEncodeToByte()
	// {
	// fail("Not yet implemented"); // TODO
	// }
	//
	// @Test
	// public void testDecodeByteArray()
	// {
	// fail("Not yet implemented"); // TODO
	// }
	//
	// @Test
	// public void testDecodeFastByteArray()
	// {
	// fail("Not yet implemented"); // TODO
	// }
	@Test
	public void testEncodeToString_And_DecodeString()
	{
		// Test conversion with line separator.
		String string_out = Base64.encodeToString(bytes_in, true);
		assertNotNull(string_out);

		// Verify that the line breaks are in the expected places.
		char[] chars_out = string_out.toCharArray();
		boolean bOK = chars_out[76] == '\r' && chars_out[77] == '\n' && chars_out[154] == '\r' && chars_out[155] == '\n'
					  && chars_out[232] == '\r' && chars_out[233] == '\n' && chars_out[310] == '\r' && chars_out[311] == '\n';
		assertTrue(bOK);

		// Convert back to byte array.
		byte[] bytes_out = Base64.decode(string_out);
		assertNotNull(bytes_out);
		assertArrayEquals(bytes_in, bytes_out);

		// Test conversion again without line separator.
		string_out = Base64.encodeToString(bytes_in, false);
		assertNotNull(string_out);

		// Convert back to byte array.
		bytes_out = Base64.decode(string_out);
		assertNotNull(bytes_out);
		assertArrayEquals(bytes_in, bytes_out);
	}

	// @Test
	// public void testDecodeFastString()
	// {
	// fail("Not yet implemented"); // TODO
	// }
}
