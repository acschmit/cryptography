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
package org.albertschmitt.crypto;

import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.UnsupportedEncodingException;
import java.nio.charset.StandardCharsets;
import java.security.NoSuchAlgorithmException;

import org.albertschmitt.crypto.common.DigestSHA;
import org.albertschmitt.crypto.common.Hex;
import org.bouncycastle.crypto.InvalidCipherTextException;
import org.junit.After;
import org.junit.Before;
import org.junit.Test;

/**
 *
 * @author acschmit
 */
public class AESServiceTest
{
	private byte[]				saltBytes;
	private char[]				password;
	private byte[]				msgBytes;
	private String				msgString;

	@Before
	public void setUp() throws UnsupportedEncodingException
	{
		StringBuilder sb = new StringBuilder();
		sb.append(
				"esse cillum dolore eu fugiat nulla pariatur. Excepteur sint occaecat cupidatat non proident, sunt in culpa qui officia deserunt mollit anim id est laborum.");
		sb.append(
				"Lorem ipsum dolor sit amet, consectetur adipiscing elit, sed do eiusmod tempor incididunt ut labore et dolore magna aliqua. Ut enim ad minim ");
		sb.append(
				"veniam, quis nostrud exercitation ullamco laboris nisi ut aliquip ex ea commodo consequat. Duis aute irure dolor in reprehenderit in voluptate velit");

		msgString = sb.toString();
		msgBytes = msgString.getBytes(StandardCharsets.UTF_8);
		password = "ZJ=ENY'2H+0bm'oyIe6J".toCharArray();
		String saltString = "253a3dd3a9aef71ca1fa2b8b3704d6724ba474342e3c2e4fd124ee74d2c56017f4a7c22951a99978c6fdfbbefb4cf775d5642ea6dcb4d9b8e164fc23099f36c4";
		saltBytes = Hex.decode(saltString);
	}

	@After
	public void tearDown()
	{
		msgString = null;
		msgBytes = null;
		password = null;
		saltBytes = null;
	}

	/**
	 * Test of generateSalt method, of class AESService.
	 *
	 * @throws java.io.IOException
	 */
	@Test
	public final void testGenerateSalt() throws IOException
	{
		System.out.println("generateSalt");
		AESService instance = new AESService();
		byte[] saltBytes = instance.generateSalt();

		assertNotNull(saltBytes);
	}

	/**
	 * Test of getAesKey method, of class AESService.
	 *
	 */
	@Test
	public void testGetAesKey()
	{
		System.out.println("getAesKey");
		AESService instance = new AESService();
		instance.generateKey();

		byte[] result = instance.getAesKey();
		assertNotNull(result);
	}

	/**
	 * Test of getHmac256Digest method, of class AESService.
	 *
	 */
	@Test
	public void testGetHmac256Digest() throws NoSuchAlgorithmException
	{
		System.out.println("getHmac256Digest");

		AESService instance = new AESService();
		instance.generateKey(password, saltBytes);

		String result = DigestSHA.sha512(msgBytes);
		String expResult = "25296335d88536dddd09ffb7bcc09646dd9b3f537beb78cf89c76077d39daedd0cb8e46cf1e9b06a99e59e5b8b7f66f307978dc6413426b13d1f724a0a030529";

		assertEquals(expResult, result);
	}

	/**
	 * Test of encode method, of class AESService.
	 *
	 * @throws java.io.IOException
	 * @throws org.bouncycastle.crypto.InvalidCipherTextException
	 */
	@Test
	public void testEncodeAndDecode_byteArr() throws InvalidCipherTextException, IOException
	{
		System.out.println("encode and decode byte array");

		AESService instance = new AESService();
		instance.generateKey(password, saltBytes);

		byte[] encData = instance.encode(msgBytes);
		byte[] decData = instance.decode(encData);

		assertArrayEquals(msgBytes, decData);
	}

	@Test
	public void testEncodeAndDecode_String() throws InvalidCipherTextException, IOException
	{
		System.out.println("encode and decode String");

		AESService instance = new AESService();
		instance.generateKey(password, saltBytes);

		byte[] encData = instance.encode(msgString);
		String encString = Hex.encode(encData);
		byte[] decData = instance.decode(encString);

		assertArrayEquals(msgBytes, decData);
	}

	/**
	 * Test of encode method, of class AESService.
	 *
	 * @throws java.io.IOException
	 * @throws org.bouncycastle.crypto.InvalidCipherTextException
	 */
	@Test
	public void testEncodeAndDecode_InputStream_OutputStream() throws IOException, InvalidCipherTextException
	{
		System.out.println("encode and decode stream");

		AESService instance = new AESService();
		instance.generateKey(password, saltBytes);

		byte[] decData;
		byte[] encData;
		try (InputStream instream = new ByteArrayInputStream(msgBytes);
			 ByteArrayOutputStream outstream = new ByteArrayOutputStream())
		{
			instance.encode(instream, outstream);
			encData = outstream.toByteArray();
			decData = instance.decode(encData);
		}
		assertArrayEquals(msgBytes, decData);

		try (InputStream instream = new ByteArrayInputStream(encData);
			 ByteArrayOutputStream outstream = new ByteArrayOutputStream())
		{
			instance.decode(instream, outstream);
			decData = outstream.toByteArray();
		}
		assertArrayEquals(msgBytes, decData);
	}

	/**
	 * Test of generateKey method, of class AESService.
	 *
	 */
	@Test
	public void testGenerateKey_0args()
	{
		System.out.println("generateKey");
		AESService instance = new AESService();
		instance.generateKey();

		byte[] aes_key = instance.getAesKey();
		assertNotNull(aes_key);
	}

	/**
	 * Test of generateKey method, of class AESService.
	 *
	 * @throws java.io.IOException
	 */
	@Test
	public void testGenerateKey_String_byteArr() throws IOException
	{
		System.out.println("generateKey");

		AESService instance = new AESService();
		instance.generateKey(password, saltBytes);

		byte[] aes_key = instance.getAesKey();
		assertNotNull(aes_key);
	}

	/**
	 * Test of setAesKey method, of class AESService.
	 *
	 */
	@Test
	public void testSetAesKey()
	{
		System.out.println("setAesKey");
		AESService instance = new AESService();
		instance.generateKey();

		byte[] result = instance.getAesKey();
		assertNotNull(result);

		instance.setAesKey(result);
	}
}
