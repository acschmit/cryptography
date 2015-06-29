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

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.UnsupportedEncodingException;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.NoSuchAlgorithmException;
import org.albertschmitt.crypto.common.DigestSHA;
import org.albertschmitt.crypto.common.Hex;
import org.bouncycastle.crypto.InvalidCipherTextException;
import org.junit.After;
import org.junit.AfterClass;
import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;
import org.junit.Before;
import org.junit.BeforeClass;
import org.junit.Test;

/**
 *
 * @author acschmit
 */
public class AESServiceTest
{

	private final String password;
	private final byte[] msgBytes;
	private final String msgString;
	private static final String CHARSET = "UTF-8";

	private static final String SALT_DAT = "./salt.dat";
	private static final int SALT_LENGTH = 32;

	public AESServiceTest() throws UnsupportedEncodingException, IOException
	{
		StringBuilder sb = new StringBuilder();
		sb.append("esse cillum dolore eu fugiat nulla pariatur. Excepteur sint occaecat cupidatat non proident, sunt in culpa qui officia deserunt mollit anim id est laborum.");
		sb.append("Lorem ipsum dolor sit amet, consectetur adipiscing elit, sed do eiusmod tempor incididunt ut labore et dolore magna aliqua. Ut enim ad minim ");
		sb.append("veniam, quis nostrud exercitation ullamco laboris nisi ut aliquip ex ea commodo consequat. Duis aute irure dolor in reprehenderit in voluptate velit");

		msgString = sb.toString();
		msgBytes = msgString.getBytes(CHARSET);
		password = "ZJ=ENY'2H+0bm'oyIe6J";

		testGenerateSalt();
	}

	@BeforeClass
	public static void setUpClass() throws IOException
	{
		System.out.println("Deleting data files.");
		Files.deleteIfExists(Paths.get(SALT_DAT));
	}

	@AfterClass
	public static void tearDownClass()
	{
	}

	@Before
	public void setUp()
	{
	}

	@After
	public void tearDown()
	{
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

		writeSaltBytes(saltBytes);

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

		// Need to use a hard coded salt so we get a predictable result from getHmac256Digest().
		String saltString = "253a3dd3a9aef71ca1fa2b8b3704d6724ba474342e3c2e4fd124ee74d2c56017f4a7c22951a99978c6fdfbbefb4cf775d5642ea6dcb4d9b8e164fc23099f36c4";
		byte[] saltBytes = Hex.decode(saltString);

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

		byte[] saltBytes = readSaltBytes();

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

		byte[] saltBytes = readSaltBytes();

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

		byte[] saltBytes = readSaltBytes();

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

		byte[] saltBytes = readSaltBytes();

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
	//--------------------------------------------------------------------------
	// Support functions.
	//--------------------------------------------------------------------------

	private byte[] readSaltBytes() throws FileNotFoundException, IOException
	{
		byte[] saltBytes;
		try (FileInputStream is = new FileInputStream(SALT_DAT))
		{
			saltBytes = new byte[SALT_LENGTH];
			is.read(saltBytes);
		}
		return saltBytes;
	}

	private void writeSaltBytes(byte[] saltBytes1) throws FileNotFoundException, IOException
	{
		try (final FileOutputStream os = new FileOutputStream(SALT_DAT))
		{
			os.write(saltBytes1);
		}
	}
}
