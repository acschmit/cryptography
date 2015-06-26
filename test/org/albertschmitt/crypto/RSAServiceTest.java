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
import java.io.OutputStream;
import org.albertschmitt.crypto.common.RSAPrivateKey;
import org.albertschmitt.crypto.common.RSAPublicKey;
import org.bouncycastle.crypto.InvalidCipherTextException;
import org.junit.After;
import org.junit.AfterClass;
import static org.junit.Assert.assertArrayEquals;
import org.junit.Before;
import org.junit.BeforeClass;
import org.junit.Test;

/**
 *
 * @author acschmit
 */
public class RSAServiceTest
{

	private static final String privateKeyfile = "./private_key.pem";
	private static final String publicKeyfile = "./public_key.pem";

	private final byte[] msgBytes;
	private static final String CHARSET = "UTF-8";

	public RSAServiceTest() throws FileNotFoundException, Exception
	{
		StringBuilder sb = new StringBuilder();
		sb.append("esse cillum dolore eu fugiat nulla pariatur. Excepteur sint occaecat cupidatat non proident, sunt in culpa qui officia deserunt mollit anim id est laborum.");
		sb.append("Lorem ipsum dolor sit amet, consectetur adipiscing elit, sed do eiusmod tempor incididunt ut labore et dolore magna aliqua. Ut enim ad minim ");
		sb.append("veniam, quis nostrud exercitation ullamco laboris nisi ut aliquip ex ea commodo consequat. Duis aute irure dolor in reprehenderit in voluptate velit");

		msgBytes = sb.toString().getBytes(CHARSET);

		testGenerateKey_String_String();
	}

	@BeforeClass
	public static void setUpClass()
	{
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
	 * Test of generateKey method, of class RSAService.
	 */
	@Test
	public final void testGenerateKey_String_String() throws FileNotFoundException, IOException
	{
		System.out.println("generateKey");
		final RSAService rsa = new RSAService();
		if (!rsa.areKeysPresent(privateKeyfile, publicKeyfile))
		{
			System.out.println("Begin Generating RSA Key Pair.");
			final OutputStream fos_private = new FileOutputStream(privateKeyfile);
			final OutputStream fos_public = new FileOutputStream(publicKeyfile);
			rsa.generateKey(fos_private, fos_public);
			System.out.println("Finish Generating RSA Key Pair.");
		}
	}

	/**
	 * Test of encode method, of class RSAService.
	 *
	 * @throws java.io.IOException
	 * @throws org.bouncycastle.crypto.InvalidCipherTextException
	 */
	@Test
	public void testEncodeAndDecode_byteArr_Key() throws IOException, InvalidCipherTextException
	{
		System.out.println("encode and decode");

		RSAService instance = new RSAService();
		RSAPrivateKey privateKey = instance.readPrivateKey(privateKeyfile);
		RSAPublicKey publicKey = instance.readPublicKey(publicKeyfile);

		byte[] enc = instance.encode(msgBytes, privateKey);
		byte[] dec = instance.decode(enc, publicKey);

		assertArrayEquals(dec, msgBytes);

		enc = instance.encode(msgBytes, publicKey);
		dec = instance.decode(enc, privateKey);

		assertArrayEquals(dec, msgBytes);
	}

	/**
	 * Test of encode method, of class RSAService.
	 *
	 * @throws java.io.IOException
	 * @throws org.bouncycastle.crypto.InvalidCipherTextException
	 */
	@Test
	public void testEncodeAndDecode_3args() throws IOException, InvalidCipherTextException
	{
		System.out.println("encode and decode stream");

		RSAService instance = new RSAService();
		RSAPrivateKey privateKey = instance.readPrivateKey(privateKeyfile);
		RSAPublicKey publicKey = instance.readPublicKey(publicKeyfile);

		byte[] decData;
		try (InputStream instream = new ByteArrayInputStream(msgBytes);
			 ByteArrayOutputStream outstream = new ByteArrayOutputStream())
		{
			instance.encode(instream, outstream, privateKey);
			byte[] encData = outstream.toByteArray();
			decData = instance.decode(encData, publicKey);
		}
		assertArrayEquals(msgBytes, decData);

		try (InputStream instream = new ByteArrayInputStream(msgBytes);
			 ByteArrayOutputStream outstream = new ByteArrayOutputStream())
		{
			instance.encode(instream, outstream, publicKey);
			byte[] encData = outstream.toByteArray();
			decData = instance.decode(encData, privateKey);
		}
		assertArrayEquals(msgBytes, decData);
	}

	/**
	 * Test of readPrivateKey method, of class RSAService.
	 *
	 * @throws java.io.IOException
	 */
	@Test
	public void testReadPrivateKey_String() throws IOException
	{
		System.out.println("readPrivateKey");
		RSAService instance = new RSAService();
		RSAPrivateKey privateKey = instance.readPrivateKey(privateKeyfile);
	}

	/**
	 * Test of readPrivateKey method, of class RSAService.
	 *
	 * @throws java.io.FileNotFoundException
	 */
	@Test
	public void testReadPrivateKey_InputStream() throws FileNotFoundException, IOException
	{
		System.out.println("readPrivateKey");
		InputStream in = new FileInputStream(privateKeyfile);
		RSAService instance = new RSAService();
		RSAPrivateKey result = instance.readPrivateKey(in);
	}

	/**
	 * Test of readPublicKey method, of class RSAService.
	 *
	 * @throws java.io.IOException
	 */
	@Test
	public void testReadPublicKey_String() throws IOException
	{
		System.out.println("readPublicKey");
		RSAService instance = new RSAService();
		RSAPublicKey publicKey = instance.readPublicKey(publicKeyfile);
	}

	/**
	 * Test of readPublicKey method, of class RSAService.
	 *
	 * @throws java.io.FileNotFoundException
	 */
	@Test
	public void testReadPublicKey_InputStream() throws FileNotFoundException, IOException
	{
		System.out.println("readPublicKey");
		InputStream in = new FileInputStream(publicKeyfile);
		RSAService instance = new RSAService();
		RSAPublicKey result = instance.readPublicKey(in);
	}

	/**
	 * Test of readPublicKeyFromPrivate method, of class RSAService.
	 *
	 * @throws java.io.IOException
	 */
	@Test
	public void testReadPublicKeyFromPrivate_String() throws IOException
	{
		System.out.println("readPublicKeyFromPrivate");
		RSAService instance = new RSAService();
		RSAPublicKey result = instance.readPublicKeyFromPrivate(privateKeyfile);
	}

	/**
	 * Test of readPublicKeyFromPrivate method, of class RSAService.
	 *
	 * @throws java.io.FileNotFoundException
	 */
	@Test
	public void testReadPublicKeyFromPrivate_InputStream() throws FileNotFoundException, IOException
	{
		System.out.println("readPublicKeyFromPrivate");
		InputStream in = new FileInputStream(privateKeyfile);
		RSAService instance = new RSAService();
		RSAPrivateKey result = instance.readPrivateKey(in);
	}
}
