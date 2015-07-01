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
import java.nio.file.Files;
import java.nio.file.Paths;
import org.albertschmitt.crypto.common.RSAPrivateKey;
import org.albertschmitt.crypto.common.RSAPublicKey;
import org.bouncycastle.crypto.InvalidCipherTextException;
import org.junit.After;
import org.junit.AfterClass;
import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertTrue;
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

	private static final String privateKeyfileDer = "./private_key.der";
	private static final String publicKeyfileDer = "./public_key.der";

	private final byte[] msgBytes;
	private static final String CHARSET = "UTF-8";

	// This is the RSA key size we will use for the tests.
	private RSAService.KEYSIZE keysize = RSAService.KEYSIZE.RSA_2K;

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
	public static void setUpClass() throws IOException
	{
		System.out.println("Deleting data files.");
		Files.deleteIfExists(Paths.get(privateKeyfile));
		Files.deleteIfExists(Paths.get(publicKeyfile));
//
//		/*
//		 * Unix command line to create the below files.
//		 * openssl genpkey -out private_key.der -outform DER -algorithm RSA -pkeyopt rsa_keygen_bits:2048
//		 * openssl rsa -inform DER -in private_key.der -outform DER -pubout -out public_key.der
//		 * base64 -b 76 public_key.der >public_key_der.txt
//		 * base64 -b 76 private_key.der >private_key_der.txt
//		 */
//		StringBuilder sbDerKey = new StringBuilder();
//		sbDerKey.append("MIIEowIBAAKCAQEAxilUCT1jsClBMi5KG3OuwrwGAM7guBXbr3evEB9fN4TDw4Vm9qBVvBTqrsAA");
//		sbDerKey.append("HaXTUrKt8MNYFe0C5fAQT1dvdNlUL7Y2eebmEfPvjWJ3LA4efqBMN4vNMWTTsPZP+sl/rPZHcbcw");
//		sbDerKey.append("tOQhpSy5Adqzwqetxf7YTCEcHGwS2RveYsgfK29P37xQLck35sJAwgugHLM0KuCPnJ3s34dHU6PB");
//		sbDerKey.append("DceE4XctCciRzaYdxcETVKog+XWaY/frURlerwiw/XZPhysnOYMRObRsHx+nEMN2GtH67KNJfpOH");
//		sbDerKey.append("gexZOnpn9pJZT5Yc8lkMV8YGsoqhpSCyX70Ve6LJhU9lPkU82qrjMQIDAQABAoIBADgfQlavlUky");
//		sbDerKey.append("Fe3hYEmwFMHAQK7/6HMadbKXYfRd/jiaGFuKr6OPu1heUC0X4bCD43rbchnrKUpkatq2h9gAumdM");
//		sbDerKey.append("meQ9ZeZWd7iD7seLKJdIlGhme8+Lf5zKoo3O5M3xPYC963QQXvIMXl8KcIdO6nRpyvR1fcrp4a1H");
//		sbDerKey.append("CnuEwhIVfeMfQ1QQsp1ZLG/Egzqz9nHTyU6VvIjSS4eo+WxIi0RVYD4AWjffpkUInHQCmS4XYRpB");
//		sbDerKey.append("VR7lxtAHpfP/P/tJRAckhQMN+NnmTAjL2HcVsLqXNp3NXuMDu7VOCjB1auVCxjO/ns3F+xT0Jm7W");
//		sbDerKey.append("3SU/mfkiqNVK6sWpwFOPo87ZpEECgYEA6CZ7UWKyEV0QWNBEcV4GQF8Uw7g4dVU8YJunl4OHj+G0");
//		sbDerKey.append("oXOHhm0faHL1XcsWKYRisp4FxeOZhrgmep1g26xJVj0nDakeImze0tvBUmezkMWfBMY1aCmoKuvU");
//		sbDerKey.append("IJpkEERaMXYAmTNV4xIaWhtwkfQUXTPVX+3YF1CslXwkrlh8WFkCgYEA2oTxsscTuaK6QO6CEm6x");
//		sbDerKey.append("kc9TOke4bmB/0TpA6HDYxHZkVpAXc9pbGEUX3mH8SR+CKAHkDZlAZgjXAMMQXak1erYENUPVRdv5");
//		sbDerKey.append("8UVbMjxSK7KS+ygSGKlOaI67o9qkKh3qJ0qBKcz8qsF3tojgtn6ulT2bFEtUcIS1C5JLtTeIBpkC");
//		sbDerKey.append("gYAKgLsximqN+Izlx75g9qUHwoV4+Vusi0epA0HIzA2VB9wZNdXa0hMKsbDCJo8BH9krRZTzSAHJ");
//		sbDerKey.append("I4myIG6iYaALw8aBirYvToeiOIj9hm2MTjSMjb8a0E+oaXT2aKXASqdd9329cKIhHM+OZhFouQc2");
//		sbDerKey.append("1EKCDYuqOl8kgDJUpPIzOQKBgHwD+1AlH5K5Qc9cDUH8xJYl/ewTjB5IcgICd5fzg3JsZqGiAU1k");
//		sbDerKey.append("3VI21EcHgTDWyv19pTn6gcvmtG7gRceCIrHT3yuDpeSR5ZYCcLFf/pqCLFyR70NDwxYf+2oQyh6E");
//		sbDerKey.append("/8DwzcE1byhRyGk14aJw3xAf+IVaA0AgcMdybbkZHP/xAoGBAKxRnenchDMmhP2vJU+8LZcxx2aO");
//		sbDerKey.append("UqiYRQ1nS5EBXZ6GfR2LBA8XcqaHPIkH8A2ssnuW4Lesvl4pq8U9oeVQeQbgEy2LFpYR/bzV/Pq3");
//		sbDerKey.append("rSNwIGgBGD0foi5GLA749Ep9eqGHOSnApkLUZlVq3UmIuJNzvTBx+2qxAYoQiXEEYOXv");
//
//		byte[] data = sbDerKey.toString().getBytes("UTF-8");
//		Path path = Paths.get(privateKeyfileDer);
//		Files.write(path, data, StandardOpenOption.CREATE);
//
//		sbDerKey = new StringBuilder();
//		sbDerKey.append("MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAxilUCT1jsClBMi5KG3OuwrwGAM7guBXb");
//		sbDerKey.append("r3evEB9fN4TDw4Vm9qBVvBTqrsAAHaXTUrKt8MNYFe0C5fAQT1dvdNlUL7Y2eebmEfPvjWJ3LA4e");
//		sbDerKey.append("fqBMN4vNMWTTsPZP+sl/rPZHcbcwtOQhpSy5Adqzwqetxf7YTCEcHGwS2RveYsgfK29P37xQLck3");
//		sbDerKey.append("5sJAwgugHLM0KuCPnJ3s34dHU6PBDceE4XctCciRzaYdxcETVKog+XWaY/frURlerwiw/XZPhysn");
//		sbDerKey.append("OYMRObRsHx+nEMN2GtH67KNJfpOHgexZOnpn9pJZT5Yc8lkMV8YGsoqhpSCyX70Ve6LJhU9lPkU8");
//		sbDerKey.append("2qrjMQIDAQAB");
//
//		data = sbDerKey.toString().getBytes("UTF-8");
//		path = Paths.get(publicKeyfileDer);
//		Files.write(path, data, StandardOpenOption.CREATE);
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
	 *
	 * @throws java.io.FileNotFoundException if file not found.
	 */
	@Test
	public final void testGenerateKey_String_String() throws FileNotFoundException, IOException
	{
		System.out.println("generateKey");
		final RSAService rsa = new RSAService(keysize);
		if (!rsa.areKeysPresent(privateKeyfile, publicKeyfile))
		{
			System.out.println("Begin Generating RSA Key Pair.");
			final OutputStream fos_private = new FileOutputStream(privateKeyfile);
			final OutputStream fos_public = new FileOutputStream(publicKeyfile);
			rsa.generateKey(fos_private, fos_public);
			System.out.println("Finish Generating RSA Key Pair.");
			assertTrue(true);
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

		RSAService instance = new RSAService(keysize);
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

		RSAService instance = new RSAService(keysize);
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
		RSAService instance = new RSAService(keysize);
		RSAPrivateKey privateKey = instance.readPrivateKey(privateKeyfile);
		assertNotNull(privateKey);
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
		RSAService instance = new RSAService(keysize);
		RSAPrivateKey result = instance.readPrivateKey(in);
		assertNotNull(result);
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
		RSAService instance = new RSAService(keysize);
		RSAPublicKey publicKey = instance.readPublicKey(publicKeyfile);
		assertNotNull(publicKey);
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
		RSAService instance = new RSAService(keysize);
		RSAPublicKey result = instance.readPublicKey(in);
		assertNotNull(result);
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
		RSAService instance = new RSAService(keysize);
		RSAPublicKey result = instance.readPublicKeyFromPrivate(privateKeyfile);
		assertNotNull(result);
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
		InputStream instream = new FileInputStream(privateKeyfile);
		RSAService instance = new RSAService(keysize);
		RSAPublicKey result = instance.readPublicKeyFromPrivate(instream);
		assertNotNull(result);
	}
}
