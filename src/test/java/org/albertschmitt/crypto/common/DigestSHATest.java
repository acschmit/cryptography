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

import static org.junit.Assert.assertEquals;

import java.io.ByteArrayInputStream;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;

import org.junit.After;
import org.junit.Before;
import org.junit.Test;

/**
 *
 * @author acschmit
 */
public class DigestSHATest
{

	/**
	 * String that SHA Digest function will be tested with. Do not change this
	 * string or the tests will all fail.
	 */
	private final static String TEST_DATA = "Lorem ipsum dolor sit amet, inceptos mauris nec, ut id, orci nulla lectus ornare nam sit dui, cras malesuada neque dicta vestibulum.";

	@Before
	public void setUp()
	{
	}

	@After
	public void tearDown()
	{
	}

	/**
	 * Test of md5 method, of class DigestSHA.
	 *
	 * @throws java.lang.Exception
	 */
	@Test
	public void testMd5() throws Exception
	{
		System.out.println("DigestSHA.md5");
		byte[] data = TEST_DATA.getBytes(StandardCharsets.UTF_8);
		String expResult = "8d51d5a313d44e1a7a9698731813add7";
		String result = DigestSHA.md5(data);
		assertEquals(expResult, result);
	}

	/**
	 * Test of sha1 method, of class DigestSHA.
	 *
	 * @throws java.lang.Exception
	 */
	@Test
	public void testSha1_byteArr() throws Exception
	{
		System.out.println("DigestSHA.sha1");
		byte[] data = TEST_DATA.getBytes(StandardCharsets.UTF_8);
		String expResult = "526d5ab7f4f28b1db8d2a4f54e3f93cbc38d7a5d";
		String result = DigestSHA.sha1(data);
		assertEquals(expResult, result);
	}

	/**
	 * Test of sha1 method, of class DigestSHA.
	 *
	 * @throws java.lang.Exception
	 */
	@Test
	public void testSha1_InputStream() throws Exception
	{
		System.out.println("DigestSHA.sha1");
		InputStream is = new ByteArrayInputStream(TEST_DATA.getBytes(StandardCharsets.UTF_8));
		String expResult = "526d5ab7f4f28b1db8d2a4f54e3f93cbc38d7a5d";
		String result = DigestSHA.sha1(is);
		assertEquals(expResult, result);
	}

	/**
	 * Test of sha256 method, of class DigestSHA.
	 *
	 * @throws java.lang.Exception
	 */
	@Test
	public void testSha256_byteArr() throws Exception
	{
		System.out.println("DigestSHA.sha256");
		byte[] data = TEST_DATA.getBytes(StandardCharsets.UTF_8);
		String expResult = "ae235deeace393d0f25bb9b768277b934eaa3812ce769b0121302ee09b20646f";
		String result = DigestSHA.sha256(data);
		assertEquals(expResult, result);
	}

	/**
	 * Test of sha256 method, of class DigestSHA.
	 *
	 * @throws java.lang.Exception
	 */
	@Test
	public void testSha256_InputStream() throws Exception
	{
		System.out.println("DigestSHA.sha256");
		InputStream is = new ByteArrayInputStream(TEST_DATA.getBytes(StandardCharsets.UTF_8));
		String expResult = "ae235deeace393d0f25bb9b768277b934eaa3812ce769b0121302ee09b20646f";
		String result = DigestSHA.sha256(is);
		assertEquals(expResult, result);
	}

	/**
	 * Test of sha384 method, of class DigestSHA.
	 *
	 * @throws java.lang.Exception
	 */
	@Test
	public void testSha384_byteArr() throws Exception
	{
		System.out.println("DigestSHA.sha384");
		byte[] data = TEST_DATA.getBytes(StandardCharsets.UTF_8);
		String expResult = "17cc84262caaca5692316af52b1d4d50d86e0ae51c28700538174da4c6935115583fa8ff55d3e644a9f02cd8d587018f";
		String result = DigestSHA.sha384(data);
		assertEquals(expResult, result);
	}

	/**
	 * Test of sha384 method, of class DigestSHA.
	 *
	 * @throws java.lang.Exception
	 */
	@Test
	public void testSha384_InputStream() throws Exception
	{
		System.out.println("DigestSHA.sha384");
		InputStream is = new ByteArrayInputStream(TEST_DATA.getBytes(StandardCharsets.UTF_8));
		String expResult = "17cc84262caaca5692316af52b1d4d50d86e0ae51c28700538174da4c6935115583fa8ff55d3e644a9f02cd8d587018f";
		String result = DigestSHA.sha384(is);
		assertEquals(expResult, result);
	}

	/**
	 * Test of sha512 method, of class DigestSHA.
	 *
	 * @throws java.lang.Exception
	 */
	@Test
	public void testSha512_byteArr() throws Exception
	{
		System.out.println("DigestSHA.sha512");
		byte[] data = TEST_DATA.getBytes(StandardCharsets.UTF_8);
		String expResult = "d1d63b225ce4d047c95e1809bf50830d960a5b649bf8f33914e2a7be58931adf50e570774f7de5574a0259f0df1338bba0b2e81b2be27ff30aff48d05bbba015";
		String result = DigestSHA.sha512(data);
		assertEquals(expResult, result);
	}

	/**
	 * Test of sha512 method, of class DigestSHA.
	 *
	 * @throws java.lang.Exception
	 */
	@Test
	public void testSha512_InputStream() throws Exception
	{
		System.out.println("DigestSHA.sha512");
		InputStream is = new ByteArrayInputStream(TEST_DATA.getBytes(StandardCharsets.UTF_8));
		String expResult = "d1d63b225ce4d047c95e1809bf50830d960a5b649bf8f33914e2a7be58931adf50e570774f7de5574a0259f0df1338bba0b2e81b2be27ff30aff48d05bbba015";
		String result = DigestSHA.sha512(is);
		assertEquals(expResult, result);
	}

}
