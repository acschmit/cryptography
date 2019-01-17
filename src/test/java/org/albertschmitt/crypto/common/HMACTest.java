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

import static org.junit.Assert.assertNotNull;

import java.io.UnsupportedEncodingException;
import java.nio.charset.StandardCharsets;

import org.junit.Before;
import org.junit.Test;

public class HMACTest
{

	private byte[] keyBytes;
	private byte[] msgBytes;
	private String msgString;

	@Before
	public void setUp() throws Exception
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

		String keyString = "253a3dd3a9aef71ca1fa2b8b3704d6724ba474342e3c2e4fd124ee74d2c56017f4a7c22951a99978c6fdfbbefb4cf775d5642ea6dcb4d9b8e164fc23099f36c4";
		keyBytes = Hex.decode(keyString);
	}

	@Test
	public final void testMd5ByteArrayByteArray() throws UnsupportedEncodingException
	{
		String result = HMAC.md5(msgBytes, keyBytes);
		assertNotNull(result);
	}

	@Test
	public final void testSha1ByteArrayByteArray() throws UnsupportedEncodingException
	{
		String result = HMAC.sha1(msgBytes, keyBytes);
		assertNotNull(result);
	}

	@Test
	public final void testSha256ByteArrayByteArray() throws UnsupportedEncodingException
	{
		String result = HMAC.sha256(msgBytes, keyBytes);
		assertNotNull(result);
	}

	@Test
	public final void testSha512ByteArrayByteArray() throws UnsupportedEncodingException
	{
		String result = HMAC.sha256(msgBytes, keyBytes);
		assertNotNull(result);
	}

	@Test
	public final void testMd5StringByteArray() throws UnsupportedEncodingException
	{
		String result = HMAC.md5(msgString, keyBytes);
		assertNotNull(result);
	}

	@Test
	public final void testSha1StringByteArray() throws UnsupportedEncodingException
	{
		String result = HMAC.sha1(msgString, keyBytes);
		assertNotNull(result);
	}

	@Test
	public final void testSha256StringByteArray() throws UnsupportedEncodingException
	{
		String result = HMAC.sha256(msgString, keyBytes);
		assertNotNull(result);
	}

	@Test
	public final void testSha512StringByteArray() throws UnsupportedEncodingException
	{
		String result = HMAC.sha512(msgString, keyBytes);
		assertNotNull(result);
	}

}
