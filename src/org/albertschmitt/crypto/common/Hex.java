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

/**
 * Convert byte arrays to hexadecimal strings and visa-versa. This class is
 * useful in situations where you want to store byte data in a text file.
 *
 */
public final class Hex
{

	/**
	 * Prevent instantiation. All methods are static.
	 */
	private Hex()
	{
	}

	/**
	 * Convert a hexadecimal string back into a byte array. This function
	 * reverses the action of the #encode(byte data[]) function.
	 *
	 * @param hexString A hexadecimal string.
	 * @return a byte array representation of the hexadecimal string.
	 */
	public static byte[] decode(String hexString)
	{
		byte[] data = new byte[hexString.length() / 2];
		char[] chars = hexString.toCharArray();
		for (int i = 0, j = 0; i < chars.length; i += 2, j++)
		{
			int low = Character.digit(chars[i + 1], 16);
			int high = Character.digit(chars[i], 16);
			data[j] = (byte) ((high << 4) + low);
		}

		return data;
	}

	/**
	 * Convert a byte array into a hexadecimal string.
	 *
	 * @param data The byte array to be converted into a hexadecimal string.
	 * @return A hexadecimal string representation of the byte data.
	 */
	public static String encode(byte[] data)
	{
		StringBuilder sb = new StringBuilder();
		for (int i = 0; i < data.length; i++)
		{
			int low = data[i] & 0xF;
			int high = (data[i] >> 4) & 0xF;
			sb.append(Character.forDigit(high, 16));
			sb.append(Character.forDigit(low, 16));
		}
		return sb.toString();
	}

}
