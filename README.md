# cryptography

An easy to use AES and RSA cryptography library written in java, built on the Bouncy Castle API.  With this library you can quickly and easily incorporate AES-256 and RSA encryption into your project.

##License
The [license](LICENSE.txt), including licenses for dependent software, can be read [here](LICENSE.txt).

##External Dependencies
This library is dependent on the following jar files in <a href="http://www.bouncycastle.org" target="_blank">Bouncy Castle Version 1.52</a> which are included in this project.

* bcpkix-jdk15on.jar
* bcprov-jdk15on.jar

##Installation instructions
This project is built in NetBeans 8.

Either download the zip file or clone the repository to obtain the full project source.  All of the required jar files are in the folder named [**jars**](https://github.com/acschmit/cryptography/tree/master/jars) including the bouncy castle jar files.  At a minimum, copy the following files into your project:

* bcpkix-jdk15on.jar
* bcprov-jdk15on.jar
* cryptography-1.0.0.jar

The remaining jar files are there if you want to attach the source, java docs or review the JUnit tests.


##Examples

For comprehensive examples download one of the zip files in the **Example Projects** folder of this project.  There is one zip file for Eclipse or NetBeans projects.  You can run each of the examples individually.

####Example 1

Adding AES256 encryption to your project can be as simple as this:
```java

import java.security.SecureRandom;
import org.albertschmitt.crypto.AESService;
import static org.albertschmitt.crypto.AESService.SALT_SIZE;

public class Example_060
{
	public static void main(String[] args) throws Exception
	{
		// Create the AES Service
		AESService aes = new AESService();

		String password = "password";
		SecureRandom random = new SecureRandom();
		byte[] salt = new byte[SALT_SIZE];
		random.nextBytes(salt);

		// Create the AES Key using password and salt.
		aes.generateKey(password, salt);

		// Encode and Decode a string then compare to verify they are the same.
		String clear_text = "This is a test";
		byte[] enc_bytes = aes.encode(clear_text.getBytes("UTF-8"));
		byte[] dec_bytes = aes.decode(enc_bytes);
		String dec_text = new String(dec_bytes, "UTF-8");

		if (clear_text.equals(dec_text))
		{
			System.out.println("Original and Decrypted are the same!");
		}
		else
		{
			System.out.println("Original and Decrypted are NOT the same!");
		}
	}
}
```
