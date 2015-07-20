# cryptography

An easy to use AES and RSA cryptography library written in java, built on the Bouncy Castle API.  With this library you can quickly and easily incorporate AES-256 and RSA encryption into your project.

If you develop in both Java and C# then this project and the <a href="https://github.com/acschmit/cryptography.Net" target="_blank">C# project</a> are worth taking a look at.  They share the same API.  The Unit Tests and Examples are the same between them as well to illustrate their similarity.

## Version 1.0.7 Updates
### Project
* Add project to Maven. This project is not in the Maven Central Repository yet. When you compile this project it will add the cryptography-1.0.7.jar file, javadoc and source jars to your local repository.  When you add the jar to your project it will automatically add the depencencies.
* Compiles in both NetBeans and Eclipse.
* Require Java 7 or 8.
 
### AESService
* Default key size is 256-bits.
* Added KEYSIZE enumerator to allow configuration for 128-bit keys if desired.
* Added constructor to allow creation of a 128-bit encryption instance.
* Updated source to use try with resources (Java 7 or later).
* Updated Javadocs.

###RSAService
* Default key size is 2048-bits.
* Added KEYSIZE enumerator to allow configuratoin for 3k or 4k keys if desired.
* Added constructor to allow creation of 3k or 4k encryption instance. 
* Updated source to use try with resources (Java 7 or later).
* Added function to generate private key with password.
* Added function to read private key with password.
* Updated Javadocs.
 
##Key Structure
Bouncy Castle saves PEM keys in PKCS#1 format but it can read PEM keys in PKCS#8 format as well.

##License
The [license](LICENSE.txt), including licenses for dependent software, can be read [here](LICENSE.txt).

##External Dependencies
This library is dependent on the following jar files in <a href="http://www.bouncycastle.org" target="_blank">Bouncy Castle Version 1.52</a>.

* bcpkix-jdk15on.jar
* bcprov-jdk15on.jar

##Installation instructions
Be sure you have Maven installed in your IDE.

Either download the zip file or clone the repository to obtain the full project source. Compile the project and it will install all jar files in your local repository.

Create a new Maven project and search the repository for **org.albertschmitt**.  Add cryptography version 1.0.7.  Once this is done your project should have the following dependencies.

* cryptography-1.0.7.jar
* bcpkix-jdk15on.jar
* bcprov-jdk15on.jar

<!--
For comprehensive examples download the zip file in the **Example Projects** folder of this project. You can run each of the examples individually.
-->
##Examples

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
