#include<openssl/bn.h>
#include <stdio.h>
#include<string.h>
#include <ctype.h>


/***
 *  @param  *p , *q pointers two big prime numbers
 *  @param  *e pointer to Modulus
 *  @return BIGNUM* pointer which is the private key
 */

BIGNUM* getPrivateKey(BIGNUM* p, BIGNUM* q, BIGNUM* e)
{

/**************************************************

  steps to calculate private key:

1. Choose two random primes p and q

2. Compute n, the product of p and q. This is the public key.

3. Compute d, the inverse of the chosen exponent, modulo (p – 1) × (q – 1).

 ***************************************************/

	BN_CTX *ctx = BN_CTX_new();

  // p
	BIGNUM* p_minus_one = BN_new();
  // q
	BIGNUM* q_minus_one = BN_new();
  // 1
  BIGNUM* one = BN_new();
  // d
	BIGNUM* tt = BN_new();
  //convert number 1 to big num
  BN_dec2bn(&one, "1");
  //(p – 1).
	BN_sub(p_minus_one, p, one);
  //(q – 1)
  BN_sub(q_minus_one, q, one);
  // (p – 1) × (q – 1)
	BN_mul(tt, p_minus_one, q_minus_one, ctx);

	BIGNUM* res = BN_new();
  // d = inverse modulo (p – 1) × (q – 1)
  BN_mod_inverse(res, e, tt, ctx);
  BN_CTX_free(ctx);
	return res;

}



BIGNUM* encryption(BIGNUM* message, BIGNUM* mod, BIGNUM* pub_key)
{
	/**********************************************************************

  Encryption : A message is translated into an integer
              and encrypted with integer math.

  c = m^e (mod n) , where:

  1. c is the ciphertext, written as an integer
  2. m is the message ,
  3. n is the modulus ,
  4. e is the exponent from the public key.


	***********************************************************************/
	BN_CTX *ctx = BN_CTX_new();
	BIGNUM* enc = BN_new();
	BN_mod_exp(enc, message, mod, pub_key, ctx);
	BN_CTX_free(ctx);
	return enc;
}

BIGNUM* decryption(BIGNUM* enc, BIGNUM* private_key, BIGNUM* public_key)
{
	/***********************************************************

  Decryption: c^d = (m^e)^d = m (mod n)

	************************************************************/

  // scratch space for temporary values
	BN_CTX *ctx = BN_CTX_new();
	BIGNUM* dec = BN_new();
  // (dec = enc^private_key  (mod  public_key) )
	BN_mod_exp(dec, enc, private_key, public_key, ctx);
	BN_CTX_free(ctx);
	return dec;
}


/*

function that converts hexademical value to integer

*/
int xtoi(char c)
{
    int v = -1;
    char w=toupper(c);
    if(w >= 'A' && w <= 'F'){
        v = w - 'A' + 0x0A;
    }else if (w >= '0' && w <= '9'){
        v = w - '0';
    }

    return v;

}
/*

 function that converts hexadecimal value to ascii

*/


int htoa(const char c, const char d)
{
	int high = xtoi(c) * 16;
	int low = xtoi(d);
	return high+low;
}

/*

  function that prints hexademical value as string

*/


void printHX(const char* st)
{
	int length = strlen(st);
	if (length % 2 != 0) {
		printf("%s\n", "invalid hex length");
		return;
	}
	int i;
	char buf = 0;
	for(i = 0; i < length; i++) {
		if(i % 2 != 0)
			printf("%c", htoa(buf, st[i]));
		else
		    buf = st[i];
	}
	printf("\n");
}

/*

  function that print bignum as string

*/

void printBN(char* msg, BIGNUM * a)
{
    char * number_str = BN_bn2hex(a);
    printf("%s 0x%s\n", msg, number_str);
    OPENSSL_free(number_str);
}


int main ()
{

	/***********  1 ****************/

	printf("\n\n\n*************************** Exercise 1 ******************************\n\n\n");

	 BIGNUM *p = BN_new();
   BIGNUM *q = BN_new();
	 BIGNUM *e = BN_new();

	  // first large prime
	  BN_hex2bn(&p, "F7E75FDC469067FFDC4E847C51F452DF");

	  // second large prime
	  BN_hex2bn(&q, "E85CED54AF57E53E092113E62F436F4F");

    //encryption exponent
	  BN_hex2bn(&e, "0D88C3");

	  BIGNUM* priv_key1 = getPrivateKey(p, q, e);
    char * priv_key_str = BN_bn2dec(priv_key1);
    printBN("the private key is: ",priv_key1);


		printf("\n*******************************************************************\n\n");

  	/************  2 *****************/

		printf("********************Exercise 2***********************************\n\n");

   /*
      Let assume that (e,n) is the public key.We must encrypt the message "A top secret!" (without quotations).
      Public keys and private key d listing below.

			n = DCBFFE3E51F62E09CE7032E2677A78946A849DC4CDDE3A4D0CB81629242FB1A5
      e = 010001 (this hex value equals to decimal 65537)
      M = A top secret!
      d = 74D806F9F3A62BAE331FFE3F0A68AFE35B3D2E4794148AACBC26AA381CD7D30D

	 */


	 	 BIGNUM* enc = BN_new();
	 	 BIGNUM* dec = BN_new();

  	// Assign the private key
  	BIGNUM* private_key = BN_new();
  	BN_hex2bn(&private_key, "74D806F9F3A62BAE331FFE3F0A68AFE35B3D2E4794148AACBC26AA381CD7D30D");

  	// Assign the public key
  	BIGNUM* public_key = BN_new();
   	BN_hex2bn(&public_key, "DCBFFE3E51F62E09CE7032E2677A78946A849DC4CDDE3A4D0CB81629242FB1A5");
  	printBN("the public key is: ", public_key);

  	// Assign the Modulus
  	BIGNUM* mod = BN_new();
  	BN_hex2bn(&mod, "010001");

  	BIGNUM* msg = BN_new();

		/*
		encryption of string 'A top secret!'
    convert the ASCII string  'A top secret!'  to hex string,
    and then hex string  to BIGNUM
		using the hex-to-bn API BN hex2bn()
		*/

		// We are using the below command in order to convert  a plain ASCII string to hex string
		// $ python -c ’print("A top secret!".encode("hex"))’
		// 4120746f702073656372657421
  	BN_hex2bn(&msg, "4120746f702073656372657421");

  	printBN("the hexademical value is: ", msg);
  	enc = encryption(msg, mod, public_key);
  	printBN("the encrypted message is: ", enc);
  	dec = decryption(enc, private_key, public_key);
  	printf("the decrypted message  is: ");
  	printHX(BN_bn2hex(dec));

		printf("\n*******************************************************************\n\n");


    /*********************************** 3 ***********************************************************/



		printf("******************** Exercise 3 ***********************************\n\n");

    /*
     Using the public and private keys from the previous exercise, we want to decrypt the ciphertext c:
		 C = "8C0F971DF2F3672B28811407E2DABBE1DA0FEBBBDFC7DCB67396567EA1E2493F" which is in hexadecimal format.
		 And then convert it to plain text again.
     In order to convert a hex string hack to plain ASCII we are using the below command:

		 $ python -c ’print("4120746f702073656372657421".decode("hex"))’
      A top secret!
		*/

  	// We must convert the ciphertext to a BIGNUM in order to prepare the computations.
  	BIGNUM* exec3 = BN_new();
  	BN_hex2bn(&exec3, "8C0F971DF2F3672B28811407E2DABBE1DA0FEBBBDFC7DCB67396567EA1E2493F");

  	// public and private keys are the same from the previous exercise.
  	// decrypt using our decryption function.
  	dec = decryption(exec3, private_key, public_key);
  	printf("the decrypted message is: ");
  	printHX(BN_bn2hex(dec));

		printf("\n*******************************************************************\n\n\n\n\n");



    /********************************* 4 *****************************************/


		printf("********************Exercise 4***********************************\n\n");

    /*
    Using the private and public keys from exercise 2, we must generate a signature for the message: "M = I owe you $2000"
		*/

    	// In this task, we are to generate the signature for a message.
    	// we must convert the message to hex.
    	// Using  the  following command to we achieve the convertation :  python -c ’print("I owe you $2000".encode("hex"))’
    	// In order to prepare computations convert to a BIGNUM.
    	BIGNUM* exec4 = BN_new();
    	BN_hex2bn(&exec4, "49206f776520796f75202432303030");

    	// We know the private key so we must encrypt.
    	enc = encryption(exec4, private_key, public_key);
    	printBN("the signature for \'I owe you $2000.\' is: ", enc);

    	// decrypt for verification purposes.
    	dec = decryption(enc, mod, public_key);
    	printf("the first plain message is: ");
    	printHX(BN_bn2hex(dec));

			/*
			Then make a small change to the M message, such as changing $ 2000 to $ 3000, and
			sign the modified message. Compare signatures and describe what
			you notice
			*/

      //hex value of the the message "I owe you  $3000 is the same as before"
			BN_hex2bn(&exec4, "49206f776520796f75202433303030");

			// We know the private key so we must encrypt.
			enc = encryption(exec4, private_key, public_key);
			printBN("the signature for \'I owe you $3000.\': ", enc);

			// decrypt for verification purposes.
			dec = decryption(enc, mod, public_key);
			printf("the second plain message is: ");
			printHX(BN_bn2hex(dec));

			printf("\n*******************************************************************\n\n\n");



      	/************************************** 5 ******************************************/

				printf("\n\n********************Exercise 5***********************************\n\n\n");


        /*
           Bob receives a message M ="Launch a missile." from Alice.Alice has a signature S and public key (e,n).
					 We must verify whether the signature belongs to Alice's.Below there are public key and signature in hexademical format:

					 M = Launch a missle.
					 S = 643D6F34902D9C7EC90CB0B2BCA36C47FA37165C0005CAB026C0542CBDB6802F
					 e = 010001 (this hex value equals to decimal 65537)
					 n = AE1CD4DC432798D933779FBD46C6E1247F0CF1233595113AA51B450F18116115
				*/

      	BIGNUM* S = BN_new();

        //assign public key
      	BN_hex2bn(&public_key, "AE1CD4DC432798D933779FBD46C6E1247F0CF1233595113AA51B450F18116115");
				//assign signature
      	BN_hex2bn(&S, "643D6F34902D9C7EC90CB0B2BCA36C47FA37165C0005CAB026C0542CBDB6802F");
      	// we decrypt the message using  the public key that has been encrypted with the private key
				//and we will compare the message with our decrypted message
      	dec = decryption(S, mod, public_key);
      	printf("the plain message (without corruption) is: ");
      	printHX(BN_bn2hex(dec));
      	printf("\n");

      	/*
				Now, consider that the signature has been corrupted (damaged) so that its last byte
				signature changes from 2F to 3F, that is, there is only one bit that has changed.
				Repeat this activity and describe what will happen in the process signature verification.
				*/

        // corrupted signature with changes from 2F to 3F
      	BN_hex2bn(&S, "643D6F34902D9C7EC90CB0B2BCA36C47FA37165C0005CAB026C0542CBDB6803F");

      	// decryption of  a corrupted message with the public key.
      	dec = decryption(S, mod, public_key);
				printf("the plain message (with corruption) is: ");
      	//prints the corrupted output here.
      	printHX(BN_bn2hex(dec));
				// changes corrupt in
      	printf("\n");
				printf("\n*******************************************************************\n\n");


         /********************************** 6 ********************************************/

		 	 printf("******************** Exercise 6 ***********************************\n\n");

      /*
			  In this activity, we will manually test an X.509 certificate
        using our program. An X.509 contains data about a public
				key and signature of the publisher in the data. We'll get a real certificate
        X.509 from a web server, we will get the publisher's public key in
        we will use this public key to verify the signature on the certificate.
      */

			/*
		   	Validating a certificate involves finding the public key of the issuer, using it to run
			  the digital signature algorithm on the computed hash, and then verifying that it
		  	matches the signature included in the certificate itself.
			*/

       // first of all we download the the certificate at github.com and save it in c0.pem and c1.pem
			 // The we must extracted the public key and modulus from the certificate of github.com web server.

       // We extract the public key (e, n) from the issuer's certificate.
			 // using the below commands :
			 // For modulus (n): $ openssl x509 -in c1.pem -noout -modulus
       // Print out all the fields, find the exponent (e): $ openssl x509 -in c1.pem -text -noout

				// Assign the public key
				BIGNUM* exec6PublicKey = BN_new();
				BN_hex2bn(&exec6PublicKey,"D753A40451F899A616484B6727AA9349D039ED0CB0B00087F1672886858C8E63DABCB14038E2D3F5ECA50518B83D3EC5991732EC188CFAF10CA6642185CB071034B052882B1F689BD2B18F12B0B3D2E7881F1FEF387754535F80793F2E1AAAA81E4B2B0DABB763B935B77D14BC594BDF514AD2A1E20CE29082876AAEEAD764D69855E8FDAF1A506C54BC11F2FD4AF29DBB7F0EF4D5BE8E16891255D8C07134EEF6DC2DECC48725868DD821E4B04D0C89DC392617DDF6D79485D80421709D6F6FFF5CBA19E145CB5657287E1C0D4157AAB7B827BBB1E4FA2AEF2123751AAD2D9B86358C9C77B573ADD8942DE4F30C9DEEC14E627E17C0719E2CDEF1F910281933");
				printBN("the public key is: ", exec6PublicKey);

				// Assign the modulus
				BIGNUM* exec6Mod = BN_new();
				BN_hex2bn(&exec6Mod, "010001");

        /*
					Export the signature from the server certificate. There is no
					a specific openssl command to extract the signature field. However, we can
					print all the fields and then copy and paste the blocks
					signature in a file (note: if the signature algorithm used in
					certificate not based on RSA, you can find another certificate).
				*/

				// We extracted the signature (sha256) from the certificate,
				// with the below command:
				// openssl x509 -in c0.pem -text -noout

				// Assign the signature to a BIGNUM
				BIGNUM* exec6_signature = BN_new();
				BN_hex2bn(&exec6_signature, "700f5a96a758e5bf8a9da827982b007f26a907daba7b82544faf69cfbcf259032bf2d5745825d81ea42076626029732ad7dccc6f77856bca6d24f83513473fd2e2690a9d342d7b7b9bcd1e75d5506c3ecb1ca330b1aa9207a93a767645bd7891c4ce1a9e22e40b89bae68cc17982a3b8d4c0fc1f2ded4d5255412aa83a2cad0772ae0ad2c667c44f07171899f765a95760155a344c11cff6cf6b213680efc6f15463263539eebbc483649b240a73eca0481673c8b9d7485556987af7bb975c69a406180478dafe9876be222f7f0777874e88199af855ec5c122a5948db493e155e675aa25eeecc53288c0e33931403640bc5e5780994015a75fc929dafed7a29");

				/*
				Remove the server certificate body. A Certification Authority
				(CA) creates the signature for a server certificate, initially calculating it
				hash certificate and then sign the hash. To verify it
				signature, we also need to create the hash from a certificate. Since the
				fragmentation is created before calculating the signature, must
				we exclude the signature block of a certificate when calculating the hash.
				Finding the part of the certificate used to create the hash
        is difficult enough without a good understanding of the form of the certificate.

				X.509 certificates are encoded using ASN.1 (Abstract Syntax Notation.One),
			  so if we can analyze ASN.1 structure, we can easily
				export any field from a certificate. Openssl has a command that says
        called asn1parse, which can be used to analyze one X.509 certificate
				*/

				// We generated the hash of the certificate body like so:
				// First, we must extract the body of the certificate
				// using the below command will give us the body of the certificate, excluding the block signature.
        // $ openssl asn1parse -i -in c0.pem -strparse 4 -out c0_body.bin -noout


				// Once we receive the body of the certificate, we can calculate its hash
				// using the following command:
			  // will give us the body of the certificate, excluding the block signature.
				// $ sha256sum c0_body.bin
				// This hash will be used for comparison for when we decrypt the signature.
				// Now we decrypt the signature using the public key and modulus given from the certificate.
				// If the signature is valid, it should match our hash of the certificate body we computed earlier.
				BIGNUM* exec6Decryption = decryption(exec6_signature, exec6Mod, exec6PublicKey);

				// Print the decrypted hash.
				// the first 32 bytes of this value should
				// match the hash generated from the body of the certificate.
				printBN("\nthe hash is: ", exec6Decryption);
				printf("\n");

				printf("the hash that calculated before was: ");
				// calculated using the following command:  $ sha256sum c0_body.bin
				printf("85088f934d3e58e3673ea5be32c7c8cf6965e4ab93fbed4fff634723f46d5693");
				printf("\n");

				printf("\n*******************************************************************\n\n");

  return 0;

}
