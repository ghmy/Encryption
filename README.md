# Encryption
Hybrid Encryption with Randomized rsa key, salt, IV and memory stream bytes placement.
AES is used for encryption. AES key is encrypted via RSA. 
Normally we would start with encrypted RSA key and append salt to it, then append IV to it and append final memory stream to it. 
But this time I randomized this append procedure. Let's suppose RSA key is 8 bytes, salt is 5 bytes, IV is 3 bytes and memory stream is 4 bytes. 
By the way, the real values are 256, 16, 16 and variable length of multiple of 4 bytes. 
But for this example, I represent 0 with RSA key, 1 with salt, 2 with IV and 3 with memory stream. 

So by randomizing this, I make a new byte array such as 10200123330002110130  which has 8 zeros, 5 ones, 3 twos and 4 threes. 
This corresponds to the bytes of the corresponding byte variables. Since sum of lenghts these four byte arrays is multiple of 4,
after appending this randomized "turn" array, total length would be multiple of 5. I append this to the beginning of the final cipher. 
Finally, I append random bytes of length 1 to 4 included. 
When decrypting the cipher, since original cipher is of length of multiple of 5, I discarded the final added 1 to 4 length random bytes. 
I then divided the length to 5. Let's call this length len. First len bytes of the cipher represent 10200123330002110130. 
So whenever I see a 0 in this array, corresponding turn in the cipher is rsa key byte and so on. 
Then rsa key is decrypted and the aes is used again for final decryption. 
