> An encrypted PKCS8-DER RSA key (2048 bits)

```sh
openssl genrsa 2048 | openssl pkcs8 -topk8 -outform DER -out key -v2 aes128 -passout pass:password
```