#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <openssl/rsa.h>
#include <openssl/pem.h>
#include <openssl/err.h>
#include <time.h>

void generate_keys() {
    RSA *rsa = RSA_generate_key(2048, RSA_F4, NULL, NULL);
    if (rsa == NULL) {
        fprintf(stderr, "Error generating RSA keys\n");
        return;
    }

    // 保存私钥
    FILE *private_file = fopen("private_key.pem", "wb");
    PEM_write_RSAPrivateKey(private_file, rsa, NULL, NULL, 0, NULL, NULL);
    fclose(private_file);

    // 保存公钥
    FILE *public_file = fopen("public_key.pem", "wb");
    PEM_write_RSA_PUBKEY(public_file, rsa);
    fclose(public_file);

    RSA_free(rsa);
}

char* base64_encode(const unsigned char* input, int length) {
    // Base64 编码实现
    BIO *b64, *bio;
    BUF_MEM *bufferPtr;

    b64 = BIO_new(BIO_f_base64());
    bio = BIO_new(BIO_s_mem());
    BIO_push(b64, bio);
    BIO_set_flags(b64, BIO_FLAGS_BASE64_NO_NL); // 不换行
    BIO_write(b64, input, length);
    BIO_flush(b64);
    BIO_get_mem_ptr(b64, &bufferPtr);
    BIO_set_close(b64, BIO_NOCLOSE);
    BIO_free_all(b64);

    char* b64text = (char*)malloc(bufferPtr->length + 1);
    memcpy(b64text, bufferPtr->data, bufferPtr->length);
    b64text[bufferPtr->length] = '\0';

    return b64text;
}

char* generate_license(const char* user_info, int expiration_days) {
    time_t now = time(NULL);
    time_t expiration_time = now + (expiration_days * 86400);

    // 创建 License 字符串
    char license[256];
    snprintf(license, sizeof(license), "{\"user_info\":\"%s\",\"expiration\":%ld}", user_info, expiration_time);

    // 签名 License
    FILE *private_file = fopen("private_key.pem", "rb");
    RSA *rsa_private = PEM_read_RSAPrivateKey(private_file, NULL, NULL, NULL);
    fclose(private_file);

    unsigned char signature[256];
    unsigned int signature_len;

    RSA_sign(NID_sha256, (unsigned char*)license, strlen(license), signature, &signature_len, rsa_private);
    RSA_free(rsa_private);

    // 将 License 和签名拼接
    char *final_license = (char*)malloc(512);
    snprintf(final_license, 512, "%s|%s", license, base64_encode(signature, signature_len));

    return final_license;
}

int main() {
    generate_keys();  // 只需运行一次生成密钥
    char* user_license = generate_license("user@example.com", 30);
    printf("Generated License: %s\n", user_license);
    free(user_license);
    return 0;
}
