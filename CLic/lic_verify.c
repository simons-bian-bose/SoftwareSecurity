#include <openssl/rsa.h>
#include <openssl/pem.h>
#include <openssl/err.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

unsigned char* base64_decode(const char* input, int* output_length) {
    // Base64 解码实现
    BIO *b64, *bio;
    BUF_MEM *bufferPtr;
    int length = strlen(input);

    b64 = BIO_new(BIO_f_base64());
    bio = BIO_new_mem_buf(input, length);
    bio = BIO_push(b64, bio);
    BIO_set_flags(b64, BIO_FLAGS_BASE64_NO_NL); // 不换行

    unsigned char* buffer = (unsigned char*)malloc(length);
    *output_length = BIO_read(bio, buffer, length);
    BIO_free_all(bio);

    return buffer;
}

int verify_license(const char* license_str) {
    // 拆分 License 和签名
    char license[256], encoded_signature[256];
    sscanf(license_str, "%[^|]|%s", license, encoded_signature);

    // 解码签名
    int signature_len;
    unsigned char* signature = base64_decode(encoded_signature, &signature_len);

    // 读取公钥
    FILE *public_file = fopen("public_key.pem", "rb");
    RSA *rsa_public = PEM_read_RSA_PUBKEY(public_file, NULL, NULL, NULL);
    fclose(public_file);

    // 验证签名
    if (RSA_verify(NID_sha256, (unsigned char*)license, strlen(license), signature, signature_len, rsa_public) != 1) {
        RSA_free(rsa_public);
        free(signature);
        return 0;  // 验证失败
    }

    // 检查有效期
    time_t now = time(NULL);
    long expiration_time;
    sscanf(license, "{\"user_info\":\"%*s\",\"expiration\":%ld}", &expiration_time);
    RSA_free(rsa_public);
    free(signature);

    return now < expiration_time;  // 返回有效性
}

int main() {
    const char* user_license = "your_generated_license_here"; // 替换为实际生成的 License
    int valid = verify_license(user_license);
    printf("License Valid: %d\n", valid);
    return 0;
}
