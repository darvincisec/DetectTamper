#include <jni.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>
#include <malloc.h>
#include <unistd.h>
#include <pthread.h>
#include <fcntl.h>
#include <ctype.h>

#include <android/log.h>
#include "mbedtls/md.h"
#include "mylibc.h"
#include "zip.h"

#define DIGEST_SIZE 32
#define SUCCESS 0
#define FAIL 1
static const char* APPNAME = "DetectTamper";

//!!!!!!!!!!!!!!!Replace APK_SIGNER_HASH value with your signing certificate hash!!!!!!!!!!!!!!!!!!!!!
//!!!! Generate sha256 of CERT.RSA $openssl dgst -sha256 ....app/<release>/META-INF/CERT.RSA

static const uint8_t APK_SIGNER_HASH[] = {0x26,0xe0,0x98,0x63,0xa3,0x1d,0x15,0x96,0x30,0x41,0x8c,0xcf,0xf5,0x69,0x5b,0xb5,0x27,0x63,0x88,0x1e,0xd9,
                                          0x39,0x77,0x97,0x90,0xcb,0x3c,0x3c,0x8f,0xe0,0xce,0x18};

static const uint8_t text_hash[32] = {0xae, 0x2c, 0xea, 0x2a, 0xbd, 0xa6, 0xf3, 0xec,
                                      0x97, 0x7f, 0x9b, 0xf6, 0x94, 0x9a, 0xfc, 0x83,
                                      0x68, 0x27, 0xcb, 0xa0, 0xa0, 0x9f, 0x6b, 0x6f,
                                      0xde, 0x52, 0xcd, 0xe2, 0xcd, 0xff, 0x31, 0x80};

static const uint8_t hmac_key[32] = {0xb6, 0x2a, 0xd0, 0xe8, 0x82, 0x6f, 0xfd, 0x9a,
                                     0x31, 0x85, 0x9d, 0xc5, 0x35, 0xdd, 0xac, 0xd6,
                                     0xb3, 0xd7, 0x3e, 0x4a, 0xc1, 0x5e, 0x78, 0x9a,
                                     0x77, 0xc4, 0x45, 0xe8, 0xad, 0xa7, 0x02, 0xeb};

extern const void* text_start();
extern const void* text_end();
extern const unsigned char rodata_start[], rodata_end[];
extern const unsigned char rodata_hash[];

__attribute__((always_inline))
int is_nativelibrary_tampered(){

    int ret = FAIL;
    const unsigned char *p1 = text_start();
    const unsigned char *p2 = text_end();
    const unsigned char *p3 = rodata_start;
    const unsigned char *p4 = rodata_end;
    unsigned char signature[DIGEST_SIZE] = "";

    my_memset(signature, 0, DIGEST_SIZE);

    __android_log_print(ANDROID_LOG_VERBOSE, APPNAME, "Text Size:%d", p2 - p1 );
    __android_log_print(ANDROID_LOG_VERBOSE, APPNAME, "ROdata Size:%d", p4 - p3);

    const mbedtls_md_info_t *md = mbedtls_md_info_from_type(MBEDTLS_MD_SHA256);

    mbedtls_md_hmac(md, hmac_key,
                    DIGEST_SIZE, p1, p2 - p1, signature);

    if(0 == my_memcmp(signature,text_hash, DIGEST_SIZE)) {

        __android_log_print(ANDROID_LOG_VERBOSE, APPNAME, "Text Hash Matches");

        my_memset(signature, 0, DIGEST_SIZE);

        mbedtls_md_hmac(md, hmac_key,
                        DIGEST_SIZE, p3, p4 - p3, signature);

        if (0 == my_memcmp(signature, rodata_hash, DIGEST_SIZE)) {
            __android_log_print(ANDROID_LOG_VERBOSE, APPNAME, "ROdata Hash Matches");
            ret = SUCCESS;
        }else{
            __android_log_print(ANDROID_LOG_VERBOSE, APPNAME, "ROdata Hash DOESNOT Matches");
            ret = FAIL;
        }
    }else{
        __android_log_print(ANDROID_LOG_VERBOSE, APPNAME, "Text Hash DOESNOT Matches");
        ret = FAIL;
    }

    return ret;

}
void print_bytearray(uint8_t* input, int length){
    int i;
    for (i = 0; i < length; i++)
    {
        __android_log_print(ANDROID_LOG_VERBOSE, APPNAME,"%02X", input[i]);
    }
}
JNIEXPORT jint
Java_com_darvin_security_MainActivity_isApkTampered(JNIEnv *env,
                                                      jobject this,
                                                      jstring apkpath){
    const char* CERT = "META-INF/CERT.RSA";
    const char *path = (*env)->GetStringUTFChars(env,apkpath,0);
    struct zip* z = NULL;
    struct zip_file* zf = NULL;
    struct zip_stat zipstat={0,};
    zip_int64_t readsize = 0;
    size_t filesize = 0;
    uint8_t* rsacert = 0;
    uint8_t signerhash[DIGEST_SIZE]={0,};
    int ret = FAIL;
    my_memset(signerhash, 0, DIGEST_SIZE);
    ret = is_nativelibrary_tampered();

    if(ret != SUCCESS){
        __android_log_print(ANDROID_LOG_VERBOSE, APPNAME, "Native Library is Tampered");
       goto cleanup;
    }

    z = zip_open(path,0, &ret);
    if(z==NULL ||  ret != 0){
        __android_log_print(ANDROID_LOG_VERBOSE, APPNAME, "ZIP OPEN FAILED");

        goto cleanup;
    }

    ret = zip_stat(z, CERT, 0, &zipstat);
    if( ret != 0){
        __android_log_print(ANDROID_LOG_VERBOSE, APPNAME, "ZIP STAT FAILED");
        goto cleanup;
    }

    rsacert = malloc( zipstat.size * sizeof(uint8_t) );

    zf = zip_fopen(z, CERT, 0);
    if(zf == NULL){
        __android_log_print(ANDROID_LOG_VERBOSE, APPNAME, "ZIP FILE NOT FOUND");
        goto cleanup;
    }

    readsize = zip_fread(zf,rsacert,zipstat.size);
    if(readsize != 0 && readsize != zipstat.size){
        __android_log_print(ANDROID_LOG_VERBOSE, APPNAME, "ZIP INTERNAL ERROR");
        goto cleanup;
    }
    __android_log_print(ANDROID_LOG_VERBOSE, APPNAME, "CERT.RSA..Size:%d",readsize);
    filesize = (size_t)readsize;
    const mbedtls_md_info_t *md = mbedtls_md_info_from_type(MBEDTLS_MD_SHA256);

    ret = mbedtls_md(md,rsacert,784, signerhash);
    if(ret != 0){
        __android_log_print(ANDROID_LOG_VERBOSE, APPNAME, "HASH INTERNAL ERROR");
        goto cleanup;
    }
    print_bytearray(signerhash, DIGEST_SIZE);
    if(0 == my_memcmp(signerhash, APK_SIGNER_HASH, DIGEST_SIZE)) {
        __android_log_print(ANDROID_LOG_VERBOSE, APPNAME, "APK Signing Certificate hash matches");
        ret = SUCCESS;
    }else {
        __android_log_print(ANDROID_LOG_VERBOSE, APPNAME, "APK Signing Certificate does not match");
        ret = FAIL;
    }

    cleanup:
    if(zf != NULL)
        zip_fclose(zf);
    if(z != NULL)
        zip_close(z);
    if(rsacert != NULL)
        free(rsacert);
    (*env)->ReleaseStringUTFChars(env, apkpath, path);
    return ret;
}


