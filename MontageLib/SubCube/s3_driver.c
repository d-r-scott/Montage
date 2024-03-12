//
// Created by lewis on 8/9/22.
//

#include "s3_driver.h"

#include <ctype.h>
#include <curl/curl.h>
#include <openssl/evp.h>
#include <openssl/hmac.h>
#include <string.h>

#include "fitsio2.h"

#define MAXLEN 8192

typedef struct    /* structure containing s3 file information */
{
    char open;
    LONGLONG currentpos;
    ULONGLONG size;
    char url[MAXLEN];
    CURL *curlContext;
} s3DriverFile;

static s3DriverFile handleTable[NMAXFILES];

static void read_env(const char *name, char *dest) {
    if (NULL != getenv(name)) {
        if (strlen(getenv(name)) > MAXLEN - 1) {
            printf("Environment variable %s is too long.", name);
            exit(1);
        }
        strcpy(dest, getenv(name));
    } else {
        printf("Environment variable %s is not set.", name);
        exit(1);
    }
}

static int encode64(unsigned s_len, char *src, unsigned d_len, char *dst) {

    static char base64[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
                           "abcdefghijklmnopqrstuvwxyz"
                           "0123456789"
                           "+/";

    unsigned triad;


    for (triad = 0; triad < s_len; triad += 3) {
        unsigned long int sr = 0;
        unsigned byte;

        for (byte = 0; (byte < 3) && (triad + byte < s_len); ++byte) {
            sr <<= 8;
            sr |= (*(src + triad + byte) & 0xff);
        }

        /* shift left to next 6 bit alignment*/
        sr <<= (6 - ((8 * byte) % 6)) % 6;

        if (d_len < 4)
            return 1;

        *(dst + 0) = *(dst + 1) = *(dst + 2) = *(dst + 3) = '=';
        switch (byte) {
            case 3:
                *(dst + 3) = base64[sr & 0x3f];
                sr >>= 6;
            case 2:
                *(dst + 2) = base64[sr & 0x3f];
                sr >>= 6;
            case 1:
                *(dst + 1) = base64[sr & 0x3f];
                sr >>= 6;
                *(dst + 0) = base64[sr & 0x3f];
        }
        dst += 4;
        d_len -= 4;
    }

    *dst = '\0';
    return 0;
}

static char *generate_sha1_hmac(char *input) {
    unsigned char out[EVP_MAX_MD_SIZE];
    char s3SecretKey[MAXLEN];
    char *result = (char *) malloc(MAXLEN);
    unsigned int len;

    read_env("S3_SECRET_KEY", (char *) &s3SecretKey);

    HMAC_CTX *h = HMAC_CTX_new();
    HMAC_Init_ex(h, &s3SecretKey, strlen((char *) &s3SecretKey), EVP_sha1(), NULL);

    HMAC_Update(h, (unsigned char *) input, strlen(input));
    HMAC_Final(h, (unsigned char *) &out, &len);

    HMAC_CTX_free(h);

    encode64(len, (char *) &out, sizeof(out), result);

    return result;
}

static struct curl_slist *init_s3_request(CURL *curlContext, char *url, const char *method) {
    char urlCopy[MAXLEN];
    strcpy((char *) urlCopy, url);
    // url format should be bucket:path
    char* rest = urlCopy;
    char *bucket = strtok_r(urlCopy, ":", &rest);
    char *path = strtok_r(NULL, "", &rest);

    if (!bucket || !path) {
        printf("Invalid bucket/path format provided: %s", url);
        return NULL;
    }

    char bucketPath[MAXLEN];
    sprintf((char *) &bucketPath, "/%s/%s", bucket, path);

    // Get the timestamp for the request
    time_t utc_now = time(NULL);
    char dateStr[MAXLEN];
    strftime((char *) &dateStr, sizeof(dateStr), "%a, %d %b %Y %H:%M:%S %z", gmtime(&utc_now));

    char signature[MAXLEN*3];
    sprintf((char *) &signature, "%s\n\napplication/zstd\n%s\n%s", method, (char *) dateStr, (char *) &bucketPath);

    char *signatureHash = generate_sha1_hmac((char *) &signature);

    struct curl_slist *header = NULL;

    /* parse the endpoint and extract the correct host */
    CURLU *h = curl_url();
    CURLUcode uc;

    char s3EndPoint[MAXLEN];
    read_env("S3_ENDPOINT", (char *) &s3EndPoint);

    uc = curl_url_set(h, CURLUPART_URL, (char *) &s3EndPoint, 0);
    if(uc) {
        printf("Unable to parse the host url: %s", (char *) &s3EndPoint);
        return NULL;
    }

    char *host;
    uc = curl_url_get(h, CURLUPART_HOST, &host, 0);
    if(uc) {
        printf("Unable to extract host component from url: %s", (char *) &s3EndPoint);
        return NULL;
    }

    char hostHdr[MAXLEN*2];
    sprintf((char *) &hostHdr, "Host: %s", host);
    header = curl_slist_append(header, (char *) &hostHdr);

    curl_free(host);
    curl_url_cleanup(h);

    char dateHdr[MAXLEN*2];
    sprintf((char *) &dateHdr, "Date: %s", (char *) &dateStr);
    header = curl_slist_append(header, (char *) &dateHdr);

    header = curl_slist_append(header, "Content-Type: application/zstd");

    char s3AccessKey[MAXLEN];
    read_env("S3_ACCESS_KEY", (char *) &s3AccessKey);

    char authHdr[MAXLEN*2];
    sprintf((char *) &authHdr, "Authorization: AWS %s:%s", (char *) &s3AccessKey, signatureHash);
    header = curl_slist_append(header, (char *) &authHdr);

    free(signatureHash);

    char urlPath[MAXLEN*3];
    sprintf((char *) &urlPath, "%s%s", (char *) &s3EndPoint, (char *) &bucketPath);
    curl_easy_setopt(curlContext, CURLOPT_URL, (char *) &urlPath);

    return header;
}

static int s3_init(void) {
    return 0;
}

static int s3_shutdown(void) {
    return 0;
}

static size_t header_callback(char *buffer, size_t size,
                              size_t nitems, void *userdata)
{
    char* buf = calloc(size * nitems + 1, 1);
    memcpy(buf, buffer, size * nitems);

    for(int i = 0; buf[i]; i++){
        buf[i] = tolower(buf[i]);
    }

    if (!memcmp(buf, "content-length", strlen("content-length"))) {
        strcpy(userdata, buf);
    }

    free(buf);
    return nitems * size;
}

static int s3_open(char *url, int rwmode, int *handle) {
    *handle = -1;
    unsigned int ii = 0;
    for (; ii < NMAXFILES; ii++)  /* find empty slot in table */
    {
        if (!handleTable[ii].open) {
            *handle = ii;
            break;
        }
    }

    if (*handle == -1) {
        return (TOO_MANY_FILES);    /* too many files opened */
    }

    handleTable[ii].curlContext = curl_easy_init();
    if (!handleTable[ii].curlContext) {
        return 1;
    }

    // Curl should follow redirects
    curl_easy_setopt(handleTable[ii].curlContext, CURLOPT_FOLLOWLOCATION, 1L);
    curl_easy_setopt(handleTable[ii].curlContext, CURLOPT_NOPROGRESS, 1L);

    handleTable[ii].open = TRUE;
    handleTable[ii].currentpos = 0;
    strcpy((char *) &handleTable[ii].url, url);

    // Check that the file exists and get it's size
    struct curl_slist *headers = init_s3_request(handleTable[ii].curlContext, url, "HEAD");
    if (!headers) {
        return 1;
    }

    curl_easy_setopt(handleTable[ii].curlContext, CURLOPT_HTTPHEADER, headers);

    // Request only the HEADers
    curl_easy_setopt(handleTable[ii].curlContext, CURLOPT_NOBODY, 1);

    char contentLengthHeader[MAXLEN] = {0};
    curl_easy_setopt(handleTable[ii].curlContext, CURLOPT_HEADERDATA, &contentLengthHeader);
    curl_easy_setopt(handleTable[ii].curlContext, CURLOPT_HEADERFUNCTION, header_callback);

    CURLcode res = curl_easy_perform(handleTable[ii].curlContext);
    /* Check for errors */
    if (res != CURLE_OK) {
        fprintf(stderr, "curl_easy_perform() failed: %s\n",
                curl_easy_strerror(res));
        return 1;
    }

    // Check that the response code is 200
    long http_code = 0;
    curl_easy_getinfo(handleTable[ii].curlContext, CURLINFO_RESPONSE_CODE, &http_code);

    if (http_code != 200) {
        printf("Unable to get S3 file details, response code was %ld\n", http_code);
        return 1;
    }

    if (!strlen((char*) &contentLengthHeader)) {
        printf("Content-Length header was not provided by remote S3 endpoint\n");
        return 1;
    }

    char* rest = (char*) &contentLengthHeader;
    strtok_r((char*) &contentLengthHeader, ":", &rest);
    char *headerValue = strtok_r(NULL, "", &rest);

    handleTable[ii].size = strtoull(headerValue, NULL, 10);

    curl_slist_free_all(headers);

    return 0;
}

static int s3_size(int handle, LONGLONG *filesize) {
    *filesize = handleTable[handle].size;
    return 0;
}

static int s3_close(int handle) {
    curl_easy_cleanup(handleTable[handle].curlContext);
    handleTable[handle].open = FALSE;
    return 0;
}

static int s3_seek(int handle, LONGLONG offset)
{
    handleTable[handle].currentpos = offset;
    return 0;
}

struct MemoryStruct {
    char *memory;
    size_t size;
};

static size_t write_data(void *contents, size_t size, size_t nmemb, void *memStruct) {
    size_t realsize = size * nmemb;
    struct MemoryStruct *mem = (struct MemoryStruct *) memStruct;

    memcpy(&(mem->memory[mem->size]), contents, realsize);
    mem->size += realsize;

    return realsize;
}

static int s3_read(int hdl, void *buffer, long nbytes) {
    curl_easy_reset(handleTable[hdl].curlContext);

    // Read a specific range from the remote file
    struct curl_slist *headers = init_s3_request(handleTable[hdl].curlContext, (char *) &handleTable[hdl].url, "GET");
    if (!headers) {
        return 1;
    }

    // Set the range header
    char rangeHdr[MAXLEN];
    sprintf((char *) &rangeHdr, "%llu-%llu", handleTable[hdl].currentpos, handleTable[hdl].currentpos + nbytes - 1);
    curl_easy_setopt(handleTable[hdl].curlContext, CURLOPT_RANGE, (char *) &rangeHdr);

    handleTable[hdl].currentpos += nbytes;

    curl_easy_setopt(handleTable[hdl].curlContext, CURLOPT_HTTPHEADER, headers);

    struct MemoryStruct memStruct;

    memStruct.memory = buffer;
    memStruct.size = 0;

    curl_easy_setopt(handleTable[hdl].curlContext, CURLOPT_WRITEDATA, &memStruct);
    curl_easy_setopt(handleTable[hdl].curlContext, CURLOPT_WRITEFUNCTION, write_data);

    CURLcode res = curl_easy_perform(handleTable[hdl].curlContext);
    /* Check for errors */
    if (res != CURLE_OK) {
        fprintf(stderr, "curl_easy_perform() failed: %s\n",
                curl_easy_strerror(res));
        return 1;
    }

    // Check that the response code is 200 or 206
    long http_code = 0;
    curl_easy_getinfo(handleTable[hdl].curlContext, CURLINFO_RESPONSE_CODE, &http_code);

    if (http_code != 200 && http_code != 206) {
        printf("Unable to download S3 file range, response code was %ld\n", http_code);
        return 1;
    }

    return 0;
}

void register_s3_driver() {
    int status = fits_register_driver(
            "s3://",
            s3_init,
            s3_shutdown,
            NULL,
            NULL,
            NULL,
            NULL,
            s3_open,
            NULL,
            NULL,
            s3_close,
            NULL,
            s3_size,
            NULL,
            s3_seek, /* Though will always succeed */
            s3_read,
            NULL
    );

    if (status) {
        printf("failed to register the s3:// driver\n");
        exit(1);
    }
}
