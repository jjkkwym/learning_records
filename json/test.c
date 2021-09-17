/*
  Copyright (c) 2009-2017 Dave Gamble and cJSON contributors

  Permission is hereby granted, free of charge, to any person obtaining a copy
  of this software and associated documentation files (the "Software"), to deal
  in the Software without restriction, including without limitation the rights
  to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
  copies of the Software, and to permit persons to whom the Software is
  furnished to do so, subject to the following conditions:

  The above copyright notice and this permission notice shall be included in
  all copies or substantial portions of the Software.

  THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
  IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
  FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
  AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
  LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
  OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
  THE SOFTWARE.
*/

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "cJSON.h"

#define VERSION_REPORT_PATH "./version_report.json"
#define STATUS_REPORT_PATH "./status_report.json"


typedef struct
{
    char *public_key;
    char *method;
}sig_t;

typedef struct
{
    sig_t
    payload_t
}version_report_t;

int write_to_file(char *path,char *buf)
{
    FILE *fp = fopen(path,"w+");
    if(fp == NULL)
    {
        return -1;
        printf("open file failed\n");
    }
    fprintf(fp,"%s",buf);
    fclose(fp);
}

/* Create a bunch of objects as demonstration. */
static int print_preallocated(cJSON *root,char *path)
{
    /* declarations */
    char *out = NULL;
    char *buf = NULL;
    char *buf_fail = NULL;
    size_t len = 0;
    size_t len_fail = 0;

    /* formatted print */
    out = cJSON_Print(root);

    /* create buffer to succeed */
    /* the extra 5 bytes are because of inaccuracies when reserving memory */
    len = strlen(out) + 5;
    buf = (char*)malloc(len);
    if (buf == NULL)
    {
        printf("Failed to allocate memory.\n");
        exit(1);
    }

    /* create buffer to fail */
    len_fail = strlen(out);
    buf_fail = (char*)malloc(len_fail);
    if (buf_fail == NULL)
    {
        printf("Failed to allocate memory.\n");
        exit(1);
    }

    /* Print to buffer */
    if (!cJSON_PrintPreallocated(root, buf, (int)len, 1)) {
        printf("cJSON_PrintPreallocated failed!\n");
        if (strcmp(out, buf) != 0) {
            printf("cJSON_PrintPreallocated not the same as cJSON_Print!\n");
            printf("cJSON_Print result:\n%s\n", out);
            printf("cJSON_PrintPreallocated result:\n%s\n", buf);
        }
        free(out);
        free(buf_fail);
        free(buf);
        return -1;
    }

    /* success */
    printf("%s\n", buf);
    
    write_to_file(path,buf);
    
    /* force it to fail */
    if (cJSON_PrintPreallocated(root, buf_fail, (int)len_fail, 1)) {
        printf("cJSON_PrintPreallocated failed to show error with insufficient memory!\n");
        printf("cJSON_Print result:\n%s\n", out);
        printf("cJSON_PrintPreallocated result:\n%s\n", buf_fail);
        free(out);
        free(buf_fail);
        free(buf);
        return -1;
    }

    free(out);
    free(buf_fail);
    free(buf);
    return 0;
}

/* Create a bunch of objects as demonstration. */
static void create_version_report(void)
{
    /* declare a few. */
    cJSON *root = NULL;
    cJSON *sig = NULL;
    cJSON *payload = NULL;
    cJSON *version_reports = NULL;
    cJSON *version_reports_sig = NULL;
    cJSON *version_reports_payload = NULL;
    root = cJSON_CreateObject();
    sig = cJSON_CreateObject();
    payload = cJSON_CreateObject();
    version_reports = cJSON_CreateObject();
    version_reports_sig = cJSON_CreateObject();
    version_reports_payload = cJSON_CreateObject();

    cJSON_AddStringToObject(version_reports_payload, "device_id", "device_id");
    cJSON_AddStringToObject(version_reports_payload, "model", "model");
    cJSON_AddStringToObject(version_reports_payload, "version", "version");
    cJSON_AddStringToObject(version_reports_payload, "filename", "filename");
    cJSON_AddStringToObject(version_reports_payload, "length", "length");
    cJSON_AddStringToObject(version_reports_payload, "hash", "hash");
    cJSON_AddStringToObject(version_reports_payload, "hash_method", "hash_method");
    cJSON_AddStringToObject(version_reports_payload, "security_attack", "security_attack");
    cJSON_AddStringToObject(version_reports_payload, "latest_verification", "latest_verification");
    cJSON_AddStringToObject(version_reports_payload, "counter", "counter");

    if (print_preallocated(root,VERSION_REPORT_PATH) != 0) {
        cJSON_Delete(root);
        exit(EXIT_FAILURE);
    }

    
    cJSON_AddStringToObject(version_reports_sig, "public_key", "public_key");
    cJSON_AddStringToObject(version_reports_sig, "method", "method");
    cJSON_AddStringToObject(version_reports_sig, "hash", "hash");
    cJSON_AddStringToObject(version_reports_sig, "hash_method", "hash_method");
    cJSON_AddStringToObject(version_reports_sig, "signature", "signature");

    cJSON_AddItemToObject(version_reports, "sig", version_reports_sig);
    cJSON_AddItemToObject(version_reports, "payload", version_reports_payload);
 
    cJSON_AddStringToObject(payload, "device_id", "device_id");
    cJSON_AddStringToObject(payload, "primary_device_id", "primary_device_id");
    cJSON_AddItemToObject(payload, "version_reports", version_reports);

    cJSON_AddStringToObject(sig, "public_key", "public_key");
    cJSON_AddStringToObject(sig, "method", "method");
    cJSON_AddStringToObject(sig, "hash", "hash");
    cJSON_AddStringToObject(sig, "hash_method", "hash_method");
    cJSON_AddStringToObject(sig, "signature", "signature");

    
    cJSON_AddItemToObject(root, "sig", sig);
    cJSON_AddItemToObject(root, "payload", payload);

    /* Print to text */
    if (print_preallocated(root,VERSION_REPORT_PATH) != 0) {
        cJSON_Delete(root);
        exit(EXIT_FAILURE);
    }
    cJSON_Delete(root);
}


static void create_status_report(void)
{
    /* declare a few. */
    cJSON *root = NULL;
    cJSON *sig = NULL;
    cJSON *payload = NULL;
    cJSON *update_reports = NULL;
    cJSON *update_reports_sig = NULL;
    cJSON *update_reports_payload = NULL;
    root = cJSON_CreateObject();
    sig = cJSON_CreateObject();
    payload = cJSON_CreateObject();

    cJSON_AddItemToObject(root, "sig", sig = cJSON_CreateObject());
    cJSON_AddStringToObject(sig, "public_key", "public_key");
    cJSON_AddStringToObject(sig, "method", "method");
    cJSON_AddStringToObject(sig, "hash", "hash");
    cJSON_AddStringToObject(sig, "hash_method", "hash_method");
    cJSON_AddStringToObject(sig, "signature", "signature");

    cJSON_AddItemToObject(root, "payload", payload = cJSON_CreateObject());
    cJSON_AddStringToObject(payload, "device_id", "device_id");
    cJSON_AddStringToObject(payload, "primary_device_id", "primary_device_id");

    cJSON_AddItemToObject(payload, "update_reports", update_reports = cJSON_CreateObject());
    cJSON_AddItemToObject(update_reports, "sig", update_reports_sig = cJSON_CreateObject());
    cJSON_AddItemToObject(update_reports, "payload", update_reports_payload = cJSON_CreateObject());
    
    cJSON_AddStringToObject(update_reports_sig, "public_key", "public_key");
    cJSON_AddStringToObject(update_reports_sig, "method", "method");
    cJSON_AddStringToObject(update_reports_sig, "hash", "hash");
    cJSON_AddStringToObject(update_reports_sig, "hash_method", "hash_method");
    cJSON_AddStringToObject(update_reports_sig, "signature", "signature");

    cJSON_AddStringToObject(update_reports_payload, "model", "model");
    cJSON_AddStringToObject(update_reports_payload, "ota_type", "ota_type");
    cJSON_AddStringToObject(update_reports_payload, "source_version", "source_version");
    cJSON_AddStringToObject(update_reports_payload, "target_version", "target_version");
    cJSON_AddStringToObject(update_reports_payload, "upgrade_status", "upgrade_status");
    cJSON_AddStringToObject(update_reports_payload, "completed_at", "completed_at");
    cJSON_AddStringToObject(update_reports_payload, "detail_msg", "detail_msg");

    /* Print to text */
    if (print_preallocated(root,STATUS_REPORT_PATH) != 0) {
        cJSON_Delete(root);
        exit(EXIT_FAILURE);
    }
    cJSON_Delete(root);
}

int CJSON_CDECL main(void)
{

    create_version_report();
    create_status_report();

    return 0;
}
