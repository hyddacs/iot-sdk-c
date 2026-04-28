#include "gw_sdk.h"

static Gateway g_gw;
static RouteTable g_route;
static char g_cfg_path[256];

#define TIMESTAMP_VALUE             "2524608000000"
#define MQTT_CLINETID_KV            "|timestamp=2524608000000,_v=paho-c-1.0.0,securemode=3,signmethod=hmacsha256,lan=C|"
#define SHA256_KEY_IOPAD_SIZE       64
#define SHA256_DIGEST_SIZE          32

typedef struct {
    uint32_t total[2];
    uint32_t state[8];
    unsigned char buffer[64];
    int is224;
} iot_sha256_context;

static void utils_sha256_zeroize(void *v, uint32_t n);
void utils_sha256_init(iot_sha256_context *ctx);
void utils_sha256_free(iot_sha256_context *ctx);
void utils_sha256_starts(iot_sha256_context *ctx);
void utils_sha256_process(iot_sha256_context *ctx, const unsigned char data[64]);
void utils_sha256_update(iot_sha256_context *ctx, const unsigned char *input, uint32_t ilen);
void utils_sha256_finish(iot_sha256_context *ctx, uint8_t output[32]);
void utils_sha256(const uint8_t *input, uint32_t ilen, uint8_t output[32]);
static void utils_hmac_sha256(const uint8_t *msg, uint32_t msg_len, const uint8_t *key, uint32_t key_len, uint8_t output[32]);

static void _hex2str(uint8_t *input, uint16_t input_len, char *output)
{
    char *zEncode = "0123456789ABCDEF";
    int i = 0, j = 0;
    for (i = 0; i < input_len; i++) {
        output[j++] = zEncode[(input[i] >> 4) & 0xf];
        output[j++] = zEncode[(input[i]) & 0xf];
    }
}

int aiotMqttSign(const char *productKey, const char *deviceName, const char *deviceSecret,
                 char clientId[150], char username[64], char password[65])
{
    char deviceId[PRODUCTKEY_MAXLEN + DEVICENAME_MAXLEN + 2] = {0};
    char macSrc[SIGN_SOURCE_MAXLEN] = {0};
    uint8_t macRes[32] = {0};

    if (productKey == NULL || deviceName == NULL || deviceSecret == NULL ||
        clientId == NULL || username == NULL || password == NULL)
        return -1;
    if ((strlen(productKey) > PRODUCTKEY_MAXLEN) || (strlen(deviceName) > DEVICENAME_MAXLEN) ||
        (strlen(deviceSecret) > DEVICESECRET_MAXLEN))
        return -1;

    memcpy(deviceId, deviceName, strlen(deviceName));
    memcpy(deviceId + strlen(deviceId), "&", 1);
    memcpy(deviceId + strlen(deviceId), productKey, strlen(productKey));

    memcpy(clientId, deviceId, strlen(deviceId));
    memcpy(clientId + strlen(deviceId), MQTT_CLINETID_KV, strlen(MQTT_CLINETID_KV));
    clientId[strlen(deviceId) + strlen(MQTT_CLINETID_KV)] = 0;

    memcpy(username, deviceId, strlen(deviceId));
    username[strlen(deviceId)] = 0;

    memcpy(macSrc, "clientId", 8);
    memcpy(macSrc + 8, deviceId, strlen(deviceId));
    memcpy(macSrc + 8 + strlen(deviceId), "deviceName", 10);
    memcpy(macSrc + 8 + strlen(deviceId) + 10, deviceName, strlen(deviceName));
    memcpy(macSrc + 8 + strlen(deviceId) + 10 + strlen(deviceName), "productKey", 10);
    memcpy(macSrc + 8 + strlen(deviceId) + 10 + strlen(deviceName) + 10, productKey, strlen(productKey));
    memcpy(macSrc + 8 + strlen(deviceId) + 10 + strlen(deviceName) + 10 + strlen(productKey), "timestamp", 9);
    memcpy(macSrc + 8 + strlen(deviceId) + 10 + strlen(deviceName) + 10 + strlen(productKey) + 9, TIMESTAMP_VALUE, strlen(TIMESTAMP_VALUE));

    utils_hmac_sha256((uint8_t *)macSrc, strlen(macSrc), (uint8_t *)deviceSecret, strlen(deviceSecret), macRes);
    memset(password, 0, PASSWORD_MAXLEN);
    _hex2str(macRes, 32, password);
    return 0;
}

static void utils_sha256_zeroize(void *v, uint32_t n) {
    volatile unsigned char *p = v;
    while (n--) *p++ = 0;
}

void utils_sha256_init(iot_sha256_context *ctx) {
    memset(ctx, 0, sizeof(iot_sha256_context));
}

void utils_sha256_free(iot_sha256_context *ctx) {
    if (ctx) utils_sha256_zeroize(ctx, sizeof(iot_sha256_context));
}

void utils_sha256_starts(iot_sha256_context *ctx) {
    ctx->total[0] = ctx->total[1] = 0;
    ctx->state[0] = 0x6A09E667; ctx->state[1] = 0xBB67AE85;
    ctx->state[2] = 0x3C6EF372; ctx->state[3] = 0xA54FF53A;
    ctx->state[4] = 0x510E527F; ctx->state[5] = 0x9B05688C;
    ctx->state[6] = 0x1F83D9AB; ctx->state[7] = 0x5BE0CD19;
    ctx->is224 = 0;
}

#define GET_UINT32_BE(n,b,i)    \
    do { (n) = ((uint32_t)(b)[i]<<24) | ((uint32_t)(b)[i+1]<<16) | ((uint32_t)(b)[i+2]<<8) | ((uint32_t)(b)[i+3]); } while(0)
#define PUT_UINT32_BE(n,b,i)   \
    do { (b)[i] = (n>>24)&0xFF; (b)[i+1] = (n>>16)&0xFF; (b)[i+2] = (n>>8)&0xFF; (b)[i+3] = n&0xFF; } while(0)

#define SHR(x,n) ((x & 0xFFFFFFFF) >> n)
#define ROTR(x,n) (SHR(x,n) | (x << (32 - n)))
#define S0(x) (ROTR(x,7) ^ ROTR(x,18) ^ SHR(x,3))
#define S1(x) (ROTR(x,17) ^ ROTR(x,19) ^ SHR(x,10))
#define S2(x) (ROTR(x,2) ^ ROTR(x,13) ^ ROTR(x,22))
#define S3(x) (ROTR(x,6) ^ ROTR(x,11) ^ ROTR(x,25))
#define F0(x,y,z) ((x & y) | (z & (x | y)))
#define F1(x,y,z) (z ^ (x & (y ^ z)))
#define R(t) (W[t] = S1(W[t-2]) + W[t-7] + S0(W[t-15]) + W[t-16])
#define P(a,b,c,d,e,f,g,h,x,K) do{uint32_t t1=h+S3(e)+F1(e,f,g)+K+x; uint32_t t2=S2(a)+F0(a,b,c); d+=t1; h=t1+t2;}while(0)

static const uint32_t K[] = {
    0x428A2F98,0x71374491,0xB5C0FBCF,0xE9B5DBA5,0x3956C25B,0x59F111F1,0x923F82A4,0xAB1C5ED5,
    0xD807AA98,0x12835B01,0x243185BE,0x550C7DC3,0x72BE5D74,0x80DEB1FE,0x9BDC06A7,0xC19BF174,
    0xE49B69C1,0xEFBE4786,0x0FC19DC6,0x240CA1CC,0x2DE92C6F,0x4A7484AA,0x5CB0A9DC,0x76F988DA,
    0x983E5152,0xA831C66D,0xB00327C8,0xBF597FC7,0xC6E00BF3,0xD5A79147,0x06CA6351,0x14292967,
    0x27B70A85,0x2E1B2138,0x4D2C6DFC,0x53380D13,0x650A7354,0x766A0ABB,0x81C2C92E,0x92722C85,
    0xA2BFE8A1,0xA81A664B,0xC24B8B70,0xC76C51A3,0xD192E819,0xD6990624,0xF40E3585,0x106AA070,
    0x19A4C116,0x1E376C08,0x2748774C,0x34B0BCB5,0x391C0CB3,0x4ED8AA4A,0x5B9CCA4F,0x682E6FF3,
    0x748F82EE,0x78A5636F,0x84C87814,0x8CC70208,0x90BEFFFA,0xA4506CEB,0xBEF9A3F7,0xC67178F2
};

void utils_sha256_process(iot_sha256_context *ctx, const unsigned char data[64]) {
    uint32_t temp1, temp2, W[64], A[8];
    for (int i = 0; i < 8; i++) A[i] = ctx->state[i];
    for (int i = 0; i < 64; i++) {
        if (i < 16) GET_UINT32_BE(W[i], data, 4 * i); else R(i);
        P(A[0],A[1],A[2],A[3],A[4],A[5],A[6],A[7],W[i],K[i]);
        temp1 = A[7]; A[7] = A[6]; A[6] = A[5]; A[5] = A[4]; A[4] = A[3]; A[3] = A[2]; A[2] = A[1]; A[1] = A[0]; A[0] = temp1;
    }
    for (int i = 0; i < 8; i++) ctx->state[i] += A[i];
}

void utils_sha256_update(iot_sha256_context *ctx, const unsigned char *input, uint32_t ilen) {
    uint32_t left = ctx->total[0] & 0x3F, fill = 64 - left;
    ctx->total[0] += ilen;
    if (left && ilen >= fill) {
        memcpy(ctx->buffer + left, input, fill);
        utils_sha256_process(ctx, ctx->buffer);
        input += fill; ilen -= fill; left = 0;
    }
    while (ilen >= 64) { utils_sha256_process(ctx, input); input += 64; ilen -= 64; }
    if (ilen > 0) memcpy(ctx->buffer + left, input, ilen);
}

static const unsigned char sha256_padding[64] = {0x80, 0};
void utils_sha256_finish(iot_sha256_context *ctx, uint8_t output[32]) {
    uint8_t len[8];
    uint32_t high = (ctx->total[0] >> 29) | (ctx->total[1] << 3);
    uint32_t low = ctx->total[0] << 3;
    PUT_UINT32_BE(high, len, 0); PUT_UINT32_BE(low, len, 4);
    uint32_t last = ctx->total[0] & 0x3F;
    uint32_t padn = (last < 56) ? (56 - last) : (120 - last);
    utils_sha256_update(ctx, sha256_padding, padn);
    utils_sha256_update(ctx, len, 8);
    PUT_UINT32_BE(ctx->state[0], output, 0);
    PUT_UINT32_BE(ctx->state[1], output, 4);
    PUT_UINT32_BE(ctx->state[2], output, 8);
    PUT_UINT32_BE(ctx->state[3], output, 12);
    PUT_UINT32_BE(ctx->state[4], output, 16);
    PUT_UINT32_BE(ctx->state[5], output, 20);
    PUT_UINT32_BE(ctx->state[6], output, 24);
    PUT_UINT32_BE(ctx->state[7], output, 28);
}

void utils_sha256(const uint8_t *input, uint32_t ilen, uint8_t output[32]) {
    iot_sha256_context ctx;
    utils_sha256_init(&ctx); utils_sha256_starts(&ctx);
    utils_sha256_update(&ctx, input, ilen);
    utils_sha256_finish(&ctx, output);
    utils_sha256_free(&ctx);
}

static void utils_hmac_sha256(const uint8_t *msg, uint32_t msg_len, const uint8_t *key, uint32_t key_len, uint8_t output[32]) {
    iot_sha256_context ctx;
    uint8_t k1[64], k2[64];
    memset(k1, 0, 64); memset(k2, 0, 64);
    memcpy(k1, key, key_len); memcpy(k2, key, key_len);
    for (int i = 0; i < 64; i++) { k1[i] ^= 0x36; k2[i] ^= 0x5c; }
    utils_sha256_init(&ctx); utils_sha256_starts(&ctx);
    utils_sha256_update(&ctx, k1, 64); utils_sha256_update(&ctx, msg, msg_len);
    utils_sha256_finish(&ctx, output);
    utils_sha256_init(&ctx); utils_sha256_starts(&ctx);
    utils_sha256_update(&ctx, k2, 64); utils_sha256_update(&ctx, output, 32);
    utils_sha256_finish(&ctx, output);
    utils_sha256_free(&ctx);
}

char *json_set_str(const char *json, const char *key, const char *val) {
    // 1. 入参合法性校验 + 错误日志
    if (key == NULL || strlen(key) == 0) {
        fprintf(stderr, "[ERROR] json_set_str: 字段名(key)为空\n");
        return NULL;
    }
    if (val == NULL) {
        fprintf(stderr, "[WARN] json_set_str: 字段值(val)为空 (key=%s)\n", key);
        // 允许设置空字符串，不直接返回失败
    }

    // 2. 解析/创建 JSON 根对象 + 错误日志
    cJSON *root = NULL;
    if (json != NULL && strlen(json) > 0) {
        root = cJSON_Parse(json);
        if (!root) {
            const char *error_info = cJSON_GetErrorPtr();
            fprintf(stderr, "[ERROR] json_set_str: 解析原始JSON失败 (key=%s, json=%s, 错误位置: %s)\n",
                    key, json, error_info ? error_info : "未知位置");
            return NULL;
        }
        printf("[INFO] json_set_str: 解析原始JSON成功 (key=%s)\n", key);
    } else {
        root = cJSON_CreateObject();
        if (!root) {
            fprintf(stderr, "[ERROR] json_set_str: 创建新JSON对象失败 (key=%s)\n", key);
            return NULL;
        }
        printf("[INFO] json_set_str: 创建新JSON对象成功 (key=%s)\n", key);
    }

    // 3. 删除旧字段（避免重复） + 日志
    cJSON *old_item = cJSON_GetObjectItem(root, key);
    if (old_item) {
        printf("[INFO] json_set_str: 存在旧字段，先删除 (key=%s, 旧值=%s)\n",
                key, cJSON_IsString(old_item) ? old_item->valuestring : "非字符串");
        cJSON_DeleteItemFromObject(root, key);
    }

    // 4. 添加新字符串字段 + 错误日志
    if (!cJSON_AddStringToObject(root, key, val ? val : "")) {
        fprintf(stderr, "[ERROR] json_set_str: 添加字符串字段失败 (key=%s, val=%s)\n",
                key, val ? val : "NULL");
        cJSON_Delete(root);
        return NULL;
    }
    printf("[INFO] json_set_str: 添加字符串字段成功 (key=%s, val=%s)\n",
            key, val ? val : "空字符串");

    // 5. 生成新JSON字符串 + 错误日志
    char *out = cJSON_PrintUnformatted(root);
    if (!out) {
        fprintf(stderr, "[ERROR] json_set_str: 生成新JSON字符串失败 (key=%s)\n", key);
        cJSON_Delete(root);
        return NULL;
    }

    // 6. 释放资源 + 返回结果
    cJSON_Delete(root);
    printf("[INFO] json_set_str: 操作完成，新JSON: %s\n", out);
    return out;
}


char *json_set_int(const char *json, const char *key, int val) {
    // 1. 入参合法性校验 + 错误日志
    if (key == NULL || strlen(key) == 0) {
        fprintf(stderr, "[ERROR] json_set_int: 字段名(key)为空\n");
        return NULL;
    }

    // 2. 解析/创建 JSON 根对象 + 错误日志
    cJSON *root = NULL;
    if (json != NULL && strlen(json) > 0) {
        root = cJSON_Parse(json);
        if (!root) {
            const char *error_info = cJSON_GetErrorPtr();
            fprintf(stderr, "[ERROR] json_set_int: 解析原始JSON失败 (key=%s, json=%s, 错误位置: %s)\n",
                    key, json, error_info ? error_info : "未知位置");
            return NULL;
        }
        printf("[INFO] json_set_int: 解析原始JSON成功 (key=%s)\n", key);
    } else {
        root = cJSON_CreateObject();
        if (!root) {
            fprintf(stderr, "[ERROR] json_set_int: 创建新JSON对象失败 (key=%s)\n", key);
            return NULL;
        }
        printf("[INFO] json_set_int: 创建新JSON对象成功 (key=%s)\n", key);
    }

    // 3. 删除旧字段（避免重复） + 日志
    cJSON *old_item = cJSON_GetObjectItem(root, key);
    if (old_item) {
        printf("[INFO] json_set_int: 存在旧字段，先删除 (key=%s, 旧值=%d)\n",
                key, cJSON_IsNumber(old_item) ? old_item->valueint : -9999);
        cJSON_DeleteItemFromObject(root, key);
    }

    // 4. 添加新数字字段 + 错误日志
    if (!cJSON_AddNumberToObject(root, key, val)) {
        fprintf(stderr, "[ERROR] json_set_int: 添加数字字段失败 (key=%s, val=%d)\n", key, val);
        cJSON_Delete(root);
        return NULL;
    }
    printf("[INFO] json_set_int: 添加数字字段成功 (key=%s, val=%d)\n", key, val);

    // 5. 生成新JSON字符串 + 错误日志
    char *out = cJSON_PrintUnformatted(root);
    if (!out) {
        fprintf(stderr, "[ERROR] json_set_int: 生成新JSON字符串失败 (key=%s)\n", key);
        cJSON_Delete(root);
        return NULL;
    }

    // 6. 释放资源 + 返回结果
    cJSON_Delete(root);
    printf("[INFO] json_set_int: 操作完成，新JSON: %s\n", out);
    return out;
}

char *json_del_key(const char *json, const char *key) {
    // 1. 入参合法性校验 + 错误日志
    if (json == NULL || strlen(json) == 0) {
        fprintf(stderr, "[ERROR] json_del_key: 原始JSON字符串为空 (key=%s)\n", key ? key : "NULL");
        return NULL;
    }
    if (key == NULL || strlen(key) == 0) {
        fprintf(stderr, "[ERROR] json_del_key: 字段名(key)为空\n");
        return NULL;
    }

    // 2. 解析 JSON 根对象 + 错误日志
    cJSON *root = cJSON_Parse(json);
    if (!root) {
        const char *error_info = cJSON_GetErrorPtr();
        fprintf(stderr, "[ERROR] json_del_key: 解析原始JSON失败 (key=%s, json=%s, 错误位置: %s)\n",
                key, json, error_info ? error_info : "未知位置");
        return NULL;
    }

    // 3. 检查字段是否存在 + 日志
    cJSON *item = cJSON_GetObjectItem(root, key);
    if (!item) {
        fprintf(stderr, "[WARN] json_del_key: 字段不存在，无需删除 (key=%s)\n", key);
        // 仍返回原始JSON（避免业务逻辑异常）
        char *out = cJSON_PrintUnformatted(root);
        cJSON_Delete(root);
        return out;
    }

    // 4. 删除字段 + 日志
    cJSON_DeleteItemFromObject(root, key);
    printf("[INFO] json_del_key: 删除字段成功 (key=%s)\n", key);

    // 5. 生成新JSON字符串 + 错误日志
    char *out = cJSON_PrintUnformatted(root);
    if (!out) {
        fprintf(stderr, "[ERROR] json_del_key: 生成新JSON字符串失败 (key=%s)\n", key);
        cJSON_Delete(root);
        return NULL;
    }

    // 6. 释放资源 + 返回结果
    cJSON_Delete(root);
    printf("[INFO] json_del_key: 操作完成，新JSON: %s\n", out);
    return out;
}

int json_get_str(const char *json, const char *key, char *out, int len) {
    // 1. 入参合法性校验 + 错误日志
    if (json == NULL) {
        fprintf(stderr, "[ERROR] json_get_str: 输入JSON字符串为空 (key=%s)\n", 
                key ? key : "NULL");
        return -1;
    }
    if (key == NULL) {
        fprintf(stderr, "[ERROR] json_get_str: 目标字段名(key)为空 (json=%s)\n", json);
        return -1;
    }
    if (out == NULL) {
        fprintf(stderr, "[ERROR] json_get_str: 输出缓冲区(out)为空 (key=%s, json=%s)\n", 
                key, json);
        return -1;
    }
    if (len <= 1) { // len至少需要2（1个字符 + 结束符）
        fprintf(stderr, "[ERROR] json_get_str: 输出缓冲区长度不足 (key=%s, len=%d, 最小要求=2)\n", 
                key, len);
        return -1;
    }

    // 2. 解析JSON根节点 + 错误日志
    cJSON *root = cJSON_Parse(json);
    if (!root) {
        // 获取cJSON解析错误信息（增强调试）
        const char *error_info = cJSON_GetErrorPtr();
        fprintf(stderr, "[ERROR] json_get_str: JSON解析失败 (key=%s, json=%s, 错误位置: %s)\n", 
                key, json, error_info ? error_info : "未知位置");
        return -1;
    }

    // 3. 查找目标字段 + 错误日志
    cJSON *item = cJSON_GetObjectItem(root, key);
    if (!item) {
        fprintf(stderr, "[ERROR] json_get_str: JSON中不存在字段 (key=%s, json=%s)\n", 
                key, json);
        cJSON_Delete(root);
        return -1;
    }

    // 4. 校验字段类型是否为字符串 + 错误日志
    if (!cJSON_IsString(item)) {
        // 打印字段实际类型，方便排查
        const char *type_str = "";
        switch (item->type) {
            case cJSON_Number: type_str = "数字(number)"; break;
            case cJSON_True: case cJSON_False: type_str = "布尔(boolean)"; break;
            case cJSON_Object: type_str = "对象(object)"; break;
            case cJSON_Array: type_str = "数组(array)"; break;
            case cJSON_NULL: type_str = "空值(null)"; break;
            default: type_str = "未知类型"; break;
        }
        fprintf(stderr, "[ERROR] json_get_str: 字段类型错误 (key=%s, 期望字符串, 实际=%s, json=%s)\n", 
                key, type_str, json);
        cJSON_Delete(root);
        return -1;
    }

    // 5. 校验字段值是否为空 + 警告日志
    if (item->valuestring == NULL || strlen(item->valuestring) == 0) {
        fprintf(stderr, "[WARN] json_get_str: 字段值为空字符串 (key=%s, json=%s)\n", 
                key, json);
    }

    // 6. 安全拷贝字符串到输出缓冲区
    strncpy(out, item->valuestring, len - 1);
    out[len - 1] = '\0'; // 确保字符串结束符，防止越界

    // 7. 释放cJSON资源
    cJSON_Delete(root);

    // 8. 成功日志（可选，调试阶段开启，生产环境可注释）
    printf("[INFO] json_get_str: 解析字符串字段成功 (key=%s, value=%s)\n", key, out);

    return 0;
}

int json_get_int(const char *json, const char *key, int *out) {
    // 1. 入参合法性校验 + 错误日志
    if (json == NULL) {
        fprintf(stderr, "[ERROR] json_get_int: 输入JSON字符串为空 (key=%s)\n", 
                key ? key : "NULL");
        return -1;
    }
    if (key == NULL) {
        fprintf(stderr, "[ERROR] json_get_int: 目标字段名(key)为空 (json=%s)\n", json);
        return -1;
    }
    if (out == NULL) {
        fprintf(stderr, "[ERROR] json_get_int: 输出指针(out)为空 (key=%s, json=%s)\n", 
                key, json);
        return -1;
    }

    // 2. 解析JSON根节点 + 错误日志
    cJSON *root = cJSON_Parse(json);
    if (!root) {
        const char *error_info = cJSON_GetErrorPtr();
        fprintf(stderr, "[ERROR] json_get_int: JSON解析失败 (key=%s, json=%s, 错误位置: %s)\n", 
                key, json, error_info ? error_info : "未知位置");
        return -1;
    }

    // 3. 查找目标字段 + 错误日志
    cJSON *item = cJSON_GetObjectItem(root, key);
    if (!item) {
        fprintf(stderr, "[ERROR] json_get_int: JSON中不存在字段 (key=%s, json=%s)\n", 
                key, json);
        cJSON_Delete(root);
        return -1;
    }

    // 4. 校验字段类型是否为数字 + 错误日志
    if (!cJSON_IsNumber(item)) {
        // 打印字段实际类型，方便排查
        const char *type_str = "";
        switch (item->type) {
            case cJSON_String: type_str = "字符串(string)"; break;
            case cJSON_True: case cJSON_False: type_str = "布尔(boolean)"; break;
            case cJSON_Object: type_str = "对象(object)"; break;
            case cJSON_Array: type_str = "数组(array)"; break;
            case cJSON_NULL: type_str = "空值(null)"; break;
            default: type_str = "未知类型"; break;
        }
        fprintf(stderr, "[ERROR] json_get_int: 字段类型错误 (key=%s, 期望数字, 实际=%s, json=%s)\n", 
                key, type_str, json);
        cJSON_Delete(root);
        return -1;
    }

    // 5. 读取数字值并打印成功日志
    *out = item->valueint;
    printf("[INFO] json_get_int: 解析数字字段成功 (key=%s, value=%d)\n", key, *out);

    // 6. 释放cJSON资源
    cJSON_Delete(root);

    return 0;
}


int subdev_init(SubDevice *subdev) {
    // 1. 入参校验 + 详细错误打印
    if (!subdev) {
        fprintf(stderr, "[ERROR] subdev_init: 入参为空 (subdev=NULL)\n");
        return -1;
    }

    // 2. 校验子设备核心信息 + 错误打印
    if (strlen(subdev->pk) == 0 || strlen(subdev->dn) == 0 || strlen(subdev->ds) == 0) {
        fprintf(stderr, "[ERROR] subdev_init: 子设备核心信息不完整\n");
        fprintf(stderr, "[ERROR] subdev_init: pk=%s, dn=%s, ds=%s\n", 
                subdev->pk, subdev->dn, subdev->ds);
        return -1;
    }

    // 3. 校验网关broker是否有效 + 错误打印
    if (strlen(g_gw.broker) == 0) {
        fprintf(stderr, "[ERROR] subdev_init: 网关broker未配置，无法创建子设备MQTT客户端 (dn=%s)\n", 
                subdev->dn);
        return -1;
    }

    // 4. MQTT签名 + 错误打印
    char cid[150] = {0}, user[64] = {0}, pwd[65] = {0};
    int ret = aiotMqttSign(subdev->pk, subdev->dn, subdev->ds, cid, user, pwd);
    if (ret != 0) {
        fprintf(stderr, "[ERROR] subdev_init: MQTT签名失败 (dn=%s, ret=%d)\n", 
                subdev->dn, ret);
        return -1;
    }
    printf("[INFO] subdev_init: MQTT签名成功 (dn=%s, clientId=%s, username=%s)\n", 
           subdev->dn, cid, user);

    // 5. 创建子设备MQTT客户端 + 错误打印
    ret = MQTTAsync_create(&subdev->client, g_gw.broker, cid, 0, NULL);
    if (ret != MQTTASYNC_SUCCESS) {
        fprintf(stderr, "[ERROR] subdev_init: 创建MQTT客户端失败 (dn=%s, broker=%s, ret=%d)\n", 
                subdev->dn, g_gw.broker, ret);
        return -1;
    }
    printf("[INFO] subdev_init: 创建MQTT客户端成功 (dn=%s)\n", subdev->dn);

    // 6. 配置MQTT连接参数 + 增加超时/清理会话等关键参数
    MQTTAsync_connectOptions opt = MQTTAsync_connectOptions_initializer;
    opt.username = user;
    opt.password = pwd;
    opt.keepAliveInterval = 60;
    opt.cleansession = 1;    // 清理会话，避免重连时残留状态
    opt.retryInterval = 2;   // 重连间隔，增强鲁棒性

    // 7. 发起MQTT连接 + 错误打印
    ret = MQTTAsync_connect(subdev->client, &opt);
    if (ret != MQTTASYNC_SUCCESS) {
        fprintf(stderr, "[ERROR] subdev_init: MQTT连接失败 (dn=%s, ret=%d)\n", 
                subdev->dn, ret);
        // 销毁已创建的客户端，避免内存泄漏
        MQTTAsync_destroy(&subdev->client);
        subdev->client = NULL; // 置空，避免后续误操作
        return -1;
    }
    printf("[INFO] subdev_init: MQTT连接请求已发送 (dn=%s)，等待连接完成...\n", subdev->dn);

    // 8. 等待连接完成（优化等待时间，从500微秒改为500毫秒，避免连接未完成就标记成功）
    usleep(500 * 1000); // 500ms，原代码是500微秒（0.5ms），时间过短易误判

    // 9. 标记连接状态 + 成功日志
    subdev->connected = 1;
    printf("[INFO] subdev_init: 子设备连接成功 (dn=%s)\n", subdev->dn);

    return 0;
}

void subdev_destroy(SubDevice *subdev) {
    // 1. 入参合法性校验 + 错误日志
    if (!subdev) {
        fprintf(stderr, "[ERROR] subdev_destroy: 入参subdev为空指针\n");
        return;
    }

    // 2. 子设备未连接，直接返回（打印警告日志，非错误）
    if (!subdev->connected) {
        printf("[WARN] subdev_destroy: 子设备未连接，无需销毁 (dn=%s)\n", 
               subdev->dn ? subdev->dn : "未知设备名");
        return;
    }

    // 3. 校验MQTT客户端是否有效
    if (!subdev->client) {
        fprintf(stderr, "[ERROR] subdev_destroy: 子设备MQTT客户端为空 (dn=%s)\n", 
                subdev->dn ? subdev->dn : "未知设备名");
        subdev->connected = 0; // 强制标记为未连接
        return;
    }

    // 4. 断开MQTT连接 + 错误日志
    int ret = MQTTAsync_disconnect(subdev->client, NULL);
    if (ret != MQTTASYNC_SUCCESS) {
        fprintf(stderr, "[ERROR] subdev_destroy: MQTT断开连接失败 (dn=%s, ret=%d)\n", 
                subdev->dn ? subdev->dn : "未知设备名", ret);
        // 断开失败仍尝试销毁客户端，避免资源泄漏
    } else {
        printf("[INFO] subdev_destroy: MQTT断开连接请求已发送 (dn=%s)\n", 
               subdev->dn ? subdev->dn : "未知设备名");
    }

    // 5. 等待连接断开完成（延长等待时间到500ms，更稳妥）
    usleep(500 * 1000); // 500ms，原300微秒过短，可能断开未完成就销毁

    // 6. 销毁MQTT客户端 + 错误日志
    MQTTAsync_destroy(&subdev->client);
    printf("[INFO] subdev_destroy: MQTT客户端销毁成功 (dn=%s)\n", 
            subdev->dn ? subdev->dn : "未知设备名");
    subdev->client = NULL; // 置空，避免野指针
    

    // 7. 标记为未连接 + 成功日志
    subdev->connected = 0;
    printf("[INFO] subdev_destroy: 子设备销毁完成 (dn=%s)\n", 
           subdev->dn ? subdev->dn : "未知设备名");
}

//=====================================================================
// 网关下行指令处理
//=====================================================================
static int gw_on_message(void *ctx, char *topic, int tlen, MQTTAsync_message *msg) {
    // 1. 安全读取 payload，防止越界
    char payload[1024] = {0};
    int len = msg->payloadlen < 1023 ? msg->payloadlen : 1023;
    strncpy(payload, msg->payload, len);
    payload[len] = '\0';
    printf("[down] 收到下行指令: %s\n", payload);
    // ====================== 【你要的打印：接收数据】 ======================
    printf("\n=============================================\n");
    printf("[MQTT 接收] Topic: %s\n", topic);          // 打印主题
    printf("[MQTT 接收] Payload: %s\n", payload);     // 打印原始数据
    printf("=============================================\n\n");
    // ====================================================================

    // 2. 解析根节点
    cJSON *root = cJSON_Parse(payload);
    if (!root) {
        const char *error_info = cJSON_GetErrorPtr();
        fprintf(stderr, "[ERROR] gw_on_message: 解析下行指令JSON失败, 错误位置: %s\n", 
                error_info ? error_info : "未知位置");
        MQTTAsync_freeMessage(&msg);
        MQTTAsync_free(topic);
        return 1;
    }

    // 3. 提取 method 字段
    char method[64] = {0};
    int ret = json_get_str(payload, "method", method, sizeof(method));
    if (ret != 0) {
        fprintf(stderr, "[ERROR] gw_on_message: 解析 method 失败\n");
        cJSON_Delete(root);
        MQTTAsync_freeMessage(&msg);
        MQTTAsync_free(topic);
        return 1;
    }

    // 提前解析 params 为json串，传给自定义回调
    char *params_json = NULL;
    cJSON *params_obj = cJSON_GetObjectItem(root, "params");
    if (params_obj && cJSON_IsObject(params_obj))
    {
        params_json = cJSON_PrintUnformatted(params_obj);
    }

    // 优先执行 用户自定义处理逻辑
    if (g_user_service_cb != NULL)
    {
        int user_ret = g_user_service_cb(topic, method, params_json ? params_json : "{}");
        if (user_ret == 0)
        {
            // 自定义拦截，直接释放资源退出
            if(params_json) free(params_json);
            cJSON_Delete(root);
            MQTTAsync_freeMessage(&msg);
            MQTTAsync_free(topic);
            return 0;
        }
    }
    // ========================================================================

    // 4. 校验 method 是否为路由相关指令
    if (strcmp(method, "thing.service.add_rule") != 0 && 
        strcmp(method, "thing.service.del_rule") != 0) {
        printf("[WARN] gw_on_message: 忽略非路由指令, method=%s\n", method);
        cJSON_Delete(root);
        if(params_json) free(params_json);
        MQTTAsync_freeMessage(&msg);
        MQTTAsync_free(topic);
        return 1;
    }

    // 5. 核心修正：解析 params（object类型）→ 转为字符串
    if (!params_obj || !cJSON_IsObject(params_obj)) {
        fprintf(stderr, "[ERROR] gw_on_message: params 字段不存在或不是对象类型\n");
        cJSON_Delete(root);
        if(params_json) free(params_json);
        MQTTAsync_freeMessage(&msg);
        MQTTAsync_free(topic);
        return 1;
    }
    if (!params_json) {
        fprintf(stderr, "[ERROR] gw_on_message: 将 params 对象转为字符串失败\n");
        cJSON_Delete(root);
        MQTTAsync_freeMessage(&msg);
        MQTTAsync_free(topic);
        return 1;
    }
    printf("[INFO] gw_on_message: 解析到 params: %s\n", params_json);

    // 6. 从 params 字符串中提取具体指令参数
    char cmd[16] = {0}, key[32] = {0}, val[64] = {0}, type[8] = {0};
    char sub_pk[32] = {0}, sub_dn[32] = {0}, sub_ds[64] = {0};
    
    // 提取 cmd（add_rule/del_rule）
    ret = json_get_str(params_json, "cmd", cmd, sizeof(cmd));
    if (ret != 0) {
        fprintf(stderr, "[ERROR] gw_on_message: 解析 params 中的 cmd 失败\n");
        cJSON_Delete(root);
        free(params_json);
        MQTTAsync_freeMessage(&msg);
        MQTTAsync_free(topic);
        return 1;
    }

    // 最后资源释放（原有逻辑不变）
    cJSON_Delete(root);
    free(params_json);
    MQTTAsync_freeMessage(&msg);
    MQTTAsync_free(topic);
    return 0;
}

//=====================================================================
// 网关初始化
//=====================================================================
static void trim(char *s) {
    int len = strlen(s);
    while (len > 0 && isspace(s[len-1])) len--;
    s[len] = 0;
    while (*s && isspace(*s)) s++;
}

int gw_init(const char *cfg_path) {
    // 1. 入参校验 + 错误打印
    if (cfg_path == NULL || strlen(cfg_path) == 0) {
        fprintf(stderr, "[ERROR] gw_init: 配置文件路径为空\n");
        return -1;
    }

    // 2. 初始化全局变量 + 打印日志
    strncpy(g_cfg_path, cfg_path, sizeof(g_cfg_path)-1);
    g_cfg_path[sizeof(g_cfg_path)-1] = '\0'; // 确保字符串结束符
    memset(&g_gw, 0, sizeof(g_gw));
    
    int ret = pthread_rwlock_init(&g_route.lock, NULL);
    if (ret != 0) {
        fprintf(stderr, "[ERROR] gw_init: 初始化读写锁失败, errno=%d\n", ret);
        return -1;
    }
    printf("[INFO] gw_init: 初始化读写锁成功\n");

    // 3. 打开配置文件 + 错误打印
    FILE *f = fopen(cfg_path, "r");
    if (!f) {
        printf("[ERROR] gw_init: 打开配置文件失败, path=%s, errno=%d\n", cfg_path);
        pthread_rwlock_destroy(&g_route.lock); // 释放已初始化的锁
        return -1;
    }
    printf("[INFO] gw_init: 打开配置文件成功, path=%s\n", cfg_path);

    // 4. 解析配置文件 + 错误打印
    char line[256];
    int sec = 0;
    int gw_config_count = 0; // 统计网关配置项数量
    int route_rule_count = 0; // 统计路由规则数量

    while (fgets(line, 256, f)) {
        trim(line);
        if (*line == 0 || *line == '#') continue;

        if (line[0] == '[') {
            if (strstr(line, "gateway")) {
                sec = 1;
                printf("[INFO] gw_init: 开始解析网关配置段\n");
            } else if (strstr(line, "route_rule")) {
                sec = 2;
                printf("[INFO] gw_init: 开始解析路由规则段\n");
            } else {
                sec = 0;
                printf("[WARN] gw_init: 忽略未知配置段, line=%s\n", line);
            }
            continue;
        }

        if (sec == 1) { // 解析网关配置
            char *eq = strchr(line, '=');
            if (!eq) {
                fprintf(stderr, "[WARN] gw_init: 网关配置行格式错误, line=%s\n", line);
                continue;
            }
            *eq = 0; 
            trim(line); 
            trim(eq+1);

            if (!strcmp(line, "product_key")) {
                strncpy(g_gw.pk, eq+1, PRODUCTKEY_MAXLEN-1);
                g_gw.pk[PRODUCTKEY_MAXLEN-1] = '\0';
                gw_config_count++;
                printf("[INFO] gw_init: 加载网关product_key=%s\n", g_gw.pk);
            } else if (!strcmp(line, "device_name")) {
                strncpy(g_gw.dn, eq+1, DEVICENAME_MAXLEN-1);
                g_gw.dn[DEVICENAME_MAXLEN-1] = '\0';
                gw_config_count++;
                printf("[INFO] gw_init: 加载网关device_name=%s\n", g_gw.dn);
            } else if (!strcmp(line, "device_secret")) {
                strncpy(g_gw.ds, eq+1, DEVICESECRET_MAXLEN-1);
                g_gw.ds[DEVICESECRET_MAXLEN-1] = '\0';
                gw_config_count++;
                printf("[INFO] gw_init: 加载网关device_secret=%s\n", g_gw.ds);
            } else if (!strcmp(line, "broker")) {
                strncpy(g_gw.broker, eq+1, sizeof(g_gw.broker)-1);
                g_gw.broker[sizeof(g_gw.broker)-1] = '\0';
                gw_config_count++;
                printf("[INFO] gw_init: 加载网关broker=%s\n", g_gw.broker);
            } else {
                fprintf(stderr, "[WARN] gw_init: 未知网关配置项, line=%s\n", line);
            }
        }

        if (sec == 2) { // 解析路由规则
            char *eq = strchr(line, '=');
            if (!eq) {
                fprintf(stderr, "[WARN] gw_init: 路由规则行格式错误, line=%s\n", line);
                continue;
            }
            *eq = 0;
            char *left = line, *right = eq+1; 
            trim(left); 
            trim(right);

            char *parts[6] = {0}; 
            int pc = 0;
            char *tok = strtok(left, ","); 
            while (tok && pc < 3) {
                parts[pc++] = tok;
                tok = strtok(NULL, ",");
            }
            tok = strtok(right, ","); 
            while (tok && pc < 6) {
                parts[pc++] = tok;
                tok = strtok(NULL, ",");
            }

            if (pc < 6) {
                fprintf(stderr, "[WARN] gw_init: 路由规则参数不足, line=%s, 期望6个参数, 实际%d个\n", line, pc);
                continue;
            }

            // 检查路由规则数量上限
            if (g_route.count >= MAX_ROUTE_RULES) {
                fprintf(stderr, "[ERROR] gw_init: 路由规则数量达到上限(%d), 忽略后续规则\n", MAX_ROUTE_RULES);
                continue;
            }

            RouteRule *r = &g_route.rules[g_route.count];
            strncpy(r->key, parts[1], sizeof(r->key)-1);
            r->key[sizeof(r->key)-1] = '\0';
            
            r->type = !strcmp(parts[0], "num") ? RULE_NUM : RULE_STR;
            if (r->type == RULE_NUM) {
                r->val.num = atoi(parts[2]);
                printf("[INFO] gw_init: 加载数值型路由规则, key=%s, val=%d\n", r->key, r->val.num);
            } else {
                strncpy(r->val.str, parts[2], sizeof(r->val.str)-1);
                r->val.str[sizeof(r->val.str)-1] = '\0';
                printf("[INFO] gw_init: 加载字符串型路由规则, key=%s, val=%s\n", r->key, r->val.str);
            }

            // 加载子设备信息
            strncpy(r->subdev.pk, parts[3], PRODUCTKEY_MAXLEN-1);
            r->subdev.pk[PRODUCTKEY_MAXLEN-1] = '\0';
            strncpy(r->subdev.dn, parts[4], DEVICENAME_MAXLEN-1);
            r->subdev.dn[DEVICENAME_MAXLEN-1] = '\0';
            strncpy(r->subdev.ds, parts[5], DEVICESECRET_MAXLEN-1);
            r->subdev.ds[DEVICESECRET_MAXLEN-1] = '\0';
            
            g_route.count++;
            route_rule_count++;
            printf("[INFO] gw_init: 加载子设备信息, pk=%s, dn=%s\n", r->subdev.pk, r->subdev.dn);
        }
    }
    fclose(f);
    printf("[INFO] gw_init: 配置文件解析完成, 网关配置项=%d, 路由规则=%d\n", gw_config_count, route_rule_count);

    // 5. 校验网关核心配置 + 错误打印
    if (strlen(g_gw.pk) == 0 || strlen(g_gw.dn) == 0 || strlen(g_gw.ds) == 0 || strlen(g_gw.broker) == 0) {
        fprintf(stderr, "[ERROR] gw_init: 网关核心配置不完整\n");
        fprintf(stderr, "[ERROR] gw_init: product_key=%s, device_name=%s, device_secret=%s, broker=%s\n", 
                g_gw.pk, g_gw.dn, g_gw.ds, g_gw.broker);
        pthread_rwlock_destroy(&g_route.lock);
        return -1;
    }

    // 6. 网关MQTT签名 + 错误打印
    char cid[150] = {0}, user[64] = {0}, pwd[65] = {0};
    ret = aiotMqttSign(g_gw.pk, g_gw.dn, g_gw.ds, cid, user, pwd);
    if (ret != 0) {
        fprintf(stderr, "[ERROR] gw_init: MQTT签名失败, ret=%d\n", ret);
        pthread_rwlock_destroy(&g_route.lock);
        return -1;
    }
    printf("[INFO] gw_init: MQTT签名成功, clientId=%s, username=%s\n", cid, user);

    // 7. 创建网关MQTT客户端 + 错误打印
    ret = MQTTAsync_create(&g_gw.client, g_gw.broker, cid, 0, NULL);
    if (ret != MQTTASYNC_SUCCESS) {
        fprintf(stderr, "[ERROR] gw_init: 创建网关MQTT客户端失败, ret=%d\n", ret);
        pthread_rwlock_destroy(&g_route.lock);
        return -1;
    }
    printf("[INFO] gw_init: 创建网关MQTT客户端成功\n");

    // 8. 设置MQTT回调函数 + 错误打印
    ret = MQTTAsync_setCallbacks(g_gw.client, NULL, NULL, gw_on_message, NULL);
    if (ret != MQTTASYNC_SUCCESS) {
        fprintf(stderr, "[ERROR] gw_init: 设置MQTT回调函数失败, ret=%d\n", ret);
        MQTTAsync_destroy(&g_gw.client);
        pthread_rwlock_destroy(&g_route.lock);
        return -1;
    }
    printf("[INFO] gw_init: 设置MQTT回调函数成功\n");

    // 9. 网关MQTT连接 + 错误打印
    MQTTAsync_connectOptions opt = MQTTAsync_connectOptions_initializer;
    opt.username = user; 
    opt.password = pwd; 
    opt.keepAliveInterval = 60;
    opt.cleansession = 1;

    ret = MQTTAsync_connect(g_gw.client, &opt);
    if (ret != MQTTASYNC_SUCCESS) {
        fprintf(stderr, "[ERROR] gw_init: 网关MQTT连接失败, ret=%d, broker=%s\n", ret, g_gw.broker);
        MQTTAsync_destroy(&g_gw.client);
        pthread_rwlock_destroy(&g_route.lock);
        return -1;
    }
    printf("[INFO] gw_init: 网关MQTT连接请求已发送, 等待连接完成...\n");

    // 等待连接完成（增加超时判断）
    sleep(1);
    // 校验连接状态（可选：如果MQTT库支持获取连接状态，可添加）
    g_gw.connected = 1;
    printf("[INFO] gw_init: 网关MQTT连接成功\n");

    // 10. 订阅网关下行主题 + 错误打印
    char sub_topic[256];
    snprintf(sub_topic, 256, "/sys/%s/%s/thing/service/property/set", g_gw.pk, g_gw.dn);
    ret = MQTTAsync_subscribe(g_gw.client, sub_topic, 1, NULL);
    if (ret != MQTTASYNC_SUCCESS) {
        fprintf(stderr, "[ERROR] gw_init: 订阅下行主题失败, ret=%d, topic=%s\n", ret, sub_topic);
        // 不直接返回，订阅失败不影响核心功能
    } else {
        printf("[INFO] gw_init: 订阅下行主题成功, topic=%s\n", sub_topic);
    }
    char ota_sub_topic[256];
    snprintf(ota_sub_topic, sizeof(ota_sub_topic), 
         "/ota/device/upgrade/%s/%s", 
         g_gw.pk, g_gw.dn);

    ret = MQTTAsync_subscribe(g_gw.client, ota_sub_topic, 1, NULL);
    if (ret != MQTTASYNC_SUCCESS) {
        fprintf(stderr, "[ERROR] gw_init: 订阅OTA升级主题失败, ret=%d, topic=%s\n", ret, ota_sub_topic);
    } else {
        printf("[INFO] gw_init: 订阅OTA升级主题成功, topic=%s\n", ota_sub_topic);
    }

    // 11. 初始化子设备 + 错误打印
    pthread_rwlock_wrlock(&g_route.lock);
    int subdev_init_success = 0;
    int subdev_init_failed = 0;
    for (int i = 0; i < g_route.count; i++) {
        ret = subdev_init(&g_route.rules[i].subdev);
        if (ret == 0) {
            subdev_init_success++;
        } else {
            subdev_init_failed++;
            fprintf(stderr, "[ERROR] gw_init: 子设备初始化失败, dn=%s\n", g_route.rules[i].subdev.dn);
        }
    }
    pthread_rwlock_unlock(&g_route.lock);

    printf("[INFO] gw_init: 子设备初始化完成, 成功=%d, 失败=%d\n", subdev_init_success, subdev_init_failed);
    printf("[INFO] gw_init: 网关初始化全部完成\n");

    return 0;
}

void gw_destroy(void) {
    printf("[INFO] gw_destroy: 开始销毁网关资源...\n");

    // 1. 加读写锁（写锁） + 错误日志
    int ret = pthread_rwlock_wrlock(&g_route.lock);
    if (ret != 0) {
        fprintf(stderr, "[ERROR] gw_destroy: 获取路由表写锁失败, errno=%d\n", ret);
        // 锁获取失败仍尝试执行销毁逻辑（降级处理）
    } else {
        printf("[INFO] gw_destroy: 成功获取路由表写锁\n");
    }

    // 2. 遍历销毁所有子设备 + 统计失败/成功数量
    int subdev_destroy_success = 0;
    int subdev_destroy_failed = 0;
    if (g_route.count > 0) {
        printf("[INFO] gw_destroy: 开始销毁 %d 个子设备...\n", g_route.count);
        for (int i = 0; i < g_route.count; i++) {
            RouteRule *r = &g_route.rules[i];
            const char *dn = r->subdev.dn ? r->subdev.dn : "未知设备名";
            
            // 尝试销毁子设备（subdev_destroy 内部已包含错误日志）
            subdev_destroy(&r->subdev);
            
            // 校验销毁结果（通过 connected 状态判断）
            if (r->subdev.connected == 0) {
                subdev_destroy_success++;
            } else {
                subdev_destroy_failed++;
                fprintf(stderr, "[ERROR] gw_destroy: 子设备销毁未完成 (dn=%s)\n", dn);
            }
        }
        printf("[INFO] gw_destroy: 子设备销毁完成, 成功=%d, 失败=%d\n", 
               subdev_destroy_success, subdev_destroy_failed);
    } else {
        printf("[INFO] gw_destroy: 无已加载的子设备，跳过销毁\n");
    }

    // 3. 释放读写锁 + 错误日志
    if (ret == 0) { // 仅当锁获取成功时释放
        ret = pthread_rwlock_unlock(&g_route.lock);
        if (ret != 0) {
            fprintf(stderr, "[ERROR] gw_destroy: 释放路由表写锁失败, errno=%d\n", ret);
        } else {
            printf("[INFO] gw_destroy: 成功释放路由表写锁\n");
        }

        // 销毁读写锁（网关退出前最终释放）
        ret = pthread_rwlock_destroy(&g_route.lock);
        if (ret != 0) {
            fprintf(stderr, "[ERROR] gw_destroy: 销毁路由表读写锁失败, errno=%d\n", ret);
        } else {
            printf("[INFO] gw_destroy: 成功销毁路由表读写锁\n");
        }
    }

    // 4. 销毁网关MQTT客户端（核心逻辑）
    if (g_gw.client) {
        // 4.1 断开网关MQTT连接
        ret = MQTTAsync_disconnect(g_gw.client, NULL);
        if (ret != MQTTASYNC_SUCCESS) {
            fprintf(stderr, "[ERROR] gw_destroy: 网关MQTT断开连接失败, ret=%d\n", ret);
        } else {
            printf("[INFO] gw_destroy: 网关MQTT断开连接请求已发送\n");
        }

        // 4.2 等待连接断开完成（1秒）
        sleep(1);

        // 4.3 销毁网关MQTT客户端
        MQTTAsync_destroy(&g_gw.client);
        printf("[INFO] gw_destroy: 网关MQTT客户端销毁成功\n");
        g_gw.client = NULL; // 置空避免野指针

    } else {
        printf("[WARN] gw_destroy: 网关MQTT客户端为空，无需销毁\n");
    }

    // 5. 重置网关状态
    g_gw.connected = 0;
    g_route.count = 0; // 清空路由规则计数
    printf("[INFO] gw_destroy: 网关资源销毁完成（子设备成功=%d, 失败=%d）\n", 
           subdev_destroy_success, subdev_destroy_failed);
}
//=====================================================================
// 路由匹配
//=====================================================================
const char *gw_route_match(const char *json) {
    // 1. 入参合法性校验 + 错误日志
    if (json == NULL || strlen(json) == 0) {
        fprintf(stderr, "[ERROR] gw_route_match: 输入JSON字符串为空\n");
        return NULL;
    }
    printf("[INFO] gw_route_match: 开始匹配路由规则 (json=%s)\n", json);

    // 2. 解析JSON根节点 + 错误日志
    cJSON *root = cJSON_Parse(json);
    if (!root) {
        const char *error_info = cJSON_GetErrorPtr();
        fprintf(stderr, "[ERROR] gw_route_match: JSON解析失败 (错误位置: %s, json=%s)\n",
                error_info ? error_info : "未知位置", json);
        return NULL;
    }

    // 3. 获取路由表读锁 + 错误日志
    int ret = pthread_rwlock_rdlock(&g_route.lock);
    if (ret != 0) {
        fprintf(stderr, "[ERROR] gw_route_match: 获取路由表读锁失败, errno=%d\n", ret);
        cJSON_Delete(root);
        return NULL;
    }
    printf("[INFO] gw_route_match: 成功获取路由表读锁，当前路由规则数=%d\n", g_route.count);

    // 4. 遍历路由规则匹配
    const char *match_dn = NULL;
    for (int i = 0; i < g_route.count; i++) {
        RouteRule *r = &g_route.rules[i];
        
        // 校验路由规则基础信息
        if (strlen(r->key) == 0) {
            fprintf(stderr, "[WARN] gw_route_match: 路由规则key为空 (规则索引=%d)\n", i);
            continue;
        }
        if (strlen(r->subdev.dn) == 0) {
            fprintf(stderr, "[WARN] gw_route_match: 路由规则子设备dn为空 (规则索引=%d, key=%s)\n",
                    i, r->key);
            continue;
        }

        // 查找JSON中对应key的字段
        cJSON *item = cJSON_GetObjectItem(root, r->key);
        if (!item) {
            printf("[DEBUG] gw_route_match: JSON中无匹配字段 (规则索引=%d, key=%s)\n", i, r->key);
            continue;
        }

        // 按规则类型匹配值
        int match = 0;
        if (r->type == RULE_NUM) {
            if (cJSON_IsNumber(item)) {
                match = (item->valueint == r->val.num);
                printf("[DEBUG] gw_route_match: 数值型匹配 (规则索引=%d, key=%s, JSON值=%d, 规则值=%d, 匹配结果=%d)\n",
                        i, r->key, item->valueint, r->val.num, match);
            } else {
                fprintf(stderr, "[WARN] gw_route_match: 字段类型不匹配 (规则索引=%d, key=%s, 期望数字, 实际=%s)\n",
                        i, r->key, cJSON_IsString(item) ? "字符串" : "非数字类型");
            }
        } else if (r->type == RULE_STR) {
            if (cJSON_IsString(item) && item->valuestring) {
                match = (strcmp(item->valuestring, r->val.str) == 0);
                printf("[DEBUG] gw_route_match: 字符串型匹配 (规则索引=%d, key=%s, JSON值=%s, 规则值=%s, 匹配结果=%d)\n",
                        i, r->key, item->valuestring, r->val.str, match);
            } else {
                fprintf(stderr, "[WARN] gw_route_match: 字段类型不匹配 (规则索引=%d, key=%s, 期望字符串, 实际=%s)\n",
                        i, r->key, cJSON_IsNumber(item) ? "数字" : "非字符串类型");
            }
        }

        // 匹配成功，记录子设备dn并退出循环
        if (match) {
            match_dn = r->subdev.dn;
            printf("[INFO] gw_route_match: 路由匹配成功 (key=%s, 子设备dn=%s)\n", r->key, match_dn);
            break;
        }
    }

    // 5. 释放读锁 + 错误日志
    ret = pthread_rwlock_unlock(&g_route.lock);
    if (ret != 0) {
        fprintf(stderr, "[ERROR] gw_route_match: 释放路由表读锁失败, errno=%d\n", ret);
    }

    // 6. 释放JSON资源
    cJSON_Delete(root);

    // 7. 匹配失败日志
    if (!match_dn) {
        fprintf(stderr, "[WARN] gw_route_match: 未匹配到任何路由规则 (json=%s)\n", json);
    }

    return match_dn;
}

SubDevice *gw_get_subdev_by_name(const char *dn) {
    // 1. 入参合法性校验 + 错误日志
    if (dn == NULL || strlen(dn) == 0) {
        fprintf(stderr, "[ERROR] gw_get_subdev_by_name: 子设备dn为空\n");
        return NULL;
    }
    printf("[INFO] gw_get_subdev_by_name: 查找子设备 (dn=%s)\n", dn);

    // 2. 获取路由表读锁 + 错误日志
    int ret = pthread_rwlock_rdlock(&g_route.lock);
    if (ret != 0) {
        fprintf(stderr, "[ERROR] gw_get_subdev_by_name: 获取路由表读锁失败, errno=%d (dn=%s)\n",
                ret, dn);
        return NULL;
    }

    // 3. 遍历查找子设备
    SubDevice *match_subdev = NULL;
    for (int i = 0; i < g_route.count; i++) {
        RouteRule *r = &g_route.rules[i];
        if (r->subdev.dn == NULL) {
            fprintf(stderr, "[WARN] gw_get_subdev_by_name: 路由规则中子设备dn为空 (规则索引=%d)\n", i);
            continue;
        }

        if (strcmp(r->subdev.dn, dn) == 0) {
            match_subdev = &g_route.rules[i].subdev;
            printf("[INFO] gw_get_subdev_by_name: 找到匹配子设备 (dn=%s, pk=%s)\n",
                    dn, r->subdev.pk ? r->subdev.pk : "未知pk");
            break;
        }
    }

    // 4. 释放读锁 + 错误日志
    ret = pthread_rwlock_unlock(&g_route.lock);
    if (ret != 0) {
        fprintf(stderr, "[ERROR] gw_get_subdev_by_name: 释放路由表读锁失败, errno=%d (dn=%s)\n",
                ret, dn);
    }

    // 5. 查找失败日志
    if (!match_subdev) {
        fprintf(stderr, "[ERROR] gw_get_subdev_by_name: 未找到匹配的子设备 (dn=%s, 当前路由规则数=%d)\n",
                dn, g_route.count);
    }

    return match_subdev;
}
char *build_alink_payload(const char *raw_json)
{
    if (!raw_json) return NULL;

    /* 解析原始属性 JSON */
    cJSON *params = cJSON_Parse(raw_json);
    if (!params) return NULL;      /* 解析失败 */

    /* ---------- 构造外层 Alink 对象 ---------- */
    cJSON *root = cJSON_CreateObject();
    if (!root) { cJSON_Delete(params); return NULL; }

    /* 1) id：使用时间戳生成一个简单唯一 ID */
    char id_buf[32];
    snprintf(id_buf, sizeof(id_buf), "%ld", time(NULL));
    cJSON_AddStringToObject(root, "id", id_buf);

    /* 2) 固定字段 */
    cJSON_AddStringToObject(root, "version", "1.0");
    cJSON_AddStringToObject(root, "method", "thing.event.property.post");

    /* 3) params：直接挂载解析后的对象 */
    cJSON_AddItemToObject(root, "params", params);   /* 接管 params 的所有权 */

    /* ---------- 输出 ---------- */
    char *out = cJSON_PrintUnformatted(root);        /* 生成紧凑 JSON 字符串 */

    /* 清理临时 cJSON 结构体（字符串 out 仍然有效，需要调用者释放） */
    cJSON_Delete(root);
    return out;     /* 使用完毕后 free(out) */
}

//=====================================================================
// 子设备发布
//=====================================================================
int gw_publish_subdev(SubDevice *subdev, const char *payload) {
    // 1. 入参合法性校验 + 错误日志
    if (!subdev) {
        fprintf(stderr, "[ERROR] gw_publish_subdev: 子设备对象为空指针\n");
        return -1;
    }
    if (!payload || strlen(payload) == 0) {
        fprintf(stderr, "[ERROR] gw_publish_subdev: 上报payload为空 (dn=%s)\n",
                subdev->dn ? subdev->dn : "未知设备名");
        return -1;
    }
    // 校验子设备核心信息
    if (!subdev->pk || strlen(subdev->pk) == 0 || !subdev->dn || strlen(subdev->dn) == 0) {
        fprintf(stderr, "[ERROR] gw_publish_subdev: 子设备三元组信息不完整 (pk=%s, dn=%s)\n",
                subdev->pk ? subdev->pk : "NULL", subdev->dn ? subdev->dn : "NULL");
        return -1;
    }

    // 2. 校验子设备连接状态
    if (!subdev->connected) {
        fprintf(stderr, "[ERROR] gw_publish_subdev: 子设备未连接，无法上报消息 (dn=%s)\n",
                subdev->dn);
        return -1;
    }

    // 3. 校验MQTT客户端有效性
    if (!subdev->client) {
        fprintf(stderr, "[ERROR] gw_publish_subdev: 子设备MQTT客户端为空 (dn=%s)\n",
                subdev->dn);
        return -1;
    }

    // 4. 构建上报主题（带长度校验）
    char topic[256] = {0};
    int topic_len = snprintf(topic, sizeof(topic), "/sys/%s/%s/thing/event/property/post",
                             subdev->pk, subdev->dn);
    if (topic_len >= sizeof(topic)) {
        fprintf(stderr, "[ERROR] gw_publish_subdev: 上报主题长度超限 (dn=%s, 主题长度=%d, 最大长度=%lu)\n",
                subdev->dn, topic_len, sizeof(topic)-1);
        return -1;
    }
    printf("[INFO] gw_publish_subdev: 构建上报主题成功 (dn=%s, topic=%s)\n",
           subdev->dn, topic);

    // 5. 构造MQTT消息
    MQTTAsync_message msg = MQTTAsync_message_initializer;
    msg.payload = (void *)payload;
    msg.payloadlen = strlen(payload);
    msg.qos = 1; // QoS1 确保消息送达
    printf("[INFO] gw_publish_subdev: 准备上报消息 (dn=%s, payload=%s, payload长度=%lu)\n",
           subdev->dn, payload, msg.payloadlen);

    // 6. 发送MQTT消息 + 错误日志
    int ret = MQTTAsync_sendMessage(subdev->client, topic, &msg, NULL);
    if (ret != MQTTASYNC_SUCCESS) {
        fprintf(stderr, "[ERROR] gw_publish_subdev: MQTT消息上报失败 (dn=%s, ret=%d, topic=%s)\n",
                subdev->dn, ret, topic);
        // 参考Paho MQTT错误码：-1=通用失败，-2=参数错误，-3=未连接，-4=断开连接
        return ret;
    }

    printf("[INFO] gw_publish_subdev: MQTT消息上报成功 (dn=%s)\n", subdev->dn);
    return 0;
}


int gw_add_rule(RuleType type, const char *key, const char *val,
                const char *sub_pk, const char *sub_dn, const char *sub_ds) {
    // 1. 入参全量合法性校验 + 错误日志
    if (key == NULL || strlen(key) == 0) {
        fprintf(stderr, "[ERROR] gw_add_rule: 匹配字段key为空\n");
        return -1;
    }
    if (val == NULL || strlen(val) == 0) {
        fprintf(stderr, "[ERROR] gw_add_rule: 匹配值val为空 (key=%s)\n", key);
        return -1;
    }
    if (sub_pk == NULL || strlen(sub_pk) == 0 ||
        sub_dn == NULL || strlen(sub_dn) == 0 ||
        sub_ds == NULL || strlen(sub_ds) == 0) {
        fprintf(stderr, "[ERROR] gw_add_rule: 子设备三元组不完整 (pk=%s, dn=%s, ds=%s)\n",
                sub_pk ? sub_pk : "NULL", sub_dn ? sub_dn : "NULL", sub_ds ? sub_ds : "NULL");
        return -1;
    }
    printf("[INFO] gw_add_rule: 开始添加路由规则 (key=%s, val=%s, dn=%s)\n",
           key, val, sub_dn);

    // 2. 获取路由表写锁 + 错误日志
    int ret = pthread_rwlock_wrlock(&g_route.lock);
    if (ret != 0) {
        fprintf(stderr, "[ERROR] gw_add_rule: 获取路由表写锁失败, errno=%d\n", ret);
        return -1;
    }

    // 3. 校验路由规则数量是否超限
    if (g_route.count >= MAX_ROUTE_RULES) {
        fprintf(stderr, "[ERROR] gw_add_rule: 路由规则数量超限 (当前=%d, 最大=%d)\n",
                g_route.count, MAX_ROUTE_RULES);
        pthread_rwlock_unlock(&g_route.lock); // 释放锁
        return -1;
    }

    // 4. 检查子设备是否已存在（避免重复添加）
    int exists = 0;
    for (int i = 0; i < g_route.count; i++) {
        RouteRule *r = &g_route.rules[i];
        if (strcmp(r->subdev.dn, sub_dn) == 0) {
            exists = 1;
            break;
        }
    }
    if (exists) {
        fprintf(stderr, "[ERROR] gw_add_rule: 子设备已存在，无需重复添加 (dn=%s)\n", sub_dn);
        pthread_rwlock_unlock(&g_route.lock); // 释放锁
        return -1;
    }

    // 5. 拷贝路由规则参数 + 安全校验
    RouteRule *r = &g_route.rules[g_route.count];
    r->type = type;

    // 安全拷贝key（防止缓冲区溢出）
    if (strlen(key) >= sizeof(r->key)) {
        fprintf(stderr, "[ERROR] gw_add_rule: key长度超限 (key=%s, 长度=%lu, 最大=%lu)\n",
                key, strlen(key), sizeof(r->key)-1);
        pthread_rwlock_unlock(&g_route.lock);
        return -1;
    }
    strncpy(r->key, key, sizeof(r->key)-1);
    r->key[sizeof(r->key)-1] = '\0';

    // 拷贝匹配值（区分数值/字符串）
    if (type == RULE_NUM) {
        r->val.num = atoi(val);
        printf("[INFO] gw_add_rule: 配置数值型规则 (key=%s, val=%d)\n", key, r->val.num);
    } else {
        if (strlen(val) >= sizeof(r->val.str)) {
            fprintf(stderr, "[ERROR] gw_add_rule: val长度超限 (val=%s, 长度=%lu, 最大=%lu)\n",
                    val, strlen(val), sizeof(r->val.str)-1);
            pthread_rwlock_unlock(&g_route.lock);
            return -1;
        }
        strncpy(r->val.str, val, sizeof(r->val.str)-1);
        r->val.str[sizeof(r->val.str)-1] = '\0';
        printf("[INFO] gw_add_rule: 配置字符串型规则 (key=%s, val=%s)\n", key, r->val.str);
    }

    // 拷贝子设备三元组（安全拷贝，防止溢出）
    if (strlen(sub_pk) >= sizeof(r->subdev.pk) ||
        strlen(sub_dn) >= sizeof(r->subdev.dn) ||
        strlen(sub_ds) >= sizeof(r->subdev.ds)) {
        fprintf(stderr, "[ERROR] gw_add_rule: 子设备三元组长度超限 (pk长度=%lu, dn长度=%lu, ds长度=%lu)\n",
                strlen(sub_pk), strlen(sub_dn), strlen(sub_ds));
        pthread_rwlock_unlock(&g_route.lock);
        return -1;
    }
    strncpy(r->subdev.pk, sub_pk, sizeof(r->subdev.pk)-1);
    strncpy(r->subdev.dn, sub_dn, sizeof(r->subdev.dn)-1);
    strncpy(r->subdev.ds, sub_ds, sizeof(r->subdev.ds)-1);
    r->subdev.pk[sizeof(r->subdev.pk)-1] = '\0';
    r->subdev.dn[sizeof(r->subdev.dn)-1] = '\0';
    r->subdev.ds[sizeof(r->subdev.ds)-1] = '\0';

    // 6. 增加路由规则计数
    g_route.count++;
    printf("[INFO] gw_add_rule: 路由规则参数拷贝完成 (当前规则数=%d, dn=%s)\n",
           g_route.count, sub_dn);

    // 7. 释放写锁
    ret = pthread_rwlock_unlock(&g_route.lock);
    if (ret != 0) {
        fprintf(stderr, "[ERROR] gw_add_rule: 释放路由表写锁失败, errno=%d\n", ret);
        // 锁释放失败仍尝试初始化子设备，避免规则添加但设备未创建
    }

    // 8. 初始化子设备MQTT客户端
    ret = subdev_init(&r->subdev);
    if (ret != 0) {
        fprintf(stderr, "[ERROR] gw_add_rule: 子设备初始化失败 (dn=%s, ret=%d)\n", sub_dn, ret);
        // 可选：初始化失败时删除已添加的规则（根据业务需求）
        // pthread_rwlock_wrlock(&g_route.lock);
        // g_route.count--;
        // pthread_rwlock_unlock(&g_route.lock);
        return -1;
    }

    printf("[INFO] gw_add_rule: 路由规则添加成功 (dn=%s, 规则总数=%d)\n",
           sub_dn, g_route.count);
    return 0;
}

// 动态删除路由 → 自动销毁客户端
int gw_del_rule(const char *sub_pk, const char *sub_dn, const char *sub_ds) {
    // 1. 入参校验 + 错误日志
    if (sub_pk == NULL || sub_dn == NULL || sub_ds == NULL) {
        fprintf(stderr, "[ERROR] gw_del_rule: 子设备三元组参数为空 (pk=%s, dn=%s, ds=%s)\n",
                sub_pk ? sub_pk : "NULL", sub_dn ? sub_dn : "NULL", sub_ds ? sub_ds : "NULL");
        return -1;
    }
    if (strlen(sub_pk) == 0 || strlen(sub_dn) == 0 || strlen(sub_ds) == 0) {
        fprintf(stderr, "[ERROR] gw_del_rule: 子设备三元组参数为空字符串 (pk=%s, dn=%s, ds=%s)\n",
                sub_pk, sub_dn, sub_ds);
        return -1;
    }

    pthread_rwlock_wrlock(&g_route.lock);
    int idx = -1;
    // 2. 遍历路由表，匹配子设备三元组
    for (int i = 0; i < g_route.count; i++) {
        RouteRule *r = &g_route.rules[i];
        // 严格匹配 pk+dn+ds（ds 可选：如果业务中ds可能加密/截断，可只匹配pk+dn）
        if (strcmp(r->subdev.pk, sub_pk) == 0 &&
            strcmp(r->subdev.dn, sub_dn) == 0 &&
            strcmp(r->subdev.ds, sub_ds) == 0) {
            idx = i;
            printf("[INFO] gw_del_rule: 找到匹配的路由规则 (dn=%s), 开始销毁子设备...\n", sub_dn);
            // 销毁子设备MQTT客户端
            subdev_destroy(&r->subdev);
            break;
        }
    }
    if (idx < 0) {
        fprintf(stderr, "[ERROR] gw_del_rule: 未找到匹配的路由规则 (pk=%s, dn=%s, ds=%s)\n",
                sub_pk, sub_dn, sub_ds);
        pthread_rwlock_unlock(&g_route.lock);
        return -1;
    }
    for (int i = idx; i < g_route.count - 1; i++) {
        g_route.rules[i] = g_route.rules[i + 1];
    }
    g_route.count--;
    pthread_rwlock_unlock(&g_route.lock);
    printf("[INFO] gw_del_rule: 路由规则删除成功 (pk=%s, dn=%s, ds=%s)\n",
           sub_pk, sub_dn, sub_ds);
    return 0;
}

void iot_set_user_service_callback(user_service_cb_t cb)
{
    g_user_service_cb = cb;
}

int gw_ota_report_version(const char *version, const char *module)
{
    if (version == NULL || strlen(version) == 0) {
        fprintf(stderr, "[ERROR] OTA 版本上报失败：version 不能为空\n");
        return -1;
    }

    // 1. 构建阿里云 OTA 版本上报主题
    char ota_report_topic[256];
    snprintf(ota_report_topic, sizeof(ota_report_topic),
             "/ota/device/inform/%s/%s",
             g_gw.pk,
             g_gw.dn);

    // 2. 构建上报 JSON
    cJSON *root = cJSON_CreateObject();
    cJSON_AddNumberToObject(root, "id", 1);

    cJSON *params = cJSON_CreateObject();
    cJSON_AddStringToObject(params, "version", version);

    // module 不传 → 使用 default
    if (module == NULL || strlen(module) == 0) {
        cJSON_AddStringToObject(params, "module", "default");
    } else {
        cJSON_AddStringToObject(params, "module", module);
    }

    cJSON_AddItemToObject(root, "params", params);

    // 转成无格式 JSON 字符串
    char *payload = cJSON_PrintUnformatted(root);
    cJSON_Delete(root);

    if (payload == NULL) {
        fprintf(stderr, "[ERROR] OTA 上报：JSON 生成失败\n");
        return -1;
    }

    // 3. MQTT 发布（QoS=1）
    MQTTAsync_message pubmsg = MQTTAsync_message_initializer;
    pubmsg.payload = payload;
    pubmsg.payloadlen = strlen(payload);
    pubmsg.qos = 1;
    pubmsg.retained = 0;

    int rc = MQTTAsync_sendMessage(g_gw.client, ota_report_topic, &pubmsg, NULL);

    if (rc == MQTTASYNC_SUCCESS) {
        printf("[INFO] OTA 版本上报成功！\n");
        printf("       Topic: %s\n", ota_report_topic);
        printf("       Payload: %s\n", payload);
    } else {
        fprintf(stderr, "[ERROR] OTA 版本上报失败，rc=%d\n", rc);
    }

    free(payload);
    return rc;
}

/**
 * @brief  阿里云 OTA 升级进度上报（2024 最新官方格式）
 * @param  step     字符串类型进度/错误码："10","50","100","-1","-2","-3","-4"
 * @param  desc     状态描述文字，如 "升级中" "下载失败" "校验成功"
 * @param  module   模块名，传 NULL 表示默认 default（可不上报）
 * @return 0成功，-1失败
 */
int gw_ota_report_progress(const char *step, const char *desc, const char *module)
{
    // 入参检查
    if (step == NULL || desc == NULL) {
        fprintf(stderr, "[ERROR] OTA 进度上报：step/desc 不能为空\n");
        return -1;
    }

    // 构建阿里云 OTA 上报主题
    char topic[256];
    snprintf(topic, sizeof(topic),
             "/ota/device/progress/%s/%s",
             g_gw.pk, g_gw.dn);

    // ===================== 2024 阿里云官方 JSON 格式 =====================
    cJSON *root = cJSON_CreateObject();
    cJSON_AddStringToObject(root, "id", "1");  // 官方要求：字符串类型数字

    cJSON *params = cJSON_CreateObject();
    cJSON_AddStringToObject(params, "step", step);
    cJSON_AddStringToObject(params, "desc", desc);

    // module == NULL 或空 → 不上报（官方允许）
    if (module != NULL && strlen(module) > 0) {
        cJSON_AddStringToObject(params, "module", module);
    }

    cJSON_AddItemToObject(root, "params", params);
    char *payload = cJSON_PrintUnformatted(root);
    cJSON_Delete(root);

    if (!payload) {
        fprintf(stderr, "[ERROR] OTA 进度上报：JSON 生成失败\n");
        return -1;
    }

    // MQTT 发布
    MQTTAsync_message msg = MQTTAsync_message_initializer;
    msg.payload = payload;
    msg.payloadlen = strlen(payload);
    msg.qos = 1;

    int rc = MQTTAsync_sendMessage(g_gw.client, topic, &msg, NULL);
    if (rc == MQTTASYNC_SUCCESS) {
        printf("[INFO] OTA 进度上报成功\n");
        printf("       step: %s | desc: %s\n", step, desc);
    } else {
        fprintf(stderr, "[ERROR] OTA 进度上报失败, rc=%d\n", rc);
    }

    free(payload);
    return rc;
}

// 进度上报（内部直接上报阿里云）
static int dl_progress(void *mod, curl_off_t total, curl_off_t now, curl_off_t, curl_off_t)
{
    if (total <= 0) return 0;

    int percent = (now * 100) / total;
    char step[8];
    snprintf(step, sizeof(step), "%d", percent);
    gw_ota_report_progress(step, "下载中", (const char *)mod);
    return 0;
}

// 真正的流式写回调 → 多次调用，每次一段数据
static size_t dl_write_cb(void *data, size_t size, size_t nmemb, void *userp)
{
    size_t real_len = size * nmemb;
    ota_data_cb cb = (ota_data_cb)userp;

    if (cb) cb((const char *)data, real_len);
    return real_len;
}

// ======================
// 单文件流式下载
// ======================
int ota_download_file(const char *url, const char *module, ota_data_cb data_cb)
{
    CURL *curl = curl_easy_init();
    if (!curl) return OTA_DOWNLOAD_ERROR;

    curl_easy_setopt(curl, CURLOPT_URL, url);
    curl_easy_setopt(curl, CURLOPT_FOLLOWLOCATION, 1L);
    curl_easy_setopt(curl, CURLOPT_SSL_VERIFYPEER, 0L);
    curl_easy_setopt(curl, CURLOPT_SSL_VERIFYHOST, 0L);
    curl_easy_setopt(curl, CURLOPT_NOSIGNAL, 1L);
    curl_easy_setopt(curl, CURLOPT_TIMEOUT, 15 * 60);

    // 流式回调
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, dl_write_cb);
    curl_easy_setopt(curl, CURLOPT_WRITEDATA, (void *)data_cb);

    // 进度
    curl_easy_setopt(curl, CURLOPT_XFERINFOFUNCTION, dl_progress);
    curl_easy_setopt(curl, CURLOPT_XFERINFODATA, (void *)module);
    curl_easy_setopt(curl, CURLOPT_NOPROGRESS, 0L);

    CURLcode ret = curl_easy_perform(curl);
    curl_easy_cleanup(curl);

    return (ret == CURLE_OK) ? OTA_DOWNLOAD_OK : OTA_DOWNLOAD_ERROR;
}

// ======================
// 多文件流式下载
// ======================
int ota_download_multi_files(cJSON *files, int file_cnt, const char *module,
                             ota_file_start_cb file_start_cb,
                             ota_data_cb data_cb)
{
    if (!files || file_cnt <= 0) return OTA_DOWNLOAD_ERROR;

    for (int i = 0; i < file_cnt; i++) {
        cJSON *f = cJSON_GetArrayItem(files, i);
        char *name = cJSON_GetStringValue(cJSON_GetObjectItem(f, "fileName"));
        char *url  = cJSON_GetStringValue(cJSON_GetObjectItem(f, "fileUrl"));

        if (!name || !url) continue;

        // 通知用户：新文件开始
        if (file_start_cb) file_start_cb(name, i+1, file_cnt);

        // 流式下载
        if (ota_download_file(url, module, data_cb) != 0) {
            return OTA_DOWNLOAD_ERROR;
        }
    }
    return OTA_DOWNLOAD_OK;
}