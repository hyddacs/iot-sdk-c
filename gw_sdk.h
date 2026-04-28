#ifndef GW_SDK_H
#define GW_SDK_H

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <pthread.h>
#include <stdint.h>
#include <curl/curl.h>
#include "MQTTAsync.h"
#include "cJSON.h"

#define MAX_ROUTE_RULES          64
#define PRODUCTKEY_MAXLEN       32
#define DEVICENAME_MAXLEN       32
#define DEVICESECRET_MAXLEN     64
#define SIGN_SOURCE_MAXLEN      256
#define PASSWORD_MAXLEN         65

// 下载结果
#define OTA_DOWNLOAD_OK      0
#define OTA_DOWNLOAD_ERROR  -1


typedef enum {
    RULE_NUM,
    RULE_STR
} RuleType;

typedef union {
    int num;
    char str[64];
} RuleValue;

typedef struct {
    char pk[PRODUCTKEY_MAXLEN];
    char dn[DEVICENAME_MAXLEN];
    char ds[DEVICESECRET_MAXLEN];
    MQTTAsync client;
    int connected;
} SubDevice;

typedef struct {
    RuleType type;
    char key[32];
    RuleValue val;
    SubDevice subdev;
} RouteRule;

typedef struct {
    RouteRule rules[MAX_ROUTE_RULES];
    int count;
    pthread_rwlock_t lock;
} RouteTable;

typedef struct {
    char pk[PRODUCTKEY_MAXLEN];
    char dn[DEVICENAME_MAXLEN];
    char ds[DEVICESECRET_MAXLEN];
    char broker[128];
    MQTTAsync client;
    int connected;
} Gateway;

// 新增：服务调用 自定义回调函数类型
typedef int (*user_service_cb_t)(const char *topic, const char *method, const char *params_json);

// OTA 升级通知回调。SDK 只解析升级元信息，下载后的数据处理由用户回调完成。
typedef void (*ota_callback_t)(
    char *module,
    char *version,
    char *signMethod,
    int isDiff,
    char *fileUrl,      // 单文件URL（多文件为NULL）
    char *fileSign,
    char *fileMd5,
    int fileSize,
    cJSON *files,       // 多文件数组（单文件为NULL）
    int fileCount       // 文件数量
);

// OTA 下载数据回调（流式）。
// SDK 不保存文件；每次收到一段下载数据，就把缓冲区指针和长度交给用户处理。
// data 只在回调期间有效，用户需要在回调内完成写 flash、写文件、校验或拷贝。
// 返回 0 表示继续下载，返回非 0 表示用户处理失败并中止下载。
typedef int (*ota_data_cb)(const char *data, size_t len);

// 多文件开始通知
typedef void (*ota_file_start_cb)(const char *file_name, int index, int total);
typedef int (*ota_file_finish_cb)(const char *file_name, int index, int total);

/**
 * @brief 网关核心初始化函数
 * @details 加载网关配置文件、初始化路由表读写锁、创建网关MQTT客户端、订阅下行主题、初始化子设备管理模块
 * @param cfg_path 配置文件路径（如 "./gateway.conf"）
 * @return 0=初始化成功，-1=初始化失败（配置文件错误/MQTT创建失败等）
 * @note 程序启动时需在主线程调用，且仅调用一次
 */
int gw_init(const char *cfg_path);

/**
 * @brief 网关资源销毁函数
 * @details 销毁所有子设备MQTT客户端、断开网关MQTT连接、释放路由表读写锁、清空路由规则
 * @note 程序退出前必须调用，确保资源完全释放，避免内存泄漏
 */
void gw_destroy(void);

// 路由匹配
/**
 * @brief 根据上报JSON数据匹配路由规则
 * @details 解析上报JSON，遍历路由表匹配key+val，返回对应的子设备deviceName
 * @param json 设备上报的原始JSON字符串（如 {"device_id":"sensor_002","temp":26}）
 * @return 匹配成功返回子设备dn（内部静态指针，无需free），NULL=无匹配规则/JSON解析失败
 * @note 内部加路由表读锁，多线程安全
 */
const char *gw_route_match(const char *json);

/**
 * @brief 根据子设备名(dn)查找对应的SubDevice结构体
 * @details 遍历路由表，按dn精确匹配子设备信息（包含MQTT客户端、连接状态、三元组等）
 * @param dn 子设备DeviceName（如 "sub_device_2"）
 * @return 成功返回SubDevice*（路由表内部指针，无需free），NULL=未找到匹配设备
 * @note 内部加路由表读锁，多线程安全
 */
SubDevice *gw_get_subdev_by_name(const char *dn);

// 发布
/**
 * @brief 构建阿里云Alink协议格式的上报payload
 * @details 将原始JSON转换为符合阿里云物模型标准的上报格式（{"id":"xxx","params":{...},"version":"1.0"}）
 * @param raw_json 原始业务数据JSON字符串
 * @return 成功返回Alink格式JSON字符串（需手动free），NULL=构建失败
 * @note 返回值必须调用free释放，避免内存泄漏
 */
char *build_alink_payload(const char *raw_json);

/**
 * @brief 使用子设备独立MQTT客户端上行消息到阿里云
 * @details 构造子设备专属上报主题，以QoS1级别发布消息，确保消息可靠送达
 * @param subdev 子设备结构体指针（需已初始化并连接）
 * @param payload Alink格式的上报JSON字符串
 * @return 0=发布成功，非0=MQTT错误码（-1=参数错误/-3=未连接等）
 * @note 需确保subdev->connected=1，否则直接返回失败
 */
int gw_publish_subdev(SubDevice *subdev, const char *payload);
int gw_publish_subdev_by_name(const char *dn, const char *payload);

// 动态增删路由
/**
 * @brief 动态添加路由规则，并自动初始化子设备MQTT客户端
 * @details 加路由表写锁，将规则添加到路由表，同步创建子设备独立MQTT客户端并连接阿里云
 * @param type 规则类型（RULE_NUM=数值匹配/RULE_STR=字符串匹配）
 * @param key 匹配字段名（如 "device_id"）
 * @param val 匹配字段值（如 "sensor_002"）
 * @param sub_pk 子设备ProductKey
 * @param sub_dn 子设备DeviceName
 * @param sub_ds 子设备DeviceSecret
 * @return 0=添加成功，-1=失败（规则超限/参数错误/子设备初始化失败等）
 * @note 自动去重，同一子设备dn不会重复添加
 */
int gw_add_rule(RuleType type, const char *key, const char *val,
                const char *sub_pk, const char *sub_dn, const char *sub_ds);

/**
 * @brief 按子设备三元组删除路由规则
 * @details 加路由表写锁，匹配三元组找到对应规则，销毁子设备MQTT客户端并从路由表删除规则
 * @param sub_pk 子设备ProductKey
 * @param sub_dn 子设备DeviceName
 * @param sub_ds 子设备DeviceSecret
 * @return 0=删除成功，-1=失败（未找到匹配规则/锁操作失败等）
 * @note 优先匹配sub_pk+sub_dn，sub_ds作为辅助校验
 */
int gw_del_rule(const char *sub_pk, const char *sub_dn, const char *sub_ds);

// 子设备连接
/**
 * @brief 初始化子设备MQTT客户端并连接阿里云
 * @details 根据子设备三元组生成MQTT连接参数，创建客户端并建立连接
 * @param subdev 子设备结构体指针（需已填充pk/dn/ds）
 * @return 0=初始化并连接成功，-1=失败（签名错误/连接超时等）
 * @note 连接成功后subdev->connected会置1
 */
int subdev_init(SubDevice *subdev);

/**
 * @brief 销毁子设备MQTT客户端
 * @details 断开子设备MQTT连接，销毁客户端资源，重置连接状态
 * @param subdev 子设备结构体指针
 * @note 未连接的子设备调用仅打印警告，不会报错
 */
void subdev_destroy(SubDevice *subdev);

// 你原始 JSON 函数（全部保留）
/**
 * @brief 向JSON中添加/修改字符串字段
 * @details 解析原始JSON，删除同名字段后添加新字符串字段，返回新JSON字符串
 * @param json 原始JSON字符串（NULL则创建新对象）
 * @param key 字段名
 * @param val 字段值（字符串）
 * @return 成功返回新JSON字符串（需手动free），NULL=失败
 * @note 返回值必须调用free释放，避免内存泄漏
 */
char *json_set_str(const char *json, const char *key, const char *val);

/**
 * @brief 向JSON中添加/修改数字字段
 * @details 解析原始JSON，删除同名字段后添加新数字字段，返回新JSON字符串
 * @param json 原始JSON字符串（NULL则创建新对象）
 * @param key 字段名
 * @param val 字段值（整数）
 * @return 成功返回新JSON字符串（需手动free），NULL=失败
 * @note 返回值必须调用free释放，避免内存泄漏
 */
char *json_set_int(const char *json, const char *key, int val);

/**
 * @brief 从JSON中删除指定字段
 * @details 解析原始JSON，删除指定字段后返回新JSON字符串
 * @param json 原始JSON字符串
 * @param key 要删除的字段名
 * @return 成功返回新JSON字符串（需手动free），NULL=JSON解析失败
 * @note 字段不存在时仍返回原始JSON（无需free原始JSON）
 */
char *json_del_key(const char *json, const char *key);

/**
 * @brief 从JSON中读取字符串字段
 * @details 解析JSON并提取指定字符串字段的值到输出缓冲区
 * @param json 原始JSON字符串
 * @param key 字段名
 * @param out 输出缓冲区（存储提取的字符串）
 * @param len 输出缓冲区长度
 * @return 0=提取成功，-1=失败（字段不存在/类型错误等）
 * @note 自动在缓冲区末尾添加结束符，防止溢出
 */
int json_get_str(const char *json, const char *key, char *out, int len);

/**
 * @brief 从JSON中读取数字字段
 * @details 解析JSON并提取指定数字字段的值到输出指针
 * @param json 原始JSON字符串
 * @param key 字段名
 * @param out 输出指针（存储提取的整数）
 * @return 0=提取成功，-1=失败（字段不存在/类型错误等）
 * @note 仅支持整数类型，浮点数会被截断
 */
int json_get_int(const char *json, const char *key, int *out);

// 全局注册自定义服务回调，外部用户可调用
void iot_set_user_service_callback(user_service_cb_t cb);

// 注册 OTA 回调
void gw_register_ota_callback(ota_callback_t cb);
void gw_register_ota_data_callback(ota_data_cb cb);
void gw_register_ota_file_start_callback(ota_file_start_cb cb);
void gw_register_ota_file_finish_callback(ota_file_finish_cb cb);

/**
 * @brief 上报当前设备 OTA 版本到阿里云 IoT 平台
 * @param version  当前固件版本号（必填，如 "1.0.0"）
 * @param module   模块名（可选，传 NULL / 空串 则使用默认 "default"）
 */
int gw_ota_report_version(const char *version, const char *module);


/**
 * @brief  阿里云 OTA 升级进度上报（2024 最新官方格式）
 * @param  step     字符串类型进度/错误码："10","50","100","-1","-2","-3","-4"。-1：升级失败。-2：下载失败。-3：校验失败。-4：烧写失败。
 * @param  desc     状态描述文字，如 "升级中" "下载失败" "校验成功"
 * @param  module   模块名，传 NULL 表示默认 default（可不上报）
 * @return 0成功，-1失败
 */
int gw_ota_report_progress(const char *step, const char *desc, const char *module);
int gw_ota_report_progress_percent(int percent, const char *desc, const char *module);

// ==============================
//  单文件下载（流式）
// ==============================
int ota_download_file(const char *url, const char *module, ota_data_cb data_cb);

// ==============================
//  多文件下载（流式）
// ==============================
int ota_download_multi_files(cJSON *files, int file_cnt, const char *module,
                             ota_file_start_cb file_start_cb,
                             ota_data_cb data_cb);
#endif
