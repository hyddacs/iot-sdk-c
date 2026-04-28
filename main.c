#include "gw_sdk.h"
#include <signal.h>

// 置 1 后会在 main() 初始化完成后直接下载下面示例 URL。
// 默认保持 0，避免设备启动时访问无效 URL；真实 OTA 流程由阿里云下发消息触发。
#define ENABLE_OTA_DIRECT_DOWNLOAD_TEST 0

static int running = 1;

// 下面 3 个变量只用于本示例：把 SDK 回调传来的 OTA 数据写入 /tmp 文件。
// 实际网关设备上通常会替换为 flash 分区句柄、升级分区偏移、校验上下文等。
static FILE *g_ota_file = NULL;
static char g_ota_file_path[256] = {0};
static size_t g_ota_file_bytes = 0;

void sig_handle(int s) {
    (void)s;
    running = 0;
}

static void sanitize_file_name(const char *src, char *dst, size_t dst_len)
{
    size_t j = 0;

    if (!src || !dst || dst_len == 0) {
        return;
    }

    // file_name 来自云端 OTA 包，不能直接拼进本地路径。
    // 这里把常见路径/文件名非法字符替换为 '_'，防止 "../" 等路径穿越。
    for (size_t i = 0; src[i] && j + 1 < dst_len; i++) {
        char c = src[i];
        if (c == '/' || c == '\\' || c == ':' || c == '*' ||
            c == '?' || c == '"' || c == '<' || c == '>' || c == '|') {
            c = '_';
        }
        dst[j++] = c;
    }
    dst[j] = '\0';
}

static void close_current_ota_file(void)
{
    // 本示例用 fclose 表示“当前文件已经完整落盘”。
    // 如果是写 flash，这里可以替换为 flush 分区缓存、结束写事务等操作。
    if (g_ota_file) {
        fclose(g_ota_file);
        g_ota_file = NULL;
        printf("[APP OTA] 文件写入完成: %s, bytes=%zu\n", g_ota_file_path, g_ota_file_bytes);
    }
    g_ota_file_bytes = 0;
    g_ota_file_path[0] = '\0';
}

static void app_ota_file_start(const char *file_name, int index, int total)
{
    char safe_name[128] = {0};

    // SDK 在单文件 OTA 时调用一次，在多文件 OTA 时每个文件开始前调用一次。
    // 多文件场景下，用户可以根据 file_name 选择不同 flash 分区或不同存储路径。
    close_current_ota_file();
    sanitize_file_name(file_name ? file_name : "ota.bin", safe_name, sizeof(safe_name));

    // 示例保存到 /tmp，文件名前面带序号，便于区分多文件升级包中的每个文件。
    snprintf(g_ota_file_path, sizeof(g_ota_file_path), "/tmp/ota_%02d_%s", index, safe_name);

    g_ota_file = fopen(g_ota_file_path, "wb");
    if (!g_ota_file) {
        fprintf(stderr, "[APP OTA] 打开OTA存储文件失败: %s\n", g_ota_file_path);
        return;
    }

    printf("[APP OTA] 开始接收文件 %d/%d: file_name=%s, save=%s\n",
           index, total, file_name ? file_name : "unknown", g_ota_file_path);
}

static int app_ota_data_handler(const char *data, size_t len)
{
    // SDK 下载线程每收到一段 HTTP 数据，就会调用一次该函数。
    // data 指针只在本次回调期间有效；如果业务需要异步处理，必须在这里拷贝。
    // 返回 0 表示这段数据处理成功，返回非 0 会让 SDK 中止下载并上报异常。
    if (!g_ota_file) {
        fprintf(stderr, "[APP OTA] OTA数据到达但存储未打开\n");
        return -1;
    }

    // 示例逻辑：写普通文件。真实设备可替换为 flash_write(partition, offset, data, len)。
    if (fwrite(data, 1, len, g_ota_file) != len) {
        fprintf(stderr, "[APP OTA] OTA数据写入失败: %s\n", g_ota_file_path);
        return -1;
    }

    g_ota_file_bytes += len;
    return 0;
}

static int app_ota_file_finish(const char *file_name, int index, int total)
{
    // SDK 在一个文件所有数据下载完成后调用该函数。
    // SDK 会先按云端下发的 fileSize/fileMd5/fileSign 做下载完整性校验；
    // 进入这里表示“下载数据本身”已经通过 SDK 校验。
    // 用户仍应在这里确认 flash 写事务结束、分区切换标记写入、镜像可启动等业务结果。
    printf("[APP OTA] 文件接收完成 %d/%d: file_name=%s\n",
           index, total, file_name ? file_name : "unknown");
    close_current_ota_file();

    // 返回非 0 时，SDK 会上报 -4（烧录/业务处理失败），并且不会上报最新版本号。
    return 0;
}

static void app_ota_notify_handler(char *module, char *version, char *signMethod,
                                   int isDiff, char *fileUrl, char *fileSign,
                                   char *fileMd5, int fileSize,
                                   cJSON *files, int fileCount)
{
    // SDK 解析到 OTA 升级通知后，会先调用该回调，把升级元信息交给用户。
    // 注意：这个回调用于查看任务信息；真正的下载数据在 app_ota_data_handler() 中处理。
    printf("[APP OTA] 收到升级任务: module=%s, version=%s, signMethod=%s, isDiff=%d\n",
           module ? module : "default",
           version ? version : "unknown",
           signMethod ? signMethod : "unknown",
           isDiff);

    if (fileUrl) {
        // 单文件 OTA：fileUrl 有值，files 为 NULL。
        printf("[APP OTA] 单文件: url=%s, size=%d, sign=%s, md5=%s\n",
               fileUrl,
               fileSize,
               fileSign ? fileSign : "",
               fileMd5 ? fileMd5 : "");
        return;
    }

    // 多文件 OTA：fileUrl 为 NULL，files 是数组。
    // 这里仅打印文件清单；每个文件真正开始下载时还会触发 app_ota_file_start()。
    printf("[APP OTA] 多文件数量: %d\n", fileCount);
    for (int i = 0; files && i < fileCount; i++) {
        cJSON *file = cJSON_GetArrayItem(files, i);
        const char *name = cJSON_GetStringValue(cJSON_GetObjectItem(file, "fileName"));
        const char *url = cJSON_GetStringValue(cJSON_GetObjectItem(file, "fileUrl"));
        cJSON *size_item = cJSON_GetObjectItem(file, "fileSize");

        if (!url) {
            url = cJSON_GetStringValue(cJSON_GetObjectItem(file, "url"));
        }
        if (!size_item) {
            size_item = cJSON_GetObjectItem(file, "size");
        }

        printf("[APP OTA]   file[%d]: name=%s, size=%d, url=%s\n",
               i + 1,
               name ? name : "unknown",
               cJSON_IsNumber(size_item) ? size_item->valueint : 0,
               url ? url : "null");
    }
}

static void register_ota_callbacks(void)
{
    // OTA任务元信息回调：拿到 version/module/url/files 等信息。
    gw_register_ota_callback(app_ota_notify_handler);

    // 文件开始回调：为单个文件选择/打开存储位置。
    gw_register_ota_file_start_callback(app_ota_file_start);

    // 文件完成回调：关闭存储、校验或确认烧录结果。
    gw_register_ota_file_finish_callback(app_ota_file_finish);

    // 数据块回调：SDK下载到的数据只进入该 handler，不在 SDK 内部落盘。
    gw_register_ota_data_callback(app_ota_data_handler);
}

#if ENABLE_OTA_DIRECT_DOWNLOAD_TEST
static void run_ota_direct_download_examples(void)
{
    // 直连下载示例只用于理解接口，不模拟阿里云 MQTT 下发。
    // 使用前请替换为真实可访问的固件 URL，并把 ENABLE_OTA_DIRECT_DOWNLOAD_TEST 改为 1。
    const char *single_url = "https://example.com/firmware/gateway_v1.2.3.bin";
    const char *multi_files_json =
        "["
        "{\"fileName\":\"app.bin\",\"fileUrl\":\"https://example.com/firmware/app.bin\",\"fileSize\":1048576},"
        "{\"fileName\":\"config.bin\",\"fileUrl\":\"https://example.com/firmware/config.bin\",\"fileSize\":131072}"
        "]";

    printf("[APP OTA TEST] 单文件URL示例: %s\n", single_url);

    // 直连测试不会经过 SDK 的 OTA 任务解析线程，所以这里手动调用 file_start/file_finish。
    app_ota_file_start("gateway_v1.2.3.bin", 1, 1);
    if (ota_download_file(single_url, "default", app_ota_data_handler) == OTA_DOWNLOAD_OK &&
        app_ota_file_finish("gateway_v1.2.3.bin", 1, 1) == 0) {
        gw_ota_report_version("1.2.3", "default");
    }

    cJSON *files = cJSON_Parse(multi_files_json);
    if (files) {
        // 多文件直连测试复用 SDK 的 ota_download_multi_files()。
        // SDK 会按总 fileSize 计算总进度，并逐个触发 file_start/file_finish。
        printf("[APP OTA TEST] 多文件URL示例: %s\n", multi_files_json);
        if (ota_download_multi_files(files, cJSON_GetArraySize(files), "default",
                                     app_ota_file_start, app_ota_data_handler) == OTA_DOWNLOAD_OK) {
            gw_ota_report_version("1.2.3", "default");
        }
        cJSON_Delete(files);
    }
}
#endif

int main() {
    signal(SIGINT, sig_handle);
    //1. 配置文件初始化，包括配置文件读取、解析、创建路由规则、客户端创建、下行指令订阅
    //"gw_route.cfg"为项目文件夹下的配置文件
    if (gw_init("gw_route.cfg") != 0) {
        printf("gw_init failed\n");
        return -1;
    }

    // OTA测试：注册用户回调。真实OTA任务从阿里云下发后，SDK会单开线程执行下载。
    register_ota_callbacks();

#if ENABLE_OTA_DIRECT_DOWNLOAD_TEST
    // 本地直连下载测试：把上面的URL替换成真实OTA包地址，再将宏改为1。
    run_ota_direct_download_examples();
#endif

    //2. 云平台测试下行指令
    int ssss=0;
    while (running) {
        printf("a");
        //3， 模拟数据来源
        const char *json ;
        if(ssss%2==0)
        {
        json=
        "{\"allowedTemp\":0.0,\"device_code\":\"123456789\","
        "\"device_id\":\"40703436630002\",\"device_temp\":0.0,"
        "\"device_time\":\"2025-05-16 10:46:22\",\"env_humi\":0.0,"
        "\"env_tempe\":0.0,\"fault_alarm\":\"\",\"left1_dwell\":1.0,"
        "\"left2_dwell\":0.0,\"operator_id\":\"ABCDE\","
        "\"process_spec\":\"WPS 21-GXGL-01\",\"project_id\":\"ABCDE\","
        "\"right1_dwell\":2.0,\"right2_dwell\":0.0,\"station_id\":\"0708\","
        "\"swing1_freq\":10,\"swing1_width\":20.0,\"swing2_freq\":0,"
        "\"swing2_width\":0.0,\"timestampSec\":1747392382,\"timestampUsec\":476425,"
        "\"torch1_current\":249.66761779785156,\"torch1_switch\":1,"
        "\"torch1_voltage\":30.939964294433594,\"torch2_current\":0.0,"
        "\"torch2_switch\":0,\"torch2_voltage\":0.0,\"trackNameTorch1\":\"HW\","
        "\"trackNameTorch2\":\"HW\",\"unit_id\":\"XG-JS-01\",\"weld_angle\":2.0,"
        "\"weld_direction\":0,\"weld_joint\":\"XG-PIPECODE-001\","
        "\"weld_layer\":\"HW\",\"weld_process\":\"weld_process\","
        "\"weld_speed\":0.0,\"weld_temp\":0.0,\"wirefeed1_speed\":11.0,"
        "\"wirefeed2_speed\":0.0}";
        }
        else
        {
            json=
            "{\"RoomTemp\":1.0,\"uid\":\"aa\"}";
        }
        //4. 根据原始数据及路由规则获取设备名
        const char *name = gw_route_match(json);
        if (name) {
            //5. 构建阿里云格式数据
            char *alink = build_alink_payload(json);
            //6. 根据设备名在SDK内部加锁查找并发送，避免动态删路由时拿到失效指针。
            if (alink) {
                gw_publish_subdev_by_name(name, alink);
                free(alink);
            }
        }else
        {
            printf("未找到设备\n");
        }
        sleep(1);
        ++ssss;
    }
    close_current_ota_file();
    //8.销毁客户端，释放资源
    gw_destroy();
    return 0;
}
