#include "gw_sdk.h"
#include <signal.h>

static volatile sig_atomic_t running = 1;

// 下面 3 个变量只用于本示例：把 SDK 回调传来的 OTA 数据写入当前目录。
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

    // 示例保存到当前程序运行目录，文件名前面带序号，便于区分多文件升级包中的每个文件。
    snprintf(g_ota_file_path, sizeof(g_ota_file_path), "./ota_%02d_%s", index, safe_name);

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
        // 单文件 OTA，或平台把“多文件升级包”打成一个 zip 后下发的场景：
        // fileUrl/url 有值，files 为 NULL，SDK 会把该 URL 当成一个完整升级包下载。
        printf("[APP OTA] 单个升级包文件: url=%s, size=%d, sign=%s, md5=%s\n",
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

int main() {
    signal(SIGINT, sig_handle);

    // 先注册 OTA 回调，再初始化网关。
    // gw_init() 会订阅 OTA 主题；如果回调注册放在 gw_init() 后面，
    // OTA 消息可能先到，导致 SDK 因缺少数据处理回调而上报失败。
    register_ota_callbacks();

    //1. 配置文件初始化，包括配置文件读取、解析、创建路由规则、客户端创建、下行指令订阅
    //"gw_route.cfg"为项目文件夹下的配置文件
    if (gw_init("gw_route.cfg") != 0) {
        printf("gw_init failed\n");
        return -1;
    }

    // 启动后先上报当前版本。平台看到当前版本为 1.0.0 后，才会判断是否需要下发 2.0.0 OTA任务。
    gw_ota_report_version("5.0.0", "default");

    // 主线程必须保持运行，才能持续接收阿里云下发的 OTA 消息。
    // 按 Ctrl+C 后会跳出循环，退出前再等待正在执行的 OTA 任务结束。
    while (running) {
        sleep(1);
    }
    if (gw_ota_is_busy()) {
        printf("[APP OTA] 检测到OTA任务仍在执行，等待完成后再退出...\n");
        gw_ota_wait_complete(-1);
    }

    close_current_ota_file();
    //8.销毁客户端，释放资源
    gw_destroy();
    return 0;
}
