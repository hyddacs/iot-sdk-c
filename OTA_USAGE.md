# OTA升级使用说明

本文说明本SDK在网关设备上处理阿里云物联网平台下行任务及OTA升级任务的流程。SDK负责订阅OTA任务、下载升级包、校验下载内容、上报进度和版本；升级包数据如何保存、烧录、解包和切换分区由用户回调函数完成。

## 1. 启动顺序

推荐主程序按以下顺序启动：

```c
register_ota_callbacks();
register_user_service_callback();

if (gw_init("gw_route.cfg") != 0) {
    return -1;
}

gw_ota_report_version("1.0.0", "default");

while (running) {
    sleep(1);
}

if (gw_ota_is_busy()) {
    gw_ota_wait_complete(-1);
}

gw_destroy();
```

注意事项：

- OTA回调必须在`gw_init()`之前注册。`gw_init()`会订阅OTA下行Topic，如果先初始化再注册回调，极端情况下可能收到OTA任务但数据回调尚未设置。
- 用户服务回调也建议在`gw_init()`之前注册。`gw_init()`订阅属性设置服务Topic后，云端服务调用会进入该回调。
- 启动后应先上报当前版本，例如`1.0.0`。SDK内部会避免在首次版本上报成功前启动OTA处理线程；如果平台提前下发OTA任务，SDK会先缓存任务，版本上报成功后再处理。
- 主线程不能在版本上报后立即退出。OTA任务在线程中执行，程序退出前应调用`gw_ota_is_busy()`和`gw_ota_wait_complete(-1)`等待任务完成。

## 1.1 下行指令异步处理模型

SDK收到阿里云平台下行消息后，`gw_on_message()`只负责快速解析、分类和投递任务，不在MQTT消息回调线程中执行耗时业务。

当前异步处理范围：

| 下行类型 | 处理方式 |
| --- | --- |
| `thing.service.add_rule` | 投递到动态路由添加线程，后台执行`gw_add_rule()` |
| `thing.service.del_rule` | 投递到动态路由删除线程，后台执行`gw_del_rule()` |
| 自定义服务调用 | 投递到用户服务线程，后台执行`user_service_cb_t`回调 |
| OTA升级通知 | 投递到OTA任务线程，后台下载、校验和调用OTA用户回调 |

因此，云端下发指令不会再因为初始化/销毁子设备MQTT客户端、用户自定义业务处理、OTA下载等耗时操作阻塞MQTT消息回调线程。动态路由内部也避免在持有路由表锁时执行子设备MQTT连接或销毁，降低对上报线程的影响。

## 2. 必须注册的用户回调

`main.c`中的示例注册了4个OTA回调：

```c
gw_register_ota_callback(app_ota_notify_handler);
gw_register_ota_file_start_callback(app_ota_file_start);
gw_register_ota_file_finish_callback(app_ota_file_finish);
gw_register_ota_data_callback(app_ota_data_handler);
```

各回调职责如下：

| 回调 | 触发时机 | 用户职责 |
| --- | --- | --- |
| `ota_callback_t` | SDK解析到OTA任务元信息后 | 查看版本、模块、URL、文件大小、签名、文件列表等信息 |
| `ota_file_start_cb` | 单个文件开始下载前 | 打开本地文件、flash分区或写入上下文 |
| `ota_data_cb` | 每收到一段升级包数据 | 立即写文件、写flash、计算业务校验或拷贝数据 |
| `ota_file_finish_cb` | 单个文件下载且SDK校验通过后 | 关闭存储、确认烧录结果、设置启动标志 |

`ota_data_cb`返回`0`表示继续下载，返回非0表示用户处理失败，SDK会中止OTA并上报异常。

## 2.1 用户服务回调示例

SDK通过`iot_set_user_service_callback()`注册云端服务调用回调。回调原型如下：

```c
typedef int (*user_service_cb_t)(const char *topic,
                                 const char *method,
                                 const char *params_json);
```

推荐在`gw_init()`之前注册：

```c
static int app_user_service_handler(const char *topic,
                                    const char *method,
                                    const char *params_json)
{
    printf("[APP SERVICE] topic=%s, method=%s, params=%s\n",
           topic ? topic : "",
           method ? method : "",
           params_json ? params_json : "{}");

    if (method && strcmp(method, "？？？") == 0) {
        printf("[APP SERVICE] handle echo: %s\n", params_json ? params_json : "{}");
        return 0;
    }

    return 0;
}

static void register_user_service_callback(void)
{
    iot_set_user_service_callback(app_user_service_handler);
}
```

返回值语义：

- 回调在线程中异步执行，返回值只用于SDK日志记录。
- 返回值不再决定是否拦截SDK内置逻辑。
- `thing.service.add_rule`和`thing.service.del_rule`由SDK内置动态路由逻辑优先处理，不经过用户服务回调拦截。

云端下发自定义服务时，`params_json`是`params`对象的紧凑JSON字符串。业务代码可以在回调中解析参数、控制本地硬件、转发到业务线程或记录日志。该回调已经不在MQTT消息回调线程中执行，耗时业务不会阻塞SDK接收后续下行消息。

## 3. 支持的OTA下发格式

### 3.1 HTTP/HTTPS单URL升级包

阿里云下发示例：

```json
{
  "code": "1000",
  "data": {
    "size": 84,
    "sign": "54d6ff5a205596db57161705764eeb1b",
    "version": "2.0.0",
    "signMethod": "Md5",
    "url": "https://ota-cn-shanghai.iot-thing.aliyuncs.com/ota/xxx/file.dav?auth_key=...",
    "md5": "54d6ff5a205596db57161705764eeb1b"
  },
  "id": 1777439217705,
  "message": "success"
}
```

SDK处理流程：

1. 校验`code`为`1000`。
2. 读取`version`、`signMethod`、`url`、`size`、`sign`、`md5`。
3. 开启OTA线程下载`url`。
4. 每收到一段HTTP数据，调用用户`ota_data_cb`。
5. 下载完成后校验文件大小和MD5/SHA256。
6. 调用`ota_file_finish_cb`。
7. 上报进度`100`，然后上报新版本号。

如果下发消息没有`fileName`字段，SDK会从URL路径里提取文件名。例如：

```text
.../cmojlc0cu00083ja0knh5grcp.dav?auth_key=...
```

保存示例文件名为：

```text
./ota_01_cmojlc0cu00083ja0knh5grcp.dav
```

### 3.2 多文件升级包被平台打成zip

有些阿里云多文件升级包不会下发`files`数组，而是下发一个zip文件URL：

```json
{
  "code": "1000",
  "data": {
    "size": 471,
    "extData": {
      "_package_udi": "测试包"
    },
    "sign": "348e8af5273bbf95607c6fb20d9ea947",
    "version": "2.0.0",
    "signMethod": "Md5",
    "url": "https://ota-cn-shanghai.iot-thing.aliyuncs.com/ota/xxx/package.zip?auth_key=...",
    "md5": "348e8af5273bbf95607c6fb20d9ea947"
  }
}
```

这种格式对设备侧来说仍然是“单个升级包文件”。SDK会下载整个zip并校验。是否解压zip、识别其中多个固件文件、分别写入不同分区，由用户在`ota_file_finish_cb`或业务逻辑中处理。

### 3.3 files数组多文件格式

SDK也兼容带`files`数组的多文件格式：

```json
{
  "code": "1000",
  "data": {
    "version": "2.0.0",
    "signMethod": "Md5",
    "files": [
      {
        "fileName": "app.bin",
        "fileUrl": "https://example.com/app.bin",
        "fileSize": 1048576,
        "fileMd5": "..."
      },
      {
        "fileName": "config.bin",
        "fileUrl": "https://example.com/config.bin",
        "fileSize": 131072,
        "fileMd5": "..."
      }
    ]
  }
}
```

SDK会逐个下载文件，并按所有文件总大小计算总进度。用户可在`ota_file_start_cb(file_name, index, total)`中根据`file_name`选择不同存储地址。

## 4. MQTT协议下载OTA升级包

阿里云也可能下发MQTT协议OTA任务：

```json
{
  "code": "1000",
  "data": {
    "size": 84,
    "streamId": 27367,
    "extData": {
      "_package_udi": "MQTT测试"
    },
    "sign": "54d6ff5a205596db57161705764eeb1b",
    "dProtocol": "mqtt",
    "version": "3.0.0",
    "signMethod": "Md5",
    "streamFileId": 1,
    "md5": "54d6ff5a205596db57161705764eeb1b"
  },
  "id": 1777442726391,
  "message": "success"
}
```

SDK识别到`dProtocol`为`mqtt`后，会使用以下Topic分片下载文件：

```text
请求Topic：/sys/${productKey}/${deviceName}/thing/file/download
响应Topic：/sys/${productKey}/${deviceName}/thing/file/download_reply
```

SDK会自动订阅`download_reply`响应Topic，并按`streamId`、`streamFileId`、`offset`、`size`循环请求分片。

请求格式示例：

```json
{
  "id": "123456",
  "version": "1.0",
  "params": {
    "fileInfo": {
      "streamId": 27367,
      "fileId": 1
    },
    "fileBlock": {
      "size": 4096,
      "offset": 0
    }
  }
}
```

响应Payload为二进制结构：

```text
2字节JSON长度（大端）
JSON字符串
文件分片数据
2字节CRC16/IBM（低字节在前）
```

SDK处理内容：

- 校验响应`id`是否匹配当前请求。
- 校验平台返回`code == 200`。
- 校验`bOffset`、`bSize`和实际分片长度。
- 校验分片CRC16/IBM。
- 将分片数据送入用户`ota_data_cb`。
- 所有分片下载完成后，继续做总大小和MD5/SHA256校验。

## 5. MQTT OTA文件名处理说明

HTTP/HTTPS OTA通常有URL，SDK可以从URL中解析文件名。

MQTT OTA下发消息只有`streamId`、`streamFileId`、`size`、`md5/sign`等字段，通常没有URL，也不一定有`fileName`字段。因此SDK无法可靠解析真实文件名。

当前SDK默认使用：

```text
mqtt_ota.bin
```

示例程序会保存为：

```text
./ota_01_mqtt_ota.bin
```

推荐使用者在业务代码中自定义文件名，例如：

- 根据目标版本命名：`gateway_3.0.0.bin`
- 根据模块命名：`default_3.0.0.bin`
- 根据`streamId`命名：`mqtt_ota_27367_1.bin`
- 根据业务分区命名：`app_partition.bin`

如果需要按版本号命名，可以在`app_ota_notify_handler()`中保存全局版本号，然后在`app_ota_file_start()`中使用该版本号生成保存路径。

示例思路：

```c
static char g_ota_version[32] = "unknown";

static void app_ota_notify_handler(char *module, char *version, ...)
{
    snprintf(g_ota_version, sizeof(g_ota_version), "%s", version ? version : "unknown");
}

static void app_ota_file_start(const char *file_name, int index, int total)
{
    if (file_name && strcmp(file_name, "mqtt_ota.bin") == 0) {
        snprintf(g_ota_file_path, sizeof(g_ota_file_path),
                 "./ota_%02d_gateway_%s.bin", index, g_ota_version);
    } else {
        snprintf(g_ota_file_path, sizeof(g_ota_file_path),
                 "./ota_%02d_%s", index, file_name ? file_name : "ota.bin");
    }
}
```

## 6. 进度和版本上报

SDK会自动上报OTA进度：

- 开始下载：`0`
- 下载过程中：按总进度上报，内部做了节流，避免频繁上报
- 下载成功：`100`
- 下载失败：`-2`
- 校验失败：`-3`
- 用户数据处理或烧录失败：`-4`

SDK在所有文件下载、校验、用户`file_finish`回调成功后，才会上报新版本号：

```c
gw_ota_report_version(version, module);
```

对于需要重启后才真正生效的设备，可以把“上报新版本号”的时机调整到重启后的启动流程中。当前示例为了演示完整OTA流程，在下载完成后立即上报新版本。

## 7. 用户回调保存文件示例

当前`main.c`示例把下载到的数据保存到当前目录：

```c
snprintf(g_ota_file_path, sizeof(g_ota_file_path), "./ota_%02d_%s", index, safe_name);
g_ota_file = fopen(g_ota_file_path, "wb");
```

每段数据到达时写文件：

```c
fwrite(data, 1, len, g_ota_file);
```

真实网关设备上通常应替换为：

- 写升级分区
- 写外部Flash
- 写临时文件后解包
- 写多个固件文件到不同地址
