# OTA升级使用说明

本文说明本SDK在网关设备上处理阿里云物联网平台OTA升级任务的流程。SDK负责订阅OTA任务、下载升级包、校验下载内容、上报进度和版本；升级包数据如何保存、烧录、解包和切换分区由用户回调函数完成。

## 1. 启动顺序

推荐主程序按以下顺序启动：

```c
register_ota_callbacks();

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
- 启动后应先上报当前版本，例如`1.0.0`。SDK内部会避免在首次版本上报成功前启动OTA处理线程；如果平台提前下发OTA任务，SDK会先缓存任务，版本上报成功后再处理。
- 主线程不能在版本上报后立即退出。OTA任务在线程中执行，程序退出前应调用`gw_ota_is_busy()`和`gw_ota_wait_complete(-1)`等待任务完成。

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

## 8. 常见问题

### 8.1 程序启动后立即退出

主线程必须持续运行，否则收不到OTA下行消息。示例中使用：

```c
while (running) {
    sleep(1);
}
```

退出前应等待OTA完成：

```c
if (gw_ota_is_busy()) {
    gw_ota_wait_complete(-1);
}
```

### 8.2 重复收到OTA升级消息

阿里云可能重复下发OTA任务。SDK已有保护：如果当前OTA任务正在执行，后续重复通知会被确认并忽略，不会重复启动下载线程。

### 8.3 MQTT回调Topic变成异常字符串

Paho的`messageArrived`回调返回值必须遵守约定：释放`message/topic`后必须返回`1`。返回`0`会触发Paho重新投递同一消息，若此时已经释放内存，会出现Topic或Payload异常。SDK已统一修复为释放后返回`1`。

### 8.4 HTTP OTA下载走了本地代理

如果环境变量配置了代理，libcurl可能尝试访问`127.0.0.1:7890`等代理地址。SDK已设置：

```c
curl_easy_setopt(curl, CURLOPT_PROXY, "");
```

避免OTA下载被环境代理劫持。

### 8.5 HTTPS证书问题

SDK默认启用TLS证书校验：

```c
CURLOPT_SSL_VERIFYPEER = 1
CURLOPT_SSL_VERIFYHOST = 2
```

如果设备没有CA证书环境，HTTPS下载可能失败。正式设备应安装CA证书，不建议关闭校验。
