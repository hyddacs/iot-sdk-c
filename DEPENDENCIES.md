# 依赖库说明

本文档说明本项目编译和运行依赖的主要第三方库、用途、链接参数和源码地址。

## 编译命令中的依赖

当前`Makefile`使用：

```make
LDFLAGS = -lpaho-mqtt3a -lcurl -lpthread
```

| 依赖 | 项目中用途 | 头文件/库 | GitHub地址 |
| --- | --- | --- | --- |
| Eclipse Paho MQTT C | MQTT异步客户端，连接阿里云IoT、订阅Topic、发布上报和OTA消息 | `MQTTAsync.h` / `-lpaho-mqtt3a` | https://github.com/eclipse-paho/paho.mqtt.c |
| libcurl | HTTP/HTTPS OTA升级包下载 | `curl/curl.h` / `-lcurl` | https://github.com/curl/curl |
| pthread | 读写锁、互斥锁、条件变量、OTA下载线程 | `pthread.h` / `-lpthread` | POSIX线程库，Linux通常由glibc提供；glibc官方源码不托管在GitHub，常用镜像为 https://github.com/bminor/glibc |
| cJSON | JSON解析和生成，项目已内置源码 | `cJSON.h` / `cJSON.c` | https://github.com/DaveGamble/cJSON |

## Ubuntu/Debian安装参考

```sh
sudo apt update
sudo apt install -y gcc make libcurl4-openssl-dev
```

Paho MQTT C库如果系统源中没有可用版本，可以从源码安装：

```sh
git clone https://github.com/eclipse-paho/paho.mqtt.c.git
cd paho.mqtt.c
cmake -B build -DPAHO_BUILD_SHARED=TRUE -DPAHO_WITH_SSL=FALSE
cmake --build build
sudo cmake --install build
sudo ldconfig
```

本项目使用异步接口`MQTTAsync_*`，因此需要链接`paho-mqtt3a`。如果后续改为TLS MQTT连接，通常需要使用SSL构建选项，并按Paho文档选择带SSL的库变体。

## 本项目内置源码

`cJSON.c`和`cJSON.h`已经直接放在仓库中，编译时不需要额外安装cJSON开发包。若要升级cJSON，建议从上表中的官方仓库同步对应版本，并保留原始版权声明。

## 运行时检查

可用以下命令检查生成程序实际链接到的动态库：

```sh
ldd ./iot_gw
```

如果运行时报`libpaho-mqtt3a.so`找不到，通常是Paho安装路径未进入动态链接器缓存。安装完成后执行`sudo ldconfig`，或将库路径加入系统动态库搜索路径。
