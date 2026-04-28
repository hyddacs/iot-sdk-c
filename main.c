#include "gw_sdk.h"
#include <signal.h>

static int running = 1;

void sig_handle(int s) {
    running = 0;
}

int main() {
    signal(SIGINT, sig_handle);
    //1. 配置文件初始化，包括配置文件读取、解析、创建路由规则、客户端创建、下行指令订阅
    //"gw_route.cfg"为项目文件夹下的配置文件
    if (gw_init("gw_route.cfg") != 0) {
        printf("gw_init failed\n");
        return -1;
    }

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
            //5. 根据设备名获取设备元信息
            SubDevice *d = gw_get_subdev_by_name(name);
            //6. 构建阿里云格式数据
            char *alink = build_alink_payload(json);
            //7. 根据设备元信息发送数据
            char payload[4096];
            snprintf(payload, sizeof(payload), alink);
            gw_publish_subdev(d, alink);
        }else
        {
            printf("未找到设备\n");
        }
        sleep(1);
        ++ssss;
    }
    //8.销毁客户端，释放资源
    gw_destroy();
    return 0;
}