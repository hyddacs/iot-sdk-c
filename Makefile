# 项目配置
TARGET = iot_gw
CC = gcc
CFLAGS = -Wall -g -O2
LDFLAGS = -lpaho-mqtt3a -lcurl -lpthread

# 源文件列表
SRCS = main.c gw_sdk.c cJSON.c
OBJS = $(SRCS:.c=.o)

# 默认目标
all: $(TARGET)

# 链接生成可执行文件
$(TARGET): $(OBJS)
	$(CC) $(CFLAGS) -o $@ $^ $(LDFLAGS)

# 编译每个.c文件为.o文件
%.o: %.c
	$(CC) $(CFLAGS) -c $< -o $@

# 清理编译产物
clean:
	rm -f $(OBJS) $(TARGET)

# 一键运行
run: $(TARGET)
	./$(TARGET)

.PHONY: all clean run