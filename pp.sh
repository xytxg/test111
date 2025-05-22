#!/bin/bash

# 固定网卡名（已修改）
INTERFACE="enp9s0f1np1"

echo "脚本开始执行..."
echo "正在持续模拟流量压力测试..."

# 无限循环下载大文件
while true; do
    curl -s -o /dev/null http://speedtest.tele2.net/10MB.zip
done &

# 无限循环上传伪数据
while true; do
    curl -s -T /dev/zero http://speedtest.tele2.net/upload.php
done &

# 每分钟显示带宽状态
while true; do
    RX=$(cat /proc/net/dev | grep $INTERFACE | awk '{print $2}')
    TX=$(cat /proc/net/dev | grep $INTERFACE | awk '{print $10}')
    echo "[$(date '+%H:%M:%S')] Down: $((RX/1024/1024)) MB | Up: $((TX/1024/1024)) MB"
    sleep 60
done
