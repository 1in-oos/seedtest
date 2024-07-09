#!/bin/bash

while true; do
    cansend can0 401#0040020000000000
    sleep 0.1  # 每隔1秒发送一次
done
