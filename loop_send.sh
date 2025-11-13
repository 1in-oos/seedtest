#!/bin/bash

while true; do
    cansend can0 401#0040020000000000
    sleep 0.4  # 每隔400ms发送一次
done
