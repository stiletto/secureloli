#!/bin/sh
mv secureloli.log "secureloli.log.$(date +%d.%m.%Y.%H.%M)"
~/virtualenv/bin/python proxy.py --address="" --port=8444 \
    --backend_connect_host="127.0.0.1" --backend_host="bnw.im" --backend_port=80
