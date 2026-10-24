#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""
Core Vault 9.0.1 - Enterprise Mica & Stream Compression
入口启动脚本
"""
import sys
import os

cur_dir = os.path.dirname(os.path.abspath(__file__))
if cur_dir not in sys.path:
    sys.path.insert(0, cur_dir)

from main import main

if __name__ == "__main__":
    main()
