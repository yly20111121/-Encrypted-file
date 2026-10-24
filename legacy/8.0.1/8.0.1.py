#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""
Core Vault 8.0.1 - Enterprise MemoryShield & Multi-Core
入口模块
"""
import sys
import os

# 将当前目录加入模块搜索路径以支持直接执行
cur_dir = os.path.dirname(os.path.abspath(__file__))
if cur_dir not in sys.path:
    sys.path.insert(0, cur_dir)

from main import main

if __name__ == "__main__":
    main()
