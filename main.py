# -*- coding:utf-8 -*-


"""
    1. init python path
    2. import
"""
import sys,os,os.path
CUR_DIR = os.path.dirname(os.path.abspath(__file__))

sys.path.append(CUR_DIR)
sys.path.append(os.path.join(CUR_DIR, "libs"))


from knsrest import serve


if __name__ == "__main__":
    serve()
