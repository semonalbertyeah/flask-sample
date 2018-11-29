# -*- coding:utf-8 -*-

import os
import xml.parsers.expat

def valid_xml(path):
    if not os.path.isfile(path):
        return False

    parser = xml.parsers.expat.ParserCreate()
    try:
        parser.ParseFile(open(path, "r"))
        return True
    except xml.parsers.expat.ExpatError as e:
        return False




