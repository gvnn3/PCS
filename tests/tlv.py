import sys
sys.path.append('../src')

import pcs

def main():
    t = pcs.Field("type", 8)
    l = pcs.Field("length", 8)
    v = pcs.Field("value", 255, type = str)
    tlv = pcs.Packet([t, l, v])
    tlv.type = 5
    tlv.length = 4
    tlv.value = "foo"
    print tlv.bytes
    
