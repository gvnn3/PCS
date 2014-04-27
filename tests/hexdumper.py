# This hack by: Raymond Hettinger
class hexdumper:
    """Given a byte array, turn it into a string. hex bytes to stdout."""
    def __init__(self):
        self.FILTER=''.join([(len(repr(chr(x)))==3) and chr(x) or '.' \
                                                    for x in range(256)])

    # pretty dumping hate machine.
    def dump(self, src, length=8):
        result=[]
        for i in range(0, len(src), length):
            s = src[i:i+length]
            hexa = ' '.join(["%02X"%ord(x) for x in s])
            printable = s.translate(self.FILTER)
            result.append("%04X   %-*s   %s\n" % \
                          (i, length*3, hexa, printable))
        return ''.join(result)

    # dump in a way which can be embedded in a python string.
    def dump2(self, src, length=8):
        result=[]
        for i in range(0, len(src), length):
            s = src[i:i+length]
            hexa = ''.join(["\\x%02X"%ord(x) for x in s])
            result.append("\"%-*s\"" % (length*3, hexa))
            if i + length < len(src):
                result.append(" \\")
            result.append("\n")
        return ''.join(result)
