import gdb
from curses.ascii import isgraph


#
# modified from:
# Memory dump formatted like xxd from gdb
# https://stackoverflow.com/questions/9233095/memory-dump-formatted-like-xxd-from-gdb
#
# usage:
# (gdb) source hexdump.py
# (gdb) hexdump <addr>
# (gdb) hexdump <addr> <count>
#
# examples:
# (gdb) hexdump x
# 0x7fffffffcf90: 30:31:32:33:34:35:36:37:38:39:20:61:62:63:64:65 |0123456789 abcde|
# 0x7fffffffcfa0: 66:67:68:69:6a:6b:6c:6d:6e:6f:70:71:72:73:74:75 |fghijklmnopqrstu|
# 0x7fffffffcfb0: 76:77:78:79:7a:20:41:42:43:44:45:46:47:48:49:4a |vwxyz ABCDEFGHIJ|
# 0x7fffffffcfc0: 4b:4c:4d:4e:4f:50:51:52:53:54:55:56:57:58:59:5a |KLMNOPQRSTUVWXYZ|
# (gdb) hexdump x 108
# 0x7fffffffcf90: 30:31:32:33:34:35:36:37:38:39:20:61:62:63:64:65 |0123456789 abcde|
# 0x7fffffffcfa0: 66:67:68:69:6a:6b:6c:6d:6e:6f:70:71:72:73:74:75 |fghijklmnopqrstu|
# 0x7fffffffcfb0: 76:77:78:79:7a:20:41:42:43:44:45:46:47:48:49:4a |vwxyz ABCDEFGHIJ|
# 0x7fffffffcfc0: 4b:4c:4d:4e:4f:50:51:52:53:54:55:56:57:58:59:5a |KLMNOPQRSTUVWXYZ|
# 0x7fffffffcfd0: 20:21:40:23:24:25:5e:26:2a:28:29:5f:2b:2d:3d:2c | !@#$%^&*()_+-=,|
# 0x7fffffffcfe0: 2e:2f:3c:3e:3f:5b:5d:5c:7b:7d:7c:3b:3a:27:22:00 |./<>?[]\{}|;:'".|
# 0x7fffffffcff0: 00:00:00:00:00:00:00:00:00:00:00:00             |............    |
# (gdb) set hexdump-width 8
# (gdb) hexdump x
# 0x7fffffffcf90: 30:31:32:33:34:35:36:37 |01234567|
# 0x7fffffffcf98: 38:39:20:61:62:63:64:65 |89 abcde|
# 0x7fffffffcfa0: 66:67:68:69:6a:6b:6c:6d |fghijklm|
# 0x7fffffffcfa8: 6e:6f:70:71:72:73:74:75 |nopqrstu|
# 0x7fffffffcfb0: 76:77:78:79:7a:20:41:42 |vwxyz AB|
# 0x7fffffffcfb8: 43:44:45:46:47:48:49:4a |CDEFGHIJ|
# 0x7fffffffcfc0: 4b:4c:4d:4e:4f:50:51:52 |KLMNOPQR|
# 0x7fffffffcfc8: 53:54:55:56:57:58:59:5a |STUVWXYZ|
# (gdb) set hexdump-noaddr
# (gdb) hexdump x
# 30:31:32:33:34:35:36:37:38:39:20:61:62:63:64:65 |0123456789 abcde|
# 66:67:68:69:6a:6b:6c:6d:6e:6f:70:71:72:73:74:75 |fghijklmnopqrstu|
# 76:77:78:79:7a:20:41:42:43:44:45:46:47:48:49:4a |vwxyz ABCDEFGHIJ|
# 4b:4c:4d:4e:4f:50:51:52:53:54:55:56:57:58:59:5a |KLMNOPQRSTUVWXYZ|
# (gdb) set hexdump-noascii
# (gdb) hexdump x
# 30:31:32:33:34:35:36:37:38:39:20:61:62:63:64:65
# 66:67:68:69:6a:6b:6c:6d:6e:6f:70:71:72:73:74:75
# 76:77:78:79:7a:20:41:42:43:44:45:46:47:48:49:4a
# 4b:4c:4d:4e:4f:50:51:52:53:54:55:56:57:58:59:5a
#

class HexDump(gdb.Command):
    """Dump memory in hex."""

    def __init__(self):
        super(HexDump, self).__init__('hexdump', gdb.COMMAND_DATA)

    def invoke(self, arg, from_tty):
        argv = gdb.string_to_argv(arg)

        if len(argv) == 0:
            raise gdb.GdbError('Argument required (starting display address).')
        if len(argv) > 2:
            raise gdb.GdbError('Excessive arguments.')
        addr = gdb.parse_and_eval(argv[0]).cast(gdb.lookup_type('void').pointer())
        count = 64
        if len(argv) == 2:
            try:
                count = int(argv[1])
            except ValueError:
                raise gdb.GdbError('Byte count must be an integer value.')

        width = gdb.parameter('hexdump-width')
        if width is None:
            # unlimited / 0 -> 16
            width = 16
        noAddr = gdb.parameter('hexdump-noaddr')
        noAscii = gdb.parameter('hexdump-noascii')

        inferior = gdb.selected_inferior()

        # returns a memoryview object
        mem = inferior.read_memory(addr, count)
        pr_addr = int(str(addr), 16)

        def chunk_of(iterable, size):
            chunk, iterable = iterable[:size], iterable[size:]
            while chunk:
                yield chunk
                chunk, iterable = iterable[:size], iterable[size:]

        def pr(b):
            # convert from single byte bytes object to integer
            c = ord(b)
            if isgraph(c) or c == ord(' '):
                return chr(c)
            return '.'

        for chunk in chunk_of(mem, width):
            # address
            if not noAddr:
                print('0x%x: ' % pr_addr, end="")
            # bytes in hex
            print(':'.join(['%02x' % ord(b) for b in chunk]) + '   ' * (width - len(chunk)) + ' ', end="")
            # ascii
            if not noAscii:
                print('|' + ''.join([pr(b) for b in chunk]) + ' ' * (width - len(chunk)) + '|')
            else:
                print('')
            pr_addr += width


class HexDumpWidth(gdb.Parameter):
    """Parameter of width for hexdump command."""

    def __init__(self):
        super(HexDumpWidth, self).__init__('hexdump-width',
                                           gdb.COMMAND_DATA,
                                           gdb.PARAM_INTEGER)
        self.value = 16

    show_doc = 'The number of bytes per line for hexdump.'
    set_doc = 'Set the number of bytes per line for hexdump.'


class HexDumpNoAddr(gdb.Parameter):
    """Parameter of addr display for hexdump command."""

    def __init__(self):
        super(HexDumpNoAddr, self).__init__('hexdump-noaddr',
                                            gdb.COMMAND_DATA,
                                            gdb.PARAM_BOOLEAN)
        self.value = False


class HexDumpNoAscii(gdb.Parameter):
    """Parameter of ascii display for hexdump command."""

    def __init__(self):
        super(HexDumpNoAscii, self).__init__('hexdump-noascii',
                                             gdb.COMMAND_DATA,
                                             gdb.PARAM_BOOLEAN)
        self.value = False


HexDump()
HexDumpWidth()
HexDumpNoAddr()
HexDumpNoAscii()
