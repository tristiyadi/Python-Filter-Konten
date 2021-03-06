#!/usr/bin/env python

import sys
import re
import datetime, time
import argparse
import nids

end_states = (nids.NIDS_CLOSE, nids.NIDS_TIMEOUT, nids.NIDS_RESET)

globs = {
    'device': None,
    'pcap': None,
    'killtcp': False,
    'regexstr': None,
    'regexobj': None,
    'regexflags': re.MULTILINE,
    'dispbytes': 0
}

matchstats = {
    'start': 0,
    'end': 0,
    'size': 0
}

def gettimestamp():
    return "%s %s" % (datetime.datetime.now().strftime("%d-%b-%Y %H:%M:%S.%f"), time.tzname[0])

def hexdump(data, length=16, sep='.'):
    lines = []
    FILTER = ''.join([(len(repr(chr(x))) == 3) and chr(x) or sep for x in range(256)])
    for c in xrange(0, len(data), length):
        chars = data[c:c+length]
        hex = ' '.join(["%02x" % ord(x) for x in chars])
        printablechars = ''.join(["%s" % ((ord(x) <= 127 and FILTER[ord(x)]) or sep) for x in chars])
        lines.append("%08x: %-*s |%s|\n" % (c, length*3, hex, printablechars))

    print ''.join(lines)

def inspect(data):
    matchobj = globs['regexobj'].search(data)

    if matchobj:
        matchstats['start'] = matchobj.start()
        matchstats['end'] = matchobj.end()
        matchstats['size'] = matchobj.end() - matchobj.start()
        return True
    else:
        return False

def udpcallback(addr, payload, pkt):
    ((src, sport), (dst, dport)) = addr
    matched = False

    print "[%s] UDP %s:%s - %s:%s (%dB)" % (gettimestamp(), src, sport, dst, dport, len(payload))
    if len(payload) > 0:
        matched = inspect(payload)
        if matched:
            print "[%s] UDP %s:%s - %s:%s matches regex \'%s\'" % (gettimestamp(), src, sport, dst, dport,
                    globs['regexstr']),
            print "@ [%d:%d] %dB" % (matchstats['start'], matchstats['end'], matchstats['size'])

            if globs['dispbytes'] > 0 and matchstats['size'] > globs['dispbytes']:
                hexdump(payload[matchstats['start']:matchstats['start'] + globs['dispbytes']])
            else:
                hexdump(payload[matchstats['start']:matchstats['end']])

def tcpcallback(tcp):
    ((src, sport), (dst, dport)) = tcp.addr
    matched = False

    if tcp.nids_state == nids.NIDS_JUST_EST:
        tcp.client.collect = 1
        tcp.server.collect = 1
        print "[%s] TCP %s:%s - %s:%s (NEW)" % (gettimestamp(), src, sport, dst, dport)

    elif tcp.nids_state == nids.NIDS_DATA:
        tcp.discard(0)
        print "[%s] TCP %s:%s - %s:%s (CTS: %dB | STC: %dB)" % (gettimestamp(), src, sport, dst, dport,
                len(tcp.server.data[:tcp.server.count]),
                len(tcp.client.data[:tcp.client.count]))

        if len(tcp.server.data[:tcp.server.count]) > 0:
            matched = inspect(tcp.server.data[:tcp.server.count])
            if matched:
                print "[%s] TCP %s:%s - %s:%s matches regex \'%s\'" % (gettimestamp(), src, sport, dst, dport,
                        globs['regexstr']),
                print "@ CTS[%d:%d] %dB" % (matchstats['start'], matchstats['end'], matchstats['size'])

                if globs['dispbytes'] > 0 and matchstats['size'] > globs['dispbytes']:
                    hexdump(tcp.server.data[matchstats['start']:matchstats['start'] + globs['dispbytes']])
                else:
                    hexdump(tcp.server.data[matchstats['start']:matchstats['end']])

                tcp.client.collect = 0
                tcp.server.collect = 0

                if globs['killtcp']:
                    tcp.kill

                return

        if len(tcp.client.data[:tcp.client.count]) > 0:
            matched = inspect(tcp.client.data[:tcp.client.count])
            if matched:
                print "[%s] TCP %s:%s - %s:%s matches regex \'%s\'" % (gettimestamp(), src, sport, dst, dport,
                        globs['regexstr']),
                print "@ STC[%d:%d] %dB" % (matchstats['start'], matchstats['end'], matchstats['size'])
                hexdump(tcp.client.data[matchstats['start']:matchstats['end']])

                if globs['dispbytes'] > 0 and matchstats['size'] > globs['dispbytes']:
                    hexdump(tcp.server.data[matchstats['start']:matchstats['start'] + globs['dispbytes']])
                else:
                    hexdump(tcp.server.data[matchstats['start']:matchstats['end']])

                tcp.client.collect = 0
                tcp.server.collect = 0

                if globs['killtcp']:
                    tcp.kill

                return

    elif tcp.nids_state in end_states:
        print "[%s] TCP %s:%s - %s:%s (CLOSE)" % (gettimestamp(), src, sport, dst, dport)

def main():
    parser = argparse.ArgumentParser(description='minips.py - A minimal IPS', version='0.1',
            epilog='EXAMPLE: %(prog)s -p test.pcap -r \'shellcode\' \n')
    inputparser = parser.add_mutually_exclusive_group(required=True)
    inputparser.add_argument('-d', '--device', action='store', dest='device',
            help='network device to collect packets from')
    inputparser.add_argument('-p', '--pcap', action='store', dest='pcap',
            help='pcap file to read packets from')
    parser.add_argument('-r', '--regex', action='store', dest='regex', required=True,
            help='regex to match over network data')
    parser.add_argument('-i', '--igncase', action='store_true', dest='igncase', default=False,
            help='perform case insensitive regex match')
    parser.add_argument('-m', '--multiline', action='store_true', dest='multiline', default=False,
            help='perform multiline regex match')
    parser.add_argument('-k', '--killtcp', action='store_true', dest='killtcp', default=False,
            help='terminate matching tcp connections')
    parser.add_argument('-b', '--dispbytes', action='store', dest='dispbytes', required=False,
            help='max bytes to display')

    args = parser.parse_args()

    if args.device:
        globs['device'] = args.device
        nids.param('device', globs['device'])

    if args.pcap:
        globs['pcap'] = args.pcap
        nids.param('filename', globs['pcap'])

    if args.killtcp:
        globs['killtcp'] = True

    if args.igncase:
        globs['regexflags'] |= re.IGNORECASE

    if args.multiline:
        globs['regexflags'] |= re.MULTILINE
        globs['regexflags'] |= re.DOTALL

    if args.regex:
        globs['regexstr'] = args.regex
        globs['regexobj'] = re.compile(globs['regexstr'], globs['regexflags'])

    if args.dispbytes:
        globs['dispbytes'] = int(args.dispbytes)

    nids.init()
    nids.register_tcp(tcpcallback)
    nids.register_udp(udpcallback)

    try:
        nids.run()
    except nids.error, e:
        print "[-] Error: %s" % (e)
    except Exception, e:
        print "[-] Exception: %s" % (e)

if __name__ == '__main__':
    main()