"""The DNS daemon. Importing the package adjusts one dnslib behaviour, below."""
from dnslib import RD, RR, DNSError

_parse = RR.parse.__func__


def _parse_empty_ok(cls, buffer):
    """dnslib refuses a record with no data ("Error: Empty RR"), but RFC 2136 needs them: the prerequisites and the deletions of a whole name
    or RRset (class ANY / NONE, `nsupdate ... delete name`) have rdlength 0, so those UPDATEs got no answer. They are read as an empty RD."""
    start = buffer.offset
    try:
        return _parse(cls, buffer)
    except DNSError as e:
        if 'Empty RR' not in str(e):
            raise
    buffer.offset = start
    rname = buffer.decode_name()
    rtype, rclass, ttl, _ = buffer.unpack('!HHIH')
    return cls(rname, rtype, rclass, ttl, RD(b''))


RR.parse = classmethod(_parse_empty_ok)
