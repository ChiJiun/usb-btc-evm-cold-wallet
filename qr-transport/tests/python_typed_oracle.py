"""Independent, dependency-free Python CBOR fixture oracle (tests only).

Parses the *raw decoded CBOR* produced by JavaScript's Blockchain Commons
codec. Never signs, imports keys, or validates blockchain transactions.
"""
import json
import sys


class Reader:
    def __init__(self, data):
        self.data = bytes.fromhex(data)
        self.offset = 0

    def take(self, n):
        if n < 0 or n > 150_000 or self.offset + n > len(self.data):
            raise ValueError("truncated or oversize CBOR")
        chunk = self.data[self.offset:self.offset + n]
        self.offset += n
        return chunk

    def uint(self, code):
        if code < 24:
            return code
        if code in (24, 25, 26, 27):
            n = 1 << (code - 24)
            value = int.from_bytes(self.take(n), "big")
            if value < 24 or (n == 2 and value <= 255) or (
                n == 4 and value <= 65535
            ) or (n == 8 and value <= 4294967295):
                raise ValueError("noncanonical CBOR integer")
            return value
        raise ValueError("indefinite/unsupported CBOR")

    def parse(self, depth=0):
        if depth > 12:
            raise ValueError("nested CBOR")
        head = self.take(1)[0]
        major, code = head >> 5, head & 31
        if major == 7:
            if code in (20, 21):
                return bool(code - 20)
            raise ValueError("unknown simple")
        n = self.uint(code)
        if major == 0:
            return n
        if major == 2:
            return {"hex": self.take(n).hex()}
        if major == 3:
            if n > 1024:
                raise ValueError("unbounded text")
            return self.take(n).decode("utf-8")
        if major == 4:
            if n > 128:
                raise ValueError("oversize list")
            return [self.parse(depth + 1) for _ in range(n)]
        if major == 5:
            if n > 20:
                raise ValueError("oversize map")
            result = {}
            for _ in range(n):
                key = self.parse(depth + 1)
                if type(key) is not int or str(key) in result:
                    raise ValueError("bad CBOR map key")
                result[str(key)] = self.parse(depth + 1)
            return result
        if major == 6:
            return {"tag": n, "value": self.parse(depth + 1)}
        raise ValueError("unsupported CBOR item")


def main():
    raw = sys.stdin.read().strip()
    if len(raw) > 300_000:
        raise ValueError("oversize fixture")
    parser = Reader(raw)
    result = parser.parse()
    if parser.offset != len(parser.data):
        raise ValueError("trailing bytes")
    print(json.dumps(result, separators=(",", ":"), sort_keys=True))


if __name__ == "__main__":
    main()
