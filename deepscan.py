#!/usr/bin/env python3
"""deepscan - in-depth file inspection for hidden content.

Looks at a file from every angle that does not require trusting it: real type
vs. extension, hashes, metadata (EXIF/XMP/PDF/Office/PNG text), data appended
after the logical end of the file, files embedded inside other files, macros
and active content, suspicious strings and secrets, entropy, LSB steganography,
invisible Unicode, extended attributes. Findings are ranked by severity.

Pure standard library. Uses `file` and `exiftool` as extras when installed.
"""
import argparse
import base64
import collections
import datetime as dt
import hashlib
import html
import itertools
import json
import math
import os
import re
import shutil
import stat
import struct
import subprocess
import sys
import textwrap
import zipfile
import zlib

VERSION = "1.0"
SEVS = ["INFO", "LOW", "MEDIUM", "HIGH"]
RANK = {s: i for i, s in enumerate(SEVS)}

# --------------------------------------------------------------------------
# helpers
# --------------------------------------------------------------------------

def clean(s, limit=400):
    """Make any value safe to print: no control chars, no terminal escapes."""
    if isinstance(s, (bytes, bytearray)):
        s = bytes(s).decode("utf-8", "replace")
    s = str(s)
    cut = len(s) > limit
    s = s[:limit]
    out = []
    for ch in s:
        if ch.isprintable():
            out.append(ch)
        elif ord(ch) < 256:
            out.append("\\x%02x" % ord(ch))
        else:
            out.append("\\u{%x}" % ord(ch))
    return "".join(out) + ("…" if cut else "")


def hx(n):
    return "0x%x" % n


def human(n):
    for unit in ("B", "KB", "MB", "GB"):
        if n < 1024 or unit == "GB":
            return ("%d %s" % (n, unit)) if unit == "B" else ("%.1f %s" % (n, unit))
        n /= 1024


def entropy(b):
    n = len(b)
    if not n:
        return 0.0
    return -sum(c / n * math.log2(c / n) for c in collections.Counter(b).values())


def printable_ratio(b):
    if not b:
        return 0.0
    return sum(1 for x in b if 32 <= x < 127 or x in (9, 10, 13)) / len(b)


def mask(s):
    s = clean(s, 80)
    return s[:4] + "…(%d chars)" % len(s) if len(s) > 6 else "…"


def gammaincc(a, x):
    """Regularised upper incomplete gamma Q(a, x) (chi-square survival)."""
    if x <= 0:
        return 1.0
    try:
        if x < a + 1:
            ap, s, d = a, 1 / a, 1 / a
            for _ in range(1000):
                ap += 1
                d *= x / ap
                s += d
                if abs(d) < abs(s) * 1e-12:
                    break
            return max(0.0, 1 - s * math.exp(-x + a * math.log(x) - math.lgamma(a)))
        b, c = x + 1 - a, 1e300
        d = 1 / b
        h = d
        for i in range(1, 1000):
            an = -i * (i - a)
            b += 2
            d = an * d + b
            d = 1e-300 if abs(d) < 1e-300 else d
            c = b + an / c
            c = 1e-300 if abs(c) < 1e-300 else c
            d = 1 / d
            de = d * c
            h *= de
            if abs(de - 1) < 1e-12:
                break
        return math.exp(-x + a * math.log(x) - math.lgamma(a)) * h
    except (OverflowError, ValueError):
        return 0.0


class Report:
    def __init__(self, path):
        self.path = path
        self.identity = collections.OrderedDict()
        self.hashes = collections.OrderedDict()
        self.metadata = []          # (group, key, value)
        self.findings = []          # dicts
        self.notes = []
        self.blobs = []             # (label, bytes) for --extract
        self.kind = "unknown"
        self.subtype = ""
        self.logical_end = None
        self.entropy_blocks = []

    def add(self, sev, cat, title, detail=None, offset=None):
        if detail is None:
            detail = []
        elif isinstance(detail, str):
            detail = [detail]
        self.findings.append({
            "severity": sev, "category": cat, "title": clean(title, 200),
            "detail": [clean(x) for x in list(detail)[:200]],
            "offset": offset,
        })

    def meta(self, group, key, value):
        v = clean(value, 600).strip()
        if v and (group, key, v) not in self.metadata and len(self.metadata) < 2000:
            self.metadata.append((group, clean(key, 80), v))

    def blob(self, label, data):
        if data and len(data) <= 64 << 20:
            self.blobs.append((label, bytes(data)))

    def worst(self):
        return max((RANK[f["severity"]] for f in self.findings), default=-1)

    def to_dict(self):
        return {
            "path": self.path, "identity": self.identity, "hashes": self.hashes,
            "metadata": [{"group": g, "key": k, "value": v} for g, k, v in self.metadata],
            "findings": sorted(self.findings, key=lambda f: -RANK[f["severity"]]),
            "notes": self.notes,
        }


# --------------------------------------------------------------------------
# type identification
# --------------------------------------------------------------------------

PE_EXTS = {"exe", "dll", "sys", "scr", "cpl", "ocx", "efi", "com", "drv", "mui", "pyd", "node"}
ELF_EXTS = {"so", "elf", "bin", "o", "ko", "out", "run", "appimage", "axf", "x86_64"}
ZIP_EXTS = {"zip", "docx", "xlsx", "pptx", "docm", "xlsm", "pptm", "dotx", "dotm", "xltx", "xltm",
            "ppsx", "odt", "ods", "odp", "odg", "jar", "apk", "epub", "whl", "xpi", "war", "ear",
            "kmz", "vsix", "nupkg", "ipa", "aar", "crx", "xlsb", "vsdx", "3mf", "egg", "cbz"}
OLE_EXTS = {"doc", "xls", "ppt", "msi", "msg", "dot", "xlt", "pps", "vsd", "db", "pub", "msp", "mpp", "xla"}
TEXT_EXTS = {"txt", "md", "csv", "json", "xml", "html", "htm", "py", "sh", "js", "ts", "c", "h", "cpp",
             "java", "go", "rs", "rb", "php", "pl", "ps1", "bat", "cmd", "vbs", "ini", "cfg", "conf",
             "yaml", "yml", "toml", "log", "svg", "css", "sql", "tex", "rst"}
CODE_EXTS = {"py", "sh", "js", "ts", "c", "h", "cpp", "java", "go", "rs", "rb", "php", "pl", "ps1",
             "bat", "cmd", "vbs", "sql", "cs", "swift", "kt", "lua"}
EXEC_KINDS = {"pe", "elf", "macho", "script", "lnk", "dex", "wasm", "class"}
ARCHIVE_KINDS = {"zip", "gzip", "bzip2", "xz", "zstd", "7z", "rar", "tar", "iso", "lz4", "cab"}
COMPRESSED_KINDS = ARCHIVE_KINDS | {"png", "jpeg", "gif", "webp", "mp4", "mp3", "ogg", "flac", "mkv",
                                    "pdf", "heif", "avi"}
ALL_EXTS = (PE_EXTS | ELF_EXTS | ZIP_EXTS | OLE_EXTS | TEXT_EXTS |
            {"png", "apng", "jpg", "jpeg", "jfif", "jpe", "gif", "bmp", "dib", "pdf", "gz", "tgz", "bz2",
             "xz", "zst", "7z", "rar", "sqlite", "sqlite3", "db3", "webp", "wav", "avi", "tif", "tiff",
             "mp3", "ogg", "flac", "mp4", "m4a", "m4v", "mov", "heic", "heif", "avif", "mkv", "webm",
             "rtf", "lnk", "class", "tar", "iso", "wasm", "ps", "eps", "ico", "cab", "dex", "psd"})


def _zip_local_ok(b):
    if len(b) < 30:
        return False
    ver, flags, method = struct.unpack_from("<HHH", b, 4)
    nlen = struct.unpack_from("<H", b, 26)[0]
    if ver > 63 or method not in (0, 1, 6, 8, 9, 12, 14, 93, 95, 96, 97, 98, 99) or not 0 < nlen <= 1024:
        return False
    name = b[30:30 + nlen]
    return len(name) < nlen or all(x >= 32 for x in name)


def _gzip_ok(b):
    if len(b) < 18 or b[3] & 0xE0:
        return False
    try:
        return len(zlib.decompressobj(31).decompress(b[:65536], 64)) > 0
    except zlib.error:
        return False


def sniff(b, strict=False):
    """Identify data by content. Returns (description, kind, valid_exts) or None.
    strict=True demands structural validation (used for embedded/decoded data)."""
    n = len(b)
    if n < 4:
        return None
    if b[:8] == b"\x89PNG\r\n\x1a\n":
        return ("PNG image", "png", {"png", "apng"})
    if b[:3] == b"\xff\xd8\xff":
        m = b[3]
        ok = (m in (0xDB, 0xEE, 0xED, 0xFE, 0xC0, 0xC2, 0xC4, 0xE2) or
              (m == 0xE0 and b[6:10] in (b"JFIF", b"JFXX")) or
              (m == 0xE1 and b[6:10] in (b"Exif", b"http")))
        if ok or not strict:
            return ("JPEG image", "jpeg", {"jpg", "jpeg", "jfif", "jpe"})
    if b[:6] in (b"GIF87a", b"GIF89a"):
        return ("GIF image", "gif", {"gif"})
    if b[:2] == b"BM" and n >= 26 and b[6:10] == b"\0\0\0\0" and \
            struct.unpack_from("<I", b, 14)[0] in (12, 40, 52, 56, 64, 108, 124):
        return ("BMP image", "bmp", {"bmp", "dib"})
    if b[:5] == b"%PDF-" and (not strict or b[5:7] in (b"1.", b"2.")):
        return ("PDF document", "pdf", {"pdf"})
    if b[:4] == b"PK\x03\x04" and (not strict or _zip_local_ok(b)):
        return ("ZIP archive", "zip", ZIP_EXTS)
    if b[:4] == b"PK\x05\x06" and not strict:
        return ("ZIP archive (empty)", "zip", ZIP_EXTS)
    if b[:8] == b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1":
        return ("OLE2 compound document (legacy Office/MSI)", "ole", OLE_EXTS)
    if b[:2] == b"MZ":
        pe = False
        if n >= 0x40:
            o = struct.unpack_from("<I", b, 0x3C)[0]
            pe = o + 4 <= n and b[o:o + 4] == b"PE\0\0"
        if pe:
            return ("Windows PE executable", "pe", PE_EXTS)
        if not strict and n >= 0x40 and b"\0" in b[:64]:
            return ("DOS MZ executable", "pe", PE_EXTS)
    if b[:4] == b"\x7fELF" and n >= 20 and b[4] in (1, 2) and b[5] in (1, 2) and b[6] == 1:
        et = struct.unpack_from("<H" if b[5] == 1 else ">H", b, 16)[0]
        if 1 <= et <= 4:
            return ("ELF " + {1: "object", 2: "executable", 3: "shared object/PIE executable",
                              4: "core dump"}[et], "elf", ELF_EXTS)
    if b[:3] == b"\x1f\x8b\x08" and (not strict or _gzip_ok(b)):
        return ("gzip compressed data", "gzip", {"gz", "tgz", "svgz", "emz", "z"})
    if b[:3] == b"BZh" and b[3:4].isdigit() and b[4:10] == b"1AY&SY":
        return ("bzip2 compressed data", "bzip2", {"bz2", "tbz2", "tbz"})
    if b[:6] == b"\xfd7zXZ\x00":
        return ("xz compressed data", "xz", {"xz", "txz"})
    if b[:4] == b"\x28\xb5\x2f\xfd":
        return ("zstd compressed data", "zstd", {"zst", "tzst"})
    if b[:4] == b"\x04\x22\x4d\x18":
        return ("LZ4 compressed data", "lz4", {"lz4"})
    if b[:6] == b"7z\xbc\xaf\x27\x1c":
        return ("7-Zip archive", "7z", {"7z"})
    if b[:6] == b"Rar!\x1a\x07":
        return ("RAR archive", "rar", {"rar"})
    if b[:4] == b"MSCF" and b[4:8] == b"\0\0\0\0":
        return ("Microsoft Cabinet archive", "cab", {"cab"})
    if b[:16] == b"SQLite format 3\x00":
        return ("SQLite database", "sqlite", {"sqlite", "db", "sqlite3", "db3"})
    if b[:4] == b"RIFF" and n >= 12:
        t = b[8:12]
        if t == b"WEBP":
            return ("WebP image", "webp", {"webp"})
        if t == b"WAVE":
            return ("WAV audio", "wav", {"wav"})
        if t == b"AVI ":
            return ("AVI video", "avi", {"avi"})
        if not strict:
            return ("RIFF container", "riff", None)
    if b[:4] in (b"II*\x00", b"MM\x00*"):
        return ("TIFF image", "tiff", {"tif", "tiff", "dng", "nef", "cr2", "arw", "orf"})
    if b[4:8] == b"ftyp" and n >= 12:
        brand = b[8:12]
        if brand in (b"heic", b"heix", b"mif1", b"avif", b"hevc", b"msf1"):
            return ("HEIF/AVIF image", "heif", {"heic", "heif", "avif"})
        return ("MP4/QuickTime media", "mp4", {"mp4", "m4a", "m4v", "mov", "3gp", "m4b", "f4v"})
    if b[:4] == b"\x1a\x45\xdf\xa3":
        return ("Matroska/WebM media", "mkv", {"mkv", "webm", "mka"})
    if b[:3] == b"ID3" and b[3] in (2, 3, 4):
        return ("MP3 audio (ID3)", "mp3", {"mp3"})
    if b[:4] == b"OggS":
        return ("Ogg media", "ogg", {"ogg", "oga", "ogv", "opus"})
    if b[:4] == b"fLaC":
        return ("FLAC audio", "flac", {"flac"})
    if b[:5] == b"{\\rtf":
        return ("RTF document", "rtf", {"rtf", "doc"})
    if b[:8] == b"\x4c\x00\x00\x00\x01\x14\x02\x00":
        return ("Windows shortcut (LNK)", "lnk", {"lnk"})
    if b[:4] in (b"\xfe\xed\xfa\xce", b"\xfe\xed\xfa\xcf", b"\xce\xfa\xed\xfe", b"\xcf\xfa\xed\xfe"):
        return ("Mach-O executable", "macho", {"dylib", "o", "bundle"})
    if b[:4] == b"\xca\xfe\xba\xbe" and n >= 8:
        if struct.unpack_from(">I", b, 4)[0] < 20:
            return ("Mach-O universal binary", "macho", {"dylib", "o", "bundle"})
        return ("Java class file", "class", {"class"})
    if b[:4] == b"dex\n":
        return ("Android DEX bytecode", "dex", {"dex"})
    if b[:4] == b"\x00asm":
        return ("WebAssembly module", "wasm", {"wasm"})
    if b[:4] == b"8BPS":
        return ("Photoshop document", "psd", {"psd", "psb"})
    if b[:4] == b"\x00\x00\x01\x00" and n >= 6 and 0 < struct.unpack_from("<H", b, 4)[0] < 256 and not strict:
        return ("Windows icon", "ico", {"ico"})
    if n >= 262 and b[257:262] == b"ustar":
        return ("tar archive", "tar", {"tar"})
    if n >= 0x8006 and b[0x8001:0x8006] == b"CD001":
        return ("ISO 9660 image", "iso", {"iso", "img"})
    if strict:
        return None
    if b[:4] == b"%!PS":
        return ("PostScript document", "text", {"ps", "eps", "ai"})
    # text?
    if b[:2] in (b"\xff\xfe", b"\xfe\xff") and n >= 4:
        return ("UTF-16 text", "text", None)
    sample = b[:8192]
    if b"\0" not in sample:
        dec = sample.decode("utf-8", "ignore")
        if len(sample) - len(dec.encode("utf-8")) <= 3 and dec and \
                sum(1 for c in dec if c in "\r\n\t\f\x1b\x08" or not (ord(c) < 32 or 0x7f <= ord(c) < 0xa0)) / len(dec) > 0.9:
            s = dec.lstrip("\ufeff \r\n\t")
            low = s[:300].lower()
            if s.startswith("#!"):
                return ("Script (%s)" % clean(s[2:].split("\n")[0].strip(), 40), "script", None)
            if "<svg" in low:
                return ("SVG image (XML text)", "text", None)
            if low.startswith("<!doctype html") or "<html" in low:
                return ("HTML document", "text", None)
            if low.startswith("<?xml"):
                return ("XML document", "text", None)
            if s.startswith("-----BEGIN "):
                return ("PEM-encoded data", "text", None)
            if low.startswith("<?php"):
                return ("PHP script", "script", None)
            return ("Text", "text", None)
    return None


# --------------------------------------------------------------------------
# metadata parsers
# --------------------------------------------------------------------------

EXIF_TAGS = {
    0x010E: "ImageDescription", 0x010F: "Make", 0x0110: "Model", 0x0131: "Software",
    0x0132: "DateTime", 0x013B: "Artist", 0x013C: "HostComputer", 0x8298: "Copyright",
    0x9003: "DateTimeOriginal", 0x9004: "DateTimeDigitized", 0x9010: "OffsetTime",
    0x9286: "UserComment", 0xA420: "ImageUniqueID", 0xA430: "CameraOwnerName",
    0xA431: "BodySerialNumber", 0xA433: "LensMake", 0xA434: "LensModel", 0xA435: "LensSerialNumber",
    0x9C9B: "XPTitle", 0x9C9C: "XPComment", 0x9C9D: "XPAuthor", 0x9C9E: "XPKeywords",
    0x9C9F: "XPSubject", 0x02BC: "XMP-packet", 0x83BB: "IPTC", 0x927C: "MakerNote",
}
TYPE_SIZE = {1: 1, 2: 1, 3: 2, 4: 4, 5: 8, 6: 1, 7: 1, 8: 2, 9: 4, 10: 8, 11: 4, 12: 8}


def parse_tiff(buf, rep, group="EXIF"):
    """Walk TIFF/EXIF IFDs and pull out identifying tags and GPS."""
    if buf[:2] == b"II":
        e = "<"
    elif buf[:2] == b"MM":
        e = ">"
    else:
        return
    if len(buf) < 8 or struct.unpack_from(e + "H", buf, 2)[0] != 42:
        return
    seen = set()
    gps = {}

    def value(typ, cnt, raw_off):
        size = TYPE_SIZE.get(typ)
        if not size or cnt > 1 << 20:
            return None
        total = size * cnt
        off = raw_off if total <= 4 else struct.unpack_from(e + "I", buf, raw_off)[0]
        data = buf[off:off + total]
        if len(data) < total:
            return None
        if typ == 2:
            return data.split(b"\0")[0].decode("utf-8", "replace")
        if typ in (1, 7, 6):
            return data
        fmt = {3: "H", 4: "I", 8: "h", 9: "i", 11: "f", 12: "d"}.get(typ)
        if fmt:
            return list(struct.unpack_from(e + fmt * cnt, data))
        f = "I" if typ == 5 else "i"
        v = struct.unpack_from(e + f * (cnt * 2), data)
        return [(v[i], v[i + 1]) for i in range(0, len(v), 2)]

    def walk(off, which, depth=0):
        if off in seen or depth > 6 or off + 2 > len(buf):
            return
        seen.add(off)
        n = struct.unpack_from(e + "H", buf, off)[0]
        if n > 500:
            return
        thumb = [None, None]
        for i in range(n):
            p = off + 2 + i * 12
            if p + 12 > len(buf):
                return
            tag, typ, cnt = struct.unpack_from(e + "HHI", buf, p)
            try:
                v = value(typ, cnt, p + 8)
            except struct.error:
                v = None
            if v is None:
                continue
            if which == "gps":
                gps[tag] = v
                continue
            if tag in (0x8769, 0x8825, 0xA005) and isinstance(v, list):
                walk(v[0], "gps" if tag == 0x8825 else "exif", depth + 1)
            elif tag == 0x0201 and isinstance(v, list):
                thumb[0] = v[0]
            elif tag == 0x0202 and isinstance(v, list):
                thumb[1] = v[0]
            elif tag in EXIF_TAGS:
                name = EXIF_TAGS[tag]
                if name in ("MakerNote", "IPTC", "XMP-packet"):
                    rep.meta(group, name, "%d bytes of vendor/private data" % len(v))
                elif name == "UserComment" and isinstance(v, bytes):
                    body = v[8:]
                    txt = body.decode("utf-16", "replace") if v[:7] == b"UNICODE" else body.decode("utf-8", "replace")
                    rep.meta(group, name, txt.strip("\0 "))
                elif name.startswith("XP") and isinstance(v, bytes):
                    rep.meta(group, name, v.decode("utf-16-le", "replace").strip("\0"))
                elif isinstance(v, str):
                    rep.meta(group, name, v)
                elif isinstance(v, bytes):
                    rep.meta(group, name, v.decode("utf-8", "replace").strip("\0"))
        if which == "ifd" and thumb[0] and thumb[1]:
            rep.meta(group, "Thumbnail", "%d bytes embedded preview" % thumb[1])
            rep.add("INFO", "metadata", "EXIF contains an embedded thumbnail",
                    "Thumbnails are not always regenerated after cropping/editing and can show the original image.")
            rep.blob("exif_thumbnail.jpg", buf[thumb[0]:thumb[0] + thumb[1]])
        nxt = off + 2 + n * 12
        if which == "ifd" and nxt + 4 <= len(buf):
            nx = struct.unpack_from(e + "I", buf, nxt)[0]
            if nx:
                walk(nx, "ifd", depth + 1)

    try:
        walk(struct.unpack_from(e + "I", buf, 4)[0], "ifd")
    except (struct.error, IndexError):
        rep.notes.append("EXIF block is malformed; parsed partially")

    def dms(v):
        vals = [a / b if b else 0.0 for a, b in v]
        vals += [0.0] * (3 - len(vals))
        return vals[0] + vals[1] / 60 + vals[2] / 3600

    try:
        if 2 in gps and 4 in gps:
            lat, lon = dms(gps[2]), dms(gps[4])
            if str(gps.get(1, "N")).upper().startswith("S"):
                lat = -lat
            if str(gps.get(3, "E")).upper().startswith("W"):
                lon = -lon
            extra = []
            if 6 in gps and gps[6][0][1]:
                extra.append("altitude %.1f m" % (gps[6][0][0] / gps[6][0][1]))
            if 29 in gps:
                extra.append("date %s" % gps[29])
            rep.meta(group, "GPS", "%.6f, %.6f" % (lat, lon))
            if lat or lon:
                rep.add("MEDIUM", "metadata", "GPS location embedded in image",
                        ["%.6f, %.6f %s" % (lat, lon, " ".join(extra)),
                         "https://www.openstreetmap.org/?mlat=%.6f&mlon=%.6f" % (lat, lon)])
    except (TypeError, IndexError, ZeroDivisionError):
        pass


RE_XMP = re.compile(rb"<x:xmpmeta.*?</x:xmpmeta>", re.S)
RE_XMP_ATTR = re.compile(r'\b((?:xmp|xmpMM|dc|pdf|photoshop|tiff|exif|xmpRights|Iptc4xmpCore|crs|GCamera|stEvt)'
                         r':\w+)="([^"]{1,400})"')
RE_XMP_ELEM = re.compile(r"<((?:xmp|xmpMM|dc|pdf|photoshop|tiff|exif|xmpRights|Iptc4xmpCore):\w+)>\s*"
                         r"(?:<rdf:(?:Alt|Seq|Bag)>\s*)?(?:<rdf:li[^>]*>)?([^<]{1,400})<")


def extract_xmp(d, rep):
    for i, m in enumerate(itertools.islice(RE_XMP.finditer(d), 4)):
        t = html.unescape(m.group().decode("utf-8", "replace"))
        for k, v in itertools.islice(itertools.chain(RE_XMP_ATTR.findall(t), RE_XMP_ELEM.findall(t)), 60):
            if v.strip():
                rep.meta("XMP", k, v.strip())


# --------------------------------------------------------------------------
# format analysers. Each returns the logical end offset of the file (or None).
# --------------------------------------------------------------------------

PNG_STD = {b"IHDR", b"PLTE", b"IDAT", b"IEND", b"tRNS", b"cHRM", b"gAMA", b"iCCP", b"sBIT", b"sRGB",
           b"bKGD", b"hIST", b"pHYs", b"sPLT", b"tIME", b"tEXt", b"zTXt", b"iTXt", b"eXIf", b"acTL",
           b"fcTL", b"fdAT", b"cICP", b"mDCv", b"cLLi", b"caBX", b"oFFs", b"pCAL", b"sCAL", b"sTER",
           b"vpAg", b"orNT", b"iDOT"}


def analyze_png(d, rep, opts):
    i, n = 8, len(d)
    end = None
    ihdr = None
    idat = []
    odd = collections.Counter()
    badcrc = 0
    while i + 12 <= n:
        ln = struct.unpack_from(">I", d, i)[0]
        typ = d[i + 4:i + 8]
        if i + 12 + ln > n:
            rep.add("LOW", "structure", "PNG chunk runs past end of file (truncated or corrupt)",
                    "chunk %s at %s declares %d bytes" % (clean(typ), hx(i), ln), i)
            break
        body = d[i + 8:i + 8 + ln]
        if zlib.crc32(typ + body) != struct.unpack_from(">I", d, i + 8 + ln)[0]:
            badcrc += 1
        if typ == b"IHDR":
            ihdr = body
        elif typ == b"IDAT":
            idat.append(body)
        elif typ == b"tEXt":
            k, _, v = body.partition(b"\0")
            rep.meta("PNG text", k.decode("latin1"), v.decode("latin1"))
        elif typ == b"zTXt":
            k, _, v = body.partition(b"\0")
            try:
                rep.meta("PNG text", k.decode("latin1"), zlib.decompressobj().decompress(v[1:], 1 << 20).decode("latin1"))
            except zlib.error:
                pass
        elif typ == b"iTXt":
            k, _, rest = body.partition(b"\0")
            if len(rest) >= 2:
                comp = rest[0]
                _lang, _, rest2 = rest[2:].partition(b"\0")
                _tk, _, txt = rest2.partition(b"\0")
                try:
                    if comp:
                        txt = zlib.decompressobj().decompress(txt, 1 << 20)
                    if b"<x:xmpmeta" not in txt:
                        rep.meta("PNG text", k.decode("latin1"), txt.decode("utf-8", "replace"))
                except zlib.error:
                    pass
        elif typ == b"eXIf":
            parse_tiff(body, rep)
        elif typ == b"tIME" and ln == 7:
            y, mo, da, h, mi, s = struct.unpack(">HBBBBB", body)
            rep.meta("PNG", "Last modified (tIME)", "%04d-%02d-%02d %02d:%02d:%02d" % (y, mo, da, h, mi, s))
        elif typ not in PNG_STD:
            odd[typ] += ln
        i += 12 + ln
        if typ == b"IEND":
            end = i
            break
    if end is None:
        rep.add("LOW", "structure", "PNG has no IEND chunk (truncated or corrupt)")
    if badcrc:
        rep.add("LOW", "structure", "%d PNG chunk(s) with wrong CRC" % badcrc,
                "Edited by hand or corrupted; some hiding tools do not fix checksums.")
    if odd:
        rep.add("LOW", "structure", "Non-standard PNG chunks present",
                ["%s: %d bytes" % (clean(k), v) for k, v in odd.items()] +
                ["Private chunks are ignored by viewers and can carry arbitrary data."])
    if ihdr and len(ihdr) == 13 and idat:
        w, h, depth, ctype, _, _, inter = struct.unpack(">IIBBBBB", ihdr)
        rep.meta("PNG", "Dimensions", "%dx%d, %d-bit, colour type %d%s" % (w, h, depth, ctype, ", interlaced" if inter else ""))
        ch = {0: 1, 2: 3, 3: 1, 4: 2, 6: 4}.get(ctype)
        if ch and w and h and not inter:
            stride = (w * ch * depth + 7) // 8
            expected = h * (stride + 1)
            cap = opts["lsb_cap"]
            want = min(expected, (max(1, cap // (stride + 1))) * (stride + 1))
            dobj = zlib.decompressobj()
            buf = b"".join(idat)
            head = bytearray()
            total = 0
            try:
                while not dobj.eof and total < (4 << 30):
                    chunk = dobj.decompress(buf, 1 << 20)
                    buf = dobj.unconsumed_tail
                    if not chunk and not buf:
                        break
                    if len(head) < want:
                        head += chunk[:want - len(head)]
                    elif total >= expected and len(head) < want + (1 << 16):
                        pass
                    if total < expected < total + len(chunk):
                        rep.blob("png_extra_idat_data.bin", chunk[expected - total:])
                    total += len(chunk)
            except zlib.error:
                rep.add("LOW", "structure", "PNG pixel stream is corrupt (zlib error)")
            if total > expected:
                rep.add("MEDIUM", "stego", "Extra data hidden after the pixel data inside the PNG image stream",
                        "%d bytes more than the %dx%d image needs" % (total - expected, w, h))
            if dobj.unused_data:
                rep.add("MEDIUM", "stego", "Data after the end of the compressed stream inside IDAT",
                        "%d bytes, starts %s" % (len(dobj.unused_data), dobj.unused_data[:24].hex()))
                rep.blob("png_idat_unused.bin", dobj.unused_data)
            if depth == 8 and ctype != 3 and head:
                px = png_unfilter(bytes(head), stride, ch)
                if px:
                    analyze_lsb(px, ch, w, rep, opts, "RGBA"[:ch] if ch >= 3 else ("YA"[:ch]))
    return end


def png_unfilter(raw, stride, ch):
    out = bytearray()
    prev = bytearray(stride)
    for r in range(len(raw) // (stride + 1)):
        base = r * (stride + 1)
        f = raw[base]
        line = bytearray(raw[base + 1:base + 1 + stride])
        if f == 1:
            for i in range(ch, stride):
                line[i] = (line[i] + line[i - ch]) & 255
        elif f == 2:
            line = bytearray((a + b) & 255 for a, b in zip(line, prev))
        elif f == 3:
            for i in range(stride):
                a = line[i - ch] if i >= ch else 0
                line[i] = (line[i] + ((a + prev[i]) >> 1)) & 255
        elif f == 4:
            for i in range(stride):
                a = line[i - ch] if i >= ch else 0
                b = prev[i]
                c = prev[i - ch] if i >= ch else 0
                p = a + b - c
                pa, pb, pc = abs(p - a), abs(p - b), abs(p - c)
                pr = a if pa <= pb and pa <= pc else (b if pb <= pc else c)
                line[i] = (line[i] + pr) & 255
        elif f != 0:
            return None
        out += line
        prev = line
    return bytes(out)


def analyze_bmp(d, rep, opts):
    size = struct.unpack_from("<I", d, 2)[0]
    try:
        off = struct.unpack_from("<I", d, 10)[0]
        w, h = struct.unpack_from("<ii", d, 18)
        bpp, comp = struct.unpack_from("<HI", d, 28)
        rep.meta("BMP", "Dimensions", "%dx%d, %d bpp" % (w, abs(h), bpp))
        if bpp in (24, 32) and comp in (0, 3) and 0 < w < 100000 and h:
            ch = bpp // 8
            stride = ((w * bpp + 31) // 32) * 4
            rows = min(abs(h), max(1, opts["lsb_cap"] // (w * ch)))
            px = bytearray()
            for r in range(rows):
                rr = (abs(h) - 1 - r) if h > 0 else r
                row = d[off + rr * stride: off + rr * stride + w * ch]
                if len(row) < w * ch:
                    break
                conv = bytearray(row)
                conv[0::ch], conv[2::ch] = row[2::ch], row[0::ch]   # BGR -> RGB
                px += conv
            if px:
                analyze_lsb(bytes(px), ch, w, rep, opts, "RGBA"[:ch])
            gap = off - 14 - struct.unpack_from("<I", d, 14)[0] - (0 if bpp > 8 else 4 << bpp)
            if bpp > 8 and comp == 0 and gap > 0:
                rep.add("LOW", "structure", "Unused gap of %d bytes between BMP header and pixel data" % gap)
    except struct.error:
        pass
    return size if 54 <= size < len(d) else None


def analyze_lsb(px, ch, width, rep, opts, names):
    """px: raw sample bytes (ch channels per pixel), top-down row order."""
    npx = len(px) // ch
    if npx < 64:
        return
    combos = []
    if ch >= 3:
        combos += [("RGB", (0, 1, 2)), ("BGR", (2, 1, 0)), ("R", (0,)), ("G", (1,)), ("B", (2,))]
        if ch == 4:
            combos += [("RGBA", (0, 1, 2, 3)), ("A", (3,))]
    else:
        combos += [("Y", (0,))]
        if ch == 2:
            combos += [("A", (1,))]
    hits = []
    want = 4096 * 8
    for plane in ([0, 1] if opts["deep"] else [0]):
        for label, idx in combos:
            need = want // len(idx) + 1
            if len(idx) == 1:
                samp = px[idx[0]:need * ch:ch]
            else:
                samp = bytearray(need * len(idx))
                for j, c in enumerate(idx):
                    part = px[c:need * ch:ch]
                    samp[j:len(part) * len(idx):len(idx)] = part
                samp = bytes(samp[:min(need, npx) * len(idx)])
            bits = bytes((b >> plane) & 1 for b in samp[:want])
            bits = bits[:len(bits) // 8 * 8]
            sl = [bits[i::8] for i in range(8)]
            for order, s in (("msb-first", sl), ("lsb-first", sl[::-1])):
                payload = bytes(a << 7 | b << 6 | c << 5 | e << 4 | f << 3 | g << 2 | h << 1 | k
                                for a, b, c, e, f, g, h, k in zip(*s))
                tag = "%s bit %d, %s" % (label, plane, order)
                for skip in (0, 4):
                    sn = sniff(payload[skip:], strict=True)
                    if sn:
                        hits.append(("HIGH", tag, "%s header%s" % (sn[0], " after 4-byte length prefix" if skip else ""), payload))
                        break
                else:
                    m = re.search(rb"[\x20-\x7e\r\n\t]{24,}", payload[:2048])
                    if m and len(set(m.group())) >= 10 and \
                            collections.Counter(m.group()).most_common(1)[0][1] <= 0.3 * len(m.group()) and \
                            sum(1 for x in m.group() if chr(x).isalnum() or x == 32) / len(m.group()) >= 0.8:
                        hits.append(("HIGH" if m.start() < 16 else "MEDIUM", tag,
                                     "readable text: " + clean(m.group()[:160]), payload))
    seen = set()
    for sev, tag, what, payload in hits:
        if what in seen:
            continue
        seen.add(what)
        rep.add(sev, "stego", "LSB steganography: hidden data in pixel least-significant bits",
                ["channel order %s" % tag, what])
        rep.blob("lsb_%s.bin" % re.sub(r"\W+", "_", tag), payload)
    # chi-square (pairs of values) on growing prefixes of the colour samples
    col = px if ch in (1, 3) else (bytes(px[i] for i in range(len(px)) if i % ch != ch - 1) if len(px) < 3_000_000 else px)
    if len(col) >= 40000:
        ps = []
        for frac in range(1, 11):
            part = col[:len(col) * frac // 10]
            hist = collections.Counter(part)
            chi, k = 0.0, 0
            for v in range(0, 256, 2):
                a, b = hist.get(v, 0), hist.get(v + 1, 0)
                e = (a + b) / 2
                if e > 5:
                    chi += (a - e) ** 2 / e
                    k += 1
            ps.append(gammaincc((k - 1) / 2, chi / 2) if k >= 20 else None)
        if ps[0] is not None and ps[0] > 0.99:
            full = sum(1 for p in ps if p is not None and p > 0.95)
            if full == 10:
                rep.add("LOW", "stego", "Pixel LSB plane is statistically indistinguishable from random",
                        "Consistent with full-capacity encrypted LSB embedding, but also with noisy or synthetic images. Weak signal on its own.")
            elif ps[-1] is not None and ps[-1] < 0.05:
                rep.add("MEDIUM", "stego", "Statistical signature of sequential LSB embedding (chi-square test)",
                        "The first ~%d%% of the sampled pixels have a randomised LSB plane, the rest look natural. "
                        "Typical of an encrypted/compressed payload written from the top of the image." % (full * 10))
    if ch == 4 and len(px) < 8_000_000:
        hidden = set()
        cnt = 0
        for i in range(3, len(px), 4):
            if px[i] == 0:
                cnt += 1
                if len(hidden) < 64:
                    hidden.add(px[i - 3:i])
        if cnt > 200 and len(hidden) > 32:
            rep.add("LOW", "stego", "Fully transparent pixels carry varied colour data",
                    "%d invisible pixels (alpha 0) hold non-uniform colours; an image or data can hide under transparency." % cnt)


def analyze_jpeg(d, rep, opts):
    i, n = 2, len(d)
    end = None
    mpf = False
    apps = collections.Counter()
    while i + 2 <= n:
        if d[i] != 0xFF:
            rep.add("LOW", "structure", "JPEG segment structure is broken at %s" % hx(i), offset=i)
            break
        m = d[i + 1]
        if m == 0xFF:
            i += 1
            continue
        if m == 0xD9:
            end = i + 2
            break
        if m == 0x01 or 0xD0 <= m <= 0xD8:
            i += 2
            continue
        if i + 4 > n:
            break
        ln = struct.unpack_from(">H", d, i + 2)[0]
        seg = d[i + 4:i + 2 + ln]
        if m == 0xE1 and seg[:6] == b"Exif\0\0":
            parse_tiff(seg[6:], rep)
        elif m == 0xE2 and seg[:4] == b"MPF\0":
            mpf = True
        elif m == 0xFE:
            rep.meta("JPEG", "Comment", seg.decode("utf-8", "replace"))
            rep.add("INFO", "metadata", "JPEG comment segment", clean(seg[:300]))
        elif m == 0xED:
            rep.meta("JPEG", "Photoshop/IPTC block", "%d bytes" % len(seg))
        if 0xE0 <= m <= 0xEF:
            apps["APP%d" % (m - 0xE0)] += len(seg)
        i += 2 + ln
        if m == 0xDA:
            rep.jpeg_sos = i
            j = i
            while True:
                j = d.find(b"\xff", j)
                if j < 0 or j + 1 >= n:
                    j = -1
                    break
                c = d[j + 1]
                if c == 0 or 0xD0 <= c <= 0xD7:
                    j += 2
                elif c == 0xFF:
                    j += 1
                else:
                    break
            if j < 0:
                break
            i = j
    if apps:
        rep.meta("JPEG", "APP segments", ", ".join("%s (%d B)" % kv for kv in sorted(apps.items())))
    if end is None:
        rep.add("LOW", "structure", "JPEG has no end-of-image marker (truncated or corrupt)")
    rep.jpeg_mpf = mpf
    return end


def analyze_gif(d, rep, opts):
    n = len(d)
    try:
        flags = d[10]
        i = 13 + (3 * (2 << (flags & 7)) if flags & 0x80 else 0)

        def subblocks(i):
            out = bytearray()
            while i < n and d[i]:
                out += d[i + 1:i + 1 + d[i]]
                i += 1 + d[i]
            return i + 1, bytes(out)

        while i < n:
            b = d[i]
            if b == 0x3B:
                return i + 1
            if b == 0x21:
                label = d[i + 1]
                i, body = subblocks(i + 2)
                if label == 0xFE:
                    rep.meta("GIF", "Comment", body.decode("utf-8", "replace"))
                    rep.add("INFO", "metadata", "GIF comment block", clean(body[:300]))
                elif label == 0xFF:
                    rep.meta("GIF", "Application extension", body[:11].decode("latin1"))
            elif b == 0x2C:
                lf = d[i + 9]
                i += 10 + (3 * (2 << (lf & 7)) if lf & 0x80 else 0)
                i, _ = subblocks(i + 1)
            else:
                rep.add("LOW", "structure", "GIF block structure is broken at %s" % hx(i), offset=i)
                return None
    except IndexError:
        pass
    rep.add("LOW", "structure", "GIF has no trailer (truncated or corrupt)")
    return None


def analyze_riff(d, rep, opts):
    size = struct.unpack_from("<I", d, 4)[0] + 8
    size += size & 1
    i = 12
    while i + 8 <= min(len(d), size):
        cc, ln = d[i:i + 4], struct.unpack_from("<I", d, i + 4)[0]
        if cc == b"EXIF":
            body = d[i + 8:i + 8 + ln]
            parse_tiff(body[6:] if body[:6] == b"Exif\0\0" else body, rep)
        elif cc == b"LIST" and d[i + 8:i + 12] == b"INFO":
            j = i + 12
            while j + 8 <= i + 8 + ln:
                k, l2 = d[j:j + 4], struct.unpack_from("<I", d, j + 4)[0]
                rep.meta("RIFF INFO", k.decode("latin1"), d[j + 8:j + 8 + l2].split(b"\0")[0].decode("utf-8", "replace"))
                j += 8 + l2 + (l2 & 1)
        i += 8 + ln + (ln & 1)
    return size if size < len(d) else None


def pdf_str(tok):
    try:
        if tok[:1] == b"<":
            raw = bytes.fromhex(re.sub(rb"\s", b"", tok[1:-1]).decode() + ("0" if len(re.sub(rb"\s", b"", tok[1:-1])) % 2 else ""))
        else:
            raw = re.sub(rb"\\([0-7]{1,3})", lambda m: bytes([int(m.group(1), 8) & 255]), tok[1:-1])
            for a, b in ((rb"\n", b"\n"), (rb"\r", b"\r"), (rb"\t", b"\t"), (rb"\(", b"("), (rb"\)", b")"), (b"\\\\", b"\\")):
                raw = raw.replace(a, b)
        if raw[:2] == b"\xfe\xff":
            return raw[2:].decode("utf-16-be", "replace")
        return raw.decode("utf-8") if raw[:3] == b"\xef\xbb\xbf" else raw.decode("latin1")
    except (ValueError, UnicodeDecodeError):
        return tok.decode("latin1")


PDF_KW = [b"/JavaScript", b"/JS", b"/OpenAction", b"/AA", b"/Launch", b"/EmbeddedFile", b"/RichMedia",
          b"/XFA", b"/AcroForm", b"/URI", b"/Encrypt", b"/ObjStm", b"/GoToR", b"/GoToE", b"/SubmitForm",
          b"/ImportData"]
RE_PDF_INFO = re.compile(rb"/(Title|Author|Subject|Keywords|Creator|Producer|CreationDate|ModDate|Company)"
                         rb"\s*(\((?:\\.|[^\\)]){0,400}\)|<[0-9A-Fa-f\s]{2,800}>)")


def analyze_pdf(d, rep, opts):
    rep.meta("PDF", "Header version", d[5:8].decode("latin1"))
    texts = [d]
    budget = 96 << 20
    nstreams = 0
    for m in re.finditer(rb"stream\r?\n", d):
        s = m.end()
        e = d.find(b"endstream", s)
        if e < 0:
            break
        nstreams += 1
        hdr = d[max(0, m.start() - 400):m.start()]
        if b"FlateDecode" not in hdr and b"/Fl" not in hdr:
            continue
        try:
            out = zlib.decompressobj().decompress(d[s:e], 8 << 20)
        except zlib.error:
            continue
        if b"/" in out[:4000] and printable_ratio(out[:512]) > 0.85 and budget > 0:
            texts.append(out)
            budget -= len(out)
    blob = b"\n".join(texts)
    if re.search(rb"/[A-Za-z]*#[4-7][0-9A-Fa-f]", blob):
        rep.add("MEDIUM", "pdf", "PDF names are hex-obfuscated (e.g. /J#61vaScript)",
                "Legitimate generators do not do this; it is used to evade scanners.")
    norm = re.sub(rb"#([0-9A-Fa-f]{2})", lambda m: bytes([int(m.group(1), 16)]), blob)
    c = {k: len(re.findall(re.escape(k) + rb"(?![A-Za-z0-9])", norm)) for k in PDF_KW}
    rep.meta("PDF", "Structure", "%d streams; " % nstreams + ", ".join("%s×%d" % (k.decode(), v) for k, v in c.items() if v))
    js = c[b"/JavaScript"] + c[b"/JS"]
    auto = c[b"/OpenAction"] + c[b"/AA"]
    if js:
        snippet = re.search(rb"/JS\s*(\((?:\\.|[^\\)]){0,300})", norm)
        rep.add("HIGH" if auto else "MEDIUM", "pdf",
                "PDF contains JavaScript" + (" that runs automatically (OpenAction/AA)" if auto else ""),
                ["code starts: " + clean(snippet.group(1)[1:200])] if snippet else [])
    elif auto:
        rep.add("LOW", "pdf", "PDF has an automatic action on open (/OpenAction or /AA)")
    if c[b"/Launch"]:
        rep.add("HIGH", "pdf", "PDF can launch an external program or file (/Launch)")
    if c[b"/EmbeddedFile"]:
        names = [pdf_str(x) for x in re.findall(rb"/Type\s*/Filespec[^>]{0,200}?/U?F\s*(\((?:\\.|[^\\)]){0,200}\))", norm)[:10]]
        rep.add("MEDIUM", "pdf", "PDF carries %d embedded file(s)" % c[b"/EmbeddedFile"], names)
    for k, why in ((b"/RichMedia", "Flash/rich media"), (b"/XFA", "XFA form (scriptable)"),
                   (b"/GoToR", "jumps to a remote document"), (b"/GoToE", "jumps into an embedded document"),
                   (b"/SubmitForm", "submits form data to a URL"), (b"/ImportData", "imports external data")):
        if c[k]:
            rep.add("LOW", "pdf", "PDF uses %s: %s" % (k.decode(), why))
    if c[b"/Encrypt"]:
        rep.add("INFO", "pdf", "PDF is encrypted; content streams could not be inspected")
    uris = list(dict.fromkeys(pdf_str(x) for x in re.findall(rb"/URI\s*(\((?:\\.|[^\\)]){1,300}\))", norm)))
    if uris:
        rep.add("INFO", "pdf", "%d link target(s) in PDF" % len(uris), uris[:40])
    eofs = len(re.findall(rb"%%EOF", d)) - (1 if b"/Linearized" in d[:2048] else 0)
    if eofs > 1:
        rep.add("LOW", "pdf", "PDF has %d incremental update%s" % (eofs - 1, "" if eofs == 2 else "s"),
                "Earlier revisions stay inside the file; text or images 'removed' later can often be recovered.")
    for k, v in RE_PDF_INFO.findall(blob)[:80]:
        rep.meta("PDF info", k.decode(), pdf_str(v))
    e = d.rfind(b"%%EOF")
    if e < 0:
        rep.add("LOW", "structure", "PDF has no %%EOF marker (truncated or corrupt)")
        return None
    e += 5
    while e < len(d) and d[e] in b"\r\n \t":
        e += 1
    return e


def zread(zf, name, limit=24 << 20):
    try:
        info = zf.getinfo(name)
        if info.file_size > limit:
            return b""
        return zf.read(name)
    except Exception:
        return b""


AUTOEXEC = [b"AutoOpen", b"Auto_Open", b"Document_Open", b"Workbook_Open", b"AutoExec", b"AutoClose",
            b"Document_Close", b"Shell", b"CreateObject", b"URLDownloadToFile", b"powershell", b"WScript",
            b"GetObject", b"Environ", b"MSXML2", b"ADODB.Stream", b"cmd.exe"]


def analyze_zip(d, rep, opts):
    n = len(d)
    eocd = d.rfind(b"PK\x05\x06")
    end = None
    if eocd >= 0 and eocd + 22 <= n:
        cd_size, cd_off, clen = struct.unpack_from("<IIH", d, eocd + 12)
        end = min(n, eocd + 22 + clen)
        if clen:
            rep.add("LOW", "archive", "ZIP archive comment (%d bytes)" % clen, clean(d[eocd + 22:eocd + 22 + clen][:300]))
        if cd_off != 0xFFFFFFFF and cd_size != 0xFFFFFFFF:
            pre = eocd - cd_size - cd_off
            if pre > 0:
                sn = sniff(d[:65536])
                what = sn[0] if sn and sn[1] != "zip" else "unknown data"
                rep.add("MEDIUM" if sn and sn[1] in ("pe", "elf") else "HIGH", "structure",
                        "%s of data placed in front of the ZIP archive (polyglot file)" % human(pre),
                        "The file opens as a ZIP but starts as: %s. Self-extracting archives look like this; so do files built to be two things at once." % what)
    try:
        zf = zipfile.ZipFile(rep.path)
    except Exception as ex:
        rep.add("LOW", "structure", "ZIP directory cannot be read: %s" % clean(ex, 100))
        return end
    with zf:
        infos = zf.infolist()
        names = [i.filename for i in infos]
        nameset = set(names)
        usize = sum(i.file_size for i in infos)
        csize = sum(i.compress_size for i in infos) or 1
        rep.meta("ZIP", "Entries", "%d files, %s uncompressed (ratio %.0f:1)" % (len(infos), human(usize), usize / csize))
        if "[Content_Types].xml" in nameset:
            rep.subtype = "ooxml"
            app = "Word" if any(x.startswith("word/") for x in names) else "Excel" if any(x.startswith("xl/") for x in names) \
                else "PowerPoint" if any(x.startswith("ppt/") for x in names) else "Office"
            rep.identity["Type"] = "Microsoft %s document (OOXML)" % app
        elif "mimetype" in nameset:
            mt = zread(zf, "mimetype", 200).decode("latin1").strip()
            rep.identity["Type"] = "ZIP container: %s" % clean(mt, 80)
            rep.subtype = "odf" if "opendocument" in mt else "epub" if "epub" in mt else ""
        elif "AndroidManifest.xml" in nameset:
            rep.subtype, rep.identity["Type"] = "apk", "Android application package (APK)"
        elif "META-INF/MANIFEST.MF" in nameset:
            rep.subtype, rep.identity["Type"] = "jar", "Java archive (JAR)"
        enc = [i.filename for i in infos if i.flag_bits & 1]
        if enc:
            rep.add("MEDIUM", "archive", "%d password-protected entr%s" % (len(enc), "y" if len(enc) == 1 else "ies"),
                    enc[:10] + ["Encrypted entries cannot be inspected by this or any scanner."])
        bad = [x for x in names if x.startswith(("/", "\\")) or ".." in x.replace("\\", "/").split("/") or re.match(r"^[A-Za-z]:", x)]
        if bad:
            rep.add("HIGH", "archive", "Entries with path traversal names (zip-slip)", bad[:10])
        if usize > (200 << 20) and usize / csize > 100:
            rep.add("MEDIUM", "archive", "Extreme compression ratio (possible zip bomb)", "%s expands to %s" % (human(csize), human(usize)))
        for i in infos:
            if i.comment:
                rep.add("LOW", "archive", "Per-entry ZIP comment on %s" % i.filename, clean(i.comment[:200]))
        # local headers not in the central directory
        local = 0
        pos = 0
        while local < 200000:
            pos = d.find(b"PK\x03\x04", pos)
            if pos < 0:
                break
            if _zip_local_ok(d[pos:pos + 1100]):
                local += 1
            pos += 4
        if local > len(infos) and rep.logical_end is None and n == os.path.getsize(rep.path):
            rep.add("LOW", "archive", "%d local file header(s) are not listed in the ZIP directory" % (local - len(infos)),
                    "Either nested archives stored without compression, or entries deliberately removed from the index so normal tools do not show them.")
        # member content checks
        doc = rep.subtype in ("ooxml", "odf", "epub")
        execs, mism = [], []
        for i in infos[:opts["zip_members"]]:
            if i.is_dir() or i.flag_bits & 1 or not i.file_size:
                continue
            try:
                with zf.open(i) as fh:
                    head = fh.read(4096)
            except Exception:
                continue
            sn = sniff(head, strict=True) or (sniff(head) if head[:2] == b"#!" else None)
            if not sn:
                continue
            ext = i.filename.rsplit(".", 1)[-1].lower() if "." in os.path.basename(i.filename) else ""
            if sn[1] in EXEC_KINDS and rep.subtype not in ("apk", "jar"):
                execs.append("%s  (%s)" % (i.filename, sn[0]))
            if sn[2] and ext in ALL_EXTS and ext not in sn[2] and sn[1] in EXEC_KINDS | ARCHIVE_KINDS:
                mism.append("%s is really: %s" % (i.filename, sn[0]))
        if mism:
            rep.add("HIGH", "archive", "Archive entries whose content does not match their extension", mism[:15])
        if execs:
            rep.add("HIGH" if doc else "MEDIUM", "archive", "%d executable/script entr%s inside the archive" %
                    (len(execs), "y" if len(execs) == 1 else "ies"), execs[:15])
        if rep.subtype == "ooxml":
            analyze_ooxml(zf, names, rep)
        elif rep.subtype == "odf":
            for g, k, v in re.findall(r"<(meta|dc):([\w-]+)[^>]*>([^<]{1,300})<", zread(zf, "meta.xml").decode("utf-8", "replace")):
                rep.meta("ODF", k, html.unescape(v))
            if any(x.startswith(("Basic/", "Scripts/")) for x in names):
                rep.add("HIGH", "macro", "OpenDocument file contains macros/scripts",
                        [x for x in names if x.startswith(("Basic/", "Scripts/"))][:10])
    return end


def analyze_ooxml(zf, names, rep):
    for g, k, v in re.findall(r"<(dc|cp|dcterms):(\w+)[^>]*>([^<]{1,300})<", zread(zf, "docProps/core.xml").decode("utf-8", "replace")):
        rep.meta("Office", k, html.unescape(v))
    for k, v in re.findall(r"<(Application|AppVersion|Company|Manager|Template|TotalTime|Pages|Words|HyperlinkBase)>([^<]{1,300})<",
                           zread(zf, "docProps/app.xml").decode("utf-8", "replace")):
        rep.meta("Office", k, html.unescape(v))
    for k, v in re.findall(r'<property[^>]*name="([^"]{1,80})"[^>]*>\s*<vt:\w+>([^<]{1,300})<',
                           zread(zf, "docProps/custom.xml").decode("utf-8", "replace")):
        rep.meta("Office custom", k, html.unescape(v))
    vba = [x for x in names if x.lower().endswith(("vbaproject.bin", "vbadata.xml")) and x.lower().endswith(".bin")]
    if vba:
        kws = set()
        for x in vba:
            body = zread(zf, x)
            kws |= {k.decode() for k in AUTOEXEC if re.search(re.escape(k), body, re.I)}
            rep.blob("vbaProject.bin", body)
        rep.add("HIGH", "macro", "Document contains VBA macros", vba +
                (["keywords seen in macro storage: " + ", ".join(sorted(kws))] if kws else []) +
                ["Install oletools and run `olevba` on the file to read the macro source."])
    if any(x.startswith("xl/macrosheets/") for x in names):
        rep.add("HIGH", "macro", "Workbook contains Excel 4.0 (XLM) macro sheets",
                [x for x in names if x.startswith("xl/macrosheets/")][:10])
    ext_hi, ext_other, links = [], [], 0
    for x in names:
        if not x.endswith(".rels"):
            continue
        for tag in re.findall(r"<Relationship\b[^>]*>", zread(zf, x).decode("utf-8", "replace")):
            if 'TargetMode="External"' not in tag:
                continue
            typ = (re.search(r'Type="[^"]*/([^"/]+)"', tag) or [None, "?"])[1]
            tgt = html.unescape((re.search(r'Target="([^"]*)"', tag) or [None, ""])[1])
            if typ == "hyperlink":
                links += 1
            elif typ in ("attachedTemplate", "oleObject", "frame", "subDocument", "externalLinkPath") or tgt.lower().startswith(("\\\\", "file:")):
                ext_hi.append("%s -> %s" % (typ, tgt))
            else:
                ext_other.append("%s -> %s" % (typ, tgt))
    if ext_hi:
        rep.add("HIGH", "macro", "Document loads content from an external location when opened",
                ext_hi[:15] + ["Remote templates/objects are a standard way to deliver macros or leak credentials (UNC paths)."])
    if ext_other:
        rep.add("MEDIUM", "macro", "External (non-hyperlink) references in the document", ext_other[:15])
    if links:
        rep.meta("Office", "External hyperlinks", str(links))
    emb = [x for x in names if "/embeddings/" in x or "/activeX/" in x]
    if emb:
        rep.add("MEDIUM", "embedded", "%d embedded object(s) / ActiveX control(s) in document" % len(emb), emb[:15])
    if any("ddeLink" in zread(zf, x).decode("utf-8", "replace") for x in names if x.startswith("xl/externalLinks/") and x.endswith(".xml")):
        rep.add("HIGH", "macro", "Workbook contains DDE links (can execute commands)")
    doc = zread(zf, "word/document.xml").decode("utf-8", "replace")
    if doc:
        dels, ins = len(re.findall(r"<w:del\b", doc)), len(re.findall(r"<w:ins\b", doc))
        if dels or ins:
            gone = " ".join(re.findall(r"<w:delText[^>]*>([^<]+)<", doc))[:300]
            rep.add("LOW", "hidden", "Tracked changes are still in the document (%d deletions, %d insertions)" % (dels, ins),
                    ["deleted text still stored: " + html.unescape(gone)] if gone else [])
        hid = re.findall(r"<w:r>(?:(?!</w:r>).)*?<w:vanish\s*/>(?:(?!</w:r>).)*?<w:t[^>]*>([^<]+)<", doc, re.S)
        if "<w:vanish" in doc:
            rep.add("MEDIUM", "hidden", "Document contains text formatted as hidden",
                    ["hidden text: " + html.unescape(" ".join(hid))[:300]] if hid else [])
        if "DDEAUTO" in doc or re.search(r"instr[^>]*>\s*DDE\b", doc):
            rep.add("HIGH", "macro", "Word document contains a DDE field (can execute commands)")
    nc = len(re.findall(r"<w:comment\b", zread(zf, "word/comments.xml").decode("utf-8", "replace")))
    if nc:
        rep.add("LOW", "hidden", "%d reviewer comment(s) stored in the document" % nc)
    wb = zread(zf, "xl/workbook.xml").decode("utf-8", "replace")
    hs = [(re.search(r'name="([^"]*)"', t) or [0, "?"])[1] + " (" + s + ")"
          for t, s in re.findall(r'(<sheet\b[^>]*state="(hidden|veryHidden)"[^>]*>)', wb)]
    if hs:
        rep.add("MEDIUM" if any("veryHidden" in x for x in hs) else "LOW", "hidden", "Workbook has hidden sheets",
                [html.unescape(x) for x in hs] + ["'veryHidden' sheets cannot be unhidden from the Excel UI."])
    hsl = [x for x in names if re.match(r"ppt/slides/slide\d+\.xml$", x) and b'show="0"' in zread(zf, x)[:600]]
    if hsl:
        rep.add("LOW", "hidden", "%d hidden slide(s) in presentation" % len(hsl), hsl[:10])


def analyze_ole(d, rep, opts):
    u = lambda s: s.encode("utf-16-le")
    if u("_VBA_PROJECT") in d or u("Macros") in d or b"_VBA_PROJECT" in d:
        kws = sorted({k.decode() for k in AUTOEXEC if re.search(re.escape(k), d, re.I)})
        rep.add("HIGH", "macro", "Legacy Office document contains VBA macro storage",
                (["keywords seen: " + ", ".join(kws)] if kws else []) +
                ["Install oletools and run `olevba` on the file to read the macro source."])
    if u("EncryptedPackage") in d:
        rep.add("MEDIUM", "structure", "Password-protected Office document (EncryptedPackage)", "Content cannot be inspected without the password.")
    if b"Equation.3" in d or u("Equation Native") in d:
        rep.add("MEDIUM", "embedded", "Equation Editor object present", "Frequently abused (CVE-2017-11882 / CVE-2018-0802).")
    if u("\x01Ole10Native") in d or b"Package\0" in d:
        rep.add("MEDIUM", "embedded", "OLE Package object (an arbitrary embedded file) present")
    if b"Excel 4.0" in d and b"Macro" in d:
        rep.add("MEDIUM", "macro", "Possible Excel 4.0 macro sheet")
    return None


def analyze_rtf(d, rep, opts):
    obj = len(re.findall(rb"\\objdata", d))
    if obj:
        auto = b"\\objupdate" in d
        rep.add("HIGH" if auto else "MEDIUM", "embedded", "RTF contains %d embedded OLE object(s)%s" %
                (obj, ", updated automatically on open" if auto else ""))
    if re.search(rb"\\template\b|INCLUDEPICTURE\s+\\?\"?(?:https?:|\\\\\\\\)", d):
        rep.add("HIGH", "macro", "RTF references a remote template or remote picture")
    e = d.rfind(b"}")
    return e + 1 if e > 0 and d[e + 1:].strip(b"\r\n\t \0") else None


def analyze_pe(d, rep, opts):
    try:
        o = struct.unpack_from("<I", d, 0x3C)[0]
        if d[o:o + 4] != b"PE\0\0":
            return None
        mach, nsec, ts = struct.unpack_from("<HHI", d, o + 4)
        optsz, chars = struct.unpack_from("<HH", d, o + 20)
        opt = o + 24
        pe64 = struct.unpack_from("<H", d, opt)[0] == 0x20B
        rep.meta("PE", "Machine", {0x14C: "x86", 0x8664: "x64", 0xAA64: "ARM64", 0x1C0: "ARM"}.get(mach, hex(mach)))
        rep.meta("PE", "Kind", ("DLL" if chars & 0x2000 else "EXE") + (", 64-bit" if pe64 else ", 32-bit"))
        if 0 < ts < 0xFFFFFFF0:
            rep.meta("PE", "Compile timestamp", dt.datetime.fromtimestamp(ts, dt.timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC"))
        end = 0
        dd = opt + (112 if pe64 else 96)
        signed = False
        if dd + 40 <= opt + optsz:
            coff, csz = struct.unpack_from("<II", d, dd + 32)
            if coff and csz:
                signed = True
                end = max(end, coff + csz)
        rep.meta("PE", "Authenticode signature", "present (not verified)" if signed else "none")
        packed = []
        for i in range(min(nsec, 96)):
            s = opt + optsz + i * 40
            name = d[s:s + 8].rstrip(b"\0").decode("latin1")
            rsz, rptr = struct.unpack_from("<II", d, s + 16)
            end = max(end, rptr + rsz)
            if rsz > 2048:
                h = entropy(d[rptr:rptr + min(rsz, 4 << 20)])
                if h > 7.3 and name not in (".rsrc", ".reloc"):
                    packed.append("%s entropy %.2f" % (clean(name), h))
            if name.upper().startswith(("UPX", ".ASPACK", ".THEMIDA", ".VMP", ".MPRESS", ".PETITE", ".ENIGMA")):
                packed.append("section name %s (known packer)" % clean(name))
        if packed:
            rep.add("MEDIUM", "entropy", "Executable looks packed or encrypted", packed[:10])
        return end if 0 < end < len(d) else None
    except struct.error:
        return None


def analyze_elf(d, rep, opts):
    try:
        e = "<" if d[5] == 1 else ">"
        is64 = d[4] == 2
        mach = struct.unpack_from(e + "H", d, 18)[0]
        rep.meta("ELF", "Architecture", {3: "x86", 62: "x86-64", 40: "ARM", 183: "AArch64", 8: "MIPS", 243: "RISC-V"}.get(mach, str(mach))
                 + (", 64-bit" if is64 else ", 32-bit"))
        if is64:
            phoff, shoff = struct.unpack_from(e + "QQ", d, 32)
            phsz, phn, shsz, shn = struct.unpack_from(e + "HHHH", d, 54)
        else:
            phoff, shoff = struct.unpack_from(e + "II", d, 28)
            phsz, phn, shsz, shn = struct.unpack_from(e + "HHHH", d, 42)
        end = max(phoff + phsz * phn, shoff + shsz * shn)
        for i in range(phn):
            p = phoff + i * phsz
            off, fsz = (struct.unpack_from(e + "Q", d, p + 8)[0], struct.unpack_from(e + "Q", d, p + 32)[0]) if is64 \
                else struct.unpack_from(e + "II", d, p + 4)[0:1] + struct.unpack_from(e + "I", d, p + 16)
            end = max(end, off + fsz)
        for i in range(shn):
            s = shoff + i * shsz
            if is64:
                typ = struct.unpack_from(e + "I", d, s + 4)[0]
                off, sz = struct.unpack_from(e + "QQ", d, s + 24)
            else:
                typ = struct.unpack_from(e + "I", d, s + 4)[0]
                off, sz = struct.unpack_from(e + "II", d, s + 16)
            if typ != 8:
                end = max(end, off + sz)
        if shn == 0:
            rep.add("LOW", "structure", "ELF has no section headers (stripped hard, common for packed binaries)")
        if b"UPX!" in d[:4096] or b"$Info: This file is packed with the UPX" in d:
            rep.add("MEDIUM", "entropy", "ELF is packed with UPX")
        return end if 0 < end < len(d) else None
    except (struct.error, IndexError):
        return None


FORMATS = {"png": analyze_png, "jpeg": analyze_jpeg, "gif": analyze_gif, "bmp": analyze_bmp, "pdf": analyze_pdf,
           "zip": analyze_zip, "ole": analyze_ole, "rtf": analyze_rtf, "pe": analyze_pe, "elf": analyze_elf,
           "webp": analyze_riff, "wav": analyze_riff, "avi": analyze_riff}

# --------------------------------------------------------------------------
# generic analysers
# --------------------------------------------------------------------------

EMBED_MAGICS = [b"\x89PNG\r\n\x1a\n", b"\xff\xd8\xff", b"%PDF-", b"PK\x03\x04", b"MZ", b"\x7fELF",
                b"7z\xbc\xaf\x27\x1c", b"Rar!\x1a\x07", b"\x1f\x8b\x08", b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1",
                b"SQLite format 3\x00", b"GIF89a", b"GIF87a", b"\xfd7zXZ\x00", b"{\\rtf"]


def scan_signatures(d, start, end, maxhits=40):
    """Validated file signatures inside d[start:end] -> {kind: (desc, [offsets])}."""
    found = collections.OrderedDict()
    for magic in EMBED_MAGICS:
        pos = start
        while True:
            i = d.find(magic, pos, end)
            if i < 0:
                break
            pos = i + 1
            sn = sniff(d[i:i + 70000], strict=True)
            if sn:
                ent = found.setdefault(sn[1], (sn[0], []))
                if len(ent[1]) >= maxhits:
                    break
                ent[1].append(i)
    return found


def analyze_embedded(d, rep):
    kind = rep.kind
    if kind in ARCHIVE_KINDS:
        return
    end = rep.logical_end if rep.logical_end else len(d)
    found = scan_signatures(d, 1, end)
    for k, (desc, offs) in found.items():
        if kind == "jpeg" and k == "jpeg":
            offs = [o for o in offs if o >= getattr(rep, "jpeg_sos", 0)]
        if kind == "pdf" and k == "jpeg":
            continue
        if kind in ("mp4", "mkv", "avi", "mp3", "flac", "ogg", "heif", "psd", "tiff") and k in ("jpeg", "png"):
            continue
        if not offs:
            continue
        container = kind in ("pe", "elf", "macho", "ole", "sqlite", "iso", "mp4", "mkv")
        if k in ("pe", "elf"):
            sev = "MEDIUM" if container else "HIGH"
        elif k in ("zip", "7z", "rar", "gzip", "xz", "ole", "sqlite", "rtf"):
            sev = "LOW" if container else "MEDIUM"
        else:
            sev = "INFO" if container else "LOW"
        rep.add(sev, "embedded", "%s embedded inside the file (%d occurrence%s)" % (desc, len(offs), "" if len(offs) == 1 else "s"),
                "at offset " + ", ".join(hx(o) for o in offs[:8]) + (" …" if len(offs) > 8 else ""), offs[0])
        if sev in ("HIGH", "MEDIUM"):
            rep.blob("embedded_%s_at_%s.bin" % (k, hx(offs[0])), d[offs[0]:end])


def report_trailing(d, rep):
    end = rep.logical_end
    if not end or end >= len(d):
        return
    tail = d[end:]
    if not tail.strip(b"\0\r\n\t "):
        rep.add("INFO", "trailing", "%d bytes of padding after the end of the %s data" % (len(tail), rep.kind), offset=end)
        return
    sn = sniff(tail[:70000])
    inner = scan_signatures(tail, 0, min(len(tail), 64 << 20), 5)
    what = sn[0] if sn else ("text: " + clean(tail[:120]) if printable_ratio(tail[:512]) > 0.9
                             else "unrecognised binary, entropy %.2f/8" % entropy(tail[:1 << 20]))
    detail = ["%s (%d bytes) starting at offset %s" % (human(len(tail)), len(tail), hx(end)), "looks like: " + what]
    extra = [v[0] for k, v in inner.items() if not sn or k != sn[1]]
    if extra:
        detail.append("also contains: " + ", ".join(extra))
    kinds = set(inner) | ({sn[1]} if sn else set())
    if len(tail) <= 512 and printable_ratio(tail) > 0.95 and not kinds - {"text", "script"}:
        rep.add("LOW", "trailing", "Short text appended after the end of the %s" % rep.identity.get("Type", rep.kind),
                ["%d bytes at offset %s: %s" % (len(tail), hx(end), clean(tail, 300))], end)
        rep.blob("trailing_data_at_%s.bin" % hx(end), tail)
        return
    if rep.kind == "jpeg" and getattr(rep, "jpeg_mpf", False) and sn and sn[1] == "jpeg" and kinds <= {"jpeg"}:
        rep.add("LOW", "trailing", "Additional image(s) stored after the main JPEG (MPF)",
                detail + ["Normal for phone/camera photos (depth map, gain map, motion photo preview), but worth a look."], end)
    else:
        sev = "HIGH" if kinds & (EXEC_KINDS | ARCHIVE_KINDS | {"ole", "pdf"}) else "MEDIUM"
        if rep.kind in ("pe", "elf"):
            sev = "MEDIUM" if sev == "HIGH" else "LOW"
            detail.append("Overlay data on executables is used by installers and self-extractors, and by droppers.")
        rep.add(sev, "trailing", "Data appended after the end of the %s" % rep.identity.get("Type", rep.kind), detail, end)
    rep.blob("trailing_data_at_%s.bin" % hx(end), tail)


RE_U16 = re.compile(rb"(?:[\x20-\x7e]\x00){8,}")
RE_URL = re.compile(rb"(?:https?|ftp|wss?|file|smb|ldaps?|sftp)://[A-Za-z0-9\-._~:/?#\[\]@!$&'()*+,;=%]{4,300}")
RE_EMAIL = re.compile(rb"(?<![A-Za-z0-9._%+\-])[A-Za-z0-9._%+\-]{2,64}@[A-Za-z0-9\-]{1,63}(?:\.[A-Za-z0-9\-]{1,63}){0,4}\.([A-Za-z]{2,10})(?![A-Za-z0-9])")
RE_IP = re.compile(rb"(?<![\d.])(?:(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)\.){3}(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(?![\d.])")
RE_B64 = re.compile(rb"(?<![A-Za-z0-9+/])[A-Za-z0-9+/]{40,}={0,2}")
RE_HEXBLOB = re.compile(rb"(?<![0-9A-Fa-f])(?:4d5a9000|4D5A9000|504b0304|504B0304|7f454c46|7F454C46)[0-9A-Fa-f]{32,}")
SECRETS = [
    ("HIGH", "Private key", re.compile(rb"-----BEGIN (?:RSA |EC |DSA |OPENSSH |PGP |ENCRYPTED )?PRIVATE KEY(?: BLOCK)?-----")),
    ("MEDIUM", "AWS access key ID", re.compile(rb"(?<![A-Z0-9])(?:AKIA|ASIA)[0-9A-Z]{16}(?![A-Z0-9])")),
    ("MEDIUM", "GitHub token", re.compile(rb"(?:ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9]{36}|github_pat_[A-Za-z0-9_]{40,}")),
    ("MEDIUM", "Slack token", re.compile(rb"xox[baprs]-[A-Za-z0-9\-]{10,}")),
    ("MEDIUM", "Google API key", re.compile(rb"AIza[0-9A-Za-z_\-]{35}")),
    ("MEDIUM", "API secret key", re.compile(rb"(?<![A-Za-z0-9])sk-[A-Za-z0-9_\-]{24,}")),
    ("LOW", "JSON Web Token", re.compile(rb"eyJ[A-Za-z0-9_\-]{10,}\.eyJ[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}")),
    ("LOW", "Hard-coded credential", re.compile(rb"(?i)(?:password|passwd|pwd|secret|api[_\-]?key|auth[_\-]?token)\"?\s*[=:]\s*['\"]?([^\s'\"<>,;]{6,64})")),
]
RE_CMD = re.compile(
    rb"(?i)(powershell(?:\.exe)?\s+[^\n]{0,80}?-(?:enc\w*|e|nop\w*|w(?:indowstyle)?\s+hidden)\b[^\n]{0,40}"
    rb"|cmd(?:\.exe)?\s*/c\s+[^\n]{1,60}|WScript\.Shell|bash\s+-i\s+>&\s*/dev/tcp/[^\s]{1,40}|/dev/tcp/\d[^\s]{0,40}"
    rb"|\bnc(?:at)?\s+(?:-\w+\s+)*-e\s+\S{1,30}|certutil(?:\.exe)?\s+[^\n]{0,40}-decode|mshta(?:\.exe)?\s+\S{1,60}"
    rb"|regsvr32\s+/s[^\n]{0,60}|Invoke-Expression|\bIEX\s*\(|DownloadString\s*\(|URLDownloadToFile|FromBase64String"
    rb"|eval\s*\(\s*(?:base64_decode|atob|unescape|gzinflate)|(?:curl|wget)\s[^\n|]{0,120}\|\s*(?:sudo\s+)?(?:ba)?sh\b"
    rb"|bitsadmin\s+/transfer|schtasks\s+/create[^\n]{0,60}|vssadmin\s+delete\s+shadows)")
BENIGN_HOSTS = ("w3.org", "schemas.openxmlformats.org", "schemas.microsoft.com", "purl.org", "ns.adobe.com",
                "xmlsoap.org", "iptc.org", "aiim.org", "useplus.org", "cipa.jp", "xml.org", "ns.google.com",
                "www.iec.ch", "color.org", "npes.org", "gnu.org/licenses", "apache.org/licenses", "openoffice.org/20",
                "oasis-open.org", "creativecommons.org/ns", "inkscape.org/namespaces", "sodipodi.sourceforge.net")
BAD_URL = ("pastebin.com", "paste.ee", "hastebin", "discord.com/api/webhooks", "discordapp.com/api/webhooks",
           "ngrok", "bit.ly/", "tinyurl.com", "transfer.sh", "anonfiles", "api.telegram.org/bot", "duckdns.org",
           ".onion", "no-ip.", "serveo.net", "t.me/", "cdn.discordapp.com/attachments", "file.io", "gofile.io",
           "ipfs.io", "portmap.io", "trycloudflare.com", "webhook.site", "requestbin", "interact.sh", "oast.")


def analyze_strings(d, rep):
    u16 = b"\n".join(m.group().decode("utf-16-le").encode() for m in itertools.islice(RE_U16.finditer(d), 50000))

    def find(rx, cap=5000):
        return itertools.islice(itertools.chain(rx.finditer(d), rx.finditer(u16)), cap)

    urls = collections.OrderedDict()
    for m in find(RE_URL):
        u = m.group().decode("latin1").rstrip(".,;:)'\"]")
        if not any(h in u for h in BENIGN_HOSTS):
            urls[u] = 1
    urls = collections.OrderedDict((u, 1) for u in urls if not re.search(r"%[sd]|\$\{|\{\w*\}", u))
    bad = [u for u in urls if any(b in u.lower() for b in BAD_URL) or re.match(r"\w+://\d+\.\d+\.\d+\.\d+", u)
           or u.lower().startswith(("file:////", "file://\\\\", "smb://"))]
    if bad:
        rep.add("MEDIUM", "strings", "%d URL(s) pointing at raw IPs, paste/tunnel/webhook services or file shares" % len(bad), bad[:40])
    rest = [u for u in urls if u not in bad]
    if rest:
        rep.add("INFO", "strings", "%d URL(s) found" % len(rest), rest[:60])
    emails = collections.OrderedDict()
    for m in find(RE_EMAIL):
        if m.group(1).lower() not in (b"png", b"jpg", b"jpeg", b"gif", b"svg", b"webp", b"css", b"js", b"so", b"h", b"py"):
            emails[m.group().decode("latin1")] = 1
    if emails:
        rep.add("INFO", "strings", "%d e-mail address(es) found" % len(emails), list(emails)[:40])
    ips = collections.OrderedDict()
    for m in find(RE_IP):
        o = [int(x) for x in m.group().split(b".")]
        if o[0] == 0 or o[1:] == [0, 0, 0] or all(x < 20 for x in o) or o[0] >= 240 or o == [127, 0, 0, 1]:
            continue
        ctx = d[max(0, m.start() - 12):m.start()].lower() if m.string is d else b""
        if b"version" in ctx or b"ver" in ctx[-5:] or ctx.endswith((b"v", b"-", b"_")):
            continue
        ips[m.group().decode()] = 1
    if ips:
        priv = [i for i in ips if re.match(r"10\.|192\.168\.|172\.(1[6-9]|2\d|3[01])\.|169\.254\.", i)]
        rep.add("INFO", "strings", "%d IP address(es) found%s" % (len(ips), " (%d internal/private)" % len(priv) if priv else ""), list(ips)[:40])
    for sev, name, rx in SECRETS:
        vals = collections.OrderedDict()
        for m in find(rx, 200):
            v = m.group(m.lastindex or 0)
            if name == "Hard-coded credential" and (len(set(v)) < 4 or v.lower() in (b"password", b"string", b"required", b"undefined") or v.startswith((b"${", b"%s", b"{{", b"<"))):
                continue
            ctx = clean(m.group()[:24]) + "…" if name == "Hard-coded credential" else mask(v)
            vals[ctx] = 1
        if vals:
            rep.add(sev, "secrets", "%s found (%d)" % (name, len(vals)), list(vals)[:10])
    cmds = collections.OrderedDict()
    for m in find(RE_CMD, 300):
        cmds[clean(m.group()[:90])] = 1
    if cmds:
        rep.add("LOW" if rep.kind in ("pe", "elf", "script", "macho") else "MEDIUM", "strings",
                "Command-execution / downloader strings (%d)" % len(cmds), list(cmds)[:20])
    # base64 / hex encoded payloads
    nb64, big, hits, texts = 0, 0, [], []
    for m in find(RE_B64, 20000):
        s = m.group()
        if re.fullmatch(rb"[0-9a-fA-F]+", s) or re.fullmatch(rb"[A-Za-z]+", s) or b"/" in s[:40] and s.count(b"/") > len(s) // 8:
            continue
        core = s.rstrip(b"=")
        try:
            dec = base64.b64decode(core[:len(core) // 4 * 4][:8192])
        except Exception:
            continue
        nb64 += 1
        big = max(big, len(s))
        sn = sniff(dec, strict=True)
        if sn and len(hits) < 10:
            hits.append((sn, m.start() if m.string is d else None, s))
        elif len(texts) < 6 and printable_ratio(dec) > 0.95 and len(set(dec)) > 8:
            texts.append("%d chars -> %s" % (len(s), clean(dec[:100])))
    for sn, off, s in hits:
        rep.add("HIGH" if sn[1] in EXEC_KINDS else "MEDIUM", "embedded", "Base64-encoded %s inside the file" % sn[0],
                "%d base64 characters%s" % (len(s), " at offset %s" % hx(off) if off is not None else ""), off)
        try:
            rep.blob("base64_decoded_%s.bin" % sn[1], base64.b64decode(s.rstrip(b"=")[:len(s.rstrip(b"=")) // 4 * 4]))
        except Exception:
            pass
    if texts and rep.kind not in ("pdf",):
        rep.add("LOW", "strings", "Base64 strings that decode to readable text", texts)
    if nb64 and big >= 2000 and not hits:
        rep.add("INFO", "strings", "%d base64-looking blob(s), largest %d characters" % (nb64, big))
    for m in find(RE_HEXBLOB, 5):
        rep.add("HIGH", "embedded", "Hex-encoded executable/archive inside the file",
                "%d hex characters starting %s" % (len(m.group()), m.group()[:16].decode()))


def analyze_entropy(d, rep):
    n = len(d)
    H = entropy(d)
    rep.identity["Entropy"] = "%.2f / 8" % H
    if n < 4096:
        return
    block = max(1024, -(-n // 512))
    hs = [entropy(d[i:i + block]) for i in range(0, n, block)]
    rep.entropy_blocks = hs
    comp = rep.kind in COMPRESSED_KINDS or rep.subtype
    if rep.kind == "unknown" and H > 7.5:
        rep.add("MEDIUM", "entropy", "File is high-entropy with no recognisable format (%.2f/8)" % H,
                "Consistent with encrypted or compressed data without a header (e.g. an encrypted container or raw ciphertext).")
    elif rep.kind in ("text", "script") and H > 6.5:
        rep.add("LOW", "entropy", "Unusually high entropy for text (%.2f/8)" % H, "Large encoded or obfuscated blobs inside.")
    if comp or H >= 7.2:
        return
    regions = []
    i = 0
    while i < len(hs):
        if hs[i] >= 7.4:
            j = i
            while j < len(hs) and hs[j] >= 7.2:
                j += 1
            if (j - i) * block >= max(8192, 3 * block):
                regions.append((i * block, min(n, j * block) - i * block))
            i = j
        else:
            i += 1
    if regions:
        rep.add("LOW" if rep.kind in ("pe", "elf", "macho", "ole", "sqlite", "tar", "iso") else "MEDIUM", "entropy",
                "%d high-entropy region(s) inside an otherwise low-entropy file" % len(regions),
                ["%s at offset %s" % (human(sz), hx(off)) for off, sz in regions[:8]] +
                ["Possible encrypted or compressed payload."])


ZW = {"\u200b", "\u200c", "\u200d", "\u2060", "\u180e", "\ufeff", "\u2061", "\u2062", "\u2063", "\u2064"}
BIDI = {"\u202a", "\u202b", "\u202c", "\u202d", "\u202e", "\u2066", "\u2067", "\u2068", "\u2069"}


def zw_decode(seq):
    cnt = collections.Counter(seq).most_common(2)
    if len(cnt) < 2 or len(seq) < 16:
        return None
    a, b = cnt[0][0], cnt[1][0]
    for z, o in ((a, b), (b, a)):
        bits = "".join("0" if c == z else "1" for c in seq if c in (a, b))
        by = bytes(int(bits[i:i + 8], 2) for i in range(0, len(bits) - 7, 8))
        if len(by) >= 2 and sum(32 <= x < 127 for x in by) / len(by) > 0.85:
            return by.decode("latin1")
    return None


def analyze_text(d, rep, ext):
    raw = d[:32 << 20]
    try:
        t = raw.decode("utf-16") if raw[:2] in (b"\xff\xfe", b"\xfe\xff") else raw.decode("utf-8", "ignore")
    except UnicodeDecodeError:
        return
    body = t[1:] if t[:1] == "\ufeff" else t
    zw = [c for c in body if c in ZW]
    if zw:
        dec = zw_decode(zw)
        rep.add("HIGH" if dec else ("MEDIUM" if len(zw) >= 8 else "LOW"), "unicode",
                "%d invisible zero-width character(s) in text" % len(zw),
                (["decodes as binary to: " + dec] if dec else []) +
                ["kinds: " + ", ".join("U+%04X×%d" % (ord(k), v) for k, v in collections.Counter(zw).most_common(5)),
                 "Used for zero-width steganography and for fingerprinting copies of a text."])
        if dec:
            rep.blob("zero_width_message.txt", dec.encode("latin1"))
    bd = [c for c in body if c in BIDI]
    if bd:
        rep.add("HIGH" if ext in CODE_EXTS or rep.kind == "script" else "MEDIUM", "unicode",
                "%d bidirectional control character(s) in text" % len(bd),
                "They reorder how text is displayed, so what you read is not what is processed ('Trojan Source').")
    tags = "".join(chr(ord(c) - 0xE0000) for c in body if 0xE0020 <= ord(c) <= 0xE007E)
    if tags:
        rep.add("HIGH", "unicode", "Hidden message in invisible Unicode tag characters",
                ["decoded: " + tags[:300], "Invisible in every editor; used to smuggle instructions/text past human review."])
        rep.blob("unicode_tag_message.txt", tags.encode())
    vs = [ord(c) for c in body if 0xFE00 <= ord(c) <= 0xFE0F or 0xE0100 <= ord(c) <= 0xE01EF]
    if len(vs) >= 16:
        by = bytes((v - 0xFE00) if v < 0xE0000 else (v - 0xE0100 + 16) for v in vs)
        rep.add("MEDIUM", "unicode", "%d variation selectors in text (can encode hidden bytes)" % len(vs),
                ["decodes to: " + clean(by[:200])] if printable_ratio(by) > 0.85 else [])
    lines = body.split("\n")
    tails = [ln.rstrip("\r")[len(ln.rstrip()):] for ln in lines]
    tw = [x for x in tails if x]
    mixed = [x for x in tw if " " in x and "\t" in x]
    if len(mixed) >= 5:
        rep.add("MEDIUM", "stego", "Whitespace steganography pattern at line ends (SNOW-style)",
                "%d lines end in mixed runs of tabs and spaces." % len(mixed))
    elif len(tw) >= 20 and len(tw) > len(lines) * 0.3 and len({len(x) for x in tw}) > 3:
        rep.add("LOW", "stego", "Many lines end in varying trailing whitespace (%d of %d)" % (len(tw), len(lines)),
                "Trailing spaces can encode hidden bits.")
    homo = re.findall(r"\b(?:[A-Za-z]+[\u0400-\u04FF\u0370-\u03FF]+|[\u0400-\u04FF\u0370-\u03FF]+[A-Za-z]+)\w*", body[:4 << 20])
    if homo:
        rep.add("LOW", "unicode", "%d word(s) mixing Latin with Cyrillic/Greek letters (homoglyphs)" % len(homo),
                ", ".join("%s [%s]" % (w, w.encode("unicode_escape").decode()) for w in list(dict.fromkeys(homo))[:6]))
    if "\x1b[" in body or "\x1b]" in body:
        conceal = "\x1b[8m" in body or re.search(r"\x1b\[\d*[ABCDK]|\x1b\[2K|\x1b\[1A", body)
        rep.add("MEDIUM" if conceal else "LOW", "unicode", "Terminal escape sequences in text",
                "Can hide or overwrite lines when the file is shown with cat/less -R" + (" (conceal/cursor-movement codes present)." if conceal else "."))
    if "\x08" in body or re.search(r"[^\r\n]\r[^\n]", body[:4 << 20]):
        rep.add("LOW", "unicode", "Backspace or bare carriage-return characters in text", "Can make a terminal display something other than the real content.")
    low = body[:200000].lower()
    if rep.identity.get("Type", "").startswith("SVG") and re.search(r"<script|\bon(?:load|click|error)\s*=|javascript:", low):
        rep.add("MEDIUM", "macro", "SVG contains script or event handlers")
    if re.search(r"<!--.{40,}?-->", body[:4 << 20], re.S) and ("<html" in low or "<svg" in low or "<?xml" in low):
        cm = re.findall(r"<!--(.{40,400}?)-->", body[:4 << 20], re.S)
        rep.add("INFO", "hidden", "%d sizeable markup comment(s)" % len(cm), [x.strip()[:200] for x in cm[:5]])


def analyze_fs(path, st, rep, sn):
    name = os.path.basename(path)
    ext = name.rsplit(".", 1)[-1].lower() if "." in name.strip(".") else ""
    if sn:
        desc, kind, exts = sn
        if exts and ext in ALL_EXTS and ext not in exts:
            rep.add("HIGH" if kind in EXEC_KINDS else "MEDIUM", "identity",
                    "Extension .%s does not match the real content: %s" % (ext, desc),
                    "The name claims one type, the bytes are another.")
        elif kind in ("text", "script") and exts is None and ext in ALL_EXTS - TEXT_EXTS - {"bin", "o", "out", "run", "db", "com"}:
            rep.add("HIGH" if kind == "script" else "MEDIUM", "identity",
                    "Extension .%s but the content is plain %s" % (ext, desc.lower()))
    if re.search(r"\.(pdf|docx?|xlsx?|pptx?|jpe?g|png|gif|txt|mp[34]|zip|rtf)\s*\.(exe|scr|bat|cmd|com|pif|js|jse|vbs|vbe|lnk|ps1|hta|jar|msi|sh|wsf)$", name, re.I):
        rep.add("HIGH", "identity", "Double extension: looks like a document, is an executable/script type", name)
    if any(c in name for c in BIDI):
        rep.add("HIGH", "identity", "File name contains a right-to-left override character", "Displayed name differs from the real one (e.g. 'gpj.exe' shown as 'exe.jpg').")
    if re.search(r"\s{6,}\.\w+$", name):
        rep.add("HIGH", "identity", "File name pads the real extension out of view with spaces")
    if st.st_mode & (stat.S_ISUID | stat.S_ISGID):
        rep.add("MEDIUM", "filesystem", "setuid/setgid bit is set", stat.filemode(st.st_mode))
    if st.st_mtime > dt.datetime.now().timestamp() + 86400:
        rep.add("LOW", "filesystem", "Modification time is in the future", "Timestamps were set manually or the source clock was wrong.")
    if hasattr(os, "listxattr"):
        try:
            for a in os.listxattr(path, follow_symlinks=False):
                if a.startswith(("security.", "system.", "trusted.")):
                    continue
                v = os.getxattr(path, a, follow_symlinks=False)
                rep.meta("xattr", a, v.decode("utf-8", "replace") if printable_ratio(v) > 0.9 else "%d bytes: %s…" % (len(v), v[:24].hex()))
                if a in ("user.xdg.origin.url", "user.xdg.referrer.url"):
                    rep.add("LOW", "filesystem", "Download origin recorded in extended attributes", "%s = %s" % (a, clean(v, 300)))
                elif len(v) > 256:
                    rep.add("MEDIUM", "filesystem", "Large extended attribute %s (%d bytes)" % (a, len(v)), "xattrs are invisible to ls/cat and can store hidden data.")
                    rep.blob("xattr_%s.bin" % re.sub(r"\W+", "_", a), v)
                else:
                    rep.add("LOW", "filesystem", "Extended attribute %s (%d bytes)" % (a, len(v)))
        except OSError:
            pass
    return ext


def run_tool(cmd, timeout=30):
    try:
        r = subprocess.run(cmd, capture_output=True, timeout=timeout)
        return r.stdout.decode("utf-8", "replace")
    except (OSError, subprocess.SubprocessError):
        return ""


def vt_lookup(sha256, rep):
    key = os.environ.get("VT_API_KEY")
    if not key:
        rep.notes.append("--vt given but VT_API_KEY is not set; lookup skipped")
        return
    import urllib.request
    import urllib.error
    req = urllib.request.Request("https://www.virustotal.com/api/v3/files/" + sha256, headers={"x-apikey": key})
    try:
        with urllib.request.urlopen(req, timeout=20) as r:
            a = json.load(r)["data"]["attributes"]
        s = a.get("last_analysis_stats", {})
        mal, tot = s.get("malicious", 0), sum(s.values()) or 1
        rep.meta("VirusTotal", "Detections", "%d / %d engines" % (mal, tot))
        if mal:
            label = (a.get("popular_threat_classification") or {}).get("suggested_threat_label", "")
            rep.add("HIGH" if mal >= 3 else "MEDIUM", "reputation", "VirusTotal: %d of %d engines flag this hash" % (mal, tot), label)
    except urllib.error.HTTPError as ex:
        rep.meta("VirusTotal", "Result", "hash not known" if ex.code == 404 else "HTTP %d" % ex.code)
    except Exception as ex:
        rep.notes.append("VirusTotal lookup failed: %s" % clean(ex, 100))


def analyze(path, opts):
    rep = Report(path)
    try:
        st = os.lstat(path)
    except OSError as ex:
        rep.notes.append("cannot stat: %s" % ex)
        return rep
    if stat.S_ISLNK(st.st_mode):
        rep.identity["Type"] = "symbolic link -> %s" % clean(os.readlink(path))
        return rep
    if not stat.S_ISREG(st.st_mode):
        rep.identity["Type"] = "not a regular file (skipped)"
        return rep
    hs = [hashlib.md5(), hashlib.sha1(), hashlib.sha256()]
    chunks, kept = [], 0
    try:
        with open(path, "rb") as fh:
            while True:
                c = fh.read(1 << 20)
                if not c:
                    break
                for h in hs:
                    h.update(c)
                if kept < opts["max_bytes"]:
                    chunks.append(c)
                    kept += len(c)
    except OSError as ex:
        rep.notes.append("cannot read: %s" % ex)
        return rep
    d = b"".join(chunks)
    del chunks
    if st.st_size > len(d):
        rep.notes.append("file is larger than --max-size; only the first %s was analysed in depth (hashes cover the whole file)" % human(len(d)))
    rep.hashes.update(zip(("MD5", "SHA-1", "SHA-256"), (h.hexdigest() for h in hs)))
    sn = sniff(d)
    fdesc = run_tool(["file", "-b", "--", path], 15).strip() if opts["have_file"] else ""
    rep.identity["Type"] = sn[0] if sn else (clean(fdesc, 120) or "unknown binary data") if d else "empty file"
    rep.kind = sn[1] if sn else "unknown"
    if fdesc:
        rep.identity["file(1)"] = clean(fdesc, 200)
    rep.identity["Size"] = "%s (%d bytes)" % (human(st.st_size), st.st_size)
    rep.identity["Mode"] = stat.filemode(st.st_mode)
    rep.identity["Modified"] = dt.datetime.fromtimestamp(st.st_mtime).strftime("%Y-%m-%d %H:%M:%S")
    rep.identity["Changed"] = dt.datetime.fromtimestamp(st.st_ctime).strftime("%Y-%m-%d %H:%M:%S")

    def step(name, fn, *a):
        try:
            return fn(*a)
        except Exception as ex:   # one broken parser must not hide the other results
            rep.notes.append("%s analysis failed: %s: %s" % (name, type(ex).__name__, clean(ex, 120)))
            return None

    ext = step("filesystem", analyze_fs, path, st, rep, sn) or ""
    if not d:
        return rep
    if rep.kind in FORMATS:
        rep.logical_end = step(rep.kind, FORMATS[rep.kind], d, rep, opts)
    elif rep.kind == "tiff":
        step("tiff", parse_tiff, d, rep)
    step("xmp", extract_xmp, d, rep)
    step("trailing", report_trailing, d, rep)
    step("embedded", analyze_embedded, d, rep)
    step("entropy", analyze_entropy, d, rep)
    step("strings", analyze_strings, d, rep)
    if rep.kind in ("text", "script"):
        step("text", analyze_text, d, rep, ext)
    if opts["have_exiftool"]:
        out = run_tool(["exiftool", "-j", "-G1", "-a", "--", path], 60)
        try:
            for k, v in json.loads(out)[0].items():
                if not k.startswith(("System:", "ExifTool:", "File:")) and k != "SourceFile":
                    rep.meta("exiftool", k, v)
        except (ValueError, IndexError, AttributeError):
            pass
    if opts["vt"]:
        step("virustotal", vt_lookup, rep.hashes["SHA-256"], rep)
    return rep


# --------------------------------------------------------------------------
# output
# --------------------------------------------------------------------------

class Style:
    def __init__(self, on):
        self.on = on

    def __call__(self, code, s):
        return "\033[%sm%s\033[0m" % (code, s) if self.on else s


SEV_COL = {"HIGH": "1;31", "MEDIUM": "33", "LOW": "36", "INFO": "2"}
VERDICT = {3: ("SUSPICIOUS", "1;31"), 2: ("REVIEW", "33"), 1: ("minor notes", "36"), 0: ("clean", "32"), -1: ("clean", "32")}
SPARK = "▁▂▃▄▅▆▇█"


def sparkline(hs, width=48):
    if not hs:
        return ""
    step = len(hs) / min(width, len(hs))
    out = []
    for i in range(min(width, len(hs))):
        seg = hs[int(i * step):max(int(i * step) + 1, int((i + 1) * step))]
        out.append(SPARK[min(7, int(max(seg)))])
    return "".join(out)


def print_report(rep, opts, c):
    w = max(60, min(shutil.get_terminal_size((100, 24)).columns, 140))
    minr = RANK[opts["min_sev"]]
    fs = sorted((f for f in rep.findings if RANK[f["severity"]] >= minr), key=lambda f: -RANK[f["severity"]])
    v, vc = VERDICT[rep.worst()]
    print()
    print(c("1", "━━ " + clean(rep.path, w - 20) + " ") + c(vc, "[" + v + "]"))
    for k, val in rep.identity.items():
        extra = ("  " + c("2", sparkline(rep.entropy_blocks))) if k == "Entropy" and rep.entropy_blocks else ""
        print("  %-10s %s%s" % (k, val[:w - 14], extra))
    for k, val in rep.hashes.items():
        print("  %-10s %s" % (k, c("2", val)))
    if rep.metadata:
        print(c("1", "  Metadata"))
        lim = len(rep.metadata) if opts["verbose"] else 30
        for g, k, val in rep.metadata[:lim]:
            line = "    %-12s %-22s " % (g[:12], k[:22])
            print(c("2", line) + val[:max(20, w - len(line)) if not opts["verbose"] else 600])
        if len(rep.metadata) > lim:
            print(c("2", "    … %d more (use -v)" % (len(rep.metadata) - lim)))
    if fs:
        counts = collections.Counter(f["severity"] for f in fs)
        print(c("1", "  Findings ") + "(" + ", ".join("%d %s" % (counts[s], s.lower()) for s in reversed(SEVS) if counts[s]) + ")")
        for f in fs:
            print("    " + c(SEV_COL[f["severity"]], "%-8s" % ("[" + f["severity"] + "]")) + " " +
                  c("2", f["category"] + " · ") + f["title"])
            lim = len(f["detail"]) if opts["verbose"] else 6
            for ln in f["detail"][:lim]:
                for part in textwrap.wrap(ln, w - 16) or [""]:
                    print(" " * 13 + c("2", part))
            if len(f["detail"]) > lim:
                print(" " * 13 + c("2", "… %d more (use -v)" % (len(f["detail"]) - lim)))
    else:
        print(c("32", "  No findings at this severity level."))
    for nt in rep.notes:
        print(c("35", "  note: ") + clean(nt))


def print_summary(reps, c):
    print()
    print(c("1", "═" * 28 + " SUMMARY " + "═" * 28))
    tot = collections.Counter()
    for r in reps:
        for f in r.findings:
            tot[f["severity"]] += 1
    print("  %d file(s) scanned: " % len(reps) + ", ".join(c(SEV_COL[s], "%d %s" % (tot[s], s.lower())) for s in reversed(SEVS)))
    ranked = sorted(reps, key=lambda r: (-r.worst(), r.path))
    if len(reps) > 1:
        for r in ranked:
            cn = collections.Counter(f["severity"] for f in r.findings)
            v, vc = VERDICT[r.worst()]
            print("  " + c(vc, "%-12s" % v) + " H:%-2d M:%-2d L:%-2d  %s" % (cn["HIGH"], cn["MEDIUM"], cn["LOW"], clean(r.path, 90)))
    top = [(r, f) for r in ranked for f in r.findings if f["severity"] in ("HIGH", "MEDIUM")]
    if top:
        print(c("1", "  What needs attention"))
        for r, f in sorted(top, key=lambda x: -RANK[x[1]["severity"]])[:25]:
            print("    " + c(SEV_COL[f["severity"]], "%-8s" % ("[" + f["severity"] + "]")) + " " + f["title"] +
                  (c("2", "  ← " + clean(os.path.basename(r.path), 40)) if len(reps) > 1 else ""))
        if len(top) > 25:
            print(c("2", "    … %d more above" % (len(top) - 25)))
    else:
        print(c("32", "  Nothing at medium or high severity."))


def write_html(reps, out):
    e = html.escape
    col = {"HIGH": "#e5484d", "MEDIUM": "#d9a400", "LOW": "#3e9fb5", "INFO": "#888"}
    p = ["<!doctype html><meta charset=utf-8><title>deepscan report</title><style>"
         "body{font:14px/1.5 system-ui,sans-serif;max-width:1100px;margin:2em auto;padding:0 1em;background:#16181c;color:#dcdfe4}"
         "h1{font-size:1.4em}h2{font-size:1.05em;margin:2em 0 .3em;word-break:break-all;border-top:1px solid #333;padding-top:1em}"
         "table{border-collapse:collapse;width:100%}td{padding:3px 8px;vertical-align:top;border-bottom:1px solid #2a2d33}"
         "td:first-child{white-space:nowrap;color:#9aa0aa}code,.m{font-family:ui-monospace,monospace;font-size:12.5px;word-break:break-all}"
         ".s{display:inline-block;min-width:4.5em;padding:0 6px;border-radius:3px;color:#fff;font-size:12px;text-align:center}"
         ".d{color:#9aa0aa;font-size:13px;word-break:break-word}h3{font-size:.95em;margin:1em 0 .2em;color:#9aa0aa}</style>",
         "<h1>deepscan report</h1><p class=d>%s · %d file(s)</p>" % (dt.datetime.now().strftime("%Y-%m-%d %H:%M"), len(reps))]
    for r in sorted(reps, key=lambda r: -r.worst()):
        p.append("<h2>%s</h2><table>" % e(clean(r.path)))
        for k, v in list(r.identity.items()) + list(r.hashes.items()):
            p.append("<tr><td>%s</td><td class=m>%s</td></tr>" % (e(k), e(v)))
        p.append("</table>")
        if r.findings:
            p.append("<h3>Findings</h3><table>")
            for f in sorted(r.findings, key=lambda f: -RANK[f["severity"]]):
                p.append("<tr><td><span class=s style='background:%s'>%s</span></td><td>%s <span class=d>(%s)</span>%s</td></tr>" % (
                    col[f["severity"]], f["severity"], e(f["title"]), e(f["category"]),
                    "".join("<div class='d m'>%s</div>" % e(x) for x in f["detail"])))
            p.append("</table>")
        if r.metadata:
            p.append("<h3>Metadata</h3><table>")
            for g, k, v in r.metadata:
                p.append("<tr><td>%s · %s</td><td class=m>%s</td></tr>" % (e(g), e(k), e(v)))
            p.append("</table>")
        for nt in r.notes:
            p.append("<p class=d>note: %s</p>" % e(clean(nt)))
    with open(out, "w", encoding="utf-8") as fh:
        fh.write("\n".join(p))


def main():
    ap = argparse.ArgumentParser(
        prog="deepscan", description="Inspect files in depth for hidden, embedded or misleading content and summarise what was found.",
        epilog="Exit status: 0 nothing notable, 1 medium-severity findings, 2 high-severity findings. "
               "Not detected: password-based JPEG stego (steghide/outguess/F5), audio/video stego, content of encrypted archives.")
    ap.add_argument("paths", nargs="+", help="files or directories (directories are walked recursively)")
    ap.add_argument("-v", "--verbose", action="store_true", help="show every metadata field and full finding details")
    ap.add_argument("-q", "--quiet", action="store_true", help="only print the final summary")
    ap.add_argument("-s", "--min-severity", default="info", choices=[s.lower() for s in SEVS], help="hide findings below this level (default: info)")
    ap.add_argument("--deep", action="store_true", help="slower: examine whole images for LSB data (and bit plane 1), more archive members")
    ap.add_argument("--json", metavar="FILE", help="write full results as JSON ('-' for stdout)")
    ap.add_argument("--html", metavar="FILE", help="write a self-contained HTML report")
    ap.add_argument("--extract", metavar="DIR", help="save carved payloads (trailing data, embedded files, LSB data, decoded blobs) into DIR")
    ap.add_argument("--vt", action="store_true", help="look the SHA-256 up on VirusTotal (sends only the hash; needs VT_API_KEY)")
    ap.add_argument("--max-size", type=int, default=512, metavar="MB", help="analyse at most this much of each file in depth (default 512)")
    ap.add_argument("--no-color", action="store_true")
    ap.add_argument("--version", action="version", version="deepscan " + VERSION)
    a = ap.parse_args()

    files = []
    for p in a.paths:
        if os.path.isdir(p) and not os.path.islink(p):
            for root, dirs, names in os.walk(p):
                dirs.sort()
                files += [os.path.join(root, n) for n in sorted(names)]
        elif os.path.lexists(p):
            files.append(p)
        else:
            print("deepscan: no such file: %s" % p, file=sys.stderr)
    if not files:
        return 3
    opts = {"deep": a.deep, "lsb_cap": (64 << 20) if a.deep else 1_500_000, "zip_members": 5000 if a.deep else 500,
            "max_bytes": a.max_size << 20, "vt": a.vt, "verbose": a.verbose, "min_sev": a.min_severity.upper(),
            "have_file": bool(shutil.which("file")), "have_exiftool": bool(shutil.which("exiftool"))}
    to_stdout = a.json == "-"
    c = Style(sys.stdout.isatty() and not a.no_color and not os.environ.get("NO_COLOR"))
    reps = []
    for f in files:
        if sys.stderr.isatty() and len(files) > 1:
            print("\r\033[Kscanning %d/%d %s" % (len(reps) + 1, len(files), clean(os.path.basename(f), 50)), end="", file=sys.stderr)
        rep = analyze(f, opts)
        reps.append(rep)
        if sys.stderr.isatty() and len(files) > 1:
            print("\r\033[K", end="", file=sys.stderr)
        if not a.quiet and not to_stdout:
            print_report(rep, opts, c)
        if a.extract and rep.blobs:
            dest = os.path.join(a.extract, re.sub(r"[^\w.\-]+", "_", os.path.basename(f)) + "." + rep.hashes.get("SHA-256", "x")[:8])
            os.makedirs(dest, exist_ok=True)
            for i, (label, data) in enumerate(rep.blobs):
                with open(os.path.join(dest, "%02d_%s" % (i, re.sub(r"[^\w.\-]+", "_", label))), "wb") as fh:
                    fh.write(data)
            rep.notes.append("%d payload(s) carved to %s" % (len(rep.blobs), dest))
            if not a.quiet and not to_stdout:
                print(c("35", "  note: ") + clean(rep.notes[-1]))
    if to_stdout:
        json.dump([r.to_dict() for r in reps], sys.stdout, indent=2, ensure_ascii=False)
        print()
    else:
        print_summary(reps, c)
        if a.json:
            with open(a.json, "w", encoding="utf-8") as fh:
                json.dump([r.to_dict() for r in reps], fh, indent=2, ensure_ascii=False)
            print("  JSON report: " + a.json)
    if a.html:
        write_html(reps, a.html)
        if not to_stdout:
            print("  HTML report: " + a.html)
    worst = max((r.worst() for r in reps), default=-1)
    return 2 if worst >= 3 else 1 if worst == 2 else 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except KeyboardInterrupt:
        sys.exit(130)
    except BrokenPipeError:
        sys.exit(0)
