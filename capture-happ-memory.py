#!/usr/bin/env python3
"""Continuously capture full Happ/xray configs from process memory.

Run this BEFORE clicking ``...`` -> ``Пинг всех`` in Happ and leave it running
while the probes materialize configs.  Every complete config is written to disk
immediately and deduplicated, so it survives Happ unloading its transient UI /
probe configs.  The output contains subscription credentials; keep it private.

Example:
    python capture-happ-memory.py --seconds 120 --interval 0.3
    python import-happ-profiles.py --captures captures
"""

import ctypes, ctypes.wintypes as w, json, hashlib, os, sys, time, re, argparse

kernel32 = ctypes.WinDLL('kernel32', use_last_error=True)
psapi = ctypes.WinDLL('psapi', use_last_error=True)

PROCESS_QUERY_LIMITED_INFORMATION = 0x1000
PROCESS_VM_READ = 0x0010
MEM_COMMIT = 0x1000
PAGE_GUARD = 0x100
PAGE_NOACCESS = 0x01


class MBI(ctypes.Structure):
    _fields_ = [
        ('BaseAddress', ctypes.c_void_p),
        ('AllocationBase', ctypes.c_void_p),
        ('AllocationProtect', w.DWORD),
        ('RegionSize', ctypes.c_size_t),
        ('State', w.DWORD),
        ('Protect', w.DWORD),
        ('Type', w.DWORD),
    ]


kernel32.VirtualQueryEx.argtypes = [w.HANDLE, ctypes.c_void_p, ctypes.POINTER(MBI), ctypes.c_size_t]
kernel32.VirtualQueryEx.restype = ctypes.c_size_t
kernel32.ReadProcessMemory.argtypes = [w.HANDLE, ctypes.c_void_p, ctypes.c_void_p, ctypes.c_size_t, ctypes.POINTER(ctypes.c_size_t)]
kernel32.ReadProcessMemory.restype = w.BOOL
kernel32.OpenProcess.argtypes = [w.DWORD, w.BOOL, w.DWORD]
kernel32.OpenProcess.restype = w.HANDLE
kernel32.CloseHandle.argtypes = [w.HANDLE]
kernel32.QueryFullProcessImageNameW.argtypes = [w.HANDLE, w.DWORD, w.LPWSTR, ctypes.POINTER(w.DWORD)]
kernel32.QueryFullProcessImageNameW.restype = w.BOOL
psapi.EnumProcesses.argtypes = [ctypes.POINTER(w.DWORD), w.DWORD, ctypes.POINTER(w.DWORD)]
psapi.EnumProcesses.restype = w.BOOL


def process_list():
    arr = (w.DWORD * 4096)()
    needed = w.DWORD()
    if not psapi.EnumProcesses(arr, ctypes.sizeof(arr), ctypes.byref(needed)):
        return []
    n = needed.value // ctypes.sizeof(w.DWORD)
    out = []
    for pid in list(arr)[:n]:
        if pid == 0:
            continue
        h = kernel32.OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, False, pid)
        if not h:
            continue
        try:
            buf = ctypes.create_unicode_buffer(1024)
            size = w.DWORD(len(buf))
            if kernel32.QueryFullProcessImageNameW(h, 0, buf, ctypes.byref(size)):
                name = os.path.basename(buf.value)
                if re.search(r'(?i)^(happ|happd|xray|sing-box|happ-tcping|tun2proxy|antifilter)', name):
                    out.append((pid, name, buf.value))
        finally:
            kernel32.CloseHandle(h)
    return out


def read_region(h, base, size):
    buf = ctypes.create_string_buffer(size)
    got = ctypes.c_size_t(0)
    if kernel32.ReadProcessMemory(h, ctypes.c_void_p(base), buf, size, ctypes.byref(got)):
        return buf.raw[:got.value]
    return None


def parse_object_at(data, start):
    # Find the end of a JSON object, respecting strings and escapes.
    depth = 0
    in_str = False
    esc = False
    end = -1
    limit = min(len(data), start + 2_000_000)
    for i in range(start, limit):
        c = data[i]
        if in_str:
            if esc:
                esc = False
            elif c == 0x5c:
                esc = True
            elif c == 0x22:
                in_str = False
            continue
        if c == 0x22:
            in_str = True
        elif c == 0x7b:
            depth += 1
        elif c == 0x7d:
            depth -= 1
            if depth == 0:
                end = i + 1
                break
    if end < 0:
        return None
    frag = data[start:end]
    try:
        text = frag.decode('utf-8')
        obj = json.loads(text)
    except Exception:
        return None
    if not isinstance(obj, dict) or 'outbounds' not in obj:
        return None
    if not isinstance(obj.get('outbounds'), list):
        return None
    return obj


def extract_config(data, hit):
    # Prefer known root prefixes near the outbounds key. Try the nearest
    # candidates first, then a small bounded fallback over preceding objects.
    candidates = []
    window_start = max(0, hit - 500_000)
    for pat in (b'{"dns"', b'{"log"', b'{"inbounds"', b'{\n    "dns"', b'{\n    "log"', b'"dns"', b'"log"'):
        pos = data.rfind(pat, window_start, hit + 1)
        while pos >= window_start:
            brace = data.rfind(b'{', max(window_start, pos - 80), pos + 1)
            if brace >= 0:
                candidates.append(brace)
            pos = data.rfind(pat, window_start, pos)
    # Fallback for unusual formatting: a small set of nearest object starts.
    pos = hit
    found = 0
    while pos >= window_start and found < 25:
        pos = data.rfind(b'{', window_start, pos)
        if pos < 0:
            break
        candidates.append(pos)
        found += 1
        pos -= 1
    seen_starts = set()
    for start in candidates:
        if start in seen_starts:
            continue
        seen_starts.add(start)
        obj = parse_object_at(data, start)
        if obj is not None:
            return obj
    return None


def server_summary(obj):
    remarks = str(obj.get('remarks') or '')
    eps = []
    for ob in obj.get('outbounds') or []:
        if not isinstance(ob, dict):
            continue
        proto = str(ob.get('protocol') or '')
        if proto not in ('vless', 'vmess', 'trojan', 'hysteria', 'ss', 'shadowsocks'):
            continue
        s = ob.get('settings') or {}
        v = s.get('vnext') if isinstance(s, dict) else None
        if isinstance(v, list) and v:
            for x in v:
                if isinstance(x, dict):
                    eps.append((proto, str(x.get('address') or ''), x.get('port')))
        else:
            a = s.get('address') if isinstance(s, dict) else None
            if a:
                eps.append((proto, str(a), s.get('port')))
    return remarks, eps


def scan_process(pid, outdir, seen, max_regions=100000):
    h = kernel32.OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION | PROCESS_VM_READ, False, pid)
    if not h:
        return 0, 0
    hits = 0
    added = 0
    addr = 0
    maxaddr = 0x7ffffffe0000
    try:
        while addr < maxaddr:
            mbi = MBI()
            if not kernel32.VirtualQueryEx(h, ctypes.c_void_p(addr), ctypes.byref(mbi), ctypes.sizeof(mbi)):
                break
            size = int(mbi.RegionSize)
            nxt = addr + max(size, 0x1000)
            if (mbi.State == MEM_COMMIT and 0 < size <= 64 * 1024 * 1024
                    and mbi.Type == 0x20000
                    and (mbi.Protect & 0x04)  # PAGE_READWRITE (heap/private)
                    and not (mbi.Protect & PAGE_GUARD) and not (mbi.Protect & PAGE_NOACCESS)):
                data = read_region(h, addr, size)
                if data:
                    start = 0
                    local_hits = 0
                    while True:
                        i = data.find(b'"outbounds"', start)
                        if i < 0:
                            break
                        hits += 1
                        local_hits += 1
                        cfg = extract_config(data, i)
                        if cfg is not None:
                            remarks, eps = server_summary(cfg)
                            canonical = json.dumps(cfg, sort_keys=True, ensure_ascii=False, separators=(',', ':'))
                            digest = hashlib.sha1(canonical.encode('utf-8')).hexdigest()
                            if digest not in seen:
                                seen.add(digest)
                                path = os.path.join(outdir, 'capture-%s.json' % digest)
                                with open(path, 'w', encoding='utf-8') as f:
                                    json.dump(cfg, f, ensure_ascii=False, indent=2)
                                added += 1
                                ep = ', '.join('%s:%s' % (e[1], e[2]) for e in eps[:3])
                                print('CAPTURE pid=%s remarks=%s servers=%s %s' % (pid, ascii(remarks), len(eps), ep), flush=True)
                        start = i + 1
                        if local_hits > 500:
                            break
            addr = nxt
    finally:
        kernel32.CloseHandle(h)
    return hits, added


def main():
    try:
        sys.stdout.reconfigure(encoding='utf-8', errors='replace')
    except Exception:
        pass
    ap = argparse.ArgumentParser()
    ap.add_argument('--seconds', type=int, default=60, help='how long to keep scanning (default 60)')
    ap.add_argument('--interval', type=float, default=0.5, help='pause between scans (default 0.5s)')
    ap.add_argument('--out', default=os.path.join(os.path.dirname(os.path.abspath(__file__)), 'captures'),
                    help='persistent capture directory (default: ./captures next to this script)')
    args = ap.parse_args()
    os.makedirs(args.out, exist_ok=True)
    seen = set()
    end = time.time() + args.seconds
    scan_no = 0
    while time.time() < end:
        scan_no += 1
        procs = process_list()
        print('--- scan %d: %s ---' % (scan_no, ', '.join('%s:%s' % (n, p) for p, n, _ in procs)), flush=True)
        for pid, name, path in procs:
            t0 = time.time()
            hits, added = scan_process(pid, args.out, seen)
            print('  %s pid=%s hits=%s new=%s %.1fs' % (name, pid, hits, added, time.time() - t0), flush=True)
        time.sleep(max(0.1, args.interval))
    print('unique configs captured:', len(seen), flush=True)


if __name__ == '__main__':
    main()
