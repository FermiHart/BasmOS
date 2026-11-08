#!/usr/bin/env python3
# SPDX-License-Identifier: BSD-3-Clause
"""Minimal QEMU i386 GDB-remote stdio client, for deterministic CPU probes.

The debugger uses hardware breakpoint requests (Z1), so guest code is not
patched. Tests that write fixture data state that scope explicitly.
"""
import os
from pathlib import Path
import select
import struct
import subprocess
import time


class Gdb:
    REGISTERS = ("eax","ecx","edx","ebx","esp","ebp","esi","edi",
                 "eip","eflags","cs","ss","ds","es","fs","gs")

    def __init__(self, image):
        command=[os.environ.get("BASMOS_QEMU","qemu-system-i386"),"-accel","tcg",
                 "-drive",f"format=raw,if=floppy,readonly=on,file={image}",
                 "-display","none","-nic","none","-serial","none","-monitor","none",
                 "-no-reboot","-no-shutdown","-S","-gdb","stdio"]
        self.process=subprocess.Popen(command,stdin=subprocess.PIPE,stdout=subprocess.PIPE,
                                      stderr=subprocess.PIPE)
        self.buffer=b""
        try:
            self.command("qSupported")
        except BaseException:
            self.close()
            raise

    def byte(self,deadline):
        if not self.buffer:
            timeout=deadline-time.monotonic()
            if timeout<=0 or not select.select([self.process.stdout],[],[],timeout)[0]:
                raise TimeoutError("GDB remote response timed out")
            self.buffer=os.read(self.process.stdout.fileno(),8192)
            if not self.buffer:
                raise RuntimeError("QEMU GDB closed: "+self.process.stderr.read().decode(errors="replace"))
        value,self.buffer=self.buffer[0],self.buffer[1:]
        return value

    def receive(self,timeout=10):
        deadline=time.monotonic()+timeout
        while self.byte(deadline)!=ord("$"):
            pass
        packet=bytearray()
        while (value:=self.byte(deadline))!=ord("#"):
            packet.append(value)
        checksum=bytes((self.byte(deadline),self.byte(deadline)))
        if sum(packet)%256!=int(checksum,16):
            raise RuntimeError("GDB remote checksum mismatch")
        self.process.stdin.write(b"+")
        self.process.stdin.flush()
        decoded=bytearray()
        pos=0
        while pos<len(packet):
            value=packet[pos]
            if value==ord("}"):
                pos+=1
                decoded.append(packet[pos]^0x20)
            elif value==ord("*"):
                pos+=1
                decoded.extend(decoded[-1:]*(packet[pos]-29))
            else:
                decoded.append(value)
            pos+=1
        return decoded.decode("ascii")

    def command(self,command):
        payload=command.encode("ascii")
        self.process.stdin.write(b"$"+payload+b"#"+f"{sum(payload)%256:02x}".encode())
        self.process.stdin.flush()
        self.console=""
        while True:
            result=self.receive()
            if result.startswith("O") and result!="OK":
                self.console+=bytes.fromhex(result[1:]).decode(errors="replace")
                continue
            if result.startswith("E"):
                raise RuntimeError(f"GDB {command[:30]} failed: {result}")
            return result

    def monitor(self,command):
        result=self.command("qRcmd,"+command.encode().hex())
        if result!="OK":
            raise RuntimeError(f"monitor failed: {result}")
        return self.console

    def registers(self):
        packet=self.command("g")
        values=struct.unpack("<16I",bytes.fromhex(packet[:128]))
        return dict(zip(self.REGISTERS,values))

    def set_register(self,name,value):
        index=self.REGISTERS.index(name)
        result=self.command(f"P{index:x}="+struct.pack("<I",value).hex())
        if result!="OK":
            raise RuntimeError(f"register write failed: {name}: {result}")

    def read(self,address,count):
        result=bytes.fromhex(self.command(f"m{address:x},{count:x}"))
        if len(result)!=count:
            raise RuntimeError("short GDB memory read")
        return result

    def write(self,address,data):
        if self.command(f"M{address:x},{len(data):x}:"+data.hex())!="OK":
            raise RuntimeError("GDB memory write failed")

    def breakpoint(self,address,remove=False):
        if self.command(f"{'z' if remove else 'Z'}1,{address:x},1")!="OK":
            raise RuntimeError("GDB hardware breakpoint failed")

    def resume(self):
        response=self.command("c")
        if not response.startswith("T05") and response!="S05":
            raise RuntimeError(f"unexpected GDB stop: {response}")

    def close(self):
        if self.process.poll() is None:
            self.process.terminate()
            try:
                self.process.wait(timeout=3)
            except subprocess.TimeoutExpired:
                self.process.kill()
                self.process.wait()
        self.stderr=self.process.stderr.read().decode(errors="replace")
        for stream in (self.process.stdin,self.process.stdout,self.process.stderr):
            stream.close()

    def __enter__(self):
        return self

    def __exit__(self,*_):
        self.close()


def syscall_site(content,symbols,task,vector):
    begin=symbols[task]
    end=symbols["task1"] if task=="task0" else symbols["exception_handler"]
    body=content[begin:end]
    offset=body.index(bytes((0xcd,vector)))
    return begin+offset


def user_contexts(image,symbols):
    content=Path(image).read_bytes()
    sites={0x33:syscall_site(content,symbols,"task0",33),
           0x3b:syscall_site(content,symbols,"task1",34)}
    records=[]
    with Gdb(image) as g:
        for offset in sites.values():
            g.breakpoint(0x7c00+offset)
        for _ in range(2):
            g.resume()
            registers=g.registers()
            cs=registers["cs"]
            if cs not in sites:
                raise RuntimeError(f"unexpected breakpoint CS: {cs:#x}")
            record={"registers":registers,"monitor":g.monitor("info registers")}
            record["tss_esp0"]=int.from_bytes(g.read(0xa04,4),"little")
            record["tss_ss0"]=int.from_bytes(g.read(0xa08,2),"little")
            record["io_bitmap_offset"]=int.from_bytes(g.read(0xa66,2),"little")
            records.append(record)
            g.breakpoint(0x7c00+sites.pop(cs),remove=True)
    return records
