#!/usr/bin/env python3
"""Exec-only private input adapter. Never logs or authorizes payload contents."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import resource
import stat

DOCKER='/Users/shaanjotgill/Library/Caches/APIContour/tools/docker-29.8.2-31ae2d64/docker'
DOCKER_SHA='31ae2d64e51d9dfc728a2934941615cdd92f31279ed6d5c1fb2bfc0a44637a8f'
SOCKET='unix:///Users/shaanjotgill/.docker/run/docker.sock'

def closed_path(path, *, private_final=False):
    path=Path(path)
    if not path.is_absolute() or '..' in path.parts: raise ValueError('path')
    fd=os.open('/',os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW)
    try:
        for part in path.parts[1:]:
            st=os.fstat(fd)
            if not stat.S_ISDIR(st.st_mode) or st.st_uid not in (0,os.getuid()) or st.st_mode&0o022: raise ValueError('ancestor')
            child=os.open(part,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW,dir_fd=fd);os.close(fd);fd=child
        st=os.fstat(fd)
        if not stat.S_ISDIR(st.st_mode) or st.st_uid not in (0,os.getuid()) or st.st_mode&0o022: raise ValueError('directory')
        if private_final and (st.st_uid!=os.getuid() or stat.S_IMODE(st.st_mode)!=0o700): raise ValueError('private directory')
        return fd
    except BaseException:
        os.close(fd);raise

def identity(st):return tuple(getattr(st,k) for k in ('st_dev','st_ino','st_mode','st_uid','st_gid','st_nlink','st_size','st_mtime_ns','st_ctime_ns'))

def checked_file(path,digest,mode,limit):
    path=Path(path);parent=closed_path(path.parent,private_final=True);fd=None
    try:
        fd=os.open(path.name,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK,dir_fd=parent);before=os.fstat(fd)
        def valid(st):return stat.S_ISREG(st.st_mode) and st.st_uid==os.getuid() and stat.S_IMODE(st.st_mode)==mode and st.st_nlink==1 and 1<=st.st_size<=limit
        if not valid(before):raise ValueError('file')
        h=hashlib.sha256();left=before.st_size
        while left:
            chunk=os.read(fd,min(left,65536))
            if not chunk:raise ValueError('file')
            h.update(chunk);left-=len(chunk)
        after=os.fstat(fd);current=os.stat(path.name,dir_fd=parent,follow_symlinks=False);again=closed_path(path.parent,private_final=True)
        try:
            if identity(os.fstat(again))!=identity(os.fstat(parent)) or not valid(after) or not valid(current) or identity(before)!=identity(after) or identity(before)!=identity(current) or h.hexdigest()!=digest:raise ValueError('file changed')
        finally:os.close(again)
        os.lseek(fd,0,os.SEEK_SET);out=fd;fd=None;return out
    finally:
        if fd is not None:os.close(fd)
        os.close(parent)

def socket_snapshot():
    path=Path(SOCKET.removeprefix('unix://'));fd=os.open('/',os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW);chain=[]
    try:
        for part in path.parent.parts[1:]:
            info=os.fstat(fd)
            if not stat.S_ISDIR(info.st_mode) or info.st_uid not in (0,os.getuid()) or info.st_mode&0o022:raise ValueError('socket ancestor')
            chain.append((info.st_dev,info.st_ino,info.st_mode,info.st_uid,info.st_gid))
            child=os.open(part,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW,dir_fd=fd);os.close(fd);fd=child
        info=os.fstat(fd)
        if not stat.S_ISDIR(info.st_mode) or info.st_uid not in (0,os.getuid()) or info.st_mode&0o022:raise ValueError('socket ancestor')
        chain.append((info.st_dev,info.st_ino,info.st_mode,info.st_uid,info.st_gid))
        sock=os.stat(path.name,dir_fd=fd,follow_symlinks=False)
        if not stat.S_ISSOCK(sock.st_mode) or sock.st_uid not in (0,os.getuid()):raise ValueError('socket')
        data={'ancestors':chain,'socket':(sock.st_dev,sock.st_ino,sock.st_mode,sock.st_uid,sock.st_gid)}
        return hashlib.sha256(json.dumps(data,sort_keys=True,separators=(',',':')).encode('ascii')).hexdigest()
    finally:os.close(fd)

def safe_close(fd):
    try:os.close(fd)
    except OSError:pass

def launch(payload,digest,config,cid,socket_digest):
    if not re.fullmatch('[0-9a-f]{64}',digest) or not re.fullmatch('[0-9a-f]{64}',cid) or not re.fullmatch('[0-9a-f]{64}',socket_digest):raise ValueError('arguments')
    socket_before=socket_snapshot()
    if socket_before!=socket_digest:raise ValueError('socket changed')
    configfd=closed_path(config,private_final=True)
    try:
        if os.listdir(configfd):raise ValueError('configuration')
        confstat=identity(os.fstat(configfd))
    finally:os.close(configfd)
    tool=checked_file(DOCKER,DOCKER_SHA,0o500,256*1024*1024)
    try:
        inp=checked_file(payload,digest,0o600,65536)
        try:
            header=os.read(inp,8)
            if len(header)!=8 or header[:4]!=b'R5I1' or int.from_bytes(header[4:],'big')<1 or int.from_bytes(header[4:],'big')>65528 or os.fstat(inp).st_size!=8+int.from_bytes(header[4:],'big'):raise ValueError('input frame')
            os.lseek(inp,0,os.SEEK_SET)
            configfd=closed_path(config,private_final=True)
            try:
                if identity(os.fstat(configfd))!=confstat or os.listdir(configfd):raise ValueError('configuration changed')
            finally:os.close(configfd)
            rechecked=checked_file(DOCKER,DOCKER_SHA,0o500,256*1024*1024)
            try:
                if identity(os.fstat(rechecked))!=identity(os.fstat(tool)):raise ValueError('tool changed')
            finally:os.close(rechecked)
            if socket_snapshot()!=socket_digest:raise ValueError('socket changed')
            home=os.environ.get('HOME')
            if not home or not Path(home).is_absolute():raise ValueError('home')
            os.dup2(inp,0)
            maximum=resource.getrlimit(resource.RLIMIT_NOFILE)[0]
            if maximum==resource.RLIM_INFINITY:raise ValueError('fd limit')
            os.closerange(3,maximum)
            os.execve(DOCKER,[DOCKER,'--host',SOCKET,'start','--attach','--interactive',cid],{'PATH':'/usr/bin:/bin','HOME':home,'DOCKER_CONFIG':str(config)})
            raise RuntimeError('exec returned')
        finally:safe_close(inp)
    finally:safe_close(tool)

def main():
    p=argparse.ArgumentParser();p.add_argument('--payload',required=True);p.add_argument('--sha256',required=True);p.add_argument('--config',required=True);p.add_argument('--cid',required=True);p.add_argument('--socket-sha256',required=True);a=p.parse_args()
    try:launch(a.payload,a.sha256,a.config,a.cid,a.socket_sha256)
    except BaseException:raise SystemExit(1) from None
if __name__=='__main__':main()
