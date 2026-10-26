#!/usr/bin/env python3
"""Apply owner-specific recovery patches inside a disposable Android workspace."""
from __future__ import print_function
import argparse
import base64
import hashlib
import io
import os
import re
import subprocess


def fingerprint(path):
    with io.open(str(path), encoding='utf-8') as f:
        line = f.read().strip()
    if not line or len(line.splitlines()) != 1:
        raise ValueError('Expected exactly one Android ADB public key.')
    token = line.split()[0]
    if not re.match(r'^[A-Za-z0-9+/]+={0,2}$', token):
        raise ValueError('Invalid public-key encoding.')
    data = base64.b64decode(token)
    if len(data) != 524 or len(line.splitlines()) != 1:
        raise ValueError('Expected one Android RSA public key (524 decoded bytes).')
    digest = hashlib.md5(data).hexdigest().upper()  # Android 6 confirmation fingerprint format.
    return ':'.join(digest[i:i + 2] for i in range(0, len(digest), 2))


def prepare(tree, key, inputs):
    tree, inputs = str(tree), str(inputs)
    def read(path):
        with io.open(path, encoding='utf-8') as f:
            return f.read()
    def write(path, text):
        with io.open(path, 'w', encoding='utf-8') as f:
            f.write(text)
    owner = fingerprint(key)
    template = read(os.path.join(inputs, 'android-revival.patch.in')).replace('@OWNER_FINGERPRINT@', owner)
    markers = {'frameworks/base/services/usb/java/com/android/server/usb/UsbDebuggingManager.java': 'MIRROR_OWNER_ADB_FINGERPRINT',
               'system/vold/cryptfs.c': 'mirror_revival_mount_unencrypted_data',
               'system/vold/CryptCommandListener.cpp': 'The revival handoff can fail after mounting data',
               'device/qcom/msm8916_32/mixer_paths_sbc.xml': 'The MIRROR\'s AUDIO-HDR',
               'frameworks/opt/net/wifi/service/java/com/android/server/wifi/WifiStateMachine.java': 'DRIVER_LOAD_RETRY_TRIES'}
    changes = []
    # Preflight all components first. A failed later hunk must not leave a newly
    # half-patched workspace that a subsequent marker check would mistake for ready.
    for part in template.split('diff --git ')[1:]:
        patch = 'diff --git ' + part
        path = part.splitlines()[0].split()[0][2:]
        target = os.path.join(tree, path)
        text = read(target)
        applied = markers[path] in text
        check_patch = patch
        if applied and path.endswith('UsbDebuggingManager.java'):
            match = re.search(r'MIRROR_OWNER_ADB_FINGERPRINT\s*=\s*"([^"]+)"', text)
            if not match:
                raise ValueError('Cannot identify previous owner fingerprint.')
            check_patch = check_patch.replace(owner, match.group(1))
            if 'the Mac key' in text:
                check_patch = check_patch.replace("the owner's key", 'the Mac key')
        command = ['patch', '--batch', '--dry-run', '-p1', '--reverse' if applied else '--forward']
        process = subprocess.Popen(command, stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                                   stderr=subprocess.STDOUT, cwd=tree)
        output, unused = process.communicate(check_patch.encode('utf-8'))
        if process.returncode:
            raise ValueError('Source differs from the complete expected recovery patch at ' + path)
        changes.append((path, target, text, patch, applied))
    for path, target, text, patch, applied in changes:
        if not applied:
            process = subprocess.Popen(['patch', '--batch', '--forward', '-p1'], stdin=subprocess.PIPE, cwd=tree)
            process.communicate(patch.encode('utf-8'))
            if process.returncode:
                raise ValueError('Recovery patch failed at ' + path)
        elif path.endswith('UsbDebuggingManager.java'):
            text, count = re.subn(r'(MIRROR_OWNER_ADB_FINGERPRINT\s*=\s*)"[^"]+"',
                                  lambda m: m.group(1) + '"' + owner + '"', text)
            if count != 1:
                raise ValueError('Could not replace the previous owner fingerprint.')
            write(target, text)
    # Keep a clear development identity and USB control. Network ADB is opt-in at runtime.
    properties = os.path.join(tree, 'device/qcom/msm8916_64/system.prop')
    text = read(properties)
    lines = [line for line in text.splitlines() if not re.match(
        r'^(service\.adb\.tcp\.port|ro\.mirror\.software_only|persist\.camera\..*debug.*|debug\.mirror\.)=', line)]
    lines.extend(['', '# Original-board MIRROR software recovery',
                  'service.adb.tcp.port=-1', 'ro.mirror.software_only=1'])
    write(properties, '\n'.join(lines) + '\n')
    # A migrated workspace may contain lab-only post-boot probes. Strip the named block.
    post = os.path.join(tree, 'device/qcom/common/rootdir/etc/init.qcom.post_boot.sh')
    text = read(post)
    text = re.sub(r'\n# Mirror revival: expose read-only CSI diagnostics for camera bring-up\.\nif .*?\nfi\n',
                  '\n', text, flags=re.S)
    write(post, text)
    return owner


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('--tree', required=True)
    parser.add_argument('--public-key', required=True)
    parser.add_argument('--inputs', required=True)
    args = parser.parse_args()
    prepare(args.tree, args.public_key, args.inputs)
    print('Prepared Android recovery for the supplied owner public key.')
