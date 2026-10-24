#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""第三方自助验证器：不信任本仓库的所有者，只信数学。

用法：
    python verify_public.py                 # 全量验
    python verify_public.py --only 12       # 只验第 12 次发布
    python verify_public.py --ots           # 连带看时间戳证明状态
    python verify_public.py --root .        # 仓库不在当前目录时指定

退出码：0 全过；1 有不通过项；2 环境/参数问题。

只依赖 Python 标准库（3.8+）。验五件事，见 README。

设计原则：**不做任何「差不多就算过」的让步**。任何一个字段缺失、任何一次哈希
对不上，都算不通过——验证器的价值全在它敢红。
"""

import argparse
import hashlib
import json
import os
import sys

CHAIN_FILES_HINT = ("portal-ops", "admin-ops", "anchor", "sandbox",
                    "sandbox-accounts", "task-market")


# --------------------------------------------------------------------------
# 基础
# --------------------------------------------------------------------------
def canon(obj):
    """与生产端完全一致的规范化：排序键、紧凑分隔符、不转义非 ASCII。"""
    return json.dumps(obj, sort_keys=True, separators=(",", ":"),
                      ensure_ascii=False).encode("utf-8")


def sha_bytes(b):
    return hashlib.sha256(b).hexdigest()


def read_jsonl(path):
    rows = []
    if not os.path.exists(path):
        return rows
    with open(path, "r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if line:
                rows.append(json.loads(line))
    return rows


def line_hash(row):
    body = {k: v for k, v in row.items() if k != "line_hash"}
    return sha_bytes(canon(body))


def recompute_root(chains):
    """六条链事实 → 总指纹。与生产端 build_anchor_root 同公式。"""
    return sha_bytes(canon({"v": 1, "chains": chains}))


# --------------------------------------------------------------------------
# 五项检查
# --------------------------------------------------------------------------
def check_index_chain(index):
    """1. 发布链没断：prev 首尾相接，每行 line_hash 自洽。"""
    bad = []
    prev = "0" * 64
    for i, row in enumerate(index, 1):
        try:
            h = line_hash(row)
        except Exception as e:                      # noqa: BLE001
            bad.append("第 %d 行无法计算哈希：%s" % (i, e))
            continue
        if row.get("line_hash") != h:
            bad.append("第 %d 行 line_hash 自相矛盾（写的是 %s，算出来 %s）"
                       % (i, str(row.get("line_hash"))[:16], h[:16]))
        if row.get("prev") != prev:
            bad.append("第 %d 行接不上前一行（prev=%s，上一行 line_hash=%s）"
                       % (i, str(row.get("prev"))[:16], prev[:16]))
        if row.get("n") != i:
            bad.append("第 %d 行序号错（写的是 %s）" % (i, row.get("n")))
        prev = row.get("line_hash") or h
    return bad


def check_manifests(root, index):
    """2. 清单没被换：索引记的指纹 = manifests/ 下文件的实际指纹。"""
    bad = []
    for row in index:
        mrel = row.get("manifest")
        if not mrel:
            bad.append("发布 #%s 缺 manifest 字段" % row.get("n"))
            continue
        p = os.path.join(root, mrel)
        if not os.path.exists(p):
            bad.append("发布 #%s 的清单文件不见了：%s" % (row.get("n"), mrel))
            continue
        with open(p, "rb") as f:
            got = sha_bytes(f.read())
        if got != row.get("manifest_sha256"):
            bad.append("发布 #%s 的清单指纹不符（索引记 %s，实际 %s）"
                       % (row.get("n"), str(row.get("manifest_sha256"))[:16],
                          got[:16]))
    return bad


def check_roots(index, manifests):
    """3. 总指纹算得对：拿清单里的链事实重算 root。"""
    bad = []
    for row, man in zip(index, manifests):
        if man is None:
            continue
        for rec in man.get("records") or []:
            chains = rec.get("chains")
            if not chains:
                bad.append("发布 #%s 有一条记录没有链事实，无法验证"
                           % row.get("n"))
                continue
            if recompute_root(chains) != rec.get("root"):
                bad.append("发布 #%s 有一条记录的 root 与链事实对不上（when=%s）"
                           % (row.get("n"), rec.get("when")))
    return bad


def check_tokens(root, manifests):
    """4. 令牌没被换：记录里的指纹 = 仓内实际文件指纹。"""
    bad = []
    for man in manifests:
        if man is None:
            continue
        for rec in man.get("records") or []:
            for key, sha_key in (("tsq_file", "tsq_sha256"),
                                 ("tsr_file", "tsr_sha256")):
                rel = rec.get(key)
                if not rel:
                    continue
                p = os.path.join(root, rel)
                if not os.path.exists(p):
                    bad.append("记录 when=%s 的 %s 不见了（%s）"
                               % (rec.get("when"), key, rel))
                    continue
                with open(p, "rb") as f:
                    got = sha_bytes(f.read())
                if got != rec.get(sha_key):
                    bad.append("记录 when=%s 的 %s 与 %s 不符"
                               % (rec.get("when"), rel, sha_key))
    return bad


def check_coverage(root, index, manifests):
    """5. 记录不重不漏：累积件条数 = 各次清单新增之和，且都在清单里出现过。"""
    bad = []
    anchors = read_jsonl(os.path.join(root, "anchors", "anchor-ext.jsonl"))
    total_new = 0
    seen_keys = []
    for row, man in zip(index, manifests):
        if man is None:
            continue
        recs = man.get("records") or []
        total_new += man.get("new_count", len(recs))
        seen_keys.extend(["%s|%s" % (r.get("when"), r.get("root")) for r in recs])
    if len(anchors) != total_new:
        bad.append("累积件 %d 条，但各次清单新增合计 %d 条（不重不漏对不上）"
                   % (len(anchors), total_new))
    got_keys = ["%s|%s" % (r.get("when"), r.get("root")) for r in anchors]
    if got_keys != seen_keys:
        bad.append("累积件与清单里的记录顺序/内容不一致")
    return bad


def report_ots(root, index):
    """--ots：看时间戳证明在不在、有没有上链（不做断言，只如实报）。"""
    import glob

    files = sorted(glob.glob(os.path.join(root, "ots", "*.ots")))
    print("\n[时间戳证明]")
    if not files:
        print("  没有 .ots 文件——说明一次都没提交过，或者被删了（删了也验得出："
              "索引还在，证明不在）")
        return
    for p in files:
        print("  %-40s %d 字节" % (os.path.basename(p), os.path.getsize(p)))
    print("  想看比特币区块高度，用官方工具：")
    print("    pip install opentimestamps-client")
    print("    ots upgrade <file>.ots   # 升级")
    print("    ots verify  <file>.ots   # 校验")


# --------------------------------------------------------------------------
def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--root", default=os.path.dirname(os.path.abspath(__file__)))
    ap.add_argument("--only", type=int, help="只验第 n 次发布")
    ap.add_argument("--ots", action="store_true", help="连带看时间戳证明")
    a = ap.parse_args()

    root = a.root
    index_path = os.path.join(root, "index.jsonl")
    if not os.path.exists(index_path):
        print("找不到 index.jsonl：%s" % index_path)
        return 2
    index = read_jsonl(index_path)
    if not index:
        print("index.jsonl 是空的")
        return 2

    checked = index
    if a.only:
        if not (1 <= a.only <= len(index)):
            print("--only %d 超出范围（1..%d）" % (a.only, len(index)))
            return 2
        checked = [index[a.only - 1]]

    manifests = []
    for row in checked:
        p = os.path.join(root, row.get("manifest") or "")
        manifests.append(json.load(open(p, encoding="utf-8"))
                         if row.get("manifest") and os.path.exists(p) else None)

    print("仓库：%s" % root)
    print("发布次数：%d ｜ 本次校验：%d 次" % (len(index), len(checked)))
    print("")

    failures = []
    steps = [
        ("发布链没断", lambda: check_index_chain(index)),
        ("清单没被换", lambda: check_manifests(root, checked)),
        ("总指纹算得对", lambda: check_roots(checked, manifests)),
        ("令牌没被换", lambda: check_tokens(root, manifests)),
        ("记录不重不漏", lambda: check_coverage(root, checked, manifests)),
    ]
    for i, (name, fn) in enumerate(steps, 1):
        try:
            bad = fn()
        except Exception as e:                      # noqa: BLE001
            bad = ["检查本身出错 %s: %s" % (type(e).__name__, e)]
        print("[%d] %-12s %s" % (i, name, "PASS" if not bad else
                                 "FAIL（%d 项）" % len(bad)))
        for b in bad:
            print("      - " + b)
        failures.extend(bad)

    if a.ots:
        report_ots(root, index)

    print("")
    if failures:
        print("VERDICT=FAIL  共 %d 项——这份公开记录不可信，别拿它当证据"
              % len(failures))
        return 1
    print("VERDICT=PASS  发布链完整、清单与令牌未被替换、总指纹与链事实一致、"
          "记录不重不漏")
    print("（这一步确认的是「公开记录自洽且没被动过」。它是否已被比特币见证，"
          "用 --ots 看，或用官方 ots 工具复核。）")
    return 0


if __name__ == "__main__":
    sys.exit(main())
