from __future__ import annotations
import hashlib
from pathlib import Path
import numpy as np
import pandas as pd

META = ["row_id", "t", "label", "block", "candidate_group"]
PROTOCOLS = ["tcp", "quic", "tls", "dns", "http", "sctp", "ngap", "gtp"]
REPEAT_EXCLUDE = [
    "frame_number", "frame_time_epoch", "frame_time_delta",
    "frame_time_delta_displayed", "sll_pkttype", "label", "timestamp_human", "type",
]
FORBIDDEN = ["label", "type", "timestamp", "frame_number", "frame_time_epoch",
             "ip_src", "ip_dst", "gtp_teid", "tcp_stream", "udp_stream", "ip_id",
             "tcp_seq", "tcp_ack", "checksum", "dns_qry_name", "http_host",
             "server_name", "row_id", "candidate_group", "block_id"]


def forbidden_feature(name):
    # "type" is the target text column, not every legitimate protocol field
    # containing this word (e.g. tls_record_content_type).
    return name in FORBIDDEN or any(name.startswith(x + "_") for x in FORBIDDEN if x != "type")


def read_capture(path: Path):
    raw = pd.read_csv(path, low_memory=False)
    assert raw.label.isin([0, 1]).all()
    assert raw.type.eq(raw.label.map({0: "normal", 1: "attack"})).all()
    assert raw.frame_time_epoch.is_monotonic_increasing
    df = raw.copy()
    df["row_id"] = np.arange(len(df))
    df["t"] = df.frame_time_epoch - df.frame_time_epoch.iloc[0]
    df["block"] = df.label.ne(df.label.shift()).cumsum().astype(int)
    tokens = df.frame_protocols.str.split(":")
    for p in PROTOCOLS:
        df[f"has_{p}"] = tokens.map(lambda v: p in v).astype(float)
    df["opaque_fragment"] = (
        df.frame_protocols.eq("sll:ethertype:ip:data") &
        df.ip_proto_1.eq(17) & df.ip_flags_mf.eq(True)
    ).astype(float)
    # These ranges express uncertainty between differently labelled observations.
    changes = np.flatnonzero(df.label.to_numpy()[1:] != df.label.to_numpy()[:-1]) + 1
    boundaries = [(float(df.t.iloc[i - 1]), float(df.t.iloc[i])) for i in changes]
    assert len(boundaries) == 4, "Protocol expects the five blocks in this source capture."
    cutoff = sum(boundaries[1]) / 2
    sha = hashlib.sha256(path.read_bytes()).hexdigest()
    return raw, df, boundaries, cutoff, sha


def candidate_repeats(raw: pd.DataFrame, tolerance: float):
    """Cluster matching exported packet fields within an anchor-based tolerance.

    Labels and capture-specific index/time/direction are NOT used in the key.
    This identifies candidates, not confirmed duplicates of full packet bytes.
    """
    fields = [c for c in raw.columns if c not in REPEAT_EXCLUDE]
    fingerprints = pd.util.hash_pandas_object(raw[fields], index=False).to_numpy()
    times = raw.frame_time_epoch.to_numpy()
    last = {}
    groups = np.empty(len(raw), dtype=np.int64)
    for i, (fp, ti) in enumerate(zip(fingerprints, times)):
        previous = last.get(fp)
        if previous is None or ti - previous[1] > tolerance:
            last[fp] = (i, ti)
            groups[i] = i
        else:
            groups[i] = previous[0]
    return groups, fields


def numeric(series: pd.Series):
    if pd.api.types.is_numeric_dtype(series) or pd.api.types.is_bool_dtype(series):
        return pd.to_numeric(series, errors="raise").astype(float)
    def parse(v):
        if pd.isna(v): return np.nan
        if isinstance(v, (bool, np.bool_)): return float(v)
        s = str(v)
        if s == "True": return 1.
        if s == "False": return 0.
        if s.startswith("0x"): return float(int(s, 16))
        return float(s)
    return series.map(parse).astype(float)


def packet_features(df: pd.DataFrame):
    # No absolute timestamps, raw ports, addresses, TEIDs, stream IDs or flags
    # whose occurrence among repeated IP headers has not been established.
    out = pd.DataFrame(index=df.index)
    out["size"] = df.frame_len.astype(float)
    for p in PROTOCOLS:
        out[f"presence_{p}"] = df[f"has_{p}"]
    for field in ["tcp_len", "tcp_window_size", "tcp_flags_syn", "tcp_flags_ack",
                  "tcp_flags_fin", "tcp_flags_reset", "quic_packet_length",
                  "quic_header_form", "quic_long_packet_type", "dns_flags_response",
                  "dns_count_answers", "tls_handshake_type", "tls_record_content_type"]:
        out[field] = numeric(df[field])
    out["gtp_length"] = df.gtp_length.astype(float)
    out["opaque_fragment"] = df.opaque_fragment
    assert not any(forbidden_feature(c) for c in out.columns)
    return out


def describe(values):
    a = np.asarray(values, dtype=float)
    a = a[np.isfinite(a)]
    if not len(a): return {k: np.nan for k in ["mean", "std", "median", "p90"]}
    return {"mean": float(a.mean()), "std": float(a.std()),
            "median": float(np.median(a)), "p90": float(np.quantile(a, .9))}


def make_windows(df, width, boundaries, capture_end, scope="all"):
    """Fixed non-overlapping windows. Empty, partial and uncertain bins are excluded."""
    work = df if scope == "all" else df.loc[df.has_gtp.eq(1)]
    work = work.copy()
    work["bin"] = np.floor(work.t / width).astype(int)
    rows, excluded = [], []
    for bid, block in work.groupby("bin", sort=True):
        start, end = float(bid * width), float((bid + 1) * width)
        reason = None
        if end > capture_end: reason = "partial_capture_end"
        elif any(start <= hi and end > lo for lo, hi in boundaries): reason = "label_boundary_uncertainty"
        elif block.label.nunique() != 1: reason = "mixed_label"
        if reason:
            excluded.append({"window_id": int(bid), "start": start, "end": end, "reason": reason})
            continue
        n = len(block)
        sizes = block.frame_len.to_numpy(float)
        dt = np.diff(block.t.to_numpy(float))  # within this window only
        d = {"window_id": int(bid), "start": start, "end": end,
             "label": int(block.label.iloc[0]), "block_id": int(block.block.iloc[0]),
             "n_rows": n, "source_row_first": int(block.row_id.min()),
             "source_row_last": int(block.row_id.max())}
        d["rate_records"] = n / width
        d["rate_bytes"] = sizes.sum() / width
        for name, v in describe(sizes).items(): d[f"size_{name}"] = v
        d["size_small_fraction"] = float((sizes <= 128).mean())
        d["size_mtu_fraction"] = float((sizes >= 1500).mean())
        hist = np.histogram(sizes, bins=[0, 64, 128, 256, 512, 1024, 1500, np.inf])[0] / n
        d["size_entropy"] = float(-np.sum(hist[hist > 0] * np.log2(hist[hist > 0])))
        for name, v in describe(dt).items(): d[f"iat_{name}"] = v
        d["iat_burst_fraction"] = float((dt < .001).mean()) if len(dt) else np.nan
        for p in PROTOCOLS: d[f"fraction_{p}"] = float(block[f"has_{p}"].mean())
        for field in ["tcp_len", "tcp_window_size", "quic_packet_length"]:
            for name, v in describe(numeric(block[field])).items():
                d[f"{field}_{name}"] = v
        for field in ["tcp_flags_syn", "tcp_flags_ack", "tcp_flags_fin",
                      "tcp_flags_reset", "quic_header_form", "dns_flags_response"]:
            a = numeric(block[field]).dropna()
            d[f"{field}_fraction"] = float(a.mean()) if len(a) else np.nan
        d["tls_handshake_fraction"] = float(block.tls_handshake_type.notna().mean())
        for name, v in describe(block.gtp_length).items(): d[f"gtp_length_{name}"] = v
        d["opaque_fragment_fraction"] = float(block.opaque_fragment.mean())
        d["opaque_fragment_byte_fraction"] = float(sizes @ block.opaque_fragment.to_numpy() / sizes.sum())
        rows.append(d)
    result = pd.DataFrame(rows)
    assert not result.empty
    assert result.groupby("window_id").size().eq(1).all()
    return result, pd.DataFrame(excluded)


def feature_groups(windows):
    metadata = {"window_id", "start", "end", "label", "block_id", "n_rows",
                "source_row_first", "source_row_last"}
    all_features = [c for c in windows if c not in metadata]
    gtp = [c for c in all_features if c.startswith("gtp_length_")]
    fragment = [c for c in all_features if c.startswith("opaque_fragment")]
    volume = [c for c in all_features if c.startswith(("rate_", "size_", "iat_"))]
    network = [c for c in all_features if c not in gtp + fragment + ["fraction_gtp"]]
    groups = {
        "volume": volume,
        "network": network,
        "network_gtp_presence": network + ["fraction_gtp"],
        "network_gtp_fields": network + ["fraction_gtp"] + gtp,
        "capture_context": network + ["fraction_gtp"] + gtp + fragment,
        "gtp_only": ["fraction_gtp"] + gtp,
        "selected_5": network + ["fraction_gtp"] + gtp + fragment,
        "selected_10": network + ["fraction_gtp"] + gtp + fragment,
    }
    for cols in groups.values():
        assert not any(forbidden_feature(c) for c in cols)
    return groups


def temporal_split(windows, cutoff, gap, direction="forward"):
    early = windows.end.le(cutoff - gap).to_numpy()
    late = windows.start.ge(cutoff + gap).to_numpy()
    train, test = (early, late) if direction == "forward" else (late, early)
    assert not (train & test).any()
    assert windows.loc[train, "label"].nunique() == 2
    assert windows.loc[test, "label"].nunique() == 2
    assert windows.loc[early, "end"].max() < windows.loc[late, "start"].min()
    return np.flatnonzero(train), np.flatnonzero(test)
