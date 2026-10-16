"""Audit the unmodified CSV and regenerate descriptive paper assets.

No learning algorithm is fitted. All retained rows preserve source order.
Usage: python scripts/prepare_dataset.py --input ../recursos/ransomware_dataset.csv
Requires: numpy, pandas, matplotlib. Outputs stay inside this project.
"""
from pathlib import Path
import argparse
import hashlib
import json

import numpy as np
import pandas as pd
import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt

ROOT = Path(__file__).resolve().parents[1]
PROTOCOLS = ["gtp", "quic", "tcp", "tls", "sctp", "ngap", "dns", "http"]


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--input", type=Path, default=ROOT.parent / "recursos" / "ransomware_dataset.csv")
    args = parser.parse_args()
    source = args.input.resolve()
    df = pd.read_csv(source, low_memory=False)
    required = {"frame_time_epoch", "frame_protocols", "label", "type", "frame_number"}
    if not required <= set(df):
        raise ValueError(f"Missing columns: {required - set(df)}")
    if not df.label.isin([0, 1]).all():
        raise ValueError("Unexpected/missing label")
    if not df.type.eq(df.label.map({0: "normal", 1: "attack"})).all():
        raise ValueError("Binary and text labels disagree")
    ts = pd.to_numeric(df.frame_time_epoch, errors="raise")
    if not ts.is_monotonic_increasing:
        raise ValueError("Source rows are not chronological; inspect before splitting")
    rel = ts - ts.iloc[0]
    out = ROOT / "data"
    out.mkdir(exist_ok=True)
    (ROOT / "figures").mkdir(exist_ok=True)
    (ROOT / "tables").mkdir(exist_ok=True)
    tokens = df.frame_protocols.fillna("").str.split(":")
    present = pd.DataFrame({p: tokens.map(lambda x: p in x) for p in PROTOCOLS})
    runs = df.label.ne(df.label.shift()).cumsum().astype(int)
    blocks = []
    for bid, group in df.groupby(runs, sort=False):
        ix = group.index
        blocks.append({"block_id": int(bid), "label": int(group.label.iloc[0]),
                       "records": len(group), "first_row_zero_based": int(ix[0]),
                       "last_row_zero_based": int(ix[-1]),
                       "first_observed_s": float(rel.loc[ix[0]]),
                       "last_observed_s": float(rel.loc[ix[-1]])})
    counts = []
    for p in PROTOCOLS:
        inside = int((present[p] & df.label.eq(1)).sum())
        outside = int((present[p] & df.label.eq(0)).sum())
        counts.append({"protocol": p, "total": inside + outside, "inside": inside,
                       "outside": outside,
                       "inside_percent": inside / df.label.eq(1).sum() * 100,
                       "outside_percent": outside / df.label.eq(0).sum() * 100})
    metadata = {"frame_number", "frame_time_epoch", "timestamp_human", "label", "type"}
    identifiers = {"eth_src", "eth_dst", "ip_src", "ip_dst", "ip_src_1", "ip_dst_1",
                   "ip_id", "udp_stream", "tcp_stream", "gtp_teid", "tcp_seq", "tcp_ack",
                   "udp_checksum", "sctp_checksum", "dns_qry_name", "dns_a", "dns_aaaa",
                   "http_request_uri", "http_request_full_uri", "http_host", "http_user_agent",
                   "tls_handshake_extensions_server_name", "tls_handshake_cert_url_url_hash"}
    # GTP field values are a separate ablation from ordinary packet/transport fields.
    # Raw TEID is deliberately excluded from predictors; it is only a grouping key.
    schema = []
    for i, col in enumerate(df.columns):
        nonnull = int(df[col].notna().sum())
        unique = int(df[col].nunique(dropna=True))
        if col == "frame_protocols":
            role, reason = "derived_indicators", "tokenise into declared protocol indicators; never use raw stack string"
        elif col in metadata:
            role, reason = "exclude", "target, absolute time or row index"
        elif nonnull == 0:
            role, reason = "exclude", "empty in this capture"
        elif col in identifiers:
            role, reason = "exclude", "identifier, endpoint/content clue or sequence/checksum"
        elif unique <= 1:
            role, reason = "presence_only", "constant when present; retain only missing/present indicator"
        else:
            role, reason = "candidate", "inspect encoding and fit preprocessing on training blocks only"
        schema.append({"position": i + 1, "field": col, "dtype": str(df[col].dtype),
                       "non_null": nonnull, "missing_percent": 100 * (1 - nonnull / len(df)),
                       "unique_non_null": unique,
                       "group": "gtp" if col.startswith("gtp_") else "network",
                       "proposed_role": role, "reason": reason})
    s = pd.DataFrame(schema)
    s.to_csv(out / "schema_audit.csv", index=False)
    pd.DataFrame(blocks).to_csv(out / "temporal_blocks.csv", index=False)
    c = pd.DataFrame(counts)
    c.to_csv(out / "protocol_counts.csv", index=False)
    # This manifest is for diagnostics/grouping, never a feature table.
    pd.DataFrame({"source_row_zero_based": df.index, "time_since_start_s": rel,
                  "temporal_block_id": runs, "label": df.label}).to_csv(out / "row_manifest.csv.gz", index=False)
    candidate_network = s.loc[(s.group.eq("network")) & s.proposed_role.eq("candidate"), "field"].tolist()
    candidate_gtp = s.loc[(s.group.eq("gtp")) & s.proposed_role.eq("candidate"), "field"].tolist()
    presence = s.loc[s.proposed_role.eq("presence_only"), "field"].tolist()
    config = {
        "status": "prospective feature plan; no model has been trained",
        "target": "label (execution period, not packet maliciousness)",
        "candidate_network_value_fields": candidate_network,
        "candidate_gtp_value_fields": candidate_gtp,
        "presence_only_fields": presence,
        "excluded_raw_fields": s.loc[s.proposed_role.eq("exclude"), "field"].tolist(),
        "protocol_presence_indicators": PROTOCOLS,
        "ablations": {
            "network": "network fields and protocol indicators excluding gtp",
            "network_plus_gtp_presence": "network + gtp-present indicator",
            "network_plus_gtp_fields": "network + gtp-present + permitted GTP values/presence",
            "gtp_only": "gtp presence and permitted GTP fields; descriptive control"},
        "requirements": [
            "Parse frame_protocols into explicit indicators; exclude the gtp token from the network baseline.",
            "Do not use raw TEID, endpoint addresses, frame/time identifiers, stream IDs or names as predictors.",
            "Do not infer inner versus outer IP/UDP from the suffix alone; validate against the original PCAP.",
            "No random packet split. Use temporal blocks, a declared gap and duplicate grouping.",
            "Each test fold needs held-out baseline AND execution intervals; holding only an attack window is insufficient.",
            "Feature selection, imputation and scaling must be fitted inside training folds only.",
            "A manifest block ID is not an independent session or a device identifier.",
            "Only exploratory within-session results are supportable from this single capture."]}
    (out / "feature_plan.json").write_text(json.dumps(config, indent=2), encoding="utf-8")
    exact_duplicate_rows = int(df.duplicated().sum())
    summary = {"source_filename": source.name, "source_sha256": hashlib.sha256(source.read_bytes()).hexdigest(),
               "source_bytes": source.stat().st_size, "records": len(df), "columns": len(df.columns),
               "capture_span_seconds": float(rel.iloc[-1]),
               "labels": {str(k): int(v) for k, v in df.label.value_counts().sort_index().items()},
               "empty_fields": df.columns[df.isna().all()].tolist(),
               "exact_duplicate_full_rows": exact_duplicate_rows,
               "near_duplicate_status": "not resolved by full-row equality; packet indices/timestamps differ",
               "blocks": blocks,
               "boundary_note": "Observed first/last labelled frames are not execution-log boundaries; no log supplied."}
    (out / "audit_summary.json").write_text(json.dumps(summary, indent=2), encoding="utf-8")
    texrows = ["% Generated by scripts/prepare_dataset.py; counts are non-exclusive.",
               r"\begin{tabular}{@{}l r r r@{}}", r"\toprule",
               "Protocol & Total & Inside windows & Outside windows " + chr(92) * 2, r"\midrule"]
    names = {"gtp": "GTP-U", **{x: x.upper() for x in PROTOCOLS if x != "gtp"}}
    for item in counts:
        texrows.append(f"{names[item['protocol']]} & {item['total']:,} & {item['inside']:,} & {item['outside']:,} " + chr(92) * 2)
    texrows.extend([r"\bottomrule", r"\end{tabular}"])
    (ROOT / "tables" / "protocol_rows.tex").write_text("\n".join(texrows) + "\n", encoding="utf-8")
    winrows = ["% Observed CSV bounds, not reconstructed execution-log times.",
               r"\begin{tabular}{@{}r r r r@{}}", r"\toprule",
               "Run & First labelled frame (s) & Last labelled frame (s) & Records " + chr(92) * 2, r"\midrule"]
    for n, block in enumerate([b for b in blocks if b["label"] == 1], 1):
        winrows.append(f"{n} & {block['first_observed_s']:.3f} & {block['last_observed_s']:.3f} & {block['records']:,} " + chr(92) * 2)
    winrows.extend([r"\bottomrule", r"\end{tabular}"])
    (ROOT / "tables" / "window_rows.tex").write_text("\n".join(winrows) + "\n", encoding="utf-8")
    plt.rcParams.update({"font.family": "DejaVu Sans", "font.size": 10, "pdf.fonttype": 42})
    fig, axes = plt.subplots(2, 1, figsize=(7.0, 6.1), constrained_layout=True)
    bins = np.arange(0, np.ceil(rel.iloc[-1]) + 1)
    bins[-1] = float(rel.iloc[-1])
    hist, edges = np.histogram(rel, bins=bins)
    axes[0].stairs(hist / np.diff(edges), edges, color="#235c80", linewidth=1)
    for n, b in enumerate([b for b in blocks if b["label"] == 1], 1):
        axes[0].axvspan(b["first_observed_s"], b["last_observed_s"], color="#dd9d5a", alpha=.22)
        axes[0].text((b["first_observed_s"] + b["last_observed_s"]) / 2, .94,
                     f"Execution {n}", ha="center", va="top", transform=axes[0].get_xaxis_transform(), fontsize=9)
    axes[0].set(xlabel="Time since first captured frame (s)", ylabel="Captured records/s",
                title="(a) Traffic rate and observed labelled spans", xlim=(0, 292))
    x = np.arange(len(c))
    axes[1].bar(x - .18, c.outside_percent, width=.36, color="#235c80", label="Outside execution windows")
    axes[1].bar(x + .18, c.inside_percent, width=.36, color="#d78d42", label="Inside execution windows")
    axes[1].set(xticks=x, xticklabels=[names[p] for p in PROTOCOLS], ylabel="Records containing protocol (%)",
                title="(b) Non-exclusive protocol presence", ylim=(0, 105))
    axes[1].legend(loc="upper right", frameon=False, fontsize=9)
    for ax in axes:
        ax.spines[["top", "right"]].set_visible(False)
        ax.set_axisbelow(True)
        ax.grid(axis="y", alpha=.18)
    fig.savefig(ROOT / "figures" / "traffic_characterisation.pdf")
    fig.savefig(ROOT / "figures" / "traffic_characterisation.png", dpi=160)
    plt.close(fig)
    print(json.dumps({"records": len(df), "columns": len(df.columns), "empty_fields": int(df.isna().all().sum()),
                      "sha256": summary["source_sha256"], "output": str(out)}, indent=2))


if __name__ == "__main__":
    main()
