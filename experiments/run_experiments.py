"""Run the complete, fixed exploratory protocol. No hyperparameter search.

From the manuscript directory:
    python experiments/run_experiments.py --input ../recursos/ransomware_dataset.csv
The input is read only. Existing derived results in --output are regenerated.
"""
from __future__ import annotations
import argparse
from datetime import datetime, timezone
import hashlib
import json
import platform
import sys
from pathlib import Path
import warnings

import joblib
import numpy as np
import pandas as pd
import scipy
import sklearn
from sklearn.model_selection import train_test_split
from sklearn.tree import DecisionTreeClassifier
from sklearn.inspection import permutation_importance

from src.data import (read_capture, candidate_repeats, make_windows,
                      feature_groups, temporal_split, packet_features)
from src.evaluation import fit_evaluate, metrics
from src.reporting import create_figures, create_report

HERE = Path(__file__).resolve().parent
PROJECT = HERE.parent


def json_write(path, obj):
    path.write_text(json.dumps(obj, indent=2, ensure_ascii=False), encoding="utf-8")


def audit(raw, df, boundaries, cutoff, config, out, sha):
    repeats = []
    for tol in config["repeat_tolerance_sensitivity_seconds"]:
        groups, fields = candidate_repeats(raw, tol)
        conflicts = pd.DataFrame({"group": groups, "label": df.label}).groupby("group").label.nunique().gt(1).sum()
        repeats.append({"tolerance_seconds": tol, "records": len(raw),
                        "retained": len(np.unique(groups)),
                        "candidate_repeated_records": len(raw) - len(np.unique(groups)),
                        "conflicting_label_groups": int(conflicts)})
    groups, fields = candidate_repeats(raw, config["repeat_tolerance_seconds"])
    df["candidate_group"] = groups
    repeated = df.row_id.ne(df.candidate_group)
    group_summary = df.groupby("candidate_group").agg(
        records=("row_id", "size"), first_time=("t", "min"), last_time=("t", "max"),
        label_count=("label", "nunique"), label=("label", "first"))
    assert group_summary.label_count.max() == 1
    assert (group_summary.last_time - group_summary.first_time).max() <= config["repeat_tolerance_seconds"] + 1e-6
    group_summary.to_csv(out / "audit" / "candidate_group_summary.csv.gz")
    df[["row_id", "t", "label", "block", "candidate_group"]].to_csv(out / "audit" / "row_manifest.csv.gz", index=False)
    pd.DataFrame(repeats).to_csv(out / "audit" / "repeat_sensitivity.csv", index=False)
    json_write(out / "audit" / "repeat_key_fields.json", fields)
    retained = df.loc[~repeated].copy()
    conditions = []
    for representation, data in [("raw", df), ("candidate_collapsed", retained)]:
        for lab in [0, 1]:
            sub = data.loc[data.label.eq(lab)]
            gtp = sub.has_gtp.eq(1)
            n = len(sub)
            conditions.append({
                "representation": representation, "label": lab, "records": n,
                "decoded_gtp": int(gtp.sum()), "decoded_gtp_percent": 100 * gtp.mean(),
                "opaque_udp_mf": int(sub.opaque_fragment.sum()),
                "opaque_udp_mf_percent": 100 * sub.opaque_fragment.mean(),
                "other": int((~gtp & sub.opaque_fragment.eq(0)).sum()),
                "tcp_all_percent": 100 * sub.has_tcp.mean(),
                "tcp_among_gtp_percent": 100 * sub.loc[gtp, "has_tcp"].mean(),
                "quic_among_gtp_percent": 100 * sub.loc[gtp, "has_quic"].mean(),
            })
    pd.DataFrame(conditions).to_csv(out / "audit" / "protocol_visibility.csv", index=False)
    redundancy = []
    for name, a, b, mask in [
        ("frame_cap_len = frame_len", df.frame_cap_len, df.frame_len, df.frame_len.notna()),
        ("ip_len_1 = frame_len - 16", df.ip_len_1, df.frame_len - 16, df.ip_len_1.notna()),
        ("gtp_length = frame_len - 52", df.gtp_length, df.frame_len - 52, df.gtp_length.notna()),
        ("udp_length_1 = gtp_length + 16", df.udp_length_1, df.gtp_length + 16, df.gtp_length.notna()),
    ]:
        redundancy.append({"relationship": name, "records_checked": int(mask.sum()),
                           "violations": int((~np.isclose(a.loc[mask], b.loc[mask], rtol=0, atol=1e-9)).sum())})
    pd.DataFrame(redundancy).to_csv(out / "audit" / "redundancy.csv", index=False)
    tunnel_rows = []
    g = retained.loc[retained.has_gtp.eq(1)].copy()
    ordering = g.groupby("gtp_teid").t.min().sort_values().index
    aliases = {v: f"T{i:02}" for i, v in enumerate(ordering, 1)}
    g["tunnel_alias"] = g.gtp_teid.map(aliases)
    for teid, sub in g.groupby("gtp_teid", sort=False):
        tunnel_rows.append({
            "tunnel_alias": aliases[teid], "teid": teid, "records": len(sub),
            "first_time_s": float(sub.t.min()), "last_time_s": float(sub.t.max()),
            "baseline_records": int(sub.label.eq(0).sum()),
            "execution_records": int(sub.label.eq(1).sum()),
            "tcp_fraction": float(sub.has_tcp.mean()),
            "quic_fraction": float(sub.has_quic.mean()),
            "source_address_count": int(sub.ip_src_1.nunique()),
            "destination_address_count": int(sub.ip_dst_1.nunique()),
        })
    pd.DataFrame(tunnel_rows).sort_values("tunnel_alias").to_csv(out / "audit" / "tunnel_summary.csv", index=False)
    g["time_bin"] = np.floor(g.t / 2).astype(int)
    g.groupby(["tunnel_alias", "time_bin"]).size().rename("records").reset_index().to_csv(out / "audit" / "tunnel_timeline.csv", index=False)
    schema = pd.DataFrame({
        "field": raw.columns, "non_null": raw.notna().sum().values,
        "unique_non_null": raw.nunique(dropna=True).values,
        "missing_percent": raw.isna().mean().values * 100,
    })
    schema.to_csv(out / "audit" / "schema.csv", index=False)
    info = {
        "source_sha256": sha, "raw_records": len(df), "retained_records": len(retained),
        "candidate_repeated_records": int(repeated.sum()),
        "candidate_repeated_percent": float(100 * repeated.mean()),
        "empty_fields": raw.columns[raw.isna().all()].tolist(),
        "gtp_message_unique_non_null": int(raw.gtp_message.nunique()),
        "gtp_flags_unique_non_null": int(raw.gtp_flags.nunique()),
        "teids_observed": int(raw.gtp_teid.nunique()),
        "opaque_udp_mf_records": int(df.opaque_fragment.sum()),
        "opaque_udp_mf_frame_lengths": sorted(df.loc[df.opaque_fragment.eq(1), "frame_len"].unique().tolist()),
        "label_boundary_uncertainty": boundaries, "temporal_cutoff_s": cutoff,
        "max_candidate_group_span_s": float((group_summary.last_time - group_summary.first_time).max()),
        "limitations": ["No original PCAP, fragment offsets, payload bytes or exact execution log available.",
                        "Repeated headers within tolerance are candidates, not proof of identical packet bytes.",
                        "Opaque UDP records with MF set cannot be assigned to a particular GTP tunnel from this CSV.",
                        "TEIDs are local grouping keys, not verified device identities."]
    }
    json_write(out / "audit" / "summary.json", info)
    return retained, info


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--input", type=Path, default=PROJECT.parent / "recursos" / "ransomware_dataset.csv")
    parser.add_argument("--output", type=Path, default=HERE / "results")
    parser.add_argument("--config", type=Path, default=HERE / "config.json")
    args = parser.parse_args()
    config = json.loads(args.config.read_text(encoding="utf-8"))
    out = args.output.resolve()
    for folder in ["audit", "features", "metrics", "predictions", "models", "figures", "tables"]:
        (out / folder).mkdir(parents=True, exist_ok=True)
    json_write(out / "config_used.json", config)
    started = datetime.now(timezone.utc).isoformat()
    raw, df, boundaries, cutoff, sha = read_capture(args.input)
    print("Auditing repeats, protocol visibility, redundancy and tunnels...", flush=True)
    retained, audit_info = audit(raw, df, boundaries, cutoff, config, out, sha)
    print(f"Records: {len(df):,}; candidate-collapsed: {len(retained):,}.", flush=True)
    results, predictions, selections, splits = [], [], [], []
    stored = {}
    widths = [config["primary_window_seconds"]] + config["sensitivity_window_seconds"]
    primary = config["primary_window_seconds"]
    seed = config["seed"]
    for representation, data in [("candidate_collapsed", retained), ("raw", df)]:
        for scope in ["all", "decoded_gtp"]:
            if representation == "raw" and scope != "all": continue
            for width in widths:
                if representation == "raw" and width != primary: continue
                windows, excluded = make_windows(data, width, boundaries, float(df.t.max()), scope)
                tag = f"{representation}_{scope}_{width}s"
                windows.to_csv(out / "features" / f"{tag}.csv", index=False)
                excluded.to_csv(out / "features" / f"{tag}_excluded.csv", index=False)
                groups = feature_groups(windows)
                json_write(out / "features" / f"{tag}_groups.json", groups)
                if representation == "candidate_collapsed" and scope == "all" and width == primary:
                    names = list(groups)
                    directions = ["forward", "reverse"]
                elif representation == "candidate_collapsed" and scope == "all":
                    names = ["network", "network_gtp_presence", "capture_context", "selected_5"]
                    directions = ["forward", "reverse"]
                else:
                    names = ["network", "capture_context", "selected_5"] if scope == "all" else ["network", "selected_5"]
                    directions = ["forward"]
                for direction in directions:
                    train, test = temporal_split(windows, cutoff, config["embargo_seconds_each_side"], direction)
                    splitmeta = windows[["window_id", "start", "end", "label", "n_rows", "block_id"]].copy()
                    splitmeta["assignment"] = "embargo"
                    splitmeta.loc[train, "assignment"] = "train"
                    splitmeta.loc[test, "assignment"] = "test"
                    splitmeta["representation"], splitmeta["scope"] = representation, scope
                    splitmeta["width"], splitmeta["direction"] = width, direction
                    splits.append(splitmeta)
                    for name in names + ["dummy"]:
                        cols = groups["volume"] if name == "dummy" else groups[name]
                        k = int(name.split("_")[1]) if name.startswith("selected_") else None
                        for kind in (["dummy"] if name == "dummy" else ["logistic", "forest"]):
                            case = f"{tag}_{direction}_{name}_{kind}_{seed}"
                            model, score, proba, pred = fit_evaluate(
                                windows.iloc[train][cols], windows.label.iloc[train],
                                windows.iloc[test][cols], windows.label.iloc[test],
                                kind, seed, config, k)
                            base = {"case": case, "representation": representation, "scope": scope,
                                    "width": width, "direction": direction, "feature_set": name,
                                    "model": kind, "seed": seed, "experiment": "main_or_sensitivity"}
                            results.append({**base, **score})
                            pp = windows.iloc[test][["window_id", "start", "end", "label"]].copy()
                            pp["case"], pp["probability"], pp["prediction"] = case, proba, pred
                            predictions.append(pp)
                            if k:
                                before = model[:3].get_feature_names_out()
                                selector = model.named_steps["select"]
                                for f, v, chosen in zip(before, selector.scores_, selector.get_support()):
                                    selections.append({**base, "feature": f, "mutual_information": v, "selected": bool(chosen)})
                            if representation == "candidate_collapsed" and width == primary and scope == "all":
                                stored[(direction, name, kind)] = (model, windows, cols, train, test, case)
                                if name in ["network", "capture_context", "selected_5"]:
                                    joblib.dump(model, out / "models" / f"{case}.joblib", compress=3)
                    print(f"Completed {tag}, {direction}: {len(train)} train / {len(test)} test windows.", flush=True)
    print("Running fixed-seed and circular-label-shift controls...", flush=True)
    controls = []
    for name in ["network", "capture_context", "selected_5"]:
        model, w, cols, train, test, reference = stored[("forward", name, "forest")]
        k = 5 if name == "selected_5" else None
        for extra_seed in config["seed_sensitivity"]:
            _, score, _, _ = fit_evaluate(w.iloc[train][cols], w.label.iloc[train],
                                         w.iloc[test][cols], w.label.iloc[test],
                                         "forest", extra_seed, config, k)
            results.append({"case": f"seed_{name}_{extra_seed}", "representation": "candidate_collapsed",
                            "scope": "all", "width": primary, "direction": "forward",
                            "feature_set": name, "model": "forest", "seed": extra_seed,
                            "experiment": "seed_sensitivity", **score})
    for kind in ["logistic", "forest"]:
        model, w, cols, train, test, reference = stored[("forward", "capture_context", kind)]
        shifts = np.random.default_rng(seed).choice(np.arange(1, len(train)), size=min(config["shift_controls"], len(train)-1), replace=False)
        for shift in shifts:
            shifted = np.roll(w.label.iloc[train].to_numpy(), int(shift))
            _, score, _, _ = fit_evaluate(w.iloc[train][cols], shifted,
                                         w.iloc[test][cols], w.label.iloc[test], kind, seed, config)
            controls.append({"model": kind, "circular_shift": int(shift), **score})
    pd.DataFrame(controls).to_csv(out / "metrics" / "circular_shift_controls.csv", index=False)
    print("Computing held-out permutation importance (interpretation only)...", flush=True)
    model, w, cols, train, test, case = stored[("forward", "capture_context", "forest")]
    model.named_steps["model"].set_params(n_jobs=1)
    pi = permutation_importance(model, w.iloc[test][cols], w.label.iloc[test], scoring="balanced_accuracy",
                                n_repeats=config["permutation_repeats"], random_state=seed, n_jobs=1)
    pd.DataFrame({"feature": cols, "mean_BA_decrease": pi.importances_mean,
                  "permutation_sd": pi.importances_std}).sort_values("mean_BA_decrease", ascending=False).to_csv(
                      out / "metrics" / "heldout_permutation_importance.csv", index=False)
    # Checkpoint the completed window analyses before the packet diagnostics.
    pd.DataFrame(results).to_csv(out / "metrics" / "window_metrics.csv", index=False)
    pd.concat(predictions, ignore_index=True).to_csv(out / "predictions" / "window_predictions.csv.gz", index=False)
    pd.DataFrame(selections).to_csv(out / "metrics" / "selection_scores.csv", index=False)
    pd.concat(splits, ignore_index=True).to_csv(out / "features" / "split_manifest.csv", index=False)
    print("Running packet-split diagnostics and time-only control...", flush=True)
    packet_results, packet_predictions = packet_diagnostics(df, retained, cutoff, config)
    packet_results.to_csv(out / "metrics" / "packet_split_diagnostics.csv", index=False)
    packet_predictions.to_csv(out / "predictions" / "packet_diagnostics.csv.gz", index=False)
    metric_df = pd.DataFrame(results)
    metric_df.to_csv(out / "metrics" / "window_metrics.csv", index=False)
    pd.concat(predictions, ignore_index=True).to_csv(out / "predictions" / "window_predictions.csv.gz", index=False)
    pd.DataFrame(selections).to_csv(out / "metrics" / "selection_scores.csv", index=False)
    pd.concat(splits, ignore_index=True).to_csv(out / "features" / "split_manifest.csv", index=False)
    stability = []
    sel = pd.DataFrame(selections)
    for k in [5, 10]:
        sets = []
        for direction in ["forward", "reverse"]:
            mask = (sel.representation.eq("candidate_collapsed") & sel.scope.eq("all") &
                    sel.width.eq(primary) & sel.direction.eq(direction) &
                    sel.feature_set.eq(f"selected_{k}") & sel.model.eq("logistic") & sel.selected)
            sets.append(set(sel.loc[mask, "feature"]))
        stability.append({"k": k, "intersection": len(sets[0] & sets[1]), "union": len(sets[0] | sets[1]),
                          "jaccard": len(sets[0] & sets[1])/len(sets[0] | sets[1]),
                          "shared_features": sorted(sets[0] & sets[1]),
                          "forward_features": sorted(sets[0]), "reverse_features": sorted(sets[1])})
    json_write(out / "metrics" / "selection_stability.json", stability)
    manifest = {
        "started_utc": started, "completed_utc": datetime.now(timezone.utc).isoformat(),
        "input_filename": args.input.name, "input_sha256": sha,
        "config_sha256": hashlib.sha256(args.config.read_bytes()).hexdigest(),
        "python": sys.version, "platform": platform.platform(),
        "versions": {"numpy": np.__version__, "pandas": pd.__version__, "scipy": scipy.__version__,
                     "scikit-learn": sklearn.__version__, "joblib": joblib.__version__},
        "window_fits_reported": len(metric_df), "shift_control_fits": len(controls),
        "packet_diagnostic_fits": len(packet_results),
        "source_code_sha256": {str(p.relative_to(HERE)): hashlib.sha256(p.read_bytes()).hexdigest()
                               for p in [Path(__file__)] + sorted((HERE/"src").glob("*.py"))},
        "interpretation": config["interpretation"],
    }
    json_write(out / "run_manifest.json", manifest)
    assert hashlib.sha256(args.input.read_bytes()).hexdigest() == sha
    create_figures(out, df, retained, config, audit_info)
    create_report(out, config, audit_info)
    print("COMPLETE", json.dumps({"window_fits":len(metric_df), "shift_controls":len(controls),
                                 "packet_diagnostics":len(packet_results), "output":str(out)}), flush=True)
    mainmask = (metric_df.representation.eq("candidate_collapsed") & metric_df.scope.eq("all") &
                metric_df.width.eq(primary) & metric_df.direction.eq("forward") &
                metric_df.experiment.eq("main_or_sensitivity"))
    print(metric_df.loc[mainmask, ["feature_set","model","retained_features","balanced_accuracy","f1"]].to_string(index=False))


def packet_diagnostics(df, retained, cutoff, config):
    x = packet_features(df)
    seed = config["seed"]
    indices = np.arange(len(df))
    random_train, random_test = train_test_split(indices, test_size=.3, stratify=df.label, random_state=seed)
    anchors = np.sort(df.candidate_group.unique())
    gt, gv = train_test_split(anchors, test_size=.3, stratify=df.label.iloc[anchors], random_state=seed)
    group_train, group_test = np.flatnonzero(df.candidate_group.isin(gt)), np.flatnonzero(df.candidate_group.isin(gv))
    early = df.t.le(cutoff - config["embargo_seconds_each_side"])
    late = df.t.ge(cutoff + config["embargo_seconds_each_side"])
    keep = df.row_id.eq(df.candidate_group)
    cases = [
        ("random_packet", random_train, random_test),
        ("random_candidate_group", group_train, group_test),
        ("forward_time", np.flatnonzero(early), np.flatnonzero(late)),
        ("forward_time_candidate_collapsed", np.flatnonzero(early & keep), np.flatnonzero(late & keep)),
    ]
    rows, predictions = [], []
    for name, train, test in cases:
        _, score, probability, pred = fit_evaluate(
            x.iloc[train], df.label.iloc[train], x.iloc[test], df.label.iloc[test],
            "forest", seed, config)
        overlap = set(df.candidate_group.iloc[train]) & set(df.candidate_group.iloc[test])
        repeated_test_fraction = df.candidate_group.iloc[test].isin(overlap).mean()
        rows.append({"split": name, "model": "forest_packet_features",
                     "shared_candidate_groups": len(overlap),
                     "test_rows_with_candidate_in_training_fraction": repeated_test_fraction, **score})
        pp = df.iloc[test][["row_id","t","label","candidate_group"]].copy()
        pp["split"], pp["probability"], pp["prediction"] = name, probability, pred
        predictions.append(pp)
        if name in ["random_packet", "forward_time"]:
            # Deliberate non-detection control: timestamps trivially encode the
            # label construction. Never part of the admissible feature sets.
            control = DecisionTreeClassifier(max_depth=4, random_state=seed)
            control.fit(df.iloc[train][["t"]], df.label.iloc[train])
            p = control.predict_proba(df.iloc[test][["t"]])[:,1]
            score, _ = metrics(df.label.iloc[test], p)
            rows.append({"split": name, "model": "time_only_invalid_detector_control",
                         "shared_candidate_groups": len(overlap),
                         "test_rows_with_candidate_in_training_fraction": repeated_test_fraction, **score})
        print(f"Packet diagnostic complete: {name}.", flush=True)
    return pd.DataFrame(rows), pd.concat(predictions, ignore_index=True)


if __name__ == "__main__":
    main()
