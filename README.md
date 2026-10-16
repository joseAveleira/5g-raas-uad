# 5G-RaaS-UAD: traffic data and reproducible analysis

Research materials for **A network traffic dataset of Android ransomware execution in a private 5G standalone network**.

This resource combines an original labelled CSV, two original packet captures, the available execution log, analysis code, prepared feature tables and recorded results. The captures contain network traffic, not an executable ransomware sample. All processing is offline.

## Is the original CSV obsolete?

No. `ransomware_dataset.csv` remains the preserved, labelled export of the November capture: **107,694 records and 85 columns**. Its hash and row order are retained. It is useful for reproducing the original descriptions and comparing representations.

The CSV is not a complete view of the inner traffic. Some columns are empty, repeated observations remain, and fragments obscure user-plane headers. The PCAP analysis adds a checked inner-header representation and derived feature tables. It does not overwrite or relabel the source CSV.

| Resource | Acquisition | Records | Role |
|---|---|---:|---|
| `ransomware-2.pcap` | 29 October 2025 | 123,003 | Companion acquisition; no verified execution-period labels |
| `ransomware-3.pcap` | 7 November 2025 | 107,694 | Acquisition corresponding to the labelled CSV |
| `ransomware_dataset.csv` | 7 November 2025 | 107,694 | Preserved labelled export |
| `attack_log_wireshark.txt` | 7 November 2025 | 4 events | Two execution intervals; reproduces every CSV label |

Large source files are compressed losslessly with gzip. See [`recursos/manifest.json`](recursos/manifest.json) for compressed and original SHA-256 checksums. No original capture bytes, packet times or labels have been changed.

## Start with the prepared data

Use Python 3.13; the reference environment used Python 3.13.5. From the repository root:

```bash
python -m venv .venv
# Activate .venv using the command for your shell.
python -m pip install -r experiments/pcap_analysis/requirements-lock.txt
python scripts/verify_release.py
python scripts/quickstart_service.py
```

The quick start fits the five-feature service-identification model from the supplied tables. It requires neither TShark nor decompression of the captures. It repeats feature selection within the October training set and evaluates once on the November set; it does not select variables on the test data. A successful run verifies the stored predictions and metrics for that case.

Useful tables:

- [`experiments/pcap_analysis/results/ransomware-2_service_prefix20_10s.csv`](experiments/pcap_analysis/results/ransomware-2_service_prefix20_10s.csv): 170 annotated October training connections.
- [`experiments/pcap_analysis/results/ransomware-3_service_prefix20_10s.csv`](experiments/pcap_analysis/results/ransomware-3_service_prefix20_10s.csv): 90 annotated November test connections.
- `experiments/pcap_analysis/results/inner_windows_*.csv`: inner-header features for temporal period classification.
- `experiments/results/features/`: original CSV feature representations and split manifests.
- `experiments/pcap_analysis/results/followup_metrics.csv`: all 52 comparisons in the second analysis phase.
- `experiments/pcap_analysis/results/followup_predictions.csv.gz`: recorded predictions for independent metric verification.

Connection IDs, row IDs, time ranges, labels and capture names are metadata. They must not be used as predictors. Domain, address, port and TEID values are excluded from the reported predictive feature sets. Annotation tables retain SNI and local addresses for provenance; these are not model inputs.

## Reproduce from the originals

Install TShark 4.6.4 in PATH in addition to the locked Python dependencies, then run:

```bash
python scripts/unpack_resources.py
python -m unittest discover -s experiments/tests -v
python experiments/pcap_analysis/test_decode.py
python experiments/run_experiments.py --input recursos/ransomware_dataset.csv
python experiments/pcap_analysis/run_pcap_study.py --resources recursos
```

The first study generates CSV features; the second uses their fixed window grids and the original captures. These commands regenerate results in `experiments/results` and `experiments/pcap_analysis/results`. Use a separate checkout if you want to preserve the packaged reference outputs for comparison. Fitted joblib models and large intermediate TShark exports are regenerated rather than distributed.

## Two different prediction targets

**Execution-period classification:** a positive label identifies a time interval when the prototype was running. Legitimate background traffic remains within positive intervals. Five selected inner-header features yield balanced accuracy 0.831 on the reported temporal comparison, with 5 false alarms among 23 baseline windows and 3 missed positive windows among 25 execution windows. Results are sensitive to temporal structure; this is one short labelled session.

**Experimental-service identification:** a positive label means the observed TLS SNI identifies the experimental service. The principal representation uses at most the first 20 packets within the first 10 seconds. Training on October and testing on November, a five-feature forest has TN=53, FP=1, FN=0 and TP=36 (balanced accuracy 0.990741). This is **not a 99.1% ransomware detection claim**. It may reflect service, client-library and device characteristics. Connections without a single observed SNI are excluded: 98 in October and 49 in November.

The five selected features in the reference fit are `up_size_mean`, `down_size_mean`, `down_size_std`, `tcp_window_raw_std` and `tcp_window_raw_p90`. Size features use declared inner-IP lengths, and TCP window fields are unscaled raw values. Header recovery does not reconstruct missing payload bytes.

The analysis is exploratory, with two acquisition days and limited device/service diversity. No cross-family, cross-site or universal malware-detection claim is supported. See the [CSV protocol](experiments/PROTOCOL.md) and [PCAP protocol](experiments/pcap_analysis/PROTOCOL.md).

## Provenance, checks and data handling

- The source CSV matches the November PCAP in frame numbers, lengths and microsecond timestamps.
- Byte grouping retains 61,501 and 53,832 network observations in October and November respectively.
- Complete inner headers are additionally recovered from 26,929 partial bodies across both captures.
- The reference decoder was compared against TShark on 88,299 complete observations and against Scapy on 1,261 stratified observations.
- The resource includes original network identifiers and service names; it is **not an anonymized dataset**. Treat source identifiers as capture-specific context.
- The publication inspection found no frames decoded as HTTP authorization, HTTP cookies, SMTP credentials, FTP passwords or IMSI in either capture. This is a bounded decoder-based check, not a guarantee that arbitrary packet bytes contain no identifiers. No TLS decryption was performed.

## Authors and citation

Diego Narciandi-Rodríguez; Jose Aveleira-Mata; María Teresa García-Ordás; Javier Alfonso-Cendón; Carmen Benavides; Isaías García-Rodríguez.

Use [`CITATION.cff`](CITATION.cff) to cite the research resource. The manuscript is a work in preparation/submission, not a published journal article. This repository does not assign authorship to software tools.

The original CSV was shared by its creators on [Figshare](https://figshare.com/s/160750e5d36974bb4c71?file=59439863) under CC BY 4.0. The inspected Figshare link was a private sharing link and did not provide a public DOI. Licensing for the additional release materials is described in [LICENSE.md](LICENSE.md).
