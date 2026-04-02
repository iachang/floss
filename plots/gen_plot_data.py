#!/usr/bin/env python3
"""Generate all CSV files for LaTeX pgfplots (sort, shuffle, Pareto sort, Pareto shuffle).
Run from project root or plots/; outputs go to plots/plot_data/."""

import os
import argparse
import pandas as pd

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
ROOT_DIR = os.path.dirname(SCRIPT_DIR)
PLOT_DATA_DIR = os.path.join(SCRIPT_DIR, "plot_data")

# Sort/shuffle grid plot sizes
SORT_PLOT_INPUTS = [9, 10, 11, 12, 13]
SORT_PLOT_INPUTS_ALONE = [9, 10]
SHUFFLE_PLOT_INPUTS = [10, 12, 14, 16, 18, 20]
SHUFFLE_PLOT_INPUTS_ALONE = [10, 12, 14, 16]

# Pareto single-point sizes
PARETO_SORT_SIZE = 13
PARETO_SHUFFLE_SIZE = 20

# AWS pricing (for Pareto cost computation)
SPOT_COST_PER_HR = 0.93
SPOT_COST_PER_S = SPOT_COST_PER_HR / 3600
STORAGE_COST_PER_GB_PER_S = 0.023 / (30 * 24 * 3600)
PUT_COST = 0.005
GET_COST = 0.0004


def compute_offline_cost(offline_prep_time, online_time, bytes_total):
    """Offline compute cost in USD."""
    bytes_gb = bytes_total / (1024**3)
    return (
        offline_prep_time * SPOT_COST_PER_S
        + (online_time + offline_prep_time) * STORAGE_COST_PER_GB_PER_S * bytes_gb
        + PUT_COST
        + GET_COST
    )


def pareto_frontier(points):
    """points: list of (x, y, label). Minimize both. Returns frontier sorted by x asc."""
    pts = sorted(points, key=lambda t: t[0])
    frontier = []
    best_y = float("inf")
    for x, y, label in pts:
        if y < best_y:
            frontier.append((x, y, label))
            best_y = y
    return frontier


def generate_sort_csv(alone: bool):
    """Merged sort benchmark CSVs for plot_sorting.tex."""
    PLOT_INPUTS = SORT_PLOT_INPUTS_ALONE if alone else SORT_PLOT_INPUTS

    def load_sort_offline(name):
        df = pd.read_csv(os.path.join(ROOT_DIR, f"sort_{name}_offline.csv"))
        df = df[df["InputSize"].isin(PLOT_INPUTS)].drop_duplicates("InputSize", keep="first")
        return df.set_index("InputSize")

    def load_sort_online(name):
        df = pd.read_csv(os.path.join(ROOT_DIR, f"sort_{name}_online.csv"))
        df = df[df["InputSize"].isin(PLOT_INPUTS)].drop_duplicates("InputSize", keep="first")
        return df.set_index("InputSize")

    def load_shuffle_offline(name):
        df = pd.read_csv(os.path.join(ROOT_DIR, f"shuffle_{name}_offline.csv"))
        df = df[df["InputSize"].isin(PLOT_INPUTS)]
        return df.set_index("InputSize")

    def load_shuffle_online(name):
        df = pd.read_csv(os.path.join(ROOT_DIR, f"shuffle_{name}_online.csv"))
        df = df[df["InputSize"].isin(PLOT_INPUTS)]
        return df.set_index("InputSize")

    floss_sort_off = load_sort_offline("floss")
    perm_sort_off = load_sort_offline("perm_network")
    simple_sort_off = load_sort_offline("simple_perm_network")
    floss_sort_on = load_sort_online("floss")
    perm_sort_on = load_sort_online("perm_network")
    simple_sort_on = load_sort_online("simple_perm_network")
    floss_shuf_off = load_shuffle_offline("floss")
    perm_shuf_off = load_shuffle_offline("perm_network")
    simple_shuf_off = load_shuffle_offline("simple_perm_network")
    opmcc_shuf_off = load_shuffle_offline("opmcc")
    floss_shuf_on = load_shuffle_online("floss")
    perm_shuf_on = load_shuffle_online("perm_network")
    simple_shuf_on = load_shuffle_online("simple_perm_network")
    opmcc_shuf_on = load_shuffle_online("opmcc")

    quicksort = pd.read_csv(os.path.join(ROOT_DIR, "sort_quicksort.csv"))
    quicksort = quicksort[quicksort["InputSize"].isin(PLOT_INPUTS)].set_index("InputSize")
    sort_net = pd.read_csv(os.path.join(ROOT_DIR, "sort_sorting_network.csv"))
    sort_net = sort_net[sort_net["InputSize"].isin(PLOT_INPUTS)].set_index("InputSize")

    def off_time(df):
        return df["OfflinePrepTime"]

    def on_time(df):
        return df["OnlineTime"]

    def off_bytes_sort(df):
        return df["BytesSent"] + df["BytesRecv"]

    def on_bytes_sort(df):
        return df["BytesSent"] + df["BytesRecv"]

    def off_bytes_mp(df):
        return df["OfflineCommunication"]

    def on_bytes_mp(df):
        return df["OnlineCommunication"]

    floss_then_qs_on = floss_shuf_on["OnlineTime"] + quicksort["OnlineTime"]
    perm_then_qs_on = perm_shuf_on["OnlineTime"] + quicksort["OnlineTime"]
    simple_then_qs_on = simple_shuf_on["OnlineTime"] + quicksort["OnlineTime"]
    opmcc_then_qs_on = opmcc_shuf_on["OnlineTime"] + quicksort["OnlineTime"]
    floss_then_qs_off = floss_shuf_off["OfflinePrepTime"] + quicksort["OfflinePrepTime"]
    perm_then_qs_off = perm_shuf_off["OfflinePrepTime"] + quicksort["OfflinePrepTime"]
    simple_then_qs_off = simple_shuf_off["OfflinePrepTime"] + quicksort["OfflinePrepTime"]
    opmcc_then_qs_off = opmcc_shuf_off["OfflinePrepTime"] + quicksort["OfflinePrepTime"]
    floss_then_qs_total = floss_then_qs_off + floss_then_qs_on
    perm_then_qs_total = perm_then_qs_off + perm_then_qs_on
    simple_then_qs_total = simple_then_qs_off + simple_then_qs_on
    opmcc_then_qs_total = opmcc_then_qs_off + opmcc_then_qs_on

    floss_sort_off_b = off_bytes_sort(floss_sort_off)
    perm_sort_off_b = off_bytes_sort(perm_sort_off)
    simple_sort_off_b = off_bytes_sort(simple_sort_off)
    floss_shuf_off_b = off_bytes_sort(floss_shuf_off)
    perm_shuf_off_b = off_bytes_sort(perm_shuf_off)
    simple_shuf_off_b = off_bytes_sort(simple_shuf_off)
    opmcc_shuf_off_b = off_bytes_sort(opmcc_shuf_off)
    floss_sort_on_b = on_bytes_sort(floss_sort_on)
    perm_sort_on_b = on_bytes_sort(perm_sort_on)
    simple_sort_on_b = on_bytes_sort(simple_sort_on)
    floss_shuf_on_b = on_bytes_sort(floss_shuf_on)
    perm_shuf_on_b = on_bytes_sort(perm_shuf_on)
    simple_shuf_on_b = on_bytes_sort(simple_shuf_on)
    opmcc_shuf_on_b = on_bytes_sort(opmcc_shuf_on)
    floss_then_qs_off_b = floss_shuf_off_b + off_bytes_mp(quicksort)
    perm_then_qs_off_b = perm_shuf_off_b + off_bytes_mp(quicksort)
    simple_then_qs_off_b = simple_shuf_off_b + off_bytes_mp(quicksort)
    opmcc_then_qs_off_b = opmcc_shuf_off_b + off_bytes_mp(quicksort)
    floss_then_qs_on_b = floss_shuf_on_b + on_bytes_mp(quicksort)
    perm_then_qs_on_b = perm_shuf_on_b + on_bytes_mp(quicksort)
    simple_then_qs_on_b = simple_shuf_on_b + on_bytes_mp(quicksort)
    opmcc_then_qs_on_b = opmcc_shuf_on_b + on_bytes_mp(quicksort)

    def to_mb(x):
        return x / (1024 * 1024)

    def build_rows(keys_dict):
        return [
            {
                "Index": i,
                "InputSize": sz,
                **{k: v.loc[sz] if sz in v.index else 0 for k, v in keys_dict.items()},
            }
            for i, sz in enumerate(PLOT_INPUTS)
        ]

    for label, keys in [
        ("sort_online_time", {
            "FLOSSRadix": on_time(floss_sort_on),
            "PermNetRadix": on_time(perm_sort_on),
            "SimplePermNetRadix": on_time(simple_sort_on),
            "FLOSSthenSort": floss_then_qs_on,
            "PermNetthenSort": perm_then_qs_on,
            "SimplePermNetthenSort": simple_then_qs_on,
            "OPMCCthenSort": opmcc_then_qs_on,
            "SortingNetwork": on_time(sort_net),
        }),
        ("sort_offline_time", {
            "FLOSSRadix": off_time(floss_sort_off),
            "PermNetRadix": off_time(perm_sort_off),
            "SimplePermNetRadix": off_time(simple_sort_off),
            "FLOSSthenSort": floss_then_qs_off,
            "PermNetthenSort": perm_then_qs_off,
            "SimplePermNetthenSort": simple_then_qs_off,
            "OPMCCthenSort": opmcc_then_qs_off,
            "SortingNetwork": off_time(sort_net),
        }),
        ("sort_total_time", {
            "FLOSSRadix": off_time(floss_sort_off) + on_time(floss_sort_on),
            "PermNetRadix": off_time(perm_sort_off) + on_time(perm_sort_on),
            "SimplePermNetRadix": off_time(simple_sort_off) + on_time(simple_sort_on),
            "FLOSSthenSort": floss_then_qs_total,
            "PermNetthenSort": perm_then_qs_total,
            "SimplePermNetthenSort": simple_then_qs_total,
            "OPMCCthenSort": opmcc_then_qs_total,
            "SortingNetwork": off_time(sort_net) + on_time(sort_net),
        }),
        ("sort_online_bandwidth", {
            "FLOSSRadix": to_mb(floss_sort_on_b),
            "PermNetRadix": to_mb(perm_sort_on_b),
            "SimplePermNetRadix": to_mb(simple_sort_on_b),
            "FLOSSthenSort": to_mb(floss_then_qs_on_b),
            "PermNetthenSort": to_mb(perm_then_qs_on_b),
            "SimplePermNetthenSort": to_mb(simple_then_qs_on_b),
            "OPMCCthenSort": to_mb(opmcc_then_qs_on_b),
            "SortingNetwork": to_mb(on_bytes_mp(sort_net)),
        }),
        ("sort_offline_bandwidth", {
            "FLOSSRadix": to_mb(floss_sort_off_b),
            "PermNetRadix": to_mb(perm_sort_off_b),
            "SimplePermNetRadix": to_mb(simple_sort_off_b),
            "FLOSSthenSort": to_mb(floss_then_qs_off_b),
            "PermNetthenSort": to_mb(perm_then_qs_off_b),
            "SimplePermNetthenSort": to_mb(simple_then_qs_off_b),
            "OPMCCthenSort": to_mb(opmcc_then_qs_off_b),
            "SortingNetwork": to_mb(off_bytes_mp(sort_net)),
        }),
        ("sort_total_bandwidth", {
            "FLOSSRadix": to_mb(floss_sort_off_b + floss_sort_on_b),
            "PermNetRadix": to_mb(perm_sort_off_b + perm_sort_on_b),
            "SimplePermNetRadix": to_mb(simple_sort_off_b + simple_sort_on_b),
            "FLOSSthenSort": to_mb(floss_then_qs_off_b + floss_then_qs_on_b),
            "PermNetthenSort": to_mb(perm_then_qs_off_b + perm_then_qs_on_b),
            "SimplePermNetthenSort": to_mb(simple_then_qs_off_b + simple_then_qs_on_b),
            "OPMCCthenSort": to_mb(opmcc_then_qs_off_b + opmcc_then_qs_on_b),
            "SortingNetwork": to_mb(off_bytes_mp(sort_net) + on_bytes_mp(sort_net)),
        }),
    ]:
        pd.DataFrame(build_rows(keys)).to_csv(
            os.path.join(PLOT_DATA_DIR, f"{label}.csv"), index=False
        )


def generate_shuffle_csv(alone: bool):
    """Merged shuffle benchmark CSVs for plot_shuffling.tex."""
    PLOT_INPUTS = SHUFFLE_PLOT_INPUTS_ALONE if alone else SHUFFLE_PLOT_INPUTS

    floss_off = pd.read_csv(os.path.join(ROOT_DIR, "shuffle_floss_offline.csv"))
    perm_off = pd.read_csv(os.path.join(ROOT_DIR, "shuffle_perm_network_offline.csv"))
    opmcc_off = pd.read_csv(os.path.join(ROOT_DIR, "shuffle_opmcc_offline.csv"))
    simple_off = pd.read_csv(os.path.join(ROOT_DIR, "shuffle_simple_perm_network_offline.csv"))
    floss_on = pd.read_csv(os.path.join(ROOT_DIR, "shuffle_floss_online.csv"))
    perm_on = pd.read_csv(os.path.join(ROOT_DIR, "shuffle_perm_network_online.csv"))
    opmcc_on = pd.read_csv(os.path.join(ROOT_DIR, "shuffle_opmcc_online.csv"))
    simple_on = pd.read_csv(os.path.join(ROOT_DIR, "shuffle_simple_perm_network_online.csv"))

    def get_off_time(df, sz):
        return df[df.InputSize == sz].OfflinePrepTime.values[0]

    def get_on_time(df, sz):
        return df[df.InputSize == sz].OnlineTime.values[0]

    def get_off_bytes(df, sz):
        r = df[df.InputSize == sz].iloc[0]
        return (r.BytesSent + r.BytesRecv) / (1024 * 1024)

    def get_on_bytes(df, sz):
        r = df[df.InputSize == sz].iloc[0]
        return (r.BytesSent + r.BytesRecv) / (1024 * 1024)

    for label, row_builder in [
        ("shuffle_online_time", lambda i, sz: {
            "Index": i, "InputSize": sz,
            "FLOSS": get_on_time(floss_on, sz), "PermNet": get_on_time(perm_on, sz),
            "OPMCC": get_on_time(opmcc_on, sz), "SimplePermNet": get_on_time(simple_on, sz),
        }),
        ("shuffle_offline_time", lambda i, sz: {
            "Index": i, "InputSize": sz,
            "FLOSS": get_off_time(floss_off, sz), "PermNet": get_off_time(perm_off, sz),
            "OPMCC": get_off_time(opmcc_off, sz), "SimplePermNet": get_off_time(simple_off, sz),
        }),
        ("shuffle_total_time", lambda i, sz: {
            "Index": i, "InputSize": sz,
            "FLOSS": get_off_time(floss_off, sz) + get_on_time(floss_on, sz),
            "PermNet": get_off_time(perm_off, sz) + get_on_time(perm_on, sz),
            "OPMCC": get_off_time(opmcc_off, sz) + get_on_time(opmcc_on, sz),
            "SimplePermNet": get_off_time(simple_off, sz) + get_on_time(simple_on, sz),
        }),
        ("shuffle_online_bandwidth", lambda i, sz: {
            "Index": i, "InputSize": sz,
            "FLOSS": get_on_bytes(floss_on, sz), "PermNet": get_on_bytes(perm_on, sz),
            "OPMCC": get_on_bytes(opmcc_on, sz), "SimplePermNet": get_on_bytes(simple_on, sz),
        }),
        ("shuffle_offline_bandwidth", lambda i, sz: {
            "Index": i, "InputSize": sz,
            "FLOSS": get_off_bytes(floss_off, sz), "PermNet": get_off_bytes(perm_off, sz),
            "OPMCC": get_off_bytes(opmcc_off, sz), "SimplePermNet": get_off_bytes(simple_off, sz),
        }),
        ("shuffle_total_bandwidth", lambda i, sz: {
            "Index": i, "InputSize": sz,
            "FLOSS": get_off_bytes(floss_off, sz) + get_on_bytes(floss_on, sz),
            "PermNet": get_off_bytes(perm_off, sz) + get_on_bytes(perm_on, sz),
            "OPMCC": get_off_bytes(opmcc_off, sz) + get_on_bytes(opmcc_on, sz),
            "SimplePermNet": get_off_bytes(simple_off, sz) + get_on_bytes(simple_on, sz),
        }),
    ]:
        rows = [row_builder(i, sz) for i, sz in enumerate(PLOT_INPUTS)]
        pd.DataFrame(rows).to_csv(os.path.join(PLOT_DATA_DIR, f"{label}.csv"), index=False)


def generate_pareto_sort_csv():
    """Pareto sort points, frontier, and per-system CSVs for plot_pareto_sort.tex."""
    SIZE = PARETO_SORT_SIZE

    def load_sort_offline(name):
        df = pd.read_csv(os.path.join(ROOT_DIR, f"sort_{name}_offline.csv"))
        return df[df["InputSize"] == SIZE].drop_duplicates("InputSize", keep="first")

    def load_sort_online(name):
        df = pd.read_csv(os.path.join(ROOT_DIR, f"sort_{name}_online.csv"))
        return df[df["InputSize"] == SIZE].drop_duplicates("InputSize", keep="first")

    def load_shuffle(name):
        df = pd.read_csv(os.path.join(ROOT_DIR, f"shuffle_{name}_offline.csv"))
        return df[df["InputSize"] == SIZE]

    def load_shuffle_online(name):
        df = pd.read_csv(os.path.join(ROOT_DIR, f"shuffle_{name}_online.csv"))
        return df[df["InputSize"] == SIZE]

    quicksort = pd.read_csv(os.path.join(ROOT_DIR, "sort_quicksort.csv"))
    quicksort = quicksort[quicksort["InputSize"] == SIZE]
    sort_net = pd.read_csv(os.path.join(ROOT_DIR, "sort_sorting_network.csv"))
    sort_net = sort_net[sort_net["InputSize"] == SIZE]

    if len(quicksort) == 0 or len(sort_net) == 0:
        raise SystemExit("Missing quicksort or sorting_network data for InputSize=13")

    rows = []
    for name, sort_name in [
        ("RadixFLOSS", "floss"),
        ("RadixPermNet", "perm_network"),
        ("RadixSimplePermNet", "simple_perm_network"),
    ]:
        off = load_sort_offline(sort_name)
        on = load_sort_online(sort_name)
        if len(off) > 0 and len(on) > 0:
            off_prep = off["OfflinePrepTime"].iloc[0]
            on_time = on["OnlineTime"].iloc[0]
            bytes_total = off["BytesSent"].iloc[0] + off["BytesRecv"].iloc[0]
            rows.append({"Name": name, "OnlineTime": on_time, "OfflineCost": compute_offline_cost(off_prep, on_time, bytes_total)})

    for name, shuffle_name in [
        ("StSFLOSS", "floss"),
        ("StSPermNet", "perm_network"),
        ("StSSimplePermNet", "simple_perm_network"),
        ("StSOPMCC", "opmcc"),
    ]:
        shuf_off = load_shuffle(shuffle_name)
        shuf_on = load_shuffle_online(shuffle_name)
        if len(shuf_off) > 0 and len(shuf_on) > 0 and len(quicksort) > 0:
            off_prep = shuf_off["OfflinePrepTime"].iloc[0] + quicksort["OfflinePrepTime"].iloc[0]
            on_time = shuf_on["OnlineTime"].iloc[0] + quicksort["OnlineTime"].iloc[0]
            shuf_bytes = shuf_off["BytesSent"].iloc[0] + shuf_off["BytesRecv"].iloc[0]
            bytes_total = shuf_bytes + quicksort["OfflineCommunication"].iloc[0]
            rows.append({"Name": name, "OnlineTime": on_time, "OfflineCost": compute_offline_cost(off_prep, on_time, bytes_total)})

    if len(sort_net) > 0:
        off_prep = sort_net["OfflinePrepTime"].iloc[0]
        on_time = sort_net["OnlineTime"].iloc[0]
        bytes_total = sort_net["OfflineCommunication"].iloc[0]
        rows.append({"Name": "SortNet", "OnlineTime": on_time, "OfflineCost": compute_offline_cost(off_prep, on_time, bytes_total)})

    df_points = pd.DataFrame(rows)
    df_points.to_csv(os.path.join(PLOT_DATA_DIR, "pareto_sort_points.csv"), index=False)

    fname_map = {
        "RadixFLOSS": "pareto_sort_radix_floss.csv",
        "RadixPermNet": "pareto_sort_radix_permnet.csv",
        "RadixSimplePermNet": "pareto_sort_radix_simplepermnet.csv",
        "StSFLOSS": "pareto_sort_sts_floss.csv",
        "StSPermNet": "pareto_sort_sts_permnet.csv",
        "StSSimplePermNet": "pareto_sort_sts_simplepermnet.csv",
        "StSOPMCC": "pareto_sort_sts_opmcc.csv",
        "SortNet": "pareto_sort_sortnet.csv",
    }
    for _, row in df_points.iterrows():
        fname = fname_map.get(row["Name"])
        if fname:
            pd.DataFrame([{"OnlineTime": row["OnlineTime"], "OfflineCost": row["OfflineCost"]}]).to_csv(
                os.path.join(PLOT_DATA_DIR, fname), index=False
            )

    highlight = {"RadixPermNet", "RadixSimplePermNet", "SortNet", "StSFLOSS", "StSPermNet", "StSOPMCC", "StSSimplePermNet"}
    points = [(float(r["OnlineTime"]), float(r["OfflineCost"]), r["Name"]) for _, r in df_points.iterrows()]
    frontier_pts = [(x, y, lbl) for (x, y, lbl) in points if lbl in highlight]
    frontier = pareto_frontier(frontier_pts)

    if len(frontier) >= 1:
        x_hi, y_hi = 1000, 10
        pad = 1.0
        x_corner = x_hi * pad
        y_corner = y_hi * pad
        frontier_sorted = sorted(frontier, key=lambda p: p[0], reverse=True)
        fx = [p[0] for p in frontier_sorted]
        fy = [p[1] for p in frontier_sorted]
        vertices = [(x_corner, y_corner), (x_corner, fy[0]), (fx[0], fy[0])]
        for i in range(1, len(fx)):
            vertices.append((fx[i - 1], fy[i]))
            vertices.append((fx[i], fy[i]))
        vertices.append((fx[-1], y_corner))
        vertices.append((x_corner, y_corner))
        pd.DataFrame(vertices, columns=["X", "Y"]).to_csv(
            os.path.join(PLOT_DATA_DIR, "pareto_sort_frontier.csv"), index=False
        )


def generate_pareto_shuffle_csv():
    """Pareto shuffle points, frontier, and per-system CSVs for plot_pareto_shuffle.tex."""
    SIZE = PARETO_SHUFFLE_SIZE
    columns = ["InputSize", "OfflinePrepTime", "BytesSent", "BytesRecv"]
    online_cols = ["InputSize", "OnlineTime"]

    floss_off = pd.read_csv(os.path.join(ROOT_DIR, "shuffle_floss_offline.csv"), usecols=columns)
    perm_off = pd.read_csv(os.path.join(ROOT_DIR, "shuffle_perm_network_offline.csv"), usecols=columns)
    opmcc_off = pd.read_csv(os.path.join(ROOT_DIR, "shuffle_opmcc_offline.csv"), usecols=columns)
    simple_off = pd.read_csv(os.path.join(ROOT_DIR, "shuffle_simple_perm_network_offline.csv"), usecols=columns)
    floss_on = pd.read_csv(os.path.join(ROOT_DIR, "shuffle_floss_online.csv"), usecols=online_cols)
    perm_on = pd.read_csv(os.path.join(ROOT_DIR, "shuffle_perm_network_online.csv"), usecols=online_cols)
    opmcc_on = pd.read_csv(os.path.join(ROOT_DIR, "shuffle_opmcc_online.csv"), usecols=online_cols)
    simple_on = pd.read_csv(os.path.join(ROOT_DIR, "shuffle_simple_perm_network_online.csv"), usecols=online_cols)

    def get_row(df_off, df_on, name):
        roff = df_off[df_off.InputSize == SIZE]
        ron = df_on[df_on.InputSize == SIZE]
        if len(roff) == 0 or len(ron) == 0:
            return None
        off_prep = roff.OfflinePrepTime.iloc[0]
        on_time = ron.OnlineTime.iloc[0]
        bytes_total = roff.BytesSent.iloc[0] + roff.BytesRecv.iloc[0]
        return {"Name": name, "OnlineTime": on_time, "OfflineCost": compute_offline_cost(off_prep, on_time, bytes_total)}

    rows = []
    for df_off, df_on, name in [
        (floss_off, floss_on, "FLOSS"),
        (perm_off, perm_on, "PermNet"),
        (opmcc_off, opmcc_on, "OPMCC"),
        (simple_off, simple_on, "SimplePermNet"),
    ]:
        r = get_row(df_off, df_on, name)
        if r:
            rows.append(r)

    df_points = pd.DataFrame(rows)
    df_points.to_csv(os.path.join(PLOT_DATA_DIR, "pareto_shuffle_points.csv"), index=False)

    for _, row in df_points.iterrows():
        fname = {"FLOSS": "pareto_shuffle_floss.csv", "PermNet": "pareto_shuffle_permnet.csv",
                 "OPMCC": "pareto_shuffle_opmcc.csv", "SimplePermNet": "pareto_shuffle_simplepermnet.csv"}[row["Name"]]
        pd.DataFrame([{"OnlineTime": row["OnlineTime"], "OfflineCost": row["OfflineCost"]}]).to_csv(
            os.path.join(PLOT_DATA_DIR, fname), index=False
        )

    highlight = {"PermNet", "SimplePermNet"}
    points = [(float(r["OnlineTime"]), float(r["OfflineCost"]), r["Name"]) for _, r in df_points.iterrows()]
    frontier_pts = [(x, y, lbl) for (x, y, lbl) in points if lbl in highlight]
    frontier = pareto_frontier(frontier_pts)

    if len(frontier) >= 1:
        x_hi, y_hi = 10000, 10
        pad = 1.0
        x_corner = x_hi * pad
        y_corner = y_hi * pad
        frontier_sorted = sorted(frontier, key=lambda p: p[0], reverse=True)
        fx = [p[0] for p in frontier_sorted]
        fy = [p[1] for p in frontier_sorted]
        vertices = [(x_corner, y_corner), (x_corner, fy[0]), (fx[0], fy[0])]
        for i in range(1, len(fx)):
            vertices.append((fx[i - 1], fy[i]))
            vertices.append((fx[i], fy[i]))
        vertices.append((fx[-1], y_corner))
        vertices.append((x_corner, y_corner))
        pd.DataFrame(vertices, columns=["X", "Y"]).to_csv(
            os.path.join(PLOT_DATA_DIR, "pareto_shuffle_frontier.csv"), index=False
        )


def main():
    parser = argparse.ArgumentParser(description="Generate all plot CSVs for pgfplots.")
    parser.add_argument(
        "--alone",
        type=int,
        choices=[0, 1],
        default=0,
        help="If 1, generate plots using ALONE-mode benchmark input sizes.",
    )
    args = parser.parse_args()
    alone = args.alone == 1

    os.makedirs(PLOT_DATA_DIR, exist_ok=True)
    generate_sort_csv(alone=alone)
    generate_shuffle_csv(alone=alone)
    if not alone:
        generate_pareto_sort_csv()
        generate_pareto_shuffle_csv()
    if not alone:
        print("Generated all plot CSVs in plots/plot_data (sort, shuffle, pareto_sort, pareto_shuffle)")
    else:
        print("Generated all plot CSVs in plots/plot_data (sort, shuffle)")


if __name__ == "__main__":
    main()
