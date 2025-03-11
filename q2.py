import pandas as pd
import matplotlib.pyplot as plt

syn_df = pd.read_csv("syn_mit.txt", sep='\t', header=None, names=["time_syn", "src", "dst", "sport", "dport"])
syn_df["time_syn"] = syn_df["time_syn"].astype(float)

# Keep only the first SYN per unique connection
syn_df = syn_df.sort_values("time_syn").groupby(["src", "dst", "sport", "dport"]).first().reset_index()

fin_rst_df = pd.read_csv("fin_reset_mit.txt", sep='\t', header=None, 
                         names=["time_end", "src", "dst", "sport", "dport", "flags"])
fin_rst_df["time_end"] = fin_rst_df["time_end"].astype(float)

ack_df = pd.read_csv("ack_packets_mit.txt", sep='\t', header=None, names=["time_ack", "src", "dst", "sport", "dport"])
ack_df["time_ack"] = ack_df["time_ack"].astype(float)

# Merge FIN/RESET with ACKs to find ACK after FIN-ACK
fin_rst_ack_df = fin_rst_df.merge(ack_df, on=["src", "dst", "sport", "dport"], how="left")

# If there's an ACK after FIN-ACK, use that as the end time
fin_rst_ack_df["time_end"] = fin_rst_ack_df.apply(
    lambda row: row["time_ack"] if row["flags"] == "0x14" and not pd.isna(row["time_ack"]) else row["time_end"], axis=1
)

# Merge SYN packets with FIN/RESET packets
merged_df = syn_df.merge(fin_rst_ack_df, on=["src", "dst", "sport", "dport"], how="left")

merged_df["time_end"].fillna(merged_df["time_syn"] + 100, inplace=True)
merged_df["duration"] = merged_df["time_end"] - merged_df["time_syn"]

# default duration 100 sec
merged_df["duration"].fillna(100, inplace=True)

# Normalize time by subtracting the first recorded timestamp
start_time = merged_df["time_syn"].min()
merged_df["normalized_time_syn"] = merged_df["time_syn"] - start_time

plt.scatter(merged_df["normalized_time_syn"], merged_df["duration"], label="Connection Duration")
plt.axvline(x=20, color='r', linestyle='--', label="Attack Start")  
plt.axvline(x=120, color='g', linestyle='--', label="Attack End")   
plt.xlabel("Connection Start Time (seconds since first SYN)")
plt.ylabel("Connection Duration (s)")
plt.legend()
plt.show()
