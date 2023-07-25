# This script can be used to process and plot data generated with the benchmarking shell script and bwm-ng.
# For one iteration of testing with different number of clients it separates the clients by looking at reoccuring zero and high packets/s.

import pandas as pd
import numpy as np
import os
import matplotlib.pyplot as plt

os.chdir(os.path.dirname(os.path.realpath(__file__)))

# Path to the folders that contain the csv outputs from bwm-ng
FOLDERS = ["20 iterations"]
data = {}
iterations = 20

for folder in FOLDERS:
    for f in os.listdir(folder):
        #Splits the file name to get the version that is used. Per default file names were of the form "test_scion-ts-scion-nts.csv"
        split = f.split(".")[0].split("_")
        version = str(split[1])

        first = 0
        last = 0
        df = pd.read_csv(folder + "/" + f, sep=";")

        # Remove noise to really have 0 packets between the bursts
        df.loc[df["packets_out/s"] < 3000, "packets_out/s"] = 0
        packets_out = df["packets_out/s"]
        complelte_data = {}

        # Compute the median per burst for each number of clients for all iterations
        for iteration in range(iterations):
            version = f"{str(split[1])} {iteration}"
            for c in [1, 2, 4, 8, 16, 32, 64, 128, 192, 256, 320, 384, 448, 512]:
                first = packets_out[last:].ne(0).idxmax()
                last = packets_out[first:].eq(0).idxmax()
                median = packets_out[first:last].loc[packets_out >= 1000].median()
                if not version in complelte_data.keys():
                    complelte_data[version] = {}
                complelte_data[version][c] = median

        # Sort data differentely to simplify computing the mean over all iterations
        sorted_data = {}
        for iteration, values in complelte_data.items():
            for clients, median in values.items():
                if not clients in sorted_data.keys():
                    sorted_data[clients] = []
                sorted_data[clients].append(median)
        data[f"{str(split[1])}"] = {clients: np.mean(value) for clients, value in sorted_data.items()}

# Plot the data
for version, values in data.items():
    lists = sorted(values.items())
    clients, packets = zip(*lists)
    plt.plot(clients, packets, label=version)
    plt.text(clients[-1], packets[-1], version)
plt.legend(loc="upper left")
plt.show()

# Sort data for saving to disk
data_dict = {}
for version, values in data.items():
    lists = sorted(values.items())
    clients, packets = zip(*lists)
    data_dict["clients"] = clients
    data_dict[version] = packets

# Store data
df = pd.DataFrame(data_dict)
df.to_csv(f"overleaf/{FOLDERS[0]}_out.csv", index=False)
df.set_index("clients").transpose().to_csv(f"overleaf/{FOLDERS[0]}_transposed.csv", index_label="version", columns=[256])
