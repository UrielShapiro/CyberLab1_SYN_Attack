import matplotlib.pyplot as plt
import numpy as np
import re


def read_data(filename):
    times = []

    with open(filename, 'r') as file:
        for line in file:
            match = re.search(r'\d+\s+([\d\.]+)\s+ms', line)
            if match:
                time = float(match.group(1))
                times.append(time)

    return times


def plot_graph(times1, times2, label1, label2, output_filename):
    # Calculate the number of packets for each unique time
    unique_times1, counts1 = np.unique(times1, return_counts=True)
    unique_times2, counts2 = np.unique(times2, return_counts=True)

    plt.figure(figsize=(10, 6))

    # Plot the first dataset
    plt.plot(unique_times1, counts1, marker='o', linestyle='-', label=label1)

    # Plot the second dataset
    plt.plot(unique_times2, counts2, marker='x', linestyle='--', label=label2)

    plt.xscale('log')
    plt.yscale('log')

    plt.xlabel('Time to Send Packet (ms)')
    plt.ylabel('Number of Packets Sent')
    plt.title('Comparison of Packet Sending Time Between C and Python')

    plt.legend()
    plt.grid(True, which="both", ls="--")
    plt.savefig(output_filename)
    plt.show()


def main():
    # Replace with your actual file paths
    input_filename1 = 'syns_results_c.txt'
    input_filename2 = 'syns_results_p.txt'

    label1 = 'C Program'
    label2 = 'Python Program'

    output_filename = 'Syn_pkts_comparison.png'

    times1 = read_data(input_filename1)
    times2 = read_data(input_filename2)

    plot_graph(times1, times2, label1, label2, output_filename)


if __name__ == "__main__":
    main()
