import matplotlib.pyplot as plt
from pathlib import Path

def plot_bar_series(series, title, xlabel, ylabel, output_path):
    plt.figure(figsize=(10, 6))
    series.plot(kind="bar")
    plt.title(title)
    plt.xlabel(xlabel)
    plt.ylabel(ylabel)
    plt.xticks(rotation=45, ha="right")
    plt.tight_layout()
    plt.savefig(output_path)
    plt.close()

def plot_line_series(series, title, xlabel, ylabel, output_path, marker="o"):
    plt.figure(figsize=(10, 6))
    plt.plot(series.index, series.values, marker=marker)
    plt.title(title)
    plt.xlabel(xlabel)
    plt.ylabel(ylabel)
    plt.xticks(rotation=30)
    plt.tight_layout()
    plt.savefig(output_path)
    plt.close()

def plot_histogram(series, title, xlabel, ylabel, output_path, bins=20):
    plt.figure(figsize=(10, 6))
    plt.hist(series, bins=bins)
    plt.title(title)
    plt.xlabel(xlabel)
    plt.ylabel(ylabel)
    plt.tight_layout()
    plt.savefig(output_path)
    plt.close()

def plot_heatmap(data, title, xlabel, ylabel, output_path):
    plt.figure(figsize=(10, 8))
    plt.imshow(data, aspect="auto", interpolation="nearest")
    plt.title(title)
    plt.xlabel(xlabel)
    plt.ylabel(ylabel)

    plt.xticks(range(len(data.columns)), data.columns)
    plt.yticks(range(len(data.index)), [str(day) for day in data.index])

    cbar = plt.colorbar()
    cbar.set_label("failed logins")

    plt.tight_layout()
    plt.savefig(output_path)
    plt.close()