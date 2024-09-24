import numpy as np
import matplotlib.pyplot as plt
from reedsolo import RSCodec

# Parameters
data_length = 100  # Length of the data signal
chip_rate = 100    # Number of chips per data bit
noise_level = 0.5  # Noise level
num_hops = 50      # Number of frequency hops
rs_n = 255         # Reed-Solomon block size (standard value for higher redundancy)
rs_k = 223         # Reed-Solomon data size (standard value for higher redundancy)

# Initialize Reed-Solomon codec
rsc = RSCodec(rs_n - rs_k)

# Generate random data signal
data_signal = np.random.randint(0, 2, data_length)
print("Original Data Signal:", data_signal[:20])  # Debugging print

# Encode the data signal with Reed-Solomon
encoded_data = []
for i in range(0, len(data_signal), rs_k):
    packet = data_signal[i:i+rs_k]
    if len(packet) < rs_k:
        packet = np.pad(packet, (0, rs_k - len(packet)), 'constant', constant_values=(0, 0))
    encoded_packet = rsc.encode(packet)
    encoded_data.extend(encoded_packet)

encoded_data = np.array(encoded_data)
print("Encoded Data:", encoded_data[:20])  # Debugging print

# Generate PN sequence
pn_sequence = np.random.randint(0, 2, len(encoded_data) * chip_rate) * 2 - 1  # Convert to -1, 1

# Spread the data signal
spread_signal = np.repeat(encoded_data, chip_rate) * pn_sequence
print("Spread Signal:", spread_signal[:200])  # Debugging print

# Frequency hopping
hop_pattern = np.random.choice(num_hops, len(spread_signal))
hopped_signal = spread_signal.copy()
for hop in range(num_hops):
    hop_indices = np.where(hop_pattern == hop)[0]
    hopped_signal[hop_indices] = spread_signal[hop_indices]

print("Hopped Signal:", hopped_signal[:200])  # Debugging print

# Channel noise simulation (Rayleigh fading)
def rayleigh_fading(signal):
    fading = np.sqrt(np.random.normal(size=len(signal))**2 + np.random.normal(size=len(signal))**2) / np.sqrt(2)
    return signal * fading

# Apply Rayleigh fading to the spread signal
faded_signal = rayleigh_fading(hopped_signal)
print("Faded Signal:", faded_signal[:200])  # Debugging print

# Add AWGN noise
noisy_signal = faded_signal + noise_level * np.random.randn(len(faded_signal))
print("Noisy Signal:", noisy_signal[:200])  # Debugging print

# Matched filtering
matched_filter = pn_sequence[::-1]
filtered_signal = np.convolve(noisy_signal, matched_filter, mode='same')
print("Filtered Signal:", filtered_signal[:200])  # Debugging print

# Despread the signal
despread_signal = filtered_signal * pn_sequence
print("Despread Signal:", despread_signal[:200])  # Debugging print

# Recover the encoded data by summing and thresholding
recovered_encoded_data = np.zeros(len(encoded_data), dtype=int)
for i in range(len(encoded_data)):
    chunk = despread_signal[i * chip_rate: (i + 1) * chip_rate]
    recovered_encoded_data[i] = 1 if np.sum(chunk) > 0 else 0

print("Recovered Encoded Data:", recovered_encoded_data[:20])  # Debugging print

# Decode the Reed-Solomon encoded data
recovered_data = []
for i in range(0, len(recovered_encoded_data), rs_n):
    packet = recovered_encoded_data[i:i+rs_n]
    try:
        decoded_packet = rsc.decode(packet)
        recovered_data.extend(decoded_packet)
    except:
        print(f"Packet {i//rs_n} could not be decoded.")
        # Add padding for undecoded packets to keep data length consistent
        recovered_data.extend([0] * rs_k)

# Ensure the recovered data length is consistent with the original data length
recovered_data = np.array(recovered_data[:data_length])
print("Recovered Data:", recovered_data[:20])  # Debugging print

# Plot the signals
plt.figure(figsize=(12, 10))

plt.subplot(6, 1, 1)
plt.plot(data_signal[:10])
plt.title("Original Data Signal")

plt.subplot(6, 1, 2)
plt.plot(spread_signal[:100])
plt.title("Spread Signal (DSSS)")

plt.subplot(6, 1, 3)
plt.plot(hopped_signal[:100])
plt.title("Spread Signal with Frequency Hopping (DSSS + FHSS)")

plt.subplot(6, 1, 4)
plt.plot(faded_signal[:100])
plt.title("Faded Signal (Rayleigh)")

plt.subplot(6, 1, 5)
plt.plot(noisy_signal[:100])
plt.title("Noisy Signal (Rayleigh + AWGN)")

plt.subplot(6, 1, 6)
plt.plot(recovered_data[:10])
plt.title("Recovered Signal")

plt.tight_layout()
plt.show()

