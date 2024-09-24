import numpy as np
from scipy.signal import upfirdn, lfilter

# Constants
c = 3e8  # Speed of light in m/s
f = 2.4e9  # Frequency in Hz (assuming 2.4 GHz for this example)
d = 25  # Distance between users in meters
Pt_dBW = 1  # Transmit power in dBW
Gt_dB = 3  # Transmit antenna gain in dB
Gr_dB = 3  # Receive antenna gain in dB
noise_floor_dBm = -100  # Noise floor in dBm
bandwidth = 1e6  # Bandwidth in Hz

# Convert to linear scale
Pt = 10**(Pt_dBW / 10)  # Transmit power in W
Gt = 10**(Gt_dB / 10)
Gr = 10**(Gr_dB / 10)
noise_floor = 10**((noise_floor_dBm - 30) / 10)  # Noise floor in W

# Path loss (Free-space path loss model)
def free_space_path_loss(d, f):
    return (4 * np.pi * d * f / c)**2

# Root Raised Cosine Filter
def rrc_filter(beta, span, sps):
    N, alpha = span * sps, beta
    t = np.arange(-N, N+1) / float(sps)
    h = np.sinc(t) * np.cos(np.pi * alpha * t) / (1 - (2 * alpha * t)**2)
    h[t == 0] = 1.0
    h[np.abs(t) == 1/(2 * alpha)] = alpha / np.sqrt(2)
    return h / np.sqrt(np.sum(h**2))

# Apply RRC filter
def apply_rrc_filter(signal, beta, span, sps, upsample=True):
    rrc = rrc_filter(beta, span, sps)
    if upsample:
        return upfirdn(rrc, signal, up=sps)
    else:
        return upfirdn(rrc, signal, down=sps)

# Rayleigh fading channel
def rayleigh_fading(num_samples):
    return (np.random.normal(size=num_samples) + 1j * np.random.normal(size=num_samples)) / np.sqrt(2)

# AWGN
def add_awgn(signal, noise_power):
    noise = np.sqrt(noise_power / 2) * (np.random.normal(size=len(signal)) + 1j * np.random.normal(size=len(signal)))
    return signal + noise

# Functions to convert text to bits and vice versa
def text_to_bits(text):
    return ''.join(format(ord(c), '08b') for c in text)

def bits_to_text(bits):
    chars = [bits[i:i+8] for i in range(0, len(bits), 8)]
    return ''.join(chr(int(c, 2)) for c in chars)

# Hamming (7,4) encoding
def hamming_encode(bits):
    G = np.array([[1, 1, 0, 1, 0, 0, 0],
                  [1, 0, 1, 0, 1, 0, 0],
                  [1, 0, 0, 0, 0, 1, 0],
                  [0, 1, 1, 0, 0, 0, 1]])
    
    n = len(bits)
    k = 4  # Hamming (7, 4)
    encoded_bits = []
    for i in range(0, n, k):
        block = np.array(list(map(int, bits[i:i+k])))
        if len(block) < k:
            block = np.pad(block, (0, k - len(block)), 'constant')
        encoded_bits.extend(np.dot(block, G) % 2)
    
    return ''.join(map(str, encoded_bits))

# QPSK modulation
def qpsk_modulate(bits):
    bit_pairs = [bits[i:i+2] for i in range(0, len(bits), 2)]
    symbols = []
    for pair in bit_pairs:
        if pair == '00':
            symbols.append(1 + 1j)
        elif pair == '01':
            symbols.append(-1 + 1j)
        elif pair == '11':
            symbols.append(-1 - 1j)
        elif pair == '10':
            symbols.append(1 - 1j)
    return np.array(symbols)

# Simulate channel with Rayleigh fading and AWGN
def simulate_channel(symbols, d, noise_floor, bandwidth, f):
    path_loss = free_space_path_loss(d, f)
    h = rayleigh_fading(len(symbols))
    faded_symbols = symbols * h * np.sqrt(Gt * Gr / path_loss)
    
    noise_power = noise_floor * bandwidth
    received_symbols = add_awgn(faded_symbols, noise_power)
    return received_symbols, h

# QPSK demodulation
def qpsk_demodulate(symbols):
    bits = []
    for sym in symbols:
        if np.real(sym) > 0 and np.imag(sym) > 0:
            bits.extend('00')
        elif np.real(sym) < 0 and np.imag(sym) > 0:
            bits.extend('01')
        elif np.real(sym) < 0 and np.imag(sym) < 0:
            bits.extend('11')
        elif np.real(sym) > 0 and np.imag(sym) < 0:
            bits.extend('10')
    return ''.join(bits)

# Hamming (7,4) decoding
def hamming_decode(bits):
    H = np.array([[1, 0, 0, 0, 1, 1, 1],
                  [0, 1, 0, 0, 1, 1, 0],
                  [0, 0, 1, 0, 1, 0, 1],
                  [0, 0, 0, 1, 0, 1, 1]])
    
    n = len(bits)
    k = 7  # Hamming (7, 4)
    decoded_bits = []
    for i in range(0, n, k):
        block = np.array(list(map(int, bits[i:i+k])))
        if len(block) < k:
            block = np.pad(block, (0, k - len(block)), 'constant')
        syndrome = np.dot(H, block) % 2
        error_pos = int(''.join(map(str, syndrome)), 2)
        if error_pos != 0:
            if error_pos <= k:
                block[error_pos - 1] ^= 1  # Correct the error
        decoded_bits.extend(block[:4])
    
    return ''.join(map(str, decoded_bits))

# Calculate SNR and BER
def calculate_snr(signal_power, noise_power):
    return 10 * np.log10(signal_power / noise_power)

def calculate_ber(original_bits, received_bits):
    errors = sum(o != r for o, r in zip(original_bits, received_bits))
    return errors / len(original_bits)

# Main script
# Verify text-to-bits and bits-to-text
original_text_user1 = "Hello"
original_text_user2 = "World"
bits_user1 = text_to_bits(original_text_user1)
bits_user2 = text_to_bits(original_text_user2)

# Verify Hamming encoding
encoded_bits_user1 = hamming_encode(bits_user1)
encoded_bits_user2 = hamming_encode(bits_user2)

# Verify QPSK modulation
modulated_user1 = qpsk_modulate(encoded_bits_user1)
modulated_user2 = qpsk_modulate(encoded_bits_user2)

# Apply RRC filter at transmitter
beta = 0.35  # Roll-off factor
span = 10  # Filter span in symbols
sps = 4  # Samples per symbol

modulated_user1_filtered = apply_rrc_filter(modulated_user1, beta, span, sps)
modulated_user2_filtered = apply_rrc_filter(modulated_user2, beta, span, sps)

# Simulate channel
received_user1, h_user1 = simulate_channel(modulated_user1_filtered, d, noise_floor, bandwidth, f)
received_user2, h_user2 = simulate_channel(modulated_user2_filtered, d, noise_floor, bandwidth, f)

# Apply RRC filter at receiver and downsample
received_user1_filtered = apply_rrc_filter(received_user1, beta, span, sps, upsample=False)
received_user2_filtered = apply_rrc_filter(received_user2, beta, span, sps, upsample=False)

# Downsample to symbol rate
received_user1_downsampled = received_user1_filtered[span*sps::sps]
received_user2_downsampled = received_user2_filtered[span*sps::sps]

# Verify QPSK demodulation
demodulated_user1 = qpsk_demodulate(received_user1_downsampled)
demodulated_user2 = qpsk_demodulate(received_user2_downsampled)

# Verify Hamming decoding
decoded_bits_user1 = hamming_decode(demodulated_user1)
decoded_bits_user2 = hamming_decode(demodulated_user2)

# Ensure that we are handling the correct number of bits for conversion back to text
decoded_bits_user1 = decoded_bits_user1[:len(bits_user1)]
decoded_bits_user2 = decoded_bits_user2[:len(bits_user2)]

# Verify bits-to-text conversion
decoded_user1_text = bits_to_text(decoded_bits_user1)
decoded_user2_text = bits_to_text(decoded_bits_user2)

print("Decoded User 1 text:", decoded_user1_text)
print("Decoded User 2 text:", decoded_user2_text)

# Calculate SNR and BER
signal_power_user1 = Pt * Gt * Gr / free_space_path_loss(d, f)
noise_power_user1 = noise_floor * bandwidth
snr_user1 = calculate_snr(signal_power_user1, noise_power_user1)
ber_user1 = calculate_ber(bits_user1, demodulated_user1[:len(bits_user1)])

signal_power_user2 = Pt * Gt * Gr / free_space_path_loss(d, f)
noise_power_user2 = noise_floor * bandwidth
snr_user2 = calculate_snr(signal_power_user2, noise_power_user2)
ber_user2 = calculate_ber(bits_user2, demodulated_user2[:len(bits_user2)])

print("User 1 SNR:", snr_user1, "dB")
print("User 1 BER:", ber_user1)
print("User 2 SNR:", snr_user2, "dB")
print("User 2 BER:", ber_user2)
