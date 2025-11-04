# Klipper Log Analyzer

A comprehensive Python tool for analyzing Klipper 3D printer log files (`klippy.log`). This analyzer detects crashes, communication issues, print jobs, temperature anomalies, and system performance problems to help diagnose and troubleshoot your 3D printer.

## Features

- **Session Analysis**: Identifies and tracks multiple Klipper sessions, including crash detection and uptime tracking
- **Print Job Detection**: Automatically detects print jobs, their duration, and completion status
- **Crash Detection**: Identifies various types of crashes including:
  - Hard crashes (corrupted log entries, system halts)
  - MCU shutdowns
  - Communication timeouts
  - Emergency stops
- **Communication Monitoring**:
  - Tracks MCU retransmission events
  - Detects sequence mismatches
  - Monitors round-trip times (RTT)
  - Identifies invalid byte transmissions
- **Temperature Monitoring**:
  - Detects temperature spikes and deviations
  - Monitors extruder and bed temperature stability
  - Tracks MCU and Raspberry Pi temperatures
- **System Performance**:
  - Monitors CPU load
  - Tracks available memory
  - Detects buffer underruns during printing
- **Interactive CLI**: User-friendly menu system for exploring analysis results
- **CSV Export**: Export statistics for further analysis in spreadsheet applications

## Requirements

- Python 3.6 or higher
- Standard Python libraries (no external dependencies required):
  - `re`, `sys`, `datetime`, `collections`, `dataclasses`, `typing`, `statistics`

## Installation

1. Clone this repository:
```bash
git clone https://github.com/yourusername/KlippyLogAnalysis.git
cd KlippyLogAnalysis
```

2. Make the script executable (optional):
```bash
chmod +x klipper_log_analyzer.py
```

## Usage

### Basic Usage

**Auto-discover log files** (recommended):
```bash
python klipper_log_analyzer.py
```
The analyzer will search common locations for Klipper log files and present a menu if multiple files are found.

**Specify a log file directly**:
```bash
python klipper_log_analyzer.py /path/to/klippy.log
```

**Show temperature anomalies only**:
```bash
python klipper_log_analyzer.py klippy.log --show-temp
```

### Search Locations

When auto-discovering, the analyzer searches:
- Current directory (`*.log`)
- Script directory (`*.log`)
- `logs/` subdirectory
- `printer_data/logs/` (common Klipper installation path)
- `/tmp/klippy.log`

### Interactive Menu

After analysis, the tool presents an interactive menu:

```
1. Show Summary - View comprehensive analysis results
3. Filter Anomalies by Category - Explore specific types of issues
4. Show Session Details - View detailed session information
5. Show Communication Timeline - Analyze retransmission events
9. Export Data (CSV) - Export statistics for external analysis
0. Exit
```

## How It Works

### Analysis Process

1. **Log Parsing**: Reads the entire `klippy.log` file and extracts:
   - Session boundaries (marked by "Starting Klippy")
   - Statistics lines (published every second during operation)
   - System metadata (device info, versions, timestamps)

2. **Session Detection**: Identifies individual Klipper sessions and determines:
   - Session start/end times
   - Crash detection through log corruption patterns
   - Shutdown reasons (user-initiated, MCU errors, system signals)
   - Uptime and statistics count

3. **Print Job Detection**: Tracks `sd_pos` values to identify:
   - Print start/end times
   - Print duration
   - Completion percentage
   - Interrupted vs. completed prints

4. **Anomaly Detection**: Analyzes statistics to find:
   - **Communication issues**: Retransmission spikes, invalid bytes, sequence mismatches
   - **Temperature problems**: Sudden spikes, deviations from target
   - **Print quality issues**: Buffer underruns, print stalls
   - **System issues**: High CPU load, low memory

5. **Retransmission Tracking**: Monitors MCU communication quality by tracking cumulative retransmission bytes

### Key Metrics Analyzed

| Metric | Description | Warning Threshold |
|--------|-------------|-------------------|
| `bytes_retransmit` | Cumulative retransmitted bytes | >100 bytes/event |
| `bytes_invalid` | Invalid bytes received | >0 |
| `srtt` | Smoothed round-trip time | >10ms |
| `buffer_time` | Print buffer time | <1.0s (during print) |
| `print_stall` | Print stalls detected | >0 |
| `sysload` | System CPU load | >2.0 |
| `memavail` | Available memory | <500MB |
| Temperature deviation | Difference from target | >10°C |
| Temperature spike | Sudden temp change | >5°C/second |

## Output Examples

### Session Details
```
Session 1 (Started: Wed Oct 31 14:22:15 2024):
  Lines: 1 - 5234
  Device: Linux raspberrypi 6.1.21-v8+
  Git Version: v0.12.0-123-g1a2b3c4d
  Uptime: 2:15:33 (8133.0s)
  Stats Count: 8122
  Status: 💥 CRASHED
  Crash Type: MCU shutdown (emergency stop or firmware error)
```

### Print Jobs Summary
```
📄 Print Jobs (2):
  1. ✅ COMPLETED
     Duration: 1:45:22
     Progress: 100.0% (2,456,789 / 2,456,789 bytes)
     File Size: ~2.34MB

  2. ❗ INTERRUPTED
     Duration: 0:32:15
     Progress: 45.2% (1,234,567 / 2,730,000 bytes)
     File Size: ~2.60MB
```

### Retransmit Events
```
🔄 RETRANSMIT EVENTS: 3 event(s) detected

Session 1: 3 retransmit events
  🔴 SEVERE Retransmit at 1:23:45
    Line: 5001
    Bytes Retransmitted: +245 bytes (Total: 1024)
    Round-Trip Time: 12.34ms
    ⚠️ WARNING: Crash occurred 15.2s AFTER this event!
```

## File Structure

```
KlippyLogAnalysis/
├── klipper_log_analyzer.py    # Main analyzer script
├── logs/                       # Example log files directory
│   └── crash3_klippy.log      # Sample log file
└── README.md                   # This file
```

## Understanding the Analysis

### Crash Types Detected

- **Hard crash (corrupted log entry)**: Sudden system halt with log corruption
- **MCU shutdown**: Firmware or emergency stop triggered
- **Communication timeout**: Lost connection to MCU
- **User-initiated restart**: Normal restart via web interface
- **System signals**: SIGTERM, SIGINT (Ctrl+C)

### Color-Coded Severity

- 🔴 **CRITICAL**: Severe issues requiring immediate attention
- ⚠️ **WARNING**: Issues that may impact print quality
- ✅ **INFO**: Normal operation or successful completion

## Contributing

Contributions are welcome! Please feel free to submit issues or pull requests.

## License

This project is open source. Please add your preferred license here.

## Acknowledgments

Designed for analyzing Klipper firmware logs. Learn more about Klipper at [klipper3d.org](https://www.klipper3d.org).

## Support

If you encounter any issues or have questions:
1. Check that your log file is a valid Klipper `klippy.log` file
2. Ensure you're using Python 3.6 or higher
3. Open an issue on GitHub with your log file details (sanitized if needed)