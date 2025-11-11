#!/usr/bin/env python3
"""
Klipper Log Analyzer - Interactive tool for analyzing klippy.log files
Detects crashes, communication issues, and system anomalies
"""

import re
import sys
from datetime import datetime, timedelta
from collections import defaultdict
from dataclasses import dataclass, field
from typing import List, Dict, Optional, Tuple
import statistics

# ANSI Color codes
class Colors:
    """ANSI color codes for terminal output"""
    RESET = '\033[0m'
    BOLD = '\033[1m'

    # Regular colors
    RED = '\033[91m'
    GREEN = '\033[92m'
    YELLOW = '\033[93m'
    BLUE = '\033[94m'
    MAGENTA = '\033[95m'
    CYAN = '\033[96m'
    WHITE = '\033[97m'

    # Bold colors
    BOLD_RED = '\033[1;91m'
    BOLD_GREEN = '\033[1;92m'
    BOLD_YELLOW = '\033[1;93m'
    BOLD_BLUE = '\033[1;94m'
    BOLD_CYAN = '\033[1;96m'

    @staticmethod
    def disable():
        """Disable colors (for non-terminal output)"""
        Colors.RESET = ''
        Colors.BOLD = ''
        Colors.RED = ''
        Colors.GREEN = ''
        Colors.YELLOW = ''
        Colors.BLUE = ''
        Colors.MAGENTA = ''
        Colors.CYAN = ''
        Colors.WHITE = ''
        Colors.BOLD_RED = ''
        Colors.BOLD_GREEN = ''
        Colors.BOLD_YELLOW = ''
        Colors.BOLD_BLUE = ''
        Colors.BOLD_CYAN = ''

# Disable colors if not outputting to a terminal
if not sys.stdout.isatty():
    Colors.disable()

@dataclass
class StatsEntry:
    """Represents a single Stats line from klippy.log"""
    line_number: int
    timestamp: float
    gcodein: int

    # MCU Communication
    mcu_awake: float
    mcu_task_avg: float
    mcu_task_stddev: float
    bytes_write: int
    bytes_read: int
    bytes_retransmit: int
    bytes_invalid: int
    send_seq: int
    receive_seq: int
    retransmit_seq: int
    srtt: float  # Smoothed round-trip time
    rttvar: float  # Round-trip time variance
    rto: float  # Retransmission timeout
    ready_bytes: int
    upcoming_bytes: int
    freq: int  # MCU clock frequency

    # Print Status
    sd_pos: Optional[int] = None
    print_time: float = 0.0
    buffer_time: float = 0.0
    print_stall: int = 0

    # Temperatures
    heater_bed_target: float = 0.0
    heater_bed_temp: float = 0.0
    heater_bed_pwm: float = 0.0
    extruder_target: float = 0.0
    extruder_temp: float = 0.0
    extruder_pwm: float = 0.0
    mcu_temp: Optional[float] = None
    rpi_temp: Optional[float] = None

    # System Resources
    sysload: float = 0.0
    cputime: float = 0.0
    memavail: int = 0

@dataclass
class PrintJob:
    """Information about a detected print job"""
    session_number: int
    start_timestamp: float
    end_timestamp: float
    start_sd_pos: int
    end_sd_pos: int
    max_sd_pos: int
    status: str  # 'completed', 'interrupted', 'ongoing'
    duration_seconds: float = 0.0

@dataclass
class SessionInfo:
    """Information about a Klipper session"""
    session_number: int
    start_line: int
    end_line: Optional[int]
    start_time: Optional[str]
    device: str
    git_version: str
    python_version: str
    crashed: bool = False
    crash_type: str = ""
    uptime_seconds: float = 0.0
    stats_count: int = 0
    print_jobs: List[PrintJob] = field(default_factory=list)

@dataclass
class RetransmitEvent:
    """Represents a retransmission event"""
    timestamp: float
    session_number: int
    bytes_retransmit_total: int
    bytes_retransmit_delta: int  # How many bytes retransmitted in this event
    retransmit_seq: int
    send_seq: int
    receive_seq: int
    srtt_ms: float
    line_number: int

@dataclass
class Anomaly:
    """Detected anomaly in the log"""
    line_number: int
    timestamp: float
    severity: str  # 'INFO', 'WARNING', 'CRITICAL'
    category: str
    message: str
    details: Dict = field(default_factory=dict)

class KlipperLogAnalyzer:
    def __init__(self, log_file: str):
        self.log_file = log_file
        self.stats: List[StatsEntry] = []
        self.sessions: List[SessionInfo] = []
        self.anomalies: List[Anomaly] = []
        self.retransmit_events: List[RetransmitEvent] = []
        self.current_session: Optional[SessionInfo] = None

    @staticmethod
    def _format_retransmit(current_value: int, previous_value: Optional[int] = None, width: int = 5) -> str:
        """Format retransmit value showing delta when increased (global helper)

        Args:
            current_value: Current cumulative retransmit bytes
            previous_value: Previous cumulative retransmit bytes (if available)
            width: Field width for formatting

        Returns:
            Formatted string showing value or delta (e.g., "  789" or "! +789")
        """
        if previous_value is not None and current_value > previous_value:
            delta = current_value - previous_value
            return f"!+{delta:>{width-2}}"  # Account for ! and +
        return f" {current_value:>{width-1}}"

    def parse_log(self):
        """Parse the entire log file"""

        with open(self.log_file, 'r', encoding='utf-8', errors='ignore') as f:
            lines = f.readlines()

        session_num = 0

        # Check if log starts mid-session (no "Starting Klippy" at beginning)
        has_early_stats = False
        first_starting_klippy_line = None

        for idx, line in enumerate(lines):
            if line.startswith('Stats ') and not has_early_stats:
                has_early_stats = True
            if 'Starting Klippy' in line and first_starting_klippy_line is None:
                first_starting_klippy_line = idx + 1
                break

        # If we found stats before the first "Starting Klippy", create early session
        if has_early_stats and (first_starting_klippy_line is None or first_starting_klippy_line > 1):
            # Create a session for pre-existing data
            session_num = 1
            self.current_session = SessionInfo(
                session_number=session_num,
                start_line=1,
                end_line=None,
                start_time="Unknown (log rolled over)",
                device="",
                git_version="",
                python_version=""
            )
            self.sessions.append(self.current_session)

        for i, line in enumerate(lines, 1):
            # Detect session starts
            if 'Starting Klippy' in line:
                # Close previous session if exists
                if self.current_session:
                    self.current_session.end_line = i - 1

                    # Check for crash indicators
                    crashed = False
                    crash_type = None

                    # 1. Check for corrupted line - text concatenated with "Starting Klippy" or null bytes
                    if re.search(r'[a-z_0-9]+Starting Klippy', line, re.IGNORECASE):
                        crashed = True
                        crash_type = "Hard crash (corrupted log entry - sudden system halt)"
                    # Check if the "Starting Klippy" line itself contains null bytes or is unusually long
                    elif '\x00' in line or len(line) > 1000:
                        crashed = True
                        crash_type = "Hard crash (log corruption - sudden system halt)"

                    # 2. Check for log corruption before "Starting Klippy" (indicates crash)
                    # Look back at previous lines to detect unusual gaps or null bytes
                    if not crashed and i >= 5:
                        # Count consecutive blank/corrupted lines before this line
                        blank_count = 0
                        null_byte_detected = False

                        for j in range(i - 2, max(0, i - 20), -1):
                            line_stripped = lines[j].strip()
                            # Check for blank lines or lines with null bytes
                            if line_stripped == '' or '\x00' in lines[j]:
                                blank_count += 1
                                if '\x00' in lines[j]:
                                    null_byte_detected = True
                            else:
                                break

                        # If we have 5+ consecutive blank/corrupted lines before "Starting Klippy", it's a crash
                        if blank_count >= 5 or null_byte_detected:
                            crashed = True
                            crash_type = "Hard crash (log corruption - sudden system halt)"

                    # 3. Check previous lines for shutdown indicators
                    if not crashed:
                        shutdown_reason = self._detect_shutdown_reason(lines, i - 1)
                        if shutdown_reason:
                            crash_type = shutdown_reason
                            # Determine if this shutdown reason indicates a crash
                            crash_keywords = ['mcu shutdown', 'emergency stop', 'firmware error',
                                            'lost communication', 'timeout', 'command error',
                                            'internal error', 'sigterm', 'sigint']
                            if any(keyword in shutdown_reason.lower() for keyword in crash_keywords):
                                crashed = True
                        else:
                            crash_type = "Normal restart"

                    self.current_session.crashed = crashed
                    self.current_session.crash_type = crash_type

                # Create new session
                session_num += 1
                self.current_session = SessionInfo(
                    session_number=session_num,
                    start_line=i,
                    end_line=None,
                    start_time=None,
                    device="",
                    git_version="",
                    python_version=""
                )
                self.sessions.append(self.current_session)

            # Extract session metadata
            if self.current_session:
                if 'Start printer at' in line:
                    match = re.search(r'Start printer at (.+) \(', line)
                    if match:
                        self.current_session.start_time = match.group(1)

                if 'Device:' in line:
                    match = re.search(r'Device: (.+)', line)
                    if match:
                        self.current_session.device = match.group(1).strip()

                if "Git version:" in line:
                    match = re.search(r"Git version: '(.+)'", line)
                    if match:
                        self.current_session.git_version = match.group(1)

                if "Python:" in line:
                    match = re.search(r"Python: '(.+)'", line)
                    if match:
                        self.current_session.python_version = match.group(1)

            # Also check if this metadata appears before any session is formally started
            # (for logs that start mid-session)
            if session_num == 1 and self.sessions and not self.sessions[0].device:
                if 'Device:' in line:
                    match = re.search(r'Device: (.+)', line)
                    if match:
                        self.sessions[0].device = match.group(1).strip()

                if "Git version:" in line:
                    match = re.search(r"Git version: '(.+)'", line)
                    if match:
                        self.sessions[0].git_version = match.group(1)

                if "Python:" in line:
                    match = re.search(r"Python: '(.+)'", line)
                    if match:
                        self.sessions[0].python_version = match.group(1)

            # Parse Stats lines
            if line.startswith('Stats '):
                stats = self._parse_stats_line(line, i)
                if stats:
                    self.stats.append(stats)
                    if self.current_session:
                        self.current_session.stats_count += 1
                        self.current_session.uptime_seconds = max(
                            self.current_session.uptime_seconds,
                            stats.timestamp
                        )

        # Close last session
        if self.current_session:
            self.current_session.end_line = len(lines)

        print(f"{Colors.GREEN}✅ Parsed {len(self.stats)} stats entries across {len(self.sessions)} sessions{Colors.RESET}")

    def _detect_shutdown_reason(self, lines: List[str], end_line_index: int) -> Optional[str]:
        """Detect why a session ended by examining lines before restart"""
        # Check last 10 lines before restart
        start_idx = max(0, end_line_index - 10)
        relevant_lines = lines[start_idx:end_line_index + 1]

        for line in reversed(relevant_lines):
            if 'webhooks client' in line.lower() and 'disconnected' in line.lower():
                return "User-initiated restart (webhooks disconnect)"
            elif 'mcu shutdown' in line.lower() or 'mcu \'mcu\' shutdown' in line.lower():
                return "MCU shutdown (emergency stop or firmware error)"
            elif 'received signal' in line.lower():
                if 'sigterm' in line.lower():
                    return "Terminated by system (SIGTERM)"
                elif 'sigint' in line.lower():
                    return "Interrupted by user (SIGINT/Ctrl+C)"
                return "Received system signal"
            elif 'command error' in line.lower() or 'internal error' in line.lower():
                return "Klipper error triggered restart"
            elif 'lost communication' in line.lower() or 'timeout' in line.lower():
                return "Communication timeout"

        return None

    def _parse_stats_line(self, line: str, line_num: int) -> Optional[StatsEntry]:
        """Parse a single Stats line"""
        try:
            # Extract timestamp
            match = re.search(r'Stats (\d+\.?\d*):', line)
            if not match:
                return None
            timestamp = float(match.group(1))

            # Helper to extract values
            def extract_float(pattern, default=0.0):
                m = re.search(pattern, line)
                return float(m.group(1)) if m else default

            def extract_int(pattern, default=0):
                m = re.search(pattern, line)
                return int(m.group(1)) if m else default

            stats = StatsEntry(
                line_number=line_num,
                timestamp=timestamp,
                gcodein=extract_int(r'gcodein=(\d+)'),
                mcu_awake=extract_float(r'mcu_awake=([\d.]+)'),
                mcu_task_avg=extract_float(r'mcu_task_avg=([\d.]+)'),
                mcu_task_stddev=extract_float(r'mcu_task_stddev=([\d.]+)'),
                bytes_write=extract_int(r'bytes_write=(\d+)'),
                bytes_read=extract_int(r'bytes_read=(\d+)'),
                bytes_retransmit=extract_int(r'bytes_retransmit=(\d+)'),
                bytes_invalid=extract_int(r'bytes_invalid=(\d+)'),
                send_seq=extract_int(r'send_seq=(\d+)'),
                receive_seq=extract_int(r'receive_seq=(\d+)'),
                retransmit_seq=extract_int(r'retransmit_seq=(\d+)'),
                srtt=extract_float(r'srtt=([\d.]+)'),
                rttvar=extract_float(r'rttvar=([\d.]+)'),
                rto=extract_float(r'rto=([\d.]+)'),
                ready_bytes=extract_int(r'ready_bytes=(\d+)'),
                upcoming_bytes=extract_int(r'upcoming_bytes=(\d+)'),
                freq=extract_int(r'freq=(\d+)'),
                sd_pos=extract_int(r'sd_pos=(\d+)', None),
                print_time=extract_float(r'print_time=([\d.]+)'),
                buffer_time=extract_float(r'buffer_time=([\d.]+)'),
                print_stall=extract_int(r'print_stall=(\d+)'),
                heater_bed_target=extract_float(r'heater_bed: target=([\d.]+)'),
                heater_bed_temp=extract_float(r'heater_bed:.*?temp=([\d.]+)'),
                heater_bed_pwm=extract_float(r'heater_bed:.*?pwm=([\d.]+)'),
                extruder_target=extract_float(r'extruder: target=([\d.]+)'),
                extruder_temp=extract_float(r'extruder:.*?temp=([\d.]+)'),
                extruder_pwm=extract_float(r'extruder:.*?pwm=([\d.]+)'),
                mcu_temp=extract_float(r'\w+_MCU: temp=([\d.]+)', None),
                rpi_temp=extract_float(r'raspberry_pi: temp=([\d.]+)', None),
                sysload=extract_float(r'sysload=([\d.]+)'),
                cputime=extract_float(r'cputime=([\d.]+)'),
                memavail=extract_int(r'memavail=(\d+)')
            )

            return stats
        except Exception as e:
            print(f"Warning: Failed to parse line {line_num}: {e}")
            return None

    def detect_print_jobs(self):
        """Detect print jobs from sd_pos progression in stats entries"""

        for session in self.sessions:
            # Get stats for this session
            session_stats = [s for s in self.stats if session.start_line <= s.line_number <= (session.end_line or float('inf'))]

            if not session_stats:
                continue

            # Track print job state
            current_print = None

            for i, stats in enumerate(session_stats):
                # Check if we have sd_pos (indicates printing or print file loaded)
                # AND buffer_time > 0 (indicates actual printing, not just loaded file)
                if stats.sd_pos is not None and stats.sd_pos > 0 and stats.buffer_time > 0:
                    # If no current print, start a new one
                    if current_print is None:
                        current_print = {
                            'start_timestamp': stats.timestamp,
                            'start_sd_pos': stats.sd_pos,
                            'max_sd_pos': stats.sd_pos,
                            'end_timestamp': stats.timestamp,
                            'end_sd_pos': stats.sd_pos,
                            'last_sd_pos': stats.sd_pos,
                        }
                    else:
                        # Update existing print
                        current_print['end_timestamp'] = stats.timestamp
                        current_print['end_sd_pos'] = stats.sd_pos
                        current_print['max_sd_pos'] = max(current_print['max_sd_pos'], stats.sd_pos)
                        current_print['last_sd_pos'] = stats.sd_pos

                # Check if print ended (sd_pos disappeared or is 0)
                elif current_print is not None:
                    # Print ended - save it
                    duration = current_print['end_timestamp'] - current_print['start_timestamp']

                    # Determine completion percentage
                    progress = (current_print['end_sd_pos'] / current_print['max_sd_pos'] * 100) if current_print['max_sd_pos'] > 0 else 0

                    # Determine status - prioritize crash detection
                    if session.crashed:
                        # If session crashed, always mark as interrupted regardless of progress
                        status = 'interrupted'
                    elif progress >= 99.5:  # Consider 99.5%+ as completed
                        status = 'completed'
                    else:
                        status = 'completed'  # Normal end (user stopped print)

                    print_job = PrintJob(
                        session_number=session.session_number,
                        start_timestamp=current_print['start_timestamp'],
                        end_timestamp=current_print['end_timestamp'],
                        start_sd_pos=current_print['start_sd_pos'],
                        end_sd_pos=current_print['end_sd_pos'],
                        max_sd_pos=current_print['max_sd_pos'],
                        status=status,
                        duration_seconds=duration
                    )
                    session.print_jobs.append(print_job)
                    current_print = None

            # If there's still a current print at the end of session stats
            if current_print is not None:
                duration = current_print['end_timestamp'] - current_print['start_timestamp']
                progress = (current_print['end_sd_pos'] / current_print['max_sd_pos'] * 100) if current_print['max_sd_pos'] > 0 else 0

                # Determine status based on session end
                if session.crashed:
                    status = 'interrupted'
                elif progress >= 99.5:
                    status = 'completed'
                else:
                    # Check if this is the last session (still ongoing)
                    if session == self.sessions[-1]:
                        status = 'ongoing'
                    else:
                        status = 'interrupted'

                print_job = PrintJob(
                    session_number=session.session_number,
                    start_timestamp=current_print['start_timestamp'],
                    end_timestamp=current_print['end_timestamp'],
                    start_sd_pos=current_print['start_sd_pos'],
                    end_sd_pos=current_print['end_sd_pos'],
                    max_sd_pos=current_print['max_sd_pos'],
                    status=status,
                    duration_seconds=duration
                )
                session.print_jobs.append(print_job)

        all_jobs = [pj for session in self.sessions for pj in session.print_jobs]
        MIN_SIGNIFICANT_SIZE = 100 * 1024  # 100KB
        MIN_SIGNIFICANT_DURATION = 30  # 30 seconds
        significant = sum(1 for pj in all_jobs if pj.max_sd_pos >= MIN_SIGNIFICANT_SIZE or pj.duration_seconds >= MIN_SIGNIFICANT_DURATION)
        tests = len(all_jobs) - significant

        if tests > 0:
            print(f"✅ Detected {significant} print job(s) and {tests} test/calibration run(s)")
        else:
            print(f"✅ Detected {significant} print job(s)")

    def detect_retransmit_events(self):
        """Detect retransmission events by tracking bytes_retransmit changes"""

        for session in self.sessions:
            # Get stats for this session
            session_stats = [s for s in self.stats if session.start_line <= s.line_number <= (session.end_line or float('inf'))]

            if not session_stats:
                continue

            # Track last retransmit count
            last_retransmit_bytes = 0

            for stats in session_stats:
                # Check if retransmit count increased
                if stats.bytes_retransmit > last_retransmit_bytes:
                    delta = stats.bytes_retransmit - last_retransmit_bytes

                    event = RetransmitEvent(
                        timestamp=stats.timestamp,
                        session_number=session.session_number,
                        bytes_retransmit_total=stats.bytes_retransmit,
                        bytes_retransmit_delta=delta,
                        retransmit_seq=stats.retransmit_seq,
                        send_seq=stats.send_seq,
                        receive_seq=stats.receive_seq,
                        srtt_ms=stats.srtt * 1000,
                        line_number=stats.line_number
                    )
                    self.retransmit_events.append(event)
                    last_retransmit_bytes = stats.bytes_retransmit

        print(f"✅ Detected {len(self.retransmit_events)} retransmit event(s)")

    def _format_session_header(self, session: SessionInfo) -> str:
        """Format session header with session number and start time"""
        if session.start_time:
            return f"Session {session.session_number} (Started: {session.start_time})"
        else:
            return f"Session {session.session_number}"

    def detect_anomalies(self):
        """Detect all anomalies in the parsed data"""

        # Track previous values for change detection
        prev_extruder_temp = None
        prev_bed_temp = None
        prev_timestamp = None
        prev_retransmit = 0
        prev_invalid = 0
        session_stats_by_session = defaultdict(list)

        # Group stats by session
        for stats in self.stats:
            for session in self.sessions:
                if session.start_line <= stats.line_number <= (session.end_line or float('inf')):
                    session_stats_by_session[session.session_number].append(stats)
                    break

        # Analyze each session
        for session_num, session_stats in session_stats_by_session.items():
            if not session_stats:
                continue

            # Communication anomalies
            for i, stats in enumerate(session_stats):
                # Retransmission spike detection
                if i > 0:
                    retrans_delta = stats.bytes_retransmit - session_stats[i-1].bytes_retransmit
                    if retrans_delta > 100:
                        self.anomalies.append(Anomaly(
                            line_number=stats.line_number,
                            timestamp=stats.timestamp,
                            severity='WARNING',
                            category='Communication',
                            message=f'Retransmission spike: +{retrans_delta} bytes',
                            details={'bytes': retrans_delta}
                        ))

                # Invalid bytes
                if stats.bytes_invalid > 0:
                    self.anomalies.append(Anomaly(
                        line_number=stats.line_number,
                        timestamp=stats.timestamp,
                        severity='CRITICAL',
                        category='Communication',
                        message=f'Invalid bytes detected: {stats.bytes_invalid}',
                        details={'bytes': stats.bytes_invalid}
                    ))

                # Print stalls
                if stats.print_stall > 0:
                    self.anomalies.append(Anomaly(
                        line_number=stats.line_number,
                        timestamp=stats.timestamp,
                        severity='WARNING',
                        category='Print Quality',
                        message=f'Print stall detected: {stats.print_stall}',
                        details={'stalls': stats.print_stall}
                    ))

                # High round-trip time
                if stats.srtt > 0.010:  # >10ms is concerning
                    self.anomalies.append(Anomaly(
                        line_number=stats.line_number,
                        timestamp=stats.timestamp,
                        severity='WARNING',
                        category='Communication',
                        message=f'High round-trip time: {stats.srtt*1000:.1f}ms',
                        details={'srtt_ms': stats.srtt * 1000}
                    ))

                # Low buffer time during printing
                if stats.sd_pos and stats.buffer_time < 1.0:
                    self.anomalies.append(Anomaly(
                        line_number=stats.line_number,
                        timestamp=stats.timestamp,
                        severity='WARNING',
                        category='Print Quality',
                        message=f'Low buffer time: {stats.buffer_time:.2f}s',
                        details={'buffer_time': stats.buffer_time}
                    ))

                # Temperature deviation (only flag if heater should be stable but isn't)
                # Skip if:
                # 1. Target is 0 (heater off, cooling down is normal)
                # 2. Temp is very far from target (>50°C = still heating up)
                # 3. PWM is at max (actively heating, not at steady state)
                # 4. Temperature is actively changing (>2°C/sec = still heating/cooling)
                if stats.extruder_target > 0 and i > 0:
                    temp_diff = abs(stats.extruder_temp - stats.extruder_target)
                    prev_stats = session_stats[i-1]
                    time_delta = stats.timestamp - prev_stats.timestamp

                    # Check if temperature is actively changing
                    if 0.5 <= time_delta <= 2.0:
                        temp_change_rate = abs(stats.extruder_temp - prev_stats.extruder_temp) / time_delta

                        # Only flag if:
                        # - Heater should be stable (temp change <0.5°C/sec = truly stable)
                        # - Deviation is significant (>10°C)
                        # - Close to target (<30°C away, not initial heat-up)
                        if temp_diff > 10.0 and temp_diff < 30.0 and temp_change_rate < 0.5:
                            self.anomalies.append(Anomaly(
                                line_number=stats.line_number,
                                timestamp=stats.timestamp,
                                severity='WARNING',
                                category='Temperature',
                                message=f'Extruder temp deviation: {temp_diff:.1f}°C (target: {stats.extruder_target:.0f}°C, actual: {stats.extruder_temp:.1f}°C, PWM: {stats.extruder_pwm:.1%})',
                                details={'deviation': temp_diff, 'target': stats.extruder_target, 'actual': stats.extruder_temp, 'pwm': stats.extruder_pwm}
                            ))

                # Temperature spike detection (sudden changes)
                if i > 0 and stats.extruder_temp > 0:
                    prev_stats = session_stats[i-1]
                    time_delta = stats.timestamp - prev_stats.timestamp

                    # Only check if we have reasonable time delta (usually 1 second)
                    if 0.5 <= time_delta <= 2.0:
                        # Extruder spike detection
                        extruder_change = abs(stats.extruder_temp - prev_stats.extruder_temp)

                        # Ignore changes when target is changing (heating/cooling intentionally)
                        target_changed = abs(stats.extruder_target - prev_stats.extruder_target) > 1.0

                        # Ignore transitions from 0°C (heater off) to ambient temperature
                        # This prevents false positives when heater turns on and reads ambient temp
                        heater_was_off = prev_stats.extruder_temp < 30.0  # Below 30°C is considered "off" or ambient

                        # Spike thresholds (per second)
                        critical_spike = 10.0 / time_delta  # 10°C per second is critical
                        warning_spike = 5.0 / time_delta    # 5°C per second is warning

                        if extruder_change > critical_spike and not target_changed and not heater_was_off:
                            self.anomalies.append(Anomaly(
                                line_number=stats.line_number,
                                timestamp=stats.timestamp,
                                severity='CRITICAL',
                                category='Temperature',
                                message=f'CRITICAL extruder spike: {extruder_change:.1f}°C in {time_delta:.1f}s',
                                details={
                                    'change': extruder_change,
                                    'time_delta': time_delta,
                                    'rate': extruder_change / time_delta,
                                    'from_temp': prev_stats.extruder_temp,
                                    'to_temp': stats.extruder_temp
                                }
                            ))
                        elif extruder_change > warning_spike and not target_changed and not heater_was_off:
                            self.anomalies.append(Anomaly(
                                line_number=stats.line_number,
                                timestamp=stats.timestamp,
                                severity='WARNING',
                                category='Temperature',
                                message=f'Extruder spike: {extruder_change:.1f}°C in {time_delta:.1f}s',
                                details={
                                    'change': extruder_change,
                                    'time_delta': time_delta,
                                    'rate': extruder_change / time_delta,
                                    'from_temp': prev_stats.extruder_temp,
                                    'to_temp': stats.extruder_temp
                                }
                            ))

                        # Bed spike detection
                        if stats.heater_bed_temp > 0 and prev_stats.heater_bed_temp > 0:
                            bed_change = abs(stats.heater_bed_temp - prev_stats.heater_bed_temp)
                            bed_target_changed = abs(stats.heater_bed_target - prev_stats.heater_bed_target) > 1.0

                            # Ignore transitions from ambient temperature
                            bed_was_off = prev_stats.heater_bed_temp < 35.0  # Below 35°C is considered "off" or ambient

                            bed_critical_spike = 8.0 / time_delta  # Bed heats slower, 8°C/s is critical
                            bed_warning_spike = 4.0 / time_delta

                            if bed_change > bed_critical_spike and not bed_target_changed and not bed_was_off:
                                self.anomalies.append(Anomaly(
                                    line_number=stats.line_number,
                                    timestamp=stats.timestamp,
                                    severity='CRITICAL',
                                    category='Temperature',
                                    message=f'CRITICAL bed spike: {bed_change:.1f}°C in {time_delta:.1f}s',
                                    details={
                                        'change': bed_change,
                                        'time_delta': time_delta,
                                        'rate': bed_change / time_delta,
                                        'from_temp': prev_stats.heater_bed_temp,
                                        'to_temp': stats.heater_bed_temp
                                    }
                                ))
                            elif bed_change > bed_warning_spike and not bed_target_changed and not bed_was_off:
                                self.anomalies.append(Anomaly(
                                    line_number=stats.line_number,
                                    timestamp=stats.timestamp,
                                    severity='WARNING',
                                    category='Temperature',
                                    message=f'Bed spike: {bed_change:.1f}°C in {time_delta:.1f}s',
                                    details={
                                        'change': bed_change,
                                        'time_delta': time_delta,
                                        'rate': bed_change / time_delta,
                                        'from_temp': prev_stats.heater_bed_temp,
                                        'to_temp': stats.heater_bed_temp
                                    }
                                ))

                # High system load
                if stats.sysload > 2.0:
                    self.anomalies.append(Anomaly(
                        line_number=stats.line_number,
                        timestamp=stats.timestamp,
                        severity='WARNING',
                        category='System',
                        message=f'High system load: {stats.sysload}',
                        details={'sysload': stats.sysload}
                    ))

                # Low memory
                if stats.memavail < 500000:  # <500MB
                    self.anomalies.append(Anomaly(
                        line_number=stats.line_number,
                        timestamp=stats.timestamp,
                        severity='WARNING',
                        category='System',
                        message=f'Low memory: {stats.memavail/1024:.0f}MB available',
                        details={'memory_kb': stats.memavail}
                    ))

                # Sequence mismatch (only if difference is significant)
                seq_diff = abs(stats.send_seq - stats.receive_seq)
                if seq_diff > 10:  # Allow small differences during normal communication
                    self.anomalies.append(Anomaly(
                        line_number=stats.line_number,
                        timestamp=stats.timestamp,
                        severity='CRITICAL',
                        category='Communication',
                        message=f'Large sequence mismatch: send={stats.send_seq} recv={stats.receive_seq} (diff={seq_diff})',
                        details={'send': stats.send_seq, 'receive': stats.receive_seq, 'diff': seq_diff}
                    ))

        print(f"{Colors.GREEN}✅ Found {len(self.anomalies)} anomalies{Colors.RESET}")

    def print_summary(self):
        """Print analysis summary"""
        # Session details
        print("\n" + "="*80)
        print(f"{Colors.BOLD_CYAN}🔄 SESSION DETAILS{Colors.RESET}")
        print(f"{'='*80}")

        for i, session in enumerate(self.sessions, 1):
            uptime_str = str(timedelta(seconds=int(session.uptime_seconds)))
            crash_marker = "💥 CRASHED" if session.crashed else "✅ Normal"

            print(f"\n{Colors.BOLD_CYAN}{self._format_session_header(session)}:{Colors.RESET}")
            print(f"  Lines: {session.start_line} - {session.end_line or 'EOF'}")
            print(f"  Device: {session.device or 'Unknown'}")
            print(f"  Git Version: {session.git_version or 'Unknown'}")

            # Show start and end times if available
            if session.start_time:
                print(f"  Started: {session.start_time}")
                # Calculate end time
                try:
                    from datetime import datetime
                    start_dt = datetime.strptime(session.start_time, "%a %b %d %H:%M:%S %Y")
                    end_dt = start_dt + timedelta(seconds=int(session.uptime_seconds))
                    print(f"  Ended: {end_dt.strftime('%a %b %d %H:%M:%S %Y')}")
                except:
                    pass  # If parsing fails, just skip end time

            print(f"  Uptime: {uptime_str} ({session.uptime_seconds:.1f}s)")
            print(f"  Stats Count: {session.stats_count}")
            print(f"  Status: {crash_marker}")
            if session.crash_type:
                ending_label = "Crash Type" if session.crashed else "Ending"
                print(f"  {ending_label}: {session.crash_type}")
            elif session.end_line:
                print(f"  Ending: Session ended (reason unknown)")

            # Show print jobs for this session
            if session.print_jobs:
                # Separate significant prints from test/calibration
                MIN_SIGNIFICANT_SIZE = 100 * 1024  # 100KB
                MIN_SIGNIFICANT_DURATION = 30  # 30 seconds

                significant_jobs = [pj for pj in session.print_jobs
                                   if pj.max_sd_pos >= MIN_SIGNIFICANT_SIZE or pj.duration_seconds >= MIN_SIGNIFICANT_DURATION]
                test_jobs = [pj for pj in session.print_jobs
                            if pj.max_sd_pos < MIN_SIGNIFICANT_SIZE and pj.duration_seconds < MIN_SIGNIFICANT_DURATION]

                # Show significant prints
                if significant_jobs:
                    print(f"\n  📄 Print Jobs ({len(significant_jobs)}):")
                    for j, pj in enumerate(significant_jobs, 1):
                        duration_str = str(timedelta(seconds=int(pj.duration_seconds)))
                        progress = (pj.end_sd_pos / pj.max_sd_pos * 100) if pj.max_sd_pos > 0 else 0

                        # Status icon
                        status_icon = {
                            'completed': '✅',
                            'interrupted': '❗',
                            'ongoing': '🔄'
                        }.get(pj.status, '❓')

                        # Format file size (sd_pos is in bytes)
                        file_size_mb = pj.max_sd_pos / (1024 * 1024)

                        print(f"    {j}. {status_icon} {pj.status.upper()}")
                        print(f"       Duration: {duration_str}")

                        # For interrupted prints where file was fully read, show differently
                        if pj.status == 'interrupted' and pj.end_sd_pos == pj.max_sd_pos:
                            print(f"       Progress: File read: {pj.end_sd_pos:,} bytes - interrupted during execution")
                        else:
                            print(f"       Progress: {progress:.1f}% ({pj.end_sd_pos:,} / {pj.max_sd_pos:,} bytes)")

                        print(f"       File Size: ~{file_size_mb:.2f}MB")

                # Show test/calibration summary if present
                if test_jobs:
                    print(f"\n  🔧 Test/Calibration Runs: {len(test_jobs)} (< 100KB or < 30s)")

        # Print jobs summary across all sessions
        all_print_jobs = [pj for session in self.sessions for pj in session.print_jobs]
        if all_print_jobs:
            # Filter for significant prints only
            MIN_SIGNIFICANT_SIZE = 100 * 1024  # 100KB
            MIN_SIGNIFICANT_DURATION = 30  # 30 seconds

            significant_prints = [pj for pj in all_print_jobs
                                 if pj.max_sd_pos >= MIN_SIGNIFICANT_SIZE or pj.duration_seconds >= MIN_SIGNIFICANT_DURATION]
            test_prints = [pj for pj in all_print_jobs
                          if pj.max_sd_pos < MIN_SIGNIFICANT_SIZE and pj.duration_seconds < MIN_SIGNIFICANT_DURATION]

            if significant_prints:
                print(f"\n{'='*80}")
                print(f"{Colors.BOLD_CYAN}📄 PRINT JOBS SUMMARY: {len(significant_prints)} print(s) detected{Colors.RESET}")
                print(f"{'='*80}")

                completed = sum(1 for pj in significant_prints if pj.status == 'completed')
                interrupted = sum(1 for pj in significant_prints if pj.status == 'interrupted')
                ongoing = sum(1 for pj in significant_prints if pj.status == 'ongoing')

                print(f"  ✅ Completed: {completed}")
                print(f"  ❗ Interrupted: {interrupted}")
                if ongoing > 0:
                    print(f"  🔄 Ongoing: {ongoing}")

                total_print_time = sum(pj.duration_seconds for pj in significant_prints)
                avg_print_time = total_print_time / len(significant_prints)
                total_time_str = str(timedelta(seconds=int(total_print_time)))
                avg_time_str = str(timedelta(seconds=int(avg_print_time)))

                print(f"\n  Total Print Time: {total_time_str}")
                print(f"  Average Print Duration: {avg_time_str}")

                if test_prints:
                    print(f"\n  🔧 Test/Calibration Runs: {len(test_prints)} (not included in statistics)")

        # Crash summary
        crashes = [s for s in self.sessions if s.crashed]
        print(f"\n{'='*80}")
        print(f"{Colors.BOLD_RED}💥 CRASH SUMMARY: {len(crashes)} crash(es) detected{Colors.RESET}")
        print(f"{'='*80}")

        if crashes:
            for crash in crashes:
                uptime_str = str(timedelta(seconds=int(crash.uptime_seconds)))
                print(f"  • {Colors.BOLD_CYAN}Session {crash.session_number}:{Colors.RESET} {crash.crash_type}")
                print(f"    Uptime before crash: {uptime_str}")

                # Show pre-crash stats
                self._show_pre_crash_stats(crash)

        # Communication statistics
        if self.stats:
            print(f"\n{'='*80}")
            print(f"{Colors.BOLD_CYAN}📡 COMMUNICATION STATISTICS{Colors.RESET}")
            print(f"{'='*80}")

            total_retrans = max(s.bytes_retransmit for s in self.stats)
            total_invalid = max(s.bytes_invalid for s in self.stats)
            avg_srtt = statistics.mean(s.srtt for s in self.stats) * 1000
            max_srtt = max(s.srtt for s in self.stats) * 1000

            print(f"  Total Retransmitted: {total_retrans} bytes")
            print(f"  Total Invalid: {total_invalid} bytes")
            print(f"  Avg Round-Trip Time: {avg_srtt:.2f}ms")
            print(f"  Max Round-Trip Time: {max_srtt:.2f}ms")

        # Retransmit events timeline
        if self.retransmit_events:
            print(f"\n{'='*80}")
            print(f"{Colors.BOLD_YELLOW}🔄 RETRANSMIT EVENTS: {len(self.retransmit_events)} event(s) detected{Colors.RESET}")
            print(f"{'='*80}")

            # Group events by session
            events_by_session = {}
            for event in self.retransmit_events:
                if event.session_number not in events_by_session:
                    events_by_session[event.session_number] = []
                events_by_session[event.session_number].append(event)

            # Display events grouped by session
            for session_num in sorted(events_by_session.keys()):
                session_events = events_by_session[session_num]
                # Find the session object
                session = next((s for s in self.sessions if s.session_number == session_num), None)
                session_header = self._format_session_header(session) if session else f"Session {session_num}"
                print(f"\n{Colors.BOLD_CYAN}{session_header}: {len(session_events)} retransmit event{'s' if len(session_events) != 1 else ''}{Colors.RESET}")
                print("-" * 80)

                for event in session_events:
                    time_str = str(timedelta(seconds=int(event.timestamp)))

                    # Determine severity based on delta
                    if event.bytes_retransmit_delta > 100:
                        severity = "🔴 SEVERE"
                    elif event.bytes_retransmit_delta > 50:
                        severity = "🟠 MODERATE"
                    else:
                        severity = "🟡 MINOR"

                    print(f"\n  {severity} Retransmit at {time_str}")
                    print(f"    Line: {event.line_number}")
                    print(f"    Bytes Retransmitted: +{event.bytes_retransmit_delta} bytes (Total: {event.bytes_retransmit_total})")

                    # Show duration info for this session
                    if len(session_events) > 1:
                        first_event = min(session_events, key=lambda e: e.timestamp)
                        last_event = max(session_events, key=lambda e: e.timestamp)
                        duration = last_event.timestamp - first_event.timestamp

                        if event == first_event:
                            print(f"    🕐 First retransmit in session")
                        elif event == last_event:
                            print(f"    🕐 Last retransmit in session (Duration: {duration:.1f}s from first)")
                        else:
                            time_since_first = event.timestamp - first_event.timestamp
                            print(f"    🕐 {time_since_first:.1f}s after first retransmit")

                    print(f"    Retransmit Seq: {event.retransmit_seq}")
                    print(f"    Send/Receive Seq: {event.send_seq} / {event.receive_seq}")
                    print(f"    Round-Trip Time: {event.srtt_ms:.2f}ms")

                    # Check if this is near a crash
                    for session in self.sessions:
                        if session.session_number == event.session_number and session.crashed:
                            time_before_crash = session.uptime_seconds - event.timestamp
                            if time_before_crash >= 0:
                                if time_before_crash < 60:  # Within 1 minute of crash
                                    print(f"    ⚠️  WARNING: Crash occurred {time_before_crash:.1f}s AFTER this event!")
                                else:
                                    minutes = int(time_before_crash / 60)
                                    print(f"    ℹ️  Crash occurred {minutes}m {time_before_crash % 60:.0f}s after this event")

            # System load stats
            print(f"\n{'='*80}")
            print(f"{Colors.BOLD_CYAN}💻 SYSTEM STATISTICS{Colors.RESET}")
            print(f"{'='*80}")

            avg_load = statistics.mean(s.sysload for s in self.stats)
            max_load = max(s.sysload for s in self.stats)
            min_mem = min(s.memavail for s in self.stats) / 1024
            avg_mem = statistics.mean(s.memavail for s in self.stats) / 1024

            print(f"  Avg System Load: {avg_load:.2f}")
            print(f"  Max System Load: {max_load:.2f}")
            print(f"  Min Memory Available: {min_mem:.0f}MB")
            print(f"  Avg Memory Available: {avg_mem:.0f}MB")

        # Anomaly summary
        print(f"\n{'='*80}")
        print(f"{Colors.BOLD_YELLOW}⚠️  ANOMALY SUMMARY: {len(self.anomalies)} anomal{'y' if len(self.anomalies)==1 else 'ies'} detected{Colors.RESET}")
        print(f"{'='*80}")

        anomaly_counts = defaultdict(int)

        for anomaly in self.anomalies:
            anomaly_counts[anomaly.category] += 1

        print(f"\n  By Category:")
        for category, count in sorted(anomaly_counts.items()):
            print(f"    {category}: {count}")

    def print_anomalies(self, limit: int = 50):
        """Print detailed anomaly list"""
        print(f"\n{'='*80}")
        print(f"⚠️  ANOMALY DETAILS (showing first {min(limit, len(self.anomalies))})")
        print(f"{'='*80}")

        # Sort by severity then timestamp
        severity_order = {'CRITICAL': 0, 'WARNING': 1, 'INFO': 2}
        sorted_anomalies = sorted(
            self.anomalies,
            key=lambda a: (severity_order[a.severity], a.timestamp)
        )

        for anomaly in sorted_anomalies[:limit]:
            time_str = str(timedelta(seconds=int(anomaly.timestamp)))
            severity_icon = {'CRITICAL': '🔴', 'WARNING': '⚠️ ', 'INFO': 'ℹ️ '}

            print(f"\n{severity_icon[anomaly.severity]} [{anomaly.severity}] Line {anomaly.line_number} @ {time_str}")
            print(f"   Category: {anomaly.category}")
            print(f"   {anomaly.message}")

    def interactive_menu(self):
        """Interactive CLI menu"""
        while True:
            print("\n" + "="*80)
            print(f"{Colors.BOLD_CYAN}🔧 INTERACTIVE ANALYZER MENU{Colors.RESET}")
            print("="*80)
            print("1. Show Summary")
            print("3. Filter Anomalies by Category")
            print("4. Show Session Details")
            print("5. Show Communication Timeline")
            print("9. Export Data (CSV)")
            print("0. Exit")

            choice = input("\nEnter choice: ").strip()

            if choice == '1':
                self.print_summary()

            elif choice == '3':
                categories = sorted(set(a.category for a in self.anomalies))
                if not categories:
                    print("\nNo anomalies to filter!")
                    continue

                print("\nAvailable categories:")
                for i, cat in enumerate(categories, 1):
                    count = sum(1 for a in self.anomalies if a.category == cat)
                    print(f"  {i}. {cat} ({count} anomalies)")
                print("  0. Back")

                try:
                    cat_choice = input("\nSelect category number (0 to go back): ").strip()
                    if cat_choice == '0':
                        continue
                    idx = int(cat_choice) - 1
                    if 0 <= idx < len(categories):
                        category = categories[idx]
                        filtered = [a for a in self.anomalies if a.category == category]
                        print(f"\nFound {len(filtered)} anomalies in category '{category}'")
                        self._print_filtered_anomalies(filtered)
                    else:
                        print("Invalid selection!")
                except ValueError:
                    print("Invalid number!")

            elif choice == '4':
                print("\n" + "="*80)
                print(f"{Colors.BOLD_CYAN}🔄 SESSION DETAILS{Colors.RESET}")
                print(f"{'='*80}")

                for i, session in enumerate(self.sessions, 1):
                    uptime_str = str(timedelta(seconds=int(session.uptime_seconds)))
                    crash_marker = "💥 CRASHED" if session.crashed else "✅ Normal"

                    print(f"\n{Colors.BOLD_CYAN}{self._format_session_header(session)}:{Colors.RESET}")
                    print(f"  Lines: {session.start_line} - {session.end_line or 'EOF'}")
                    print(f"  Device: {session.device or 'Unknown'}")
                    print(f"  Git Version: {session.git_version or 'Unknown'}")

                    # Show start and end times if available
                    if session.start_time:
                        print(f"  Started: {session.start_time}")
                        # Calculate end time
                        try:
                            from datetime import datetime
                            start_dt = datetime.strptime(session.start_time, "%a %b %d %H:%M:%S %Y")
                            end_dt = start_dt + timedelta(seconds=int(session.uptime_seconds))
                            print(f"  Ended: {end_dt.strftime('%a %b %d %H:%M:%S %Y')}")
                        except:
                            pass  # If parsing fails, just skip end time

                    print(f"  Uptime: {uptime_str} ({session.uptime_seconds:.1f}s)")
                    print(f"  Stats Count: {session.stats_count}")
                    print(f"  Status: {crash_marker}")
                    if session.crash_type:
                        ending_label = "Crash Type" if session.crashed else "Ending"
                        print(f"  {ending_label}: {session.crash_type}")
                    elif session.end_line:
                        print(f"  Ending: Session ended (reason unknown)")

                    # Show print jobs for this session
                    if session.print_jobs:
                        # Separate significant prints from test/calibration
                        MIN_SIGNIFICANT_SIZE = 100 * 1024  # 100KB
                        MIN_SIGNIFICANT_DURATION = 30  # 30 seconds

                        significant_jobs = [pj for pj in session.print_jobs
                                           if pj.max_sd_pos >= MIN_SIGNIFICANT_SIZE or pj.duration_seconds >= MIN_SIGNIFICANT_DURATION]
                        test_jobs = [pj for pj in session.print_jobs
                                    if pj.max_sd_pos < MIN_SIGNIFICANT_SIZE and pj.duration_seconds < MIN_SIGNIFICANT_DURATION]

                        # Show significant prints
                        if significant_jobs:
                            print(f"\n  📄 Print Jobs ({len(significant_jobs)}):")
                            for j, pj in enumerate(significant_jobs, 1):
                                duration_str = str(timedelta(seconds=int(pj.duration_seconds)))
                                progress = (pj.end_sd_pos / pj.max_sd_pos * 100) if pj.max_sd_pos > 0 else 0

                                # Status icon
                                status_icon = {
                                    'completed': '✅',
                                    'interrupted': '❗',
                                    'ongoing': '🔄'
                                }.get(pj.status, '❓')

                                # Format file size (sd_pos is in bytes)
                                file_size_mb = pj.max_sd_pos / (1024 * 1024)

                                print(f"    {j}. {status_icon} {pj.status.upper()}")
                                print(f"       Duration: {duration_str}")

                                # For interrupted prints where file was fully read, show differently
                                if pj.status == 'interrupted' and pj.end_sd_pos == pj.max_sd_pos:
                                    print(f"       Progress: File read: {pj.end_sd_pos:,} bytes - interrupted during execution")
                                else:
                                    print(f"       Progress: {progress:.1f}% ({pj.end_sd_pos:,} / {pj.max_sd_pos:,} bytes)")

                                print(f"       File Size: ~{file_size_mb:.2f}MB")

                        # Show test/calibration summary if present
                        if test_jobs:
                            print(f"\n  🔧 Test/Calibration Runs: {len(test_jobs)} (< 100KB or < 30s)")

            elif choice == '5':
                self._show_communication_timeline()

            elif choice == '9':
                self.export_csv()

            elif choice == '0':
                print("\n👋 Goodbye!")
                break

            else:
                print("Invalid choice!")

    def _show_pre_crash_stats(self, crashed_session: SessionInfo):
        """Show detailed stats from the last 10 entries before crash"""
        # Get stats for this session
        session_stats = [s for s in self.stats
                        if crashed_session.start_line <= s.line_number <= (crashed_session.end_line or float('inf'))]

        if len(session_stats) < 2:
            return

        # Get last 10 stats before crash
        pre_crash_stats = session_stats[-10:] if len(session_stats) >= 10 else session_stats

        print(f"\n    📊 PRE-CRASH ANALYSIS (Last {len(pre_crash_stats)} stats entries):")
        print(f"    " + "="*120)
        # Fixed-width columns accounting for icons
        print(f"    {'':3} {'Time':<10} {'Extruder':>11} {'Bed':>10} {'MCU':>5} {'RPi':>5} {'Load':>6} {'Mem':>7} {'Buf':>6} {'Retx':>5} {'Seq':>9}")
        print(f"    " + "="*120)

        for i, stats in enumerate(pre_crash_stats):
            time_str = str(timedelta(seconds=int(stats.timestamp)))

            # Format metrics with consistent widths
            mem_mb = stats.memavail / 1024
            ext_str = f"{stats.extruder_temp:.1f}/{stats.extruder_target:.0f}" if stats.extruder_temp > 0 else "-"
            bed_str = f"{stats.heater_bed_temp:.1f}/{stats.heater_bed_target:.0f}" if stats.heater_bed_temp > 0 else "-"
            buffer_str = f"{stats.buffer_time:.2f}s" if stats.buffer_time > 0 else "-"
            mem_str = f"{mem_mb:.0f}MB"

            # Sequence sync indicator
            seq_sync = "✓" if stats.send_seq == stats.receive_seq else "✗"

            # Warning icons (using single-char equivalents that won't break alignment)
            load_warn = "!" if stats.sysload > 2.0 else ("*" if stats.sysload > 1.5 else " ")
            mem_warn = "!" if mem_mb < 300 else ("*" if mem_mb < 500 else " ")
            temp_diff = abs(stats.extruder_temp - stats.extruder_target)
            temp_warn = "!" if temp_diff > 10 else ("*" if temp_diff > 5 else " ")
            buf_warn = "!" if stats.buffer_time < 0.5 and stats.sd_pos else ("*" if stats.buffer_time < 1.0 and stats.sd_pos else " ")

            # Mark last entry before crash
            marker = "💥" if i == len(pre_crash_stats) - 1 else "  "

            # Format retransmit value showing delta when increased
            prev_retx = pre_crash_stats[i-1].bytes_retransmit if i > 0 else None
            retx_str = self._format_retransmit(stats.bytes_retransmit, prev_retx, width=5)

            # Format MCU and RPi temperatures
            mcu_str = f"{stats.mcu_temp:.0f}°" if stats.mcu_temp is not None else "  -"
            rpi_str = f"{stats.rpi_temp:.0f}°" if stats.rpi_temp is not None else "  -"

            # Thermal warnings
            mcu_warn = "!" if stats.mcu_temp and stats.mcu_temp > 60 else (" " if stats.mcu_temp else " ")
            rpi_warn = "!" if stats.rpi_temp and stats.rpi_temp > 75 else ("*" if stats.rpi_temp and stats.rpi_temp > 65 else " ")

            print(f"    {marker} {time_str:<10} {temp_warn}{ext_str:>10} {bed_str:>10} "
                  f"{mcu_warn}{mcu_str:>4} {rpi_warn}{rpi_str:>4} {load_warn}{stats.sysload:>5.2f} {mem_warn}{mem_str:>6} "
                  f"{buf_warn}{buffer_str:>5} {retx_str} {seq_sync} {stats.send_seq:>7}")

        print(f"    " + "="*120)
        print(f"    Legend: ! = Critical/Warning  * = Warning  ✓ = Synced  ✗ = Mismatch")
        print(f"    Retx: cumulative bytes (! = new retransmit with delta shown)")
        print(f"    " + "="*120)

        # Analysis summary
        last_stat = pre_crash_stats[-1]
        issues = []

        if last_stat.sysload > 2.0:
            issues.append("🔴 HIGH CPU LOAD")
        if last_stat.memavail / 1024 < 300:
            issues.append("🔴 LOW MEMORY")
        if last_stat.buffer_time < 0.5 and last_stat.sd_pos:
            issues.append("🔴 BUFFER UNDERRUN")
        if abs(last_stat.extruder_temp - last_stat.extruder_target) > 10:
            issues.append("⚠️  TEMPERATURE DEVIATION")

        # Check for retransmit spike in last 10 entries
        if len(pre_crash_stats) >= 2:
            retrans_delta = pre_crash_stats[-1].bytes_retransmit - pre_crash_stats[0].bytes_retransmit
            if retrans_delta > 50:
                issues.append(f"🔴 RETRANSMIT SPIKE (+{retrans_delta} bytes)")

        # Check for temperature spikes in last 10 entries
        if len(pre_crash_stats) >= 2:
            for i in range(1, len(pre_crash_stats)):
                prev = pre_crash_stats[i-1]
                curr = pre_crash_stats[i]
                time_delta = curr.timestamp - prev.timestamp

                if 0.5 <= time_delta <= 2.0:
                    # Check extruder spike
                    if curr.extruder_temp > 0 and prev.extruder_temp > 0:
                        ext_change = abs(curr.extruder_temp - prev.extruder_temp)
                        target_changed = abs(curr.extruder_target - prev.extruder_target) > 1.0

                        if ext_change > 10.0 and not target_changed:
                            issues.append(f"🔴 EXTRUDER SPIKE: {ext_change:.1f}°C in {time_delta:.1f}s")
                        elif ext_change > 5.0 and not target_changed:
                            issues.append(f"⚠️  EXTRUDER SPIKE: {ext_change:.1f}°C in {time_delta:.1f}s")

                    # Check bed spike
                    if curr.heater_bed_temp > 0 and prev.heater_bed_temp > 0:
                        bed_change = abs(curr.heater_bed_temp - prev.heater_bed_temp)
                        bed_target_changed = abs(curr.heater_bed_target - prev.heater_bed_target) > 1.0

                        if bed_change > 8.0 and not bed_target_changed:
                            issues.append(f"🔴 BED SPIKE: {bed_change:.1f}°C in {time_delta:.1f}s")
                        elif bed_change > 4.0 and not bed_target_changed:
                            issues.append(f"⚠️  BED SPIKE: {bed_change:.1f}°C in {time_delta:.1f}s")

        if issues:
            print(f"\n    ⚠️  WARNING SIGNS BEFORE CRASH:")
            for issue in issues:
                print(f"       {issue}")
        else:
            print(f"\n    ✅ All metrics normal before crash - likely thermal/power issue")

        print()

    def _print_filtered_anomalies(self, anomalies: List[Anomaly]):
        """Print filtered anomalies grouped by session"""
        # Initialize all sessions with empty lists
        anomalies_by_session = {session.session_number: [] for session in self.sessions}

        # Group anomalies by session
        for anomaly in anomalies[:50]:
            # Find which session this anomaly belongs to
            session_num = None
            for session in self.sessions:
                if session.start_line <= anomaly.line_number <= (session.end_line or float('inf')):
                    session_num = session.session_number
                    break

            if session_num is not None:
                anomalies_by_session[session_num].append(anomaly)

        # Print anomalies grouped by session
        for session_num in sorted(anomalies_by_session.keys()):
            session_anomalies = anomalies_by_session[session_num]
            # Find the session object
            session = next((s for s in self.sessions if s.session_number == session_num), None)
            session_header = self._format_session_header(session) if session else f"Session {session_num}"
            print(f"\n{Colors.BOLD_CYAN}{session_header}: {len(session_anomalies)} anomal{'y' if len(session_anomalies)==1 else 'ies'}{Colors.RESET}")
            print("-" * 80)

            if not session_anomalies:
                print(f"{Colors.GREEN}  ✅ No anomalies in this session{Colors.RESET}")
            else:
                for anomaly in session_anomalies:
                    time_str = str(timedelta(seconds=int(anomaly.timestamp)))
                    print(f"\nLine {anomaly.line_number} @ {time_str}")
                    print(f"  {anomaly.message}")

                    # Show system stats context for the anomaly
                    self._show_anomaly_stats(anomaly)

                    # Show context for temperature spikes
                    if anomaly.category == 'Temperature' and 'spike' in anomaly.message.lower():
                        self._show_temperature_spike_context(anomaly)

                    # Show context for low buffer events
                    if anomaly.category == 'Print Quality' and 'buffer' in anomaly.message.lower():
                        self._show_buffer_context(anomaly)

    def _show_anomaly_stats(self, anomaly: Anomaly):
        """Show system stats at the time of the anomaly"""
        # Find the stats entry for this anomaly
        stats = None
        for s in self.stats:
            if s.line_number == anomaly.line_number:
                stats = s
                break

        if not stats:
            return

        # Build stats display
        stats_parts = []

        # Print status indicator
        if stats.sd_pos and stats.sd_pos > 0:
            status_icon = "🖨️  PRINTING"
        else:
            status_icon = "⏸️  IDLE"
        stats_parts.append(status_icon)

        # System metrics (always show)
        mem_mb = stats.memavail / 1024
        stats_parts.append(f"Load: {stats.sysload:.2f}")
        stats_parts.append(f"Mem: {mem_mb:.0f}MB")

        # Temperatures (if available)
        if stats.rpi_temp:
            stats_parts.append(f"RPi: {stats.rpi_temp:.0f}°C")
        if stats.mcu_temp:
            stats_parts.append(f"MCU: {stats.mcu_temp:.0f}°C")

        # Print status (if printing)
        if stats.sd_pos and stats.sd_pos > 0:
            stats_parts.append(f"Buf: {stats.buffer_time:.2f}s")
            if stats.print_stall > 0:
                stats_parts.append(f"⚠️ Stalls: {stats.print_stall}")

        # Temperatures
        if stats.extruder_target > 0:
            stats_parts.append(f"Ext: {stats.extruder_temp:.1f}/{stats.extruder_target:.0f}°C")
        if stats.heater_bed_target > 0:
            stats_parts.append(f"Bed: {stats.heater_bed_temp:.1f}/{stats.heater_bed_target:.0f}°C")

        print(f"  📊 {' | '.join(stats_parts)}")

    def _show_temperature_spike_context(self, anomaly: Anomaly):
        """Show temperature values before and after a spike"""
        # Find the stats entry for this anomaly
        spike_stats = None
        spike_index = None

        for i, stats in enumerate(self.stats):
            if stats.line_number == anomaly.line_number:
                spike_stats = stats
                spike_index = i
                break

        if not spike_stats or spike_index is None:
            return

        # Get 5 entries before and 5 entries after
        context_before = 5
        context_after = 5
        start_idx = max(0, spike_index - context_before)
        end_idx = min(len(self.stats), spike_index + context_after + 1)

        context_stats = self.stats[start_idx:end_idx]

        # Determine which heater spiked
        is_extruder_spike = 'extruder' in anomaly.message.lower()
        is_bed_spike = 'bed' in anomaly.message.lower()

        print(f"\n  📊 Temperature context (±{context_before} entries):")
        print(f"  {'':3} {'Time':<10} {'Extruder':>12} {'Target':>8} {'Bed':>10} {'Target':>8}")
        print(f"  " + "-"*60)

        for i, stats in enumerate(context_stats):
            time_str = str(timedelta(seconds=int(stats.timestamp)))

            # Format temperatures
            ext_temp = f"{stats.extruder_temp:.1f}°C" if stats.extruder_temp > 0 else "-"
            ext_target = f"{stats.extruder_target:.0f}°C" if stats.extruder_target > 0 else "-"
            bed_temp = f"{stats.heater_bed_temp:.1f}°C" if stats.heater_bed_temp > 0 else "-"
            bed_target = f"{stats.heater_bed_target:.0f}°C" if stats.heater_bed_target > 0 else "-"

            # Calculate change from previous
            change_marker = "   "
            if i > 0:
                prev_stats = context_stats[i-1]
                time_delta = stats.timestamp - prev_stats.timestamp

                if is_extruder_spike and 0.5 <= time_delta <= 2.0:
                    ext_change = stats.extruder_temp - prev_stats.extruder_temp
                    if abs(ext_change) > 5.0:
                        change_marker = f"({ext_change:+.1f})" if ext_change != 0 else "   "
                elif is_bed_spike and 0.5 <= time_delta <= 2.0:
                    bed_change = stats.heater_bed_temp - prev_stats.heater_bed_temp
                    if abs(bed_change) > 4.0:
                        change_marker = f"({bed_change:+.1f})" if bed_change != 0 else "   "

            # Mark the spike line
            marker = "💥" if stats.line_number == anomaly.line_number else "  "

            # Highlight extruder or bed based on spike type
            if stats.line_number == anomaly.line_number:
                if is_extruder_spike:
                    print(f"  {marker} {time_str:<10} !{ext_temp:>11} {ext_target:>8} {bed_temp:>10} {bed_target:>8} {change_marker}")
                else:
                    print(f"  {marker} {time_str:<10} {ext_temp:>12} {ext_target:>8} !{bed_temp:>9} {bed_target:>8} {change_marker}")
            else:
                print(f"  {marker} {time_str:<10} {ext_temp:>12} {ext_target:>8} {bed_temp:>10} {bed_target:>8} {change_marker}")

        print(f"  " + "-"*60)
        print(f"  ! = Spike detected at this point")
        print()

    def _show_buffer_context(self, anomaly: Anomaly):
        """Show system metrics around a low buffer event"""
        # Find the stats entry for this anomaly
        buffer_stats = None
        buffer_index = None

        for i, stats in enumerate(self.stats):
            if stats.line_number == anomaly.line_number:
                buffer_stats = stats
                buffer_index = i
                break

        if not buffer_stats or buffer_index is None:
            return

        # Get 3 entries before and 3 entries after
        context_before = 3
        context_after = 3
        start_idx = max(0, buffer_index - context_before)
        end_idx = min(len(self.stats), buffer_index + context_after + 1)

        context_stats = self.stats[start_idx:end_idx]

        print(f"\n  📊 Buffer context (±{context_before} entries):")
        print(f"  {'':3} {'Time':<10} {'Buffer':>8} {'Load':>6} {'Mem':>7} {'Stall':>6} {'Retx':>6} {'Seq':>4}")
        print(f"  " + "-"*70)

        for i, stats in enumerate(context_stats):
            time_str = str(timedelta(seconds=int(stats.timestamp)))
            buffer_str = f"{stats.buffer_time:.2f}s" if stats.buffer_time > 0 else "0.00s"
            mem_mb = stats.memavail / 1024
            mem_str = f"{mem_mb:.0f}MB"
            stall_str = f"{stats.print_stall}" if stats.print_stall > 0 else "-"
            seq_sync = "✓" if stats.send_seq == stats.receive_seq else "✗"

            # Check if retransmit happened (cumulative value increased)
            prev_retx = context_stats[i-1].bytes_retransmit if i > 0 else None
            retx_str = self._format_retransmit(stats.bytes_retransmit, prev_retx, width=6)

            # Mark the anomaly line
            marker = "!" if stats.line_number == anomaly.line_number else " "

            # Highlight low buffer
            buf_warn = "!" if stats.buffer_time < 1.0 and stats.sd_pos else " "
            load_warn = "!" if stats.sysload > 1.5 else " "

            print(f"  {marker}  {time_str:<10} {buf_warn}{buffer_str:>7} {load_warn}{stats.sysload:>5.2f} {mem_str:>7} "
                  f"{stall_str:>6} {retx_str:>6} {seq_sync:>4}")

        print(f"  " + "-"*70)
        print(f"  ! = Low buffer/high load/retransmit occurred  Retx: cumulative bytes (! = new retransmit)")
        print()

    def _show_line_context(self, line_num: int):
        """Show context around a line number"""
        matching_stats = [s for s in self.stats if abs(s.line_number - line_num) <= 5]
        if matching_stats:
            print(f"\nStats near line {line_num}:")
            for stats in sorted(matching_stats, key=lambda s: s.line_number):
                print(f"  Line {stats.line_number}: time={stats.timestamp:.1f}s, "
                      f"retrans={stats.bytes_retransmit}, load={stats.sysload}")
        else:
            print(f"No stats found near line {line_num}")

    def _show_communication_timeline(self):
        """Show communication timeline with retransmit events highlighted"""
        print("\n📊 Communication Timeline")
        print("="*80)

        # Show retransmit events first
        if self.retransmit_events:
            print("\n🔄 RETRANSMIT EVENTS:")
            for event in self.retransmit_events:
                time_str = str(timedelta(seconds=int(event.timestamp)))
                if event.bytes_retransmit_delta > 100:
                    severity = "🔴"
                elif event.bytes_retransmit_delta > 50:
                    severity = "🟠"
                else:
                    severity = "🟡"
                print(f"  {severity} {time_str} (Session {event.session_number}): +{event.bytes_retransmit_delta} bytes retransmitted")
        else:
            print("\n✅ No retransmit events detected - excellent communication health!")

        print("\n" + "="*80)
        print("DETAILED TIMELINE (sampled):")

        for session in self.sessions:
            session_stats = [s for s in self.stats
                           if session.start_line <= s.line_number <= (session.end_line or float('inf'))]

            if not session_stats:
                continue

            print(f"\n{Colors.BOLD_CYAN}{self._format_session_header(session)}:{Colors.RESET}")

            # Get retransmit events for this session
            session_retransmits = [e for e in self.retransmit_events if e.session_number == session.session_number]
            retransmit_times = {int(e.timestamp) for e in session_retransmits}

            # Sample every N entries for readability
            sample_rate = max(1, len(session_stats) // 20)
            sampled_stats = session_stats[::sample_rate]

            for i, stats in enumerate(sampled_stats):
                time_str = str(timedelta(seconds=int(stats.timestamp)))

                # Check if this is near a retransmit event
                is_retransmit = int(stats.timestamp) in retransmit_times
                retrans_marker = "🔄" if is_retransmit else ("📤" if stats.bytes_retransmit > 0 else "  ")

                # Format retransmit value showing delta when increased
                prev_retx = sampled_stats[i-1].bytes_retransmit if i > 0 else None
                retx_str = self._format_retransmit(stats.bytes_retransmit, prev_retx, width=5)

                print(f"  {retrans_marker} {time_str}: Retx {retx_str:>6}, "
                      f"RTT={stats.srtt*1000:.1f}ms, load={stats.sysload:.2f}")

    def export_csv(self):
        """Export stats to CSV"""
        output_file = self.log_file.replace('.log', '_analysis.csv')

        try:
            with open(output_file, 'w') as f:
                # Header
                f.write("line,timestamp,bytes_retransmit,bytes_invalid,send_seq,receive_seq,"
                       "srtt_ms,sysload,memavail_mb,print_stall,buffer_time,extruder_temp,"
                       "extruder_target,bed_temp,bed_target\n")

                # Data
                for stats in self.stats:
                    f.write(f"{stats.line_number},{stats.timestamp},{stats.bytes_retransmit},"
                           f"{stats.bytes_invalid},{stats.send_seq},{stats.receive_seq},"
                           f"{stats.srtt*1000:.2f},{stats.sysload},{stats.memavail/1024:.0f},"
                           f"{stats.print_stall},{stats.buffer_time},{stats.extruder_temp},"
                           f"{stats.extruder_target},{stats.heater_bed_temp},{stats.heater_bed_target}\n")

            print(f"\n✅ Exported to {output_file}")
        except Exception as e:
            print(f"\n❌ Export failed: {e}")

def find_log_files():
    """Search for Klipper log files in current directory, script directory, and subdirectories"""
    import os
    import glob

    log_files = []

    # Get the script's directory
    script_dir = os.path.dirname(os.path.abspath(__file__))

    # Search patterns - will be applied to both current dir and script dir
    relative_patterns = [
        'klippy.log',
        '*.log',
        'logs/klippy.log',
        'logs/*.log',
        '*/klippy.log',
        '*/*.log',
        'printer_data/logs/*.log',
        '../printer_data/logs/*.log',
    ]

    # Absolute patterns
    absolute_patterns = [
        '/tmp/klippy.log',
    ]

    # Search from current working directory
    for pattern in relative_patterns:
        matches = glob.glob(pattern)
        for match in matches:
            if os.path.isfile(match) and match not in log_files:
                # Filter out non-Klipper logs
                if 'klippy' in os.path.basename(match).lower() or match.endswith('klippy.log'):
                    log_files.append(os.path.abspath(match))

    # Search from script's directory
    for pattern in relative_patterns:
        script_pattern = os.path.join(script_dir, pattern)
        matches = glob.glob(script_pattern)
        for match in matches:
            abs_match = os.path.abspath(match)
            if os.path.isfile(abs_match) and abs_match not in log_files:
                # Filter out non-Klipper logs
                if 'klippy' in os.path.basename(abs_match).lower() or match.endswith('klippy.log'):
                    log_files.append(abs_match)

    # Search absolute patterns
    for pattern in absolute_patterns:
        matches = glob.glob(pattern)
        for match in matches:
            abs_match = os.path.abspath(match)
            if os.path.isfile(abs_match) and abs_match not in log_files:
                if 'klippy' in os.path.basename(abs_match).lower() or match.endswith('klippy.log'):
                    log_files.append(abs_match)

    return sorted(set(log_files))

def main():
    import os

    log_file = None

    # Check for flags
    show_temp = '--show-temp' in sys.argv
    if show_temp:
        sys.argv.remove('--show-temp')

    if len(sys.argv) < 2:
        # Auto-discover log files
        print("🔍 No log file specified. Searching for Klipper logs...")
        log_files = find_log_files()

        if not log_files:
            print("\n❌ No Klipper log files found!")
            print("\nUsage: python klipper_log_analyzer.py <klippy.log>")
            print("\nSearched locations:")
            print("  - Current directory (*.log)")
            print("  - Script directory (*.log)")
            print("  - Subdirectories (*/*.log)")
            print("  - Common paths (printer_data/logs/, /tmp/)")
            sys.exit(1)

        if len(log_files) == 1:
            log_file = log_files[0]
            print(f"✅ Found: {log_file}\n")
        else:
            print(f"\n📁 Found {len(log_files)} log file(s):\n")
            for i, lf in enumerate(log_files, 1):
                size_mb = os.path.getsize(lf) / (1024 * 1024)
                print(f"  {i}. {lf} ({size_mb:.1f}MB)")
            print(f"  0. Exit")

            try:
                choice = input("\nSelect file number (0 to exit): ").strip()
                if choice == '0':
                    sys.exit(0)

                idx = int(choice) - 1
                if 0 <= idx < len(log_files):
                    log_file = log_files[idx]
                else:
                    print("Invalid selection!")
                    sys.exit(1)
            except (ValueError, KeyboardInterrupt):
                print("\nCancelled.")
                sys.exit(1)
    else:
        log_file = sys.argv[1]

    print("\n" + "="*80)
    print(f"{Colors.BOLD_CYAN}📊 KLIPPER LOG ANALYSIS{Colors.RESET}")
    print("="*80)

    analyzer = KlipperLogAnalyzer(log_file)
    analyzer.parse_log()
    analyzer.detect_print_jobs()
    analyzer.detect_retransmit_events()
    analyzer.detect_anomalies()
    analyzer.print_summary()

    # If --show-temp flag, automatically show temperature anomalies
    if show_temp:
        temp_anomalies = [a for a in analyzer.anomalies if a.category == 'Temperature']
        if temp_anomalies:
            print("\n" + "="*80)
            print(f"🌡️  TEMPERATURE ANOMALIES: {len(temp_anomalies)} detected")
            print("="*80)
            analyzer._print_filtered_anomalies(temp_anomalies)
        else:
            print("\n✅ No temperature anomalies detected!")
        return

    # Automatically enter interactive mode
    analyzer.interactive_menu()

if __name__ == '__main__':
    main()
