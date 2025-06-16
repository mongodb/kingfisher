#!/usr/bin/env bash

# Name of the application (used for pid lookup, log and plot filenames)
APP_NAME="kingfisher"

# Remove old log (if it exists) so we start fresh
LOG_FILE="${APP_NAME}_mem.log"
PLOT_FILE="${APP_NAME}_rss.png"
[ -f "$LOG_FILE" ] && rm "$LOG_FILE"
[ -f "$PLOT_FILE" ] && rm "$PLOT_FILE"

# Find the main PID
main_pid=$(pidof "$APP_NAME")
if [[ -z "$main_pid" ]]; then
  echo "Error: no running process named '$APP_NAME' found."
  exit 1
fi

# Determine page size in KiB
page_kb=$(( $(getconf PAGESIZE) / 1024 ))

# Monitor loop: sum VmRSS across parent + direct children
while [[ -d /proc/$main_pid ]]; do
  ts=$(date +%s)
  pids="$main_pid $(pgrep -P $main_pid)"

  total_kb=0
  for pid in $pids; do
    if rss_kb=$(awk '/VmRSS/ {print $2}' /proc/$pid/status 2>/dev/null); then
      total_kb=$(( total_kb + rss_kb ))
    fi
  done

  # Convert KiB → MiB (2 decimal places) and log
  total_mb=$(awk "BEGIN {printf \"%.2f\", $total_kb/1024}")
  echo "$ts $total_mb" >> "$LOG_FILE"

  sleep 0.5
done

# Once monitoring ends, generate the plot
gnuplot -persist <<EOF
  set terminal pngcairo size 1280,720
  set output "$PLOT_FILE"
  set xdata time
  set timefmt "%s"
  set format x "%H:%M:%S"
  set xlabel "Time"
  set ylabel "RSS (MiB)"
  set title "${APP_NAME^} Memory Usage"
  set grid
  plot "$LOG_FILE" using 1:2 with lines linewidth 2 title "RSS"
EOF

echo "Memory log written to $LOG_FILE"
echo "Plot generated as $PLOT_FILE"
