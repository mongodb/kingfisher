const RESET = '\x1b[0m';
const DIM = '\x1b[2m';
const BOLD = '\x1b[1m';
const CYAN = '\x1b[36m';
const GREEN = '\x1b[32m';
const YELLOW = '\x1b[33m';
const RED = '\x1b[31m';

const SPINNER = ['⠋', '⠙', '⠹', '⠸', '⠼', '⠴', '⠦', '⠧', '⠇', '⠏'];

export function formatNumber(value) {
  return new Intl.NumberFormat('en-US').format(Math.round(value ?? 0));
}

export function formatBytes(value) {
  if (value === null || value === undefined) return 'no limit';
  if (value >= 1024 ** 3) return `${(value / 1024 ** 3).toFixed(2)} GB`;
  if (value >= 1024 ** 2) return `${(value / 1024 ** 2).toFixed(1)} MB`;
  if (value >= 1024) return `${(value / 1024).toFixed(1)} KB`;
  return `${Math.round(value)} B`;
}

export function formatElapsed(milliseconds) {
  const seconds = Math.max(0, Math.floor(milliseconds / 1000));
  const minutes = Math.floor(seconds / 60);
  if (minutes >= 60) {
    const hours = Math.floor(minutes / 60);
    return `${hours}h ${String(minutes % 60).padStart(2, '0')}m`;
  }
  return `${String(minutes).padStart(2, '0')}:${String(seconds % 60).padStart(2, '0')}`;
}

/**
 * One-line live progress display, in the spirit of the kingfisher CLI: a
 * spinner, the current phase, and a few counters that update in place on a TTY.
 * Without a TTY it degrades to periodic block lines so logs stay readable.
 */
export function createProgress({ stream = process.stdout, quiet = false, enabled } = {}) {
  const tty = Boolean(stream.isTTY);
  const useColor = tty && !process.env.NO_COLOR;
  const active = enabled ?? tty;
  const paint = (code, text) => (useColor ? `${code}${text}${RESET}` : text);

  let state = null;
  let width = 0;
  let frame = 0;
  let lastWrite = 0;
  let lastBlock = 0;
  let closed = false;

  const clearLine = () => {
    if (!tty || width === 0) return;
    stream.write(`\r${' '.repeat(width)}\r`);
    width = 0;
  };

  const render = () => {
    if (closed || !state) return;
    const now = Date.now();
    if (now - lastWrite < 90) return;
    lastWrite = now;
    const elapsed = formatElapsed(now - state.startedAt);
    const rate = state.bytes > 0 && now > state.startedAt
      ? `${formatBytes((state.bytes / (now - state.startedAt)) * 1000)}/s`
      : '0 B/s';
    const parts = [];
    if (state.phase === 'validating') {
      parts.push(`${formatNumber(state.validated)}/${formatNumber(state.reportable)} findings checked`);
      if (state.findings) parts.push(paint(YELLOW, `${formatNumber(state.findings)} findings`));
    } else {
      if (state.inputs) parts.push(`${formatNumber(state.inputs)} inputs`);
      if (state.bytes) parts.push(formatBytes(state.bytes));
      if (state.bytes) parts.push(rate);
      if (state.findings) parts.push(paint(YELLOW, `${formatNumber(state.findings)} findings`));
    }
    parts.push(elapsed);
    const text = `${SPINNER[frame++ % SPINNER.length]} ${paint(CYAN, state.phase.padEnd(10))} ${parts.join(paint(DIM, ' · '))}`;

    if (!tty) {
      if (now - lastBlock > 10_000) {
        lastBlock = now;
        stream.write(`${text}\n`);
      }
      return;
    }
    const padding = width > text.length ? ' '.repeat(width - text.length) : '';
    stream.write(`\r${text}${padding}`);
    width = text.length;
  };

  const timer = setInterval(render, 120);
  timer.unref?.();

  return {
    /**
     * Start or update the live line. `phase` switches the leading label; the
     * counters are absolute values, not deltas.
     */
    update(patch) {
      if (quiet || !active) return;
      if (!state) state = { phase: 'scanning', startedAt: Date.now(), inputs: 0, bytes: 0, findings: 0 };
      Object.assign(state, patch);
      render();
    },

    /** Print a permanent line, keeping the live line below it. */
    log(line = '') {
      if (quiet) return;
      clearLine();
      stream.write(`${line}\n`);
    },

    /** Headline block printed before any work starts. */
    banner(title, rows) {
      if (quiet) return;
      const lines = [paint(BOLD, title)];
      const labelWidth = Math.max(...rows.map(([label]) => label.length));
      for (const [label, value] of rows) {
        lines.push(`  ${paint(DIM, label.padEnd(labelWidth))}  ${value}`);
      }
      stream.write(`${lines.join('\n')}\n\n`);
    },

    done(line) {
      if (quiet) return;
      clearLine();
      if (line) stream.write(`${paint(GREEN, '✓')} ${line}\n`);
    },

    stop() {
      closed = true;
      clearInterval(timer);
      clearLine();
    },
  };
}
