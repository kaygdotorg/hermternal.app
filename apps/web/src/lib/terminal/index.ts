export {
  createTerminalRenderer,
  createWTermGhosttyAdapter,
  DEFAULT_PENDING_WRITE_LIMIT_BYTES,
  DEFAULT_SCROLLBACK_LIMIT_BYTES,
  DEFAULT_TERMINAL_COLS,
  DEFAULT_TERMINAL_ROWS,
  MAX_PENDING_OPERATION_COUNT,
  MAX_SCROLLBACK_LIMIT_BYTES
} from './renderer';

export type {
  MountedTerminal,
  MountedTerminalDisposeOptions,
  PasteRequest,
  TerminalAdapterOptions,
  TerminalRenderer,
  TerminalRendererAdapter,
  TerminalRendererError,
  TerminalRendererErrorCode,
  TerminalRendererOptions,
  TerminalRendererState,
  TerminalSize
} from './renderer';
