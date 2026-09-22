export const COMMAND_LEVELS = {
  1:'Safe/read-only operations',
  2:'Low-impact operations',
  3:'Normal mutating operations',
  4:'High-impact operations',
  5:'Dangerous/destructive operations',
} as const;

export function isCommandLevel(value:unknown): value is 1|2|3|4|5 {
  return value===1||value===2||value===3||value===4||value===5;
}
