import { en, type MessageKey } from "./en";

export type { MessageKey };

/**
 * The message for key, with each {name} replaced by params[name]. The result
 * is plain text: parameters are inserted as text and never parsed (S-34).
 */
export function t(key: MessageKey, params?: Record<string, string | number>): string {
  const msg: string = en[key];
  if (!params) return msg;
  return msg.replace(/\{(\w+)\}/g, (m, name: string) => (name in params ? String(params[name]) : m));
}
