const DEFAULT_MAX_DEPTH = 16;
// The route caps permit 100 sessions or 500 messages. A minimal message row
// costs one object node plus role and content scalar nodes; optional pinned tool
// metadata is covered by the remaining bounded node budget.
const DEFAULT_MAX_NODES = 4_096;
const DEFAULT_MAX_STRING_LENGTH = 8_192;
const DEFAULT_MAX_ARRAY_LENGTH = 500;
const DEFAULT_MAX_OBJECT_KEYS = 64;
const MAX_SAFE_INTEGER = Number.MAX_SAFE_INTEGER;

export interface StrictJsonLimits {
  maxDepth?: number;
  maxNodes?: number;
  maxStringLength?: number;
  maxArrayLength?: number;
  maxObjectKeys?: number;
}

export type StrictJsonValue =
  | null
  | boolean
  | number
  | string
  | StrictJsonValue[]
  | { [key: string]: StrictJsonValue };

export class StrictJsonError extends Error {
  constructor() {
    super('The REST response was not valid bounded JSON.');
    this.name = 'StrictJsonError';
  }
}

/**
 * Parses an already bounded UTF-8 response without JSON.parse's duplicate-key
 * ambiguity. Route projections require reviewed fields and ignore bounded
 * additive fields after this parser returns; keeping those checks separate lets
 * every route share the same depth, node, string, and number limits. Structured
 * arrays and dictionaries remain intact for the reviewed message projection;
 * this parser does not flatten, coerce, or log their nested values.
 */
export function parseStrictJson(text: string, limits: StrictJsonLimits = {}): StrictJsonValue {
  const parser = new JsonParser({
    maxDepth: limits.maxDepth ?? DEFAULT_MAX_DEPTH,
    maxNodes: limits.maxNodes ?? DEFAULT_MAX_NODES,
    maxStringLength: limits.maxStringLength ?? DEFAULT_MAX_STRING_LENGTH,
    maxArrayLength: limits.maxArrayLength ?? DEFAULT_MAX_ARRAY_LENGTH,
    maxObjectKeys: limits.maxObjectKeys ?? DEFAULT_MAX_OBJECT_KEYS
  });

  return parser.parse(text);
}

interface NormalizedLimits {
  maxDepth: number;
  maxNodes: number;
  maxStringLength: number;
  maxArrayLength: number;
  maxObjectKeys: number;
}

function hasForbiddenControlCharacters(value: string): boolean {
  for (const character of value) {
    const codePoint = character.codePointAt(0);
    // Raw controls are rejected while parsing. Escaped tab, LF, and CR are
    // valid JSON whitespace in transcript content and remain data after decode.
    if (
      codePoint !== undefined &&
      codePoint <= 0x1f &&
      codePoint !== 0x09 &&
      codePoint !== 0x0a &&
      codePoint !== 0x0d
    ) {
      return true;
    }
  }
  return false;
}

class JsonParser {
  private readonly limits: NormalizedLimits;
  private index = 0;
  private nodes = 0;

  constructor(limits: NormalizedLimits) {
    if (
      !Number.isInteger(limits.maxDepth) ||
      limits.maxDepth < 1 ||
      !Number.isInteger(limits.maxNodes) ||
      limits.maxNodes < 1 ||
      !Number.isInteger(limits.maxStringLength) ||
      limits.maxStringLength < 1 ||
      !Number.isInteger(limits.maxArrayLength) ||
      limits.maxArrayLength < 1 ||
      !Number.isInteger(limits.maxObjectKeys) ||
      limits.maxObjectKeys < 1
    ) {
      throw new StrictJsonError();
    }

    this.limits = limits;
  }

  parse(text: string): StrictJsonValue {
    if (text.length === 0) {
      throw new StrictJsonError();
    }

    const value = this.parseValue(text, 0);
    this.skipWhitespace(text);

    if (this.index !== text.length) {
      throw new StrictJsonError();
    }

    return value;
  }

  private parseValue(text: string, depth: number): StrictJsonValue {
    if (depth > this.limits.maxDepth) {
      throw new StrictJsonError();
    }

    this.skipWhitespace(text);
    const character = text[this.index];

    if (character === '{') {
      return this.parseObject(text, depth + 1);
    }

    if (character === '[') {
      return this.parseArray(text, depth + 1);
    }

    if (character === '"') {
      return this.parseString(text);
    }

    if (character === 't' && text.startsWith('true', this.index)) {
      this.index += 4;
      this.countNode();
      return true;
    }

    if (character === 'f' && text.startsWith('false', this.index)) {
      this.index += 5;
      this.countNode();
      return false;
    }

    if (character === 'n' && text.startsWith('null', this.index)) {
      this.index += 4;
      this.countNode();
      return null;
    }

    return this.parseNumber(text);
  }

  private parseObject(text: string, depth: number): { [key: string]: StrictJsonValue } {
    this.index += 1;
    this.countNode();
    const result: { [key: string]: StrictJsonValue } = Object.create(null) as {
      [key: string]: StrictJsonValue;
    };
    const keys = new Set<string>();

    this.skipWhitespace(text);
    if (text[this.index] === '}') {
      this.index += 1;
      return result;
    }

    while (this.index < text.length) {
      if (keys.size >= this.limits.maxObjectKeys || text[this.index] !== '"') {
        throw new StrictJsonError();
      }

      const key = this.parseString(text);
      if (keys.has(key)) {
        throw new StrictJsonError();
      }
      keys.add(key);

      this.skipWhitespace(text);
      if (text[this.index] !== ':') {
        throw new StrictJsonError();
      }
      this.index += 1;

      const value = this.parseValue(text, depth);
      result[key] = value;

      this.skipWhitespace(text);
      if (text[this.index] === '}') {
        this.index += 1;
        return result;
      }

      if (text[this.index] !== ',') {
        throw new StrictJsonError();
      }
      this.index += 1;
      this.skipWhitespace(text);
    }

    throw new StrictJsonError();
  }

  private parseArray(text: string, depth: number): StrictJsonValue[] {
    this.index += 1;
    this.countNode();
    const result: StrictJsonValue[] = [];

    this.skipWhitespace(text);
    if (text[this.index] === ']') {
      this.index += 1;
      return result;
    }

    while (this.index < text.length) {
      if (result.length >= this.limits.maxArrayLength) {
        throw new StrictJsonError();
      }

      result.push(this.parseValue(text, depth));
      this.skipWhitespace(text);

      if (text[this.index] === ']') {
        this.index += 1;
        return result;
      }

      if (text[this.index] !== ',') {
        throw new StrictJsonError();
      }
      this.index += 1;
      this.skipWhitespace(text);
    }

    throw new StrictJsonError();
  }

  private parseString(text: string): string {
    if (text[this.index] !== '"') {
      throw new StrictJsonError();
    }

    const start = this.index;
    this.index += 1;

    while (this.index < text.length) {
      const character = text[this.index];

      if (character === '"') {
        this.index += 1;
        const raw = text.slice(start, this.index);
        let value: unknown;

        try {
          value = JSON.parse(raw) as unknown;
        } catch {
          throw new StrictJsonError();
        }

        if (
          typeof value !== 'string' ||
          value.length > this.limits.maxStringLength ||
          hasForbiddenControlCharacters(value)
        ) {
          throw new StrictJsonError();
        }

        this.countNode();
        return value;
      }

      if (character === '\\') {
        this.index += 1;
        const escape = text[this.index];

        if (!escape || !'"\\/bfnrtu'.includes(escape)) {
          throw new StrictJsonError();
        }

        if (escape === 'u') {
          const codePoint = text.slice(this.index + 1, this.index + 5);
          if (!/^[0-9a-fA-F]{4}$/u.test(codePoint)) {
            throw new StrictJsonError();
          }
          this.index += 4;
        }
      } else if (character < ' ') {
        throw new StrictJsonError();
      }

      this.index += 1;

      if (this.index - start > this.limits.maxStringLength * 6 + 2) {
        throw new StrictJsonError();
      }
    }

    throw new StrictJsonError();
  }

  private parseNumber(text: string): number {
    const match = text.slice(this.index).match(/^-?(?:0|[1-9][0-9]*)(?:\.[0-9]+)?(?:[eE][+-]?[0-9]+)?/u);

    if (!match) {
      throw new StrictJsonError();
    }

    const literal = match[0];
    const value = Number(literal);

    if (!Number.isFinite(value) || (Number.isInteger(value) && Math.abs(value) > MAX_SAFE_INTEGER)) {
      throw new StrictJsonError();
    }

    this.index += literal.length;
    this.countNode();
    return value;
  }

  private skipWhitespace(text: string): void {
    while (this.index < text.length) {
      const code = text.charCodeAt(this.index);
      if (code !== 9 && code !== 10 && code !== 13 && code !== 32) {
        break;
      }
      this.index += 1;
    }
  }

  private countNode(): void {
    this.nodes += 1;
    if (this.nodes > this.limits.maxNodes) {
      throw new StrictJsonError();
    }
  }
}
