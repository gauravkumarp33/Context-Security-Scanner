import { Environment, Finding, ScanResult, Severity } from './types';

const VALID_SEVERITIES: ReadonlySet<string> = new Set<Severity>([
  'low',
  'medium',
  'high',
  'critical',
]);

const VALID_ENVIRONMENTS: ReadonlySet<string> = new Set<Environment>([
  'production',
  'local-testing',
  'unknown',
]);

/**
 * Parses and defensively validates raw scanner output.
 * Throws a clear Error if the JSON is malformed or the top-level / item shape is invalid.
 * Tolerates missing optional or context fields by supplying safe default values without throwing.
 */
export function parseScanResult(raw: string | unknown): ScanResult {
  let parsed: unknown;

  if (typeof raw === 'string') {
    const trimmed = raw.trim();
    if (!trimmed) {
      throw new Error('Malformed JSON: raw scan output is empty');
    }
    try {
      parsed = JSON.parse(trimmed);
    } catch (err) {
      const msg = err instanceof Error ? err.message : String(err);
      throw new Error(`Malformed JSON in scan result: ${msg}`);
    }
  } else {
    parsed = raw;
  }

  if (parsed === null || parsed === undefined || typeof parsed !== 'object') {
    throw new Error('Wrong shape: scan result must be a JSON array or an object');
  }

  let rawList: unknown[];
  let status: string | undefined;
  let errors: string[] | undefined;

  if (Array.isArray(parsed)) {
    rawList = parsed;
  } else {
    const obj = parsed as Record<string, unknown>;
    if (!Array.isArray(obj.findings)) {
      throw new Error(
        'Wrong shape: expected a JSON array of findings or an object containing a "findings" array'
      );
    }
    rawList = obj.findings;
    if (typeof obj.status === 'string') {
      status = obj.status;
    }
    if (Array.isArray(obj.errors)) {
      errors = obj.errors.filter((e): e is string => typeof e === 'string');
    }
  }

  const findings: Finding[] = rawList.map((item, index) => {
    if (item === null || typeof item !== 'object' || Array.isArray(item)) {
      throw new Error(`Wrong shape: finding at index ${index} must be an object`);
    }

    const rawFinding = item as Record<string, unknown>;

    // Required fields: file, line, rule_id, severity, message
    if (typeof rawFinding.file !== 'string' || rawFinding.file.trim().length === 0) {
      throw new Error(
        `Wrong shape: finding at index ${index} is missing a non-empty string "file"`
      );
    }

    if (
      typeof rawFinding.line !== 'number' ||
      !Number.isInteger(rawFinding.line) ||
      rawFinding.line < 1
    ) {
      throw new Error(
        `Wrong shape: finding at index ${index} has invalid "line" (expected integer >= 1, got ${String(
          rawFinding.line
        )})`
      );
    }

    if (
      typeof rawFinding.rule_id !== 'string' ||
      rawFinding.rule_id.trim().length === 0
    ) {
      throw new Error(
        `Wrong shape: finding at index ${index} is missing a non-empty string "rule_id"`
      );
    }

    if (
      typeof rawFinding.severity !== 'string' ||
      !VALID_SEVERITIES.has(rawFinding.severity)
    ) {
      throw new Error(
        `Wrong shape: finding at index ${index} has invalid severity "${String(
          rawFinding.severity
        )}". Allowed: low, medium, high, critical`
      );
    }

    if (typeof rawFinding.message !== 'string') {
      throw new Error(
        `Wrong shape: finding at index ${index} is missing required string "message"`
      );
    }

    // Defensive handling for optional/context fields: do not throw if missing
    let environment: Environment = 'unknown';
    if (
      typeof rawFinding.environment === 'string' &&
      VALID_ENVIRONMENTS.has(rawFinding.environment)
    ) {
      environment = rawFinding.environment as Environment;
    }

    let confidence = 0.0;
    if (
      typeof rawFinding.confidence === 'number' &&
      !Number.isNaN(rawFinding.confidence)
    ) {
      confidence = Math.max(0.0, Math.min(1.0, rawFinding.confidence));
    }

    let recommendation = '';
    if (typeof rawFinding.recommendation === 'string') {
      recommendation = rawFinding.recommendation;
    }

    return {
      file: rawFinding.file,
      line: rawFinding.line,
      rule_id: rawFinding.rule_id,
      severity: rawFinding.severity as Severity,
      message: rawFinding.message,
      environment,
      confidence,
      recommendation,
    };
  });

  return {
    findings,
    ...(status !== undefined ? { status } : {}),
    ...(errors !== undefined ? { errors } : {}),
  };
}
