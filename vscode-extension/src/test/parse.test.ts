import * as assert from 'assert';
import { parseScanResult } from '../parse';

function runTests() {
  console.log('Running parseScanResult unit tests...');

  // Test Case 1: Valid scan result array
  {
    const validJson = JSON.stringify([
      {
        file: 'deploy/k8s/deployment.yaml',
        line: 42,
        rule_id: 'SEC-ENV-001',
        severity: 'critical',
        message: 'Hardcoded production API secret key detected in deployment manifest',
        environment: 'production',
        confidence: 0.95,
        recommendation: 'Migrate the hardcoded secret to a secure secrets manager.',
      },
      {
        file: 'tests/test_auth.py',
        line: 15,
        rule_id: 'SEC-TEST-002',
        severity: 'low',
        message: 'Weak mock token found in test suite',
        environment: 'local-testing',
        confidence: 0.85,
        recommendation: 'Ensure test mock credentials are restricted exclusively to test servers.',
      },
    ]);

    const result = parseScanResult(validJson);
    assert.strictEqual(result.findings.length, 2, 'Should parse 2 findings');
    assert.strictEqual(result.findings[0].rule_id, 'SEC-ENV-001');
    assert.strictEqual(result.findings[0].line, 42);
    assert.strictEqual(result.findings[0].severity, 'critical');
    assert.strictEqual(result.findings[0].environment, 'production');
    assert.strictEqual(result.findings[0].confidence, 0.95);
    assert.strictEqual(result.findings[1].rule_id, 'SEC-TEST-002');
    console.log('✓ Valid scan result parsed successfully');
  }

  // Test Case 2: Malformed JSON string
  {
    const malformedJson = '{"file": "deploy/k8s/deployment.yaml", line: 42,';
    assert.throws(
      () => {
        parseScanResult(malformedJson);
      },
      (err: Error) => {
        return (
          err instanceof Error &&
          err.message.includes('Malformed JSON in scan result')
        );
      },
      'Should throw a clear error for malformed JSON'
    );
    console.log('✓ Malformed JSON throws clear error');
  }

  // Test Case 3: Missing optional / context fields (environment, confidence, recommendation)
  {
    const missingOptionalFieldsJson = JSON.stringify([
      {
        file: 'config/app.conf',
        line: 10,
        rule_id: 'SEC-OPT-001',
        severity: 'high',
        message: 'Potentially insecure default setting',
        // environment, confidence, and recommendation are intentionally omitted
      },
    ]);

    // Must NOT throw on missing optional fields
    const result = parseScanResult(missingOptionalFieldsJson);
    assert.strictEqual(result.findings.length, 1);
    const finding = result.findings[0];
    assert.strictEqual(finding.rule_id, 'SEC-OPT-001');
    assert.strictEqual(finding.file, 'config/app.conf');
    assert.strictEqual(finding.line, 10);
    assert.strictEqual(finding.severity, 'high');
    assert.strictEqual(finding.message, 'Potentially insecure default setting');
    // Safe defaults
    assert.strictEqual(finding.environment, 'unknown', 'Default environment should be unknown');
    assert.strictEqual(finding.confidence, 0.0, 'Default confidence should be 0.0');
    assert.strictEqual(finding.recommendation, '', 'Default recommendation should be empty string');
    console.log('✓ Missing optional fields parsed defensively with default values without throwing');
  }

  // Test Case 4: Wrong shape (missing required fields or invalid types)
  {
    const wrongShapeNumber = 42;
    assert.throws(
      () => {
        parseScanResult(wrongShapeNumber);
      },
      /Wrong shape/,
      'Should throw clear error when scan result is not an array or object'
    );

    const wrongShapeItem = JSON.stringify([
      {
        // missing "file"
        line: 10,
        rule_id: 'SEC-001',
        severity: 'high',
        message: 'test',
      },
    ]);
    assert.throws(
      () => {
        parseScanResult(wrongShapeItem);
      },
      /missing a non-empty string "file"/,
      'Should throw clear error when required "file" field is missing'
    );

    const invalidSeverityItem = JSON.stringify([
      {
        file: 'src/index.ts',
        line: 1,
        rule_id: 'SEC-001',
        severity: 'extreme-danger', // invalid enum
        message: 'test',
      },
    ]);
    assert.throws(
      () => {
        parseScanResult(invalidSeverityItem);
      },
      /invalid severity/,
      'Should throw clear error when severity is not an allowed enum'
    );

    console.log('✓ Wrong shape inputs throw clear descriptive errors');
  }

  // Test Case 5: Trailing stderr-style text after JSON and leading banners
  {
    const jsonOutput = JSON.stringify([
      {
        file: 'src/config.py',
        line: 12,
        rule_id: 'SEC-004',
        severity: 'high',
        message: 'Insecure config',
        environment: 'production',
        confidence: 0.9,
        evidence: ['matched in deploy script'],
        recommendation: 'Fix config',
      },
    ]);
    const noisyOutput = `Starting scanner v1.0...\n${jsonOutput}\n[WARNING] Non-critical warning emitted to stdout/stderr\nDeprecation notice: xyz\n`;
    const result = parseScanResult(noisyOutput);
    assert.strictEqual(result.findings.length, 1);
    assert.strictEqual(result.findings[0].rule_id, 'SEC-004');
    assert.deepStrictEqual(result.findings[0].evidence, ['matched in deploy script']);
    console.log('✓ Handled trailing stderr-style noise and leading banners around JSON');
  }

  // Test Case 6: Missing environment field normalized to 'unknown'
  {
    const missingEnvJson = JSON.stringify([
      {
        file: 'lib/db.ts',
        line: 7,
        rule_id: 'SEC-005',
        severity: 'medium',
        message: 'No env specified',
        // environment omitted
        confidence: 0.5,
      },
    ]);
    const result = parseScanResult(missingEnvJson);
    assert.strictEqual(result.findings.length, 1);
    assert.strictEqual(result.findings[0].environment, 'unknown');
    assert.strictEqual(result.findings[0].confidence, 0.5);
    assert.deepStrictEqual(result.findings[0].evidence, []);
    assert.strictEqual(result.findings[0].recommendation, '');
    console.log('✓ Missing environment field safely normalized to "unknown"');
  }

  // Test Case 7: Object wrapped in { findings: [...] }
  {
    const wrappedJson = JSON.stringify({
      status: 'success',
      findings: [
        {
          file: 'main.py',
          line: 20,
          rule_id: 'SEC-006',
          severity: 'critical',
          message: 'Root access',
          environment: 'production',
          confidence: 1.0,
        },
      ],
    });
    const result = parseScanResult(wrappedJson);
    assert.strictEqual(result.findings.length, 1);
    assert.strictEqual(result.findings[0].rule_id, 'SEC-006');
    assert.strictEqual(result.status, 'success');
    console.log('✓ Successfully parsed { findings: [...] } wrapped object');
  }

  console.log('\nAll parseScanResult unit tests passed successfully!\n');
}

runTests();

