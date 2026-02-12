/**
 * Weak Module - Intentionally non-compliant for tier enforcement testing
 * 
 * MISSING (for enterprise tier):
 * - No error taxonomy
 * - No config abstraction (hardcoded values)
 * - No tests
 * - No input validation
 * - No logging
 * - No shutdown handling
 */

// Hardcoded config - BAD
const API_KEY = "sk-hardcoded-secret-key";
const TIMEOUT = 5000;

// No types for errors - BAD
export function fetchData(url: string) {
  // No validation - BAD
  return fetch(url, {
    headers: { Authorization: API_KEY },
    signal: AbortSignal.timeout(TIMEOUT)
  }).then(r => r.json());
}

// No error handling - BAD
export function processItems(items: any[]) {
  return items.map(item => {
    return {
      id: item.id,
      name: item.name.toUpperCase(), // Will crash on null
      value: item.value * 2
    };
  });
}

// Global mutable state - BAD
let counter = 0;

export function incrementCounter() {
  counter++;
  return counter;
}

export function getCounter() {
  return counter;
}

// No cleanup/shutdown - BAD
const connections: any[] = [];

export function addConnection(conn: any) {
  connections.push(conn);
}
