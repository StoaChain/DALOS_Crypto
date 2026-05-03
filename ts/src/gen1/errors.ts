/**
 * Typed exception classes for the gen1 surface.
 *
 * These classes are caught by consumers via `instanceof` checks rather
 * than string matching. The explicit `this.name` assignment is required
 * because ES2015 class extension does not auto-propagate the subclass
 * name onto Error subclasses — without it, `error.name` would default
 * to `'Error'` and break catch-by-name patterns.
 *
 * Copyright (C) 2026 AncientHoldings GmbH. All rights reserved.
 */

export class SchnorrSignError extends Error {
  constructor(message: string) {
    super(message);
    this.name = 'SchnorrSignError';
  }
}
