/**
 * PIIDetector - Detects Personally Identifiable Information in text
 */

export interface PIIFinding {
  type: string;
  value: string;
  index: number;
  confidence: "low" | "medium" | "high";
}

export class PIIDetector {
  private patterns: Record<string, RegExp> = {
    email: /[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}/g,
    phone: /(\+?\d{1,2}\s?)?(\(?\d{3}\)?[\s.-]?)?\d{3}[\s.-]?\d{4}/g,
    ssn: /\b\d{3}-\d{2}-\d{4}\b/g,
    credit_card: /\b(?:\d{4}[ -]?){3}\d{4}\b/g,
    api_key: /\b(?:sk|pk|ak|key|auth|token)_[a-zA-Z0-9]{20,}\b/gi,
    ipv4: /\b(?:\d{1,3}\.){3}\d{1,3}\b/g,
    mac_address: /\b(?:[0-9A-Fa-f]{2}[:-]){5}(?:[0-9A-Fa-f]{2})\b/g,
  };

  /**
   * Scan text for PII
   */
  public scan(text: string): PIIFinding[] {
    const findings: PIIFinding[] = [];

    for (const [type, pattern] of Object.entries(this.patterns)) {
      let match;
      while ((match = pattern.exec(text)) !== null) {
        const value = match[0];
        
        // Additional validation for certain types
        if (type === "credit_card" && !this.validateLuhn(value)) {
          continue;
        }

        findings.push({
          type,
          value: this.mask(value),
          index: match.index,
          confidence: this.calculateConfidence(type, value),
        });
      }
    }

    return findings;
  }

  /**
   * Validate credit card numbers using Luhn algorithm
   */
  private validateLuhn(cardNumber: string): boolean {
    const digits = cardNumber.replace(/\D/g, "");
    let sum = 0;
    let shouldDouble = false;

    for (let i = digits.length - 1; i >= 0; i--) {
      let digit = parseInt(digits.charAt(i), 10);

      if (shouldDouble) {
        digit *= 2;
        if (digit > 9) digit -= 9;
      }

      sum += digit;
      shouldDouble = !shouldDouble;
    }

    return sum % 10 === 0;
  }

  /**
   * Calculate confidence level of a finding
   */
  private calculateConfidence(type: string, value: string): "low" | "medium" | "high" {
    switch (type) {
      case "credit_card":
      case "ssn":
        return "high";
      case "email":
        return value.includes(".com") || value.includes(".org") ? "high" : "medium";
      case "api_key":
        return value.length > 32 ? "high" : "medium";
      default:
        return "medium";
    }
  }

  /**
   * Mask sensitive value for reporting
   */
  private mask(value: string): string {
    if (value.length <= 4) return "****";
    const visible = Math.min(4, Math.floor(value.length / 4));
    return value.slice(0, visible) + "*".repeat(value.length - visible * 2) + value.slice(-visible);
  }
}
