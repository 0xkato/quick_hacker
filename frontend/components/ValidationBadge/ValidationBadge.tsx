'use client';

import React from 'react';
import { ValidationResult } from '@/types';
import './ValidationBadge.css';

interface ValidationBadgeProps {
  validationResult?: ValidationResult | null;
}

export const ValidationBadge: React.FC<ValidationBadgeProps> = ({ validationResult }) => {
  if (!validationResult) {
    return null;
  }

  const { is_valid, confidence, reasoning } = validationResult;

  return (
    <div className={`validation-badge ${is_valid ? 'valid' : 'invalid'}`}>
      <span className="validation-status">
        {is_valid ? '✓ LLM Validated' : '✗ LLM Rejected'}
      </span>
      {confidence !== null && (
        <span className="validation-confidence">
          {confidence}% confidence
        </span>
      )}
      {reasoning && reasoning.length > 0 && (
        <div className="validation-reasoning">
          <strong>Reasoning:</strong>
          <ul>
            {reasoning.map((r, i) => (
              <li key={i}>{r}</li>
            ))}
          </ul>
        </div>
      )}
    </div>
  );
};
