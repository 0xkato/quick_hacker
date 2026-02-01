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
    <div className={`validation-badge-container ${is_valid ? 'valid' : 'invalid'}`}>
      <div className="validation-badge-header">
        <span className={`validation-status-indicator ${is_valid ? 'confirmed' : 'rejected'}`}>
          {is_valid ? '● CONFIRMED' : '● REJECTED'}
        </span>
        {confidence !== null && (
          <span className="validation-confidence">
            {confidence}%
          </span>
        )}
      </div>
      {reasoning && reasoning.length > 0 && (
        <div className="validation-reasoning">
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
