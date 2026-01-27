import { render, screen } from '@testing-library/react';
import { ValidationBadge } from './ValidationBadge';
import { ValidationResult } from '@/types';

describe('ValidationBadge', () => {
  it('should render nothing when validationResult is null', () => {
    const { container } = render(<ValidationBadge validationResult={null} />);
    expect(container.firstChild).toBeNull();
  });

  it('should render nothing when validationResult is undefined', () => {
    const { container } = render(<ValidationBadge validationResult={undefined} />);
    expect(container.firstChild).toBeNull();
  });

  it('should render valid badge when is_valid is true', () => {
    const validResult: ValidationResult = {
      is_valid: true,
      reasoning: ['Test reason'],
      categories: ['xss'],
      confidence: 85,
      investigation_steps: ['Step 1'],
      timestamp: '2024-01-01T00:00:00Z',
    };

    render(<ValidationBadge validationResult={validResult} />);
    expect(screen.getByText(/LLM Validated/i)).toBeInTheDocument();
  });

  it('should render invalid badge when is_valid is false', () => {
    const invalidResult: ValidationResult = {
      is_valid: false,
      reasoning: ['Not exploitable'],
      categories: [],
      confidence: 90,
      investigation_steps: null,
      timestamp: '2024-01-01T00:00:00Z',
    };

    render(<ValidationBadge validationResult={invalidResult} />);
    expect(screen.getByText(/LLM Rejected/i)).toBeInTheDocument();
  });

  it('should display confidence when present', () => {
    const result: ValidationResult = {
      is_valid: true,
      reasoning: ['Test'],
      categories: [],
      confidence: 75,
      investigation_steps: null,
      timestamp: '2024-01-01T00:00:00Z',
    };

    render(<ValidationBadge validationResult={result} />);
    expect(screen.getByText('75% confidence')).toBeInTheDocument();
  });

  it('should not display confidence when null', () => {
    const result: ValidationResult = {
      is_valid: true,
      reasoning: ['Test'],
      categories: [],
      confidence: null,
      investigation_steps: null,
      timestamp: '2024-01-01T00:00:00Z',
    };

    render(<ValidationBadge validationResult={result} />);
    expect(screen.queryByText(/confidence/i)).not.toBeInTheDocument();
  });

  it('should display reasoning list', () => {
    const result: ValidationResult = {
      is_valid: true,
      reasoning: ['Reason 1', 'Reason 2', 'Reason 3'],
      categories: [],
      confidence: 80,
      investigation_steps: null,
      timestamp: '2024-01-01T00:00:00Z',
    };

    render(<ValidationBadge validationResult={result} />);
    expect(screen.getByText('Reason 1')).toBeInTheDocument();
    expect(screen.getByText('Reason 2')).toBeInTheDocument();
    expect(screen.getByText('Reason 3')).toBeInTheDocument();
  });

  it('should not display reasoning section when empty array', () => {
    const result: ValidationResult = {
      is_valid: true,
      reasoning: [],
      categories: [],
      confidence: 80,
      investigation_steps: null,
      timestamp: '2024-01-01T00:00:00Z',
    };

    render(<ValidationBadge validationResult={result} />);
    expect(screen.queryByText('Reasoning:')).not.toBeInTheDocument();
  });

  it('should apply valid styling classes when is_valid is true', () => {
    const result: ValidationResult = {
      is_valid: true,
      reasoning: ['Test'],
      categories: [],
      confidence: 80,
      investigation_steps: null,
      timestamp: '2024-01-01T00:00:00Z',
    };

    const { container } = render(<ValidationBadge validationResult={result} />);
    const badge = container.querySelector('.validation-badge');
    expect(badge).toHaveClass('valid');
  });

  it('should apply invalid styling classes when is_valid is false', () => {
    const result: ValidationResult = {
      is_valid: false,
      reasoning: ['Test'],
      categories: [],
      confidence: 80,
      investigation_steps: null,
      timestamp: '2024-01-01T00:00:00Z',
    };

    const { container } = render(<ValidationBadge validationResult={result} />);
    const badge = container.querySelector('.validation-badge');
    expect(badge).toHaveClass('invalid');
  });
});
