import type { Metadata } from 'next';
import './globals.css';

export const metadata: Metadata = {
  title: 'quick_hack - Security Auditing IDE',
  description: 'AI-powered security code auditing in your browser',
};

export default function RootLayout({
  children,
}: {
  children: React.ReactNode;
}) {
  return (
    <html lang="en">
      <body className="antialiased">{children}</body>
    </html>
  );
}
