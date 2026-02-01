import type { Metadata } from 'next';
import { JetBrains_Mono } from 'next/font/google';
import './globals.css';
import { AuthProvider } from '../contexts/AuthContext';

const jetbrainsMono = JetBrains_Mono({
  subsets: ['latin'],
  variable: '--font-mono',
  display: 'swap',
});

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
    <html lang="en" className={jetbrainsMono.variable}>
      <body className="antialiased font-mono">
        <AuthProvider>
          {children}
        </AuthProvider>
      </body>
    </html>
  );
}
