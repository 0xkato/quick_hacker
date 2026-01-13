'use client';

import { useState } from 'react';

import { LoginForm } from './LoginForm';
import { RegisterForm } from './RegisterForm';

export function AuthScreen() {
  const [mode, setMode] = useState<'login' | 'register'>('login');

  return (
    <div className="h-screen flex items-center justify-center bg-vsc-bg">
      <div className="w-full max-w-md bg-gray-800 rounded-lg p-6 border border-gray-700 shadow-xl">
        <div className="mb-6">
          <h1 className="text-2xl font-bold text-white">quick_hack</h1>
          <p className="text-gray-400 text-sm">Sign in to continue.</p>
        </div>

        {mode === 'login' ? (
          <LoginForm onSwitchToRegister={() => setMode('register')} />
        ) : (
          <RegisterForm onSwitchToLogin={() => setMode('login')} />
        )}
      </div>
    </div>
  );
}

