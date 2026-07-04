import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import { render, screen } from '@testing-library/react';
import { expect, test } from 'vitest';
import { App } from '../src/App';

function renderApp() {
  const queryClient = new QueryClient({
    defaultOptions: { queries: { retry: false } }
  });
  render(
    <QueryClientProvider client={queryClient}>
      <App />
    </QueryClientProvider>
  );
}

test('renders operational gateway dashboard', async () => {
  renderApp();
  expect(screen.getByText('ChatGPT MCP SSH Gateway')).toBeInTheDocument();
  expect(screen.getByRole('button', { name: /add ssh device/i })).toBeInTheDocument();
  expect(screen.getByText('New SSH device')).toBeInTheDocument();
});
