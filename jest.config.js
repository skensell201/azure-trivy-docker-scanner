module.exports = {
  projects: [
    {
      displayName: 'task',
      preset: 'ts-jest',
      testEnvironment: 'node',
      roots: ['<rootDir>/src/shared', '<rootDir>/src/task', '<rootDir>/test'],
      testMatch: ['**/__tests__/**/*.test.ts', '**/test/**/*.test.ts'],
      clearMocks: true,
    },
    {
      displayName: 'hub',
      preset: 'ts-jest',
      testEnvironment: 'jsdom',
      roots: ['<rootDir>/src/hub'],
      testMatch: ['**/__tests__/**/*.test.tsx'],
      moduleNameMapper: { '\\.(css|scss)$': '<rootDir>/test/styleMock.js' },
      clearMocks: true,
    },
  ],
};
