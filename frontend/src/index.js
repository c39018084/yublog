// Block WebSocket connections before any modules load
if (typeof WebSocket !== 'undefined') {
  const OriginalWebSocket = WebSocket;
  window.WebSocket = function(url, protocols) {
    if (url && (url.includes('/ws') || url.includes('ws://') || url.includes('wss://'))) {
      console.log('Blocking WebSocket connection:', url);
      // Return a mock WebSocket that does nothing
      return {
        addEventListener: () => {},
        removeEventListener: () => {},
        send: () => {},
        close: () => {},
        readyState: 3, // CLOSED
        CONNECTING: 0,
        OPEN: 1,
        CLOSING: 2,
        CLOSED: 3
      };
    }
    return new OriginalWebSocket(url, protocols);
  };
  // Copy static properties
  Object.assign(window.WebSocket, OriginalWebSocket);
}

import React from 'react';
import ReactDOM from 'react-dom/client';
import { createBrowserRouter, RouterProvider } from 'react-router-dom';
import './index.css';
import App from './App';
import { AuthProvider } from './contexts/AuthContext';
import reportWebVitals from './reportWebVitals';

// Create router with future flags to eliminate deprecation warnings
const router = createBrowserRouter([
  {
    path: "*",
    element: <App />,
  }
], {
  future: {
    v7_startTransition: true,
    v7_relativeSplatPath: true,
    v7_fetcherPersist: true,
    v7_normalizeFormMethod: true,
    v7_partialHydration: true,
    v7_skipActionErrorRevalidation: true,
  }
});

const root = ReactDOM.createRoot(document.getElementById('root'));
root.render(
  <React.StrictMode>
    <AuthProvider>
      <RouterProvider router={router} />
    </AuthProvider>
  </React.StrictMode>
);

// If you want to start measuring performance in your app, pass a function
// to log results (for example: reportWebVitals(console.log))
// or send to an analytics endpoint. Learn more: https://bit.ly/CRA-vitals
reportWebVitals(); 