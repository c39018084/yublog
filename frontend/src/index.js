import React from 'react';
import ReactDOM from 'react-dom/client';
import { BrowserRouter } from 'react-router-dom';
import './index.css';
import App from './App';
import { AuthProvider } from './contexts/AuthContext';
import reportWebVitals from './reportWebVitals';

// Disable ALL WebSocket connections globally - must run before React renders
(function() {
  if (typeof window !== 'undefined' && window.WebSocket) {
    const OriginalWebSocket = window.WebSocket;
    
    window.WebSocket = function(url, protocols) {
      console.log('[BLOCKED] WebSocket connection attempt to:', url);
      
      // Return a dummy WebSocket object for ALL connections
      const dummySocket = {
        addEventListener: function() { console.log('[BLOCKED] WebSocket addEventListener called'); },
        removeEventListener: function() { console.log('[BLOCKED] WebSocket removeEventListener called'); },
        send: function() { console.log('[BLOCKED] WebSocket send called'); },
        close: function() { console.log('[BLOCKED] WebSocket close called'); },
        dispatchEvent: function() { return false; },
        readyState: 3, // CLOSED
        bufferedAmount: 0,
        extensions: '',
        protocol: '',
        url: url || '',
        CONNECTING: 0,
        OPEN: 1,
        CLOSING: 2,
        CLOSED: 3,
        onopen: null,
        onmessage: null,
        onerror: null,
        onclose: null
      };
      
      // Immediately trigger close event
      setTimeout(() => {
        if (dummySocket.onclose) {
          dummySocket.onclose({ code: 1000, reason: 'WebSocket blocked by override' });
        }
      }, 1);
      
      return dummySocket;
    };
    
    // Set static properties
    window.WebSocket.CONNECTING = 0;
    window.WebSocket.OPEN = 1;
    window.WebSocket.CLOSING = 2;
    window.WebSocket.CLOSED = 3;
    
    console.log('[WebSocket Override] All WebSocket connections are now blocked');
  }
})();

const root = ReactDOM.createRoot(document.getElementById('root'));
root.render(
  <React.StrictMode>
    <BrowserRouter
      future={{
        v7_startTransition: true,
        v7_relativeSplatPath: true
      }}
    >
      <AuthProvider>
        <App />
      </AuthProvider>
    </BrowserRouter>
  </React.StrictMode>
);

// If you want to start measuring performance in your app, pass a function
// to log results (for example: reportWebVitals(console.log))
// or send to an analytics endpoint. Learn more: https://bit.ly/CRA-vitals
reportWebVitals(); 