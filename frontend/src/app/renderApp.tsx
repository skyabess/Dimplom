import React from 'react';
import ReactDOM from 'react-dom/client';
import App from '../App';
import '../index.css';

export const renderApp = (element: HTMLElement) => {
  ReactDOM.createRoot(element).render(
    <React.StrictMode>
      <App />
    </React.StrictMode>,
  );
};
