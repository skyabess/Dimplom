import { renderApp } from './app/renderApp';

const rootElement = document.getElementById('root');

if (!rootElement) {
  throw new Error('Root element #root was not found');
}

renderApp(rootElement);
