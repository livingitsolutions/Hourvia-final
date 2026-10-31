import { StrictMode } from 'react';
import { createRoot } from 'react-dom/client';
import { BrowserRouter } from 'react-router-dom';
import { AuthProvider } from './application/auth';
import { unconfiguredAuth } from './infrastructure/unconfigured-auth';
import App from './presentation/App';
import './presentation/styles.css';
createRoot(document.getElementById('root')!).render(<StrictMode><BrowserRouter><AuthProvider service={unconfiguredAuth}><App/></AuthProvider></BrowserRouter></StrictMode>);
