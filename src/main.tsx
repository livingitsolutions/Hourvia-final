import { StrictMode } from 'react';
import { createRoot } from 'react-dom/client';
import { BrowserRouter } from 'react-router-dom';
import { AuthProvider } from './application/auth';
import { createPlatformApi, createWorkspaceAdminApi, serverSessionAuth } from './infrastructure/server-session-auth';
import App from './presentation/App';
import './presentation/styles.css';
createRoot(document.getElementById('root')!).render(<StrictMode><BrowserRouter><AuthProvider service={serverSessionAuth} access={serverSessionAuth} admin={createWorkspaceAdminApi()} platform={createPlatformApi()}><App/></AuthProvider></BrowserRouter></StrictMode>);
