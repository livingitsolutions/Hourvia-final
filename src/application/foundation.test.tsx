// @vitest-environment jsdom
import { afterEach, describe, expect, it } from 'vitest';
import { cleanup, render, screen, waitFor, fireEvent } from '@testing-library/react';
import { MemoryRouter } from 'react-router-dom';
import { authorization, canNavigate, type Principal } from '../domain/permissions';
import { AuthProvider, safeDestination } from './auth';
import type { Authentication } from '../domain/contracts';
import { unconfiguredAuth } from '../infrastructure/unconfigured-auth';
import App from '../presentation/App';
afterEach(cleanup);
const contractor: Principal = { id:'c1', name:'Test Contractor', role:'contractor', workspaceId:'thrivesource', assignedContractorIds:[], approvalAuthorized:false };
const manager: Principal = { ...contractor, id:'m1', role:'workspace_manager', assignedContractorIds:['c1'] };
function mount(path: string, user: Principal | null = null, service?: Authentication) { const auth = service ?? { getSession:async () => user, signIn:async () => { throw new Error('Unavailable'); }, signOut:async () => {} }; return render(<MemoryRouter initialEntries={[path]}><AuthProvider service={auth}><App/></AuthProvider></MemoryRouter>); }
describe('deny-by-default permissions', () => {
  it('denies anonymous, unknown role, cross-workspace and missing scope access', () => {
    expect(authorization.can(null,'dashboard',{workspaceId:'thrivesource'})).toBe(false);
    expect(authorization.can({...contractor,role:'unknown' as Principal['role']},'dashboard',{workspaceId:'thrivesource'})).toBe(false);
    expect(authorization.can(contractor,'dtr.own',{workspaceId:'other',contractorId:'c1'})).toBe(false);
    expect(authorization.can(contractor,'dtr.own',{workspaceId:'thrivesource'})).toBe(false);
  });
  it('limits contractors to their own resources', () => {
    expect(authorization.can(contractor,'dtr.own',{workspaceId:'thrivesource',contractorId:'c1'})).toBe(true);
    expect(authorization.can(contractor,'dtr.own',{workspaceId:'thrivesource',contractorId:'c2'})).toBe(false);
    expect(canNavigate(contractor,'workspace.manage')).toBe(false);
  });
  it('requires both manager assignment and approval authority', () => {
    expect(authorization.can(manager,'contractors.records',{workspaceId:'thrivesource',contractorId:'c1'})).toBe(true);
    expect(authorization.can(manager,'contractors.records',{workspaceId:'thrivesource',contractorId:'c2'})).toBe(false);
    expect(canNavigate(manager,'approvals.review')).toBe(false);
    expect(authorization.can({...manager,approvalAuthorized:true},'approvals.review',{workspaceId:'thrivesource',contractorId:'c1'})).toBe(true);
    expect(authorization.can({...manager,approvalAuthorized:true},'approvals.review',{workspaceId:'thrivesource',contractorId:'c2'})).toBe(false);
    expect(canNavigate({...manager,assignedContractorIds:[]},'reports.read')).toBe(false);
  });
  it('allows admins workspace management only inside ThriveSource', () => {
    const admin: Principal = {...contractor,role:'workspace_admin'};
    expect(canNavigate(admin,'workspace.manage')).toBe(true);
    expect(authorization.can(admin,'workspace.manage',{workspaceId:'other'})).toBe(false);
  });
});
describe('routing and login', () => {
  it('rejects unsafe redirect destinations', () => { for (const path of ['https://example.org','//example.org','/\\example.org','/login?next=/','/\nother']) expect(safeDestination(path)).toBe('/dashboard'); expect(safeDestination('/my-dtr?month=10#day')).toBe('/my-dtr?month=10#day'); });
  it('redirects root to login and validates the form', async () => { mount('/'); await screen.findByRole('heading',{name:'Your workday starts here.'}); fireEvent.click(screen.getByRole('button',{name:'Sign in'})); expect(await screen.findByText('Enter a valid work email address.')).toBeTruthy(); expect(screen.getByText('Enter your password.')).toBeTruthy(); });
  it('denies production sign in and session creation', async () => { expect(await unconfiguredAuth.getSession()).toBeNull(); await expect(unconfiguredAuth.signIn({email:'test@example.org',password:'anything'})).rejects.toThrow('not connected'); });
  it('restores intended destinations after contract authentication', async () => { mount('/login?next=%2Fmy-dtr',contractor); expect(await screen.findByRole('heading',{name:'My DTR'})).toBeTruthy(); });
  it('protects direct routes', async () => { mount('/settings'); expect(await screen.findByRole('heading',{name:'Your workday starts here.'})).toBeTruthy(); expect(screen.queryByRole('heading',{name:'Workspace Settings'})).toBeNull(); });
  it('protects role routes even when visited directly', async () => { mount('/settings',contractor); expect(await screen.findByRole('heading',{name:'This page isn’t available to you.'})).toBeTruthy(); expect(screen.queryByRole('link',{name:'Workspace Settings'})).toBeNull(); expect(screen.getByRole('link',{name:'My DTR'})).toBeTruthy(); });
  it('shows manager navigation scoped to assignments and authority', async () => { mount('/dashboard',manager); await screen.findByRole('heading',{name:'Dashboard'}); expect(screen.getByRole('link',{name:'Contractor Directory'})).toBeTruthy(); expect(screen.queryByRole('link',{name:'Approval Queue'})).toBeNull(); expect(screen.queryByRole('link',{name:'Time Tracker'})).toBeNull(); });
  it('fails closed on session service failure', async () => { mount('/dashboard',null,{...unconfiguredAuth,getSession:async () => {throw new Error('offline');}}); expect(await screen.findByRole('alert')).toBeTruthy(); expect(screen.queryByRole('heading',{name:'Dashboard'})).toBeNull(); });
  it('renders a public 404 for unknown routes', async () => { mount('/missing'); await waitFor(() => expect(screen.getByRole('heading',{name:'A little off the clock.'})).toBeTruthy()); });
});
