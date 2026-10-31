import type { Permission } from '../domain/permissions';
export const screens: readonly { path: string; title: string; group: string; permission: Permission; description: string }[] = [
  { path:'/dashboard', title:'Dashboard', group:'Workspace', permission:'dashboard', description:'Your workspace at a glance. Activity and time summaries will appear here.' },
  { path:'/tracker', title:'Time Tracker', group:'My workspace', permission:'tracker.own', description:'Track project work, take a break, and review each completed shift.' },
  { path:'/my-dtr', title:'My DTR', group:'My workspace', permission:'dtr.own', description:'Your daily time records, organized by the workspace calendar.' },
  { path:'/my-timesheets', title:'My Timesheets', group:'My workspace', permission:'timesheets.own', description:'Review your time for each semi-monthly cutoff.' },
  { path:'/manual-requests', title:'Manual Time Requests', group:'My workspace', permission:'requests.own', description:'Submit time corrections for authorized review.' },
  { path:'/contractors', title:'Contractor Directory', group:'Management', permission:'directory.read', description:'Find contractors within your authorized workspace scope.' },
  { path:'/contractor-records', title:'Contractor DTR and Timesheets', group:'Management', permission:'contractors.records', description:'Review daily records and timesheets for authorized contractors.' },
  { path:'/approvals', title:'Approval Queue', group:'Management', permission:'approvals.review', description:'Review manual time requests within your approval authority.' },
  { path:'/cutoff-review', title:'Cutoff Review', group:'Management', permission:'cutoffs.review', description:'Review the 1–15 and 16–month-end reporting periods.' },
  { path:'/reports', title:'Reports', group:'Management', permission:'reports.read', description:'Understand project time within your authorized scope.' },
  { path:'/settings', title:'Workspace Settings', group:'Administration', permission:'workspace.manage', description:'Manage ThriveSource workspace policies and calendar time zone.' },
];
