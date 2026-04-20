# Quantum Risk Audit MVP - Project State

## Project Goal
Build a repo-link based MVP for a Quantum Risk Audit Copilot.

## MVP Flow
1. User pastes a GitHub repository link
2. System fetches repo files
3. System scans files for cryptographic touchpoints
4. System identifies quantum-vulnerable crypto usage
5. System shows affected files/modules
6. System explains risk in simple language
7. System suggests post-quantum migration actions
8. System generates a simple audit report

## Folder Structure
- frontend -> user interface
- backend -> scanning logic, repo fetching, report logic
- docs -> project notes and planning

## Rule
Keep MVP small and focused.
Do not add extra features before core scan flow works.

## Current Progress
- Base project folder created
- Frontend initialized with Next.js, TypeScript, Tailwind
- Backend initialized with Express, TypeScript
- Internal folder structure created

## Next Build Focus
1. Start backend server
2. Create frontend home page shell
3. Add repo link input
4. Connect frontend to backend
5. Fetch GitHub repo files
6. Scan repo files for crypto touchpoints